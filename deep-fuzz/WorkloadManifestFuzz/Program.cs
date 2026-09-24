using System.Text;
using System.Text.Json;
using Microsoft.NET.Sdk.WorkloadManifestReader;

internal sealed class ChunkedReadStream : Stream
{
    private readonly byte[] _data;
    private readonly int _maxChunk;
    private readonly Random? _random;
    private int _pos;

    public ChunkedReadStream(byte[] data, int maxChunk, int seed = 0, bool randomize = false)
    {
        _data = data;
        _maxChunk = Math.Max(1, maxChunk);
        if (randomize) _random = new Random(seed);
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _data.Length;
    public override long Position { get => _pos; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_pos >= _data.Length) return 0;
        int cap = _random is null ? _maxChunk : _random.Next(1, _maxChunk + 1);
        int n = Math.Min(Math.Min(count, cap), _data.Length - _pos);
        Buffer.BlockCopy(_data, _pos, buffer, offset, n);
        _pos += n;
        return n;
    }

    public override int Read(Span<byte> buffer)
    {
        if (_pos >= _data.Length) return 0;
        int cap = _random is null ? _maxChunk : _random.Next(1, _maxChunk + 1);
        int n = Math.Min(Math.Min(buffer.Length, cap), _data.Length - _pos);
        _data.AsSpan(_pos, n).CopyTo(buffer);
        _pos += n;
        return n;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal sealed record Outcome(bool Success, string Fingerprint, string Exception, string Unexpected)
{
    public string Stable() => $"{Success}|{Exception}|{Fingerprint}";
}

internal static class Program
{
    static readonly string[] Seeds =
    [
        """{"version":"1.0.0","workloads":{},"packs":{}}""",
        """{"version":5,"description":"x","workloads":{},"packs":{}}""",
        """{"version":"8.0.100","workloads":{"w":{"description":"demo","packs":["p"]}},"packs":{"p":{"kind":"sdk","version":"1.2.3"}}}""",
        """{"version":"9.0.100","depends-on":{"a":"1.0.0","B":"2.0.0"},"workloads":{},"packs":{}}""",
        """{"version":"10.0.100","data":{"a":[1,2,{"x":true,"y":null}]},"workloads":{},"packs":{}}""",
        """{"version":"11.0.100","workloads":{"a":{"packs":["p1","p2"]},"b":{"packs":[]}},"packs":{"p1":{"kind":"framework","version":"1.0.0"},"p2":{"kind":"template","version":"2.0.0"}}}"""
    ];

    public static int Main(string[] args)
    {
        int iterations = args.Length > 0 && int.TryParse(args[0], out var n) ? n : 70000;
        int seed = args.Length > 1 && int.TryParse(args[1], out var s) ? s : 97531;
        string outDir = args.Length > 2 ? args[2] : "out";
        Directory.CreateDirectory(outDir);

        var rng = new Random(seed);
        int candidates = 0;
        for (int i = 0; i < iterations; i++)
        {
            byte[] input = Encoding.UTF8.GetBytes(Mutate(rng, Seeds[rng.Next(Seeds.Length)]));
            Outcome baseline = Parse(input, 0, i);

            if (!string.IsNullOrEmpty(baseline.Unexpected))
            {
                Save(outDir, ++candidates, i, 0, input, baseline, baseline);
                if (candidates >= 200) break;
                continue;
            }

            for (int mode = 1; mode <= 4; mode++)
            {
                Outcome other = Parse(input, mode, i);
                if (!string.IsNullOrEmpty(other.Unexpected) || baseline.Stable() != other.Stable())
                {
                    Save(outDir, ++candidates, i, mode, input, baseline, other);
                    if (candidates >= 200) goto Done;
                }
            }
        }

    Done:
        File.WriteAllText(Path.Combine(outDir, "summary.txt"),
            $"iterations={iterations}{Environment.NewLine}seed={seed}{Environment.NewLine}candidates={candidates}{Environment.NewLine}");
        Console.WriteLine($"DONE iterations={iterations} candidates={candidates}");
        return 0;
    }

    static Outcome Parse(byte[] input, int mode, int caseIndex)
    {
        try
        {
            using Stream stream = mode switch
            {
                0 => new MemoryStream(input, writable: false),
                1 => new ChunkedReadStream(input, 1),
                2 => new ChunkedReadStream(input, 2),
                3 => new ChunkedReadStream(input, 7),
                _ => new ChunkedReadStream(input, 31, unchecked(caseIndex * 7919 + 17), randomize: true)
            };

            WorkloadManifest m = WorkloadManifestReader.ReadWorkloadManifest("fuzz", stream, "manifest.json");
            string workloads = string.Join(",", m.Workloads.Keys.Select(k => k.ToString()).OrderBy(x => x, StringComparer.Ordinal));
            string packs = string.Join(",", m.Packs.Keys.Select(k => k.ToString()).OrderBy(x => x, StringComparer.Ordinal));
            string fp = $"{m.Id}|{m.Version}|{Hex(m.Description ?? "")}|W:{workloads}|P:{packs}";
            return new Outcome(true, fp, "", "");
        }
        catch (Exception ex) when (ex is WorkloadManifestFormatException or JsonException or ArgumentException or FormatException or IOException or OverflowException)
        {
            return new Outcome(false, "", ex.GetType().FullName ?? ex.GetType().Name, "");
        }
        catch (Exception ex)
        {
            return new Outcome(false, "", ex.GetType().FullName ?? ex.GetType().Name, ex.ToString());
        }
    }

    static string Hex(string s) => Convert.ToHexString(Encoding.UTF8.GetBytes(s));

    static string Mutate(Random r, string seed)
    {
        string s = seed;
        string[] tokens =
        [
            "{", "}", "[", "]", ":", ",", """, "\\", "\u0000", "\uD800", "\uFFFF",
            ""version":", ""workloads":", ""packs":", ""depends-on":", ""data":",
            "null", "true", "false", "0", "-1", "2147483648", "9223372036854775808",
            ""1.0.0"", ""999999999.999999999.999999999"", ""../x"", ""A"", ""a""
        ];

        int ops = r.Next(1, 14);
        for (int op = 0; op < ops; op++)
        {
            int choice = r.Next(8);
            if (choice == 0 && s.Length > 0)
            {
                int p = r.Next(s.Length);
                s = s[..p] + (char)r.Next(0x20, 0x100) + s[(p + 1)..];
            }
            else if (choice == 1 && s.Length < 65536)
            {
                int p = r.Next(s.Length + 1);
                string t = tokens[r.Next(tokens.Length)];
                s = (s[..p] + t + s[p..]);
            }
            else if (choice == 2 && s.Length > 1)
            {
                int p = r.Next(s.Length);
                int len = r.Next(1, Math.Min(256, s.Length - p) + 1);
                s = s[..p] + s[(p + len)..];
            }
            else if (choice == 3 && s.Length > 0 && s.Length < 65536)
            {
                int p = r.Next(s.Length);
                int len = Math.Min(r.Next(1, 257), s.Length - p);
                s = (s + s.Substring(p, len)).Length > 65536 ? (s + s.Substring(p, len))[..65536] : s + s.Substring(p, len);
            }
            else if (choice == 4 && s.Length < 65536)
                s = (s + new string(r.Next(2) == 0 ? '[' : '{', r.Next(1, 128)))[..Math.Min(65536, s.Length + r.Next(1, 128))];
            else if (choice == 5)
                s = s.Replace("version", r.Next(2) == 0 ? "Version" : "VERSION", StringComparison.Ordinal);
            else if (choice == 6 && s.Length > 0)
                s = new string(s.Reverse().ToArray());
            else if (s.Length < 65536)
                s += tokens[r.Next(tokens.Length)];
        }

        return s.Length <= 65536 ? s : s[..65536];
    }

    static void Save(string outDir, int id, int caseIndex, int mode, byte[] input, Outcome baseline, Outcome other)
    {
        string stem = $"candidate-{id:D4}-{caseIndex:D7}-m{mode}";
        File.WriteAllBytes(Path.Combine(outDir, stem + ".bin"), input);
        File.WriteAllText(Path.Combine(outDir, stem + ".json"), JsonSerializer.Serialize(new
        {
            caseIndex,
            mode,
            baseline,
            other
        }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
