using System.Buffers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;

internal sealed class CaptureHandler : IHttpHeadersHandler, IHttpRequestLineHandler
{
    public string StartLine { get; private set; } = "";
    public List<string> Headers { get; } = [];
    public bool HeadersComplete { get; private set; }

    public void OnStartLine(HttpVersionAndMethod vm, TargetOffsetPathLength target, Span<byte> startLine)
        => StartLine = $"{vm.Method}|{vm.Version}|{target.Offset}|{target.Length}|{target.IsEncoded}|{Convert.ToHexString(startLine)}";

    public void OnStaticIndexedHeader(int index)
        => Headers.Add($"S:{index}");

    public void OnStaticIndexedHeader(int index, ReadOnlySpan<byte> value)
        => Headers.Add($"SV:{index}:{Convert.ToHexString(value)}");

    public void OnHeader(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
        => Headers.Add($"H:{Convert.ToHexString(name)}:{Convert.ToHexString(value)}");

    public void OnHeadersComplete(bool endStream)
    {
        HeadersComplete = true;
        Headers.Add($"E:{endStream}");
    }

    public string Fingerprint()
        => StartLine + "||" + string.Join("|", Headers) + $"||C:{HeadersComplete}";
}

internal sealed record Outcome(bool LineComplete, bool HeadersParsed, long Consumed, long Remaining, string Fingerprint, string Exception, string Unexpected)
{
    public string Stable()
        => $"{LineComplete}/{HeadersParsed}/{Consumed}/{Remaining}/{Exception}/{Fingerprint}";
}

internal sealed class Segment : ReadOnlySequenceSegment<byte>
{
    public Segment(ReadOnlyMemory<byte> memory) => Memory = memory;
    public Segment Append(ReadOnlyMemory<byte> memory)
    {
        var next = new Segment(memory) { RunningIndex = RunningIndex + Memory.Length };
        Next = next;
        return next;
    }
}

internal static class Program
{
    static readonly byte[][] Seeds =
    [
        A("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        A("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"),
        A("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        A("GET /a%2fb?x=%5c HTTP/1.1\r\nHost: x\r\nX-A: b\r\n\r\n"),
        A("OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"),
        A("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        A("GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        A("GET / HTTP/1.0\r\n\r\n"),
        A("GET / HTTP/1.1\nHost: x\n\n"),
        A("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
        A("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    ];

    static byte[] A(string s) => Encoding.ASCII.GetBytes(s);

    public static int Main(string[] args)
    {
        int iterations = args.Length > 0 && int.TryParse(args[0], out var n) ? n : 60000;
        int seed = args.Length > 1 && int.TryParse(args[1], out var s) ? s : 24681357;
        string outDir = args.Length > 2 ? args[2] : "out";
        Directory.CreateDirectory(outDir);

        var rng = new Random(seed);
        int candidates = 0;
        for (int i = 0; i < iterations; i++)
        {
            byte[] input = Mutate(rng, Seeds[rng.Next(Seeds.Length)]);
            Outcome baseline = Parse(input, 0, i);

            if (!string.IsNullOrEmpty(baseline.Unexpected))
            {
                Save(outDir, ++candidates, i, 0, input, baseline, baseline);
                continue;
            }

            for (int mode = 1; mode <= 3; mode++)
            {
                Outcome split = Parse(input, mode, i);
                bool mismatch = baseline.Stable() != split.Stable();
                bool unexpected = !string.IsNullOrEmpty(split.Unexpected);
                if (mismatch || unexpected)
                {
                    Save(outDir, ++candidates, i, mode, input, baseline, split);
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
        ReadOnlySequence<byte> seq = BuildSequence(input, mode, caseIndex);
        var reader = new SequenceReader<byte>(seq);
        var handler = new CaptureHandler();
        var parser = new HttpParser<CaptureHandler>(showErrorDetails: false);
        bool line = false, headers = false;
        try
        {
            line = parser.ParseRequestLine(handler, ref reader);
            if (line)
                headers = parser.ParseHeaders(handler, ref reader);

            return new Outcome(line, headers, reader.Consumed, reader.Remaining, handler.Fingerprint(), "", "");
        }
        catch (BadHttpRequestException ex)
        {
            return new Outcome(line, headers, reader.Consumed, reader.Remaining, handler.Fingerprint(),
                $"BadHttpRequest:{ex.StatusCode}", "");
        }
        catch (Exception ex)
        {
            return new Outcome(line, headers, reader.Consumed, reader.Remaining, handler.Fingerprint(),
                ex.GetType().FullName ?? ex.GetType().Name, ex.ToString());
        }
    }

    static ReadOnlySequence<byte> BuildSequence(byte[] data, int mode, int caseIndex)
    {
        if (mode == 0 || data.Length == 0)
            return new ReadOnlySequence<byte>(data);

        List<(int start, int len)> chunks = [];
        if (mode == 1 && data.Length <= 768)
        {
            for (int i = 0; i < data.Length; i++) chunks.Add((i, 1));
        }
        else if (mode == 2)
        {
            int start = 0;
            for (int i = 0; i < data.Length && chunks.Count < 1023; i++)
            {
                byte b = data[i];
                if (b is (byte)'\r' or (byte)'\n' or (byte)':' or (byte)' ' or (byte)'%' or (byte)'?' or (byte)'/' or (byte)'\\')
                {
                    int len = i + 1 - start;
                    if (len > 0) chunks.Add((start, len));
                    start = i + 1;
                }
            }
            if (start < data.Length) chunks.Add((start, data.Length - start));
            if (chunks.Count == 0) chunks.Add((0, data.Length));
        }
        else
        {
            var r = new Random(unchecked(caseIndex * 1103515245 + mode * 12345 + 17));
            int p = 0;
            while (p < data.Length)
            {
                int len = Math.Min(data.Length - p, r.Next(1, 18));
                chunks.Add((p, len));
                p += len;
            }
        }

        if (chunks.Count <= 1)
            return new ReadOnlySequence<byte>(data);

        Segment? first = null, last = null;
        foreach (var (start, len) in chunks)
        {
            ReadOnlyMemory<byte> mem = data.AsMemory(start, len);
            if (first is null)
            {
                first = last = new Segment(mem);
            }
            else
            {
                last = last!.Append(mem);
            }
        }
        return new ReadOnlySequence<byte>(first!, 0, last!, last!.Memory.Length);
    }

    static byte[] Mutate(Random r, byte[] seed)
    {
        byte[] d = seed.ToArray();
        byte[][] tokens =
        [
            A("\r\n"), A("\n"), A("\r"), A(":"), A(" "), A("\t"), A("%00"), A("%2f"), A("%5c"),
            A("Content-Length: 0\r\n"), A("Content-Length: 18446744073709551615\r\n"),
            A("Transfer-Encoding: chunked\r\n"), A("Transfer-Encoding: identity\r\n"),
            A("Host: a\r\n"), A("\r\n\r\n"), A("HTTP/1.1"), A("HTTP/1.0"),
            [0], [0xff], [0x7f], [0x80]
        ];

        int ops = r.Next(1, 14);
        for (int op = 0; op < ops; op++)
        {
            int choice = r.Next(8);
            if (choice == 0 && d.Length > 0)
                d[r.Next(d.Length)] ^= (byte)(1 << r.Next(8));
            else if (choice == 1 && d.Length > 0)
                d[r.Next(d.Length)] = (byte)r.Next(256);
            else if (choice == 2 && d.Length < 65536)
            {
                byte[] t = tokens[r.Next(tokens.Length)];
                int p = r.Next(d.Length + 1);
                d = d[..p].Concat(t).Concat(d[p..]).Take(65536).ToArray();
            }
            else if (choice == 3 && d.Length > 1)
            {
                int p = r.Next(d.Length);
                int len = r.Next(1, Math.Min(256, d.Length - p) + 1);
                d = d[..p].Concat(d[(p + len)..]).ToArray();
            }
            else if (choice == 4 && d.Length > 0 && d.Length < 65536)
            {
                int p = r.Next(d.Length);
                int len = Math.Min(r.Next(1, 257), d.Length - p);
                d = d.Concat(d.AsSpan(p, len).ToArray()).Take(65536).ToArray();
            }
            else if (choice == 5 && d.Length > 1)
                Array.Reverse(d, r.Next(d.Length), Math.Min(r.Next(1, 64), d.Length));
            else if (choice == 6 && d.Length < 65536)
                d = d.Concat(Enumerable.Repeat((byte)r.Next(256), r.Next(1, 512))).Take(65536).ToArray();
            else if (d.Length > 0)
            {
                int p = r.Next(d.Length);
                d[p] = r.Next(2) == 0 ? (byte)'\r' : (byte)'\n';
            }
        }
        return d;
    }

    static void Save(string outDir, int id, int caseIndex, int mode, byte[] input, Outcome baseline, Outcome split)
    {
        string stem = $"candidate-{id:D4}-{caseIndex:D7}-m{mode}";
        File.WriteAllBytes(Path.Combine(outDir, stem + ".bin"), input);
        File.WriteAllText(Path.Combine(outDir, stem + ".json"), JsonSerializer.Serialize(new
        {
            caseIndex,
            mode,
            baseline,
            split
        }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
