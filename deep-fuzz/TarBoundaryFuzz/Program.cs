using System.Formats.Tar;
using System.Text;
using System.Text.Json;

internal sealed record Candidate(int CaseIndex, int Mode, string EntryName, string LinkName, string Observation, string Exception);

internal static class Program
{
    public static int Main(string[] args)
    {
        int iterations = args.Length > 0 && int.TryParse(args[0], out var n) ? n : 8000;
        int seed = args.Length > 1 && int.TryParse(args[1], out var s) ? s : 314159;
        string outDir = args.Length > 2 ? args[2] : "out";
        Directory.CreateDirectory(outDir);

        var rng = new Random(seed);
        int candidates = 0;

        for (int i = 0; i < iterations; i++)
        {
            int mode = rng.Next(3);
            string root = Path.Combine(Path.GetTempPath(), "dotnet-tar-fuzz", $"{Environment.ProcessId}-{i}");
            string dest = Path.Combine(root, "dest");
            string outside = Path.Combine(root, "outside");
            Directory.CreateDirectory(dest);
            Directory.CreateDirectory(outside);

            string outsideTarget = Path.Combine(outside, "target.txt");
            File.WriteAllText(outsideTarget, "SAFE", Encoding.UTF8);

            string token = $"p{i:D6}.txt";
            string sep = PickSeparator(rng);
            string directName = PickTraversal(rng, sep, token);
            string linkName = PickLinkTarget(rng, sep);

            byte[] archive;
            string entryName;
            try
            {
                archive = mode switch
                {
                    0 => BuildDirectTraversalArchive(directName, out entryName),
                    1 => BuildSymlinkChainArchive(linkName, token, sep, out entryName),
                    _ => BuildHardlinkOverwriteArchive(linkName, out entryName)
                };
            }
            catch (Exception ex)
            {
                Save(outDir, ++candidates, archive: null, new Candidate(i, mode, directName, linkName, "archive-construction", ex.ToString()));
                Cleanup(root);
                if (candidates >= 100) break;
                continue;
            }

            string exception = "";
            try
            {
                using var ms = new MemoryStream(archive, writable: false);
                TarFile.ExtractToDirectory(ms, dest, overwriteFiles: true);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                exception = ex.GetType().FullName ?? ex.GetType().Name;
            }
            catch (Exception ex)
            {
                Save(outDir, ++candidates, archive, new Candidate(i, mode, entryName, linkName, "unexpected-exception", ex.ToString()));
                Cleanup(root);
                if (candidates >= 100) break;
                continue;
            }

            bool escapedPayload = Directory.EnumerateFiles(outside, "*", SearchOption.AllDirectories)
                .Any(p => !Path.GetFullPath(p).Equals(Path.GetFullPath(outsideTarget), StringComparison.OrdinalIgnoreCase));

            string targetContents = File.Exists(outsideTarget) ? File.ReadAllText(outsideTarget, Encoding.UTF8) : "<missing>";
            bool modifiedOutside = targetContents != "SAFE";

            if (escapedPayload || modifiedOutside)
            {
                string observation = $"escapedPayload={escapedPayload};modifiedOutside={modifiedOutside};target={Convert.ToHexString(Encoding.UTF8.GetBytes(targetContents))}";
                Save(outDir, ++candidates, archive, new Candidate(i, mode, entryName, linkName, observation, exception));
                if (candidates >= 100)
                {
                    Cleanup(root);
                    break;
                }
            }

            Cleanup(root);
        }

        File.WriteAllText(Path.Combine(outDir, "summary.txt"),
            $"iterations={iterations}{Environment.NewLine}seed={seed}{Environment.NewLine}candidates={candidates}{Environment.NewLine}os={Environment.OSVersion}{Environment.NewLine}");
        Console.WriteLine($"DONE iterations={iterations} candidates={candidates}");
        return 0;
    }

    static string PickSeparator(Random r)
    {
        if (OperatingSystem.IsWindows())
            return r.Next(3) switch { 0 => "/", 1 => "\\", _ => r.Next(2) == 0 ? "/\\" : "\\/" };
        return "/";
    }

    static string PickTraversal(Random r, string sep, string token)
    {
        return r.Next(6) switch
        {
            0 => $"..{sep}outside{sep}{token}",
            1 => $"a{sep}..{sep}..{sep}outside{sep}{token}",
            2 => $".{sep}..{sep}outside{sep}{token}",
            3 => $"a{sep}.{sep}..{sep}..{sep}outside{sep}{token}",
            4 => $"a{sep}b{sep}..{sep}..{sep}..{sep}outside{sep}{token}",
            _ => $"..{sep}outside{sep}.{sep}{token}"
        };
    }

    static string PickLinkTarget(Random r, string sep)
        => r.Next(3) switch
        {
            0 => $"..{sep}outside",
            1 => $".{sep}..{sep}outside",
            _ => $"a{sep}..{sep}..{sep}outside"
        };

    static byte[] BuildDirectTraversalArchive(string name, out string entryName)
    {
        entryName = name;
        using var ms = new MemoryStream();
        using (var writer = new TarWriter(ms, leaveOpen: true))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("PAYLOAD"), writable: false)
            };
            writer.WriteEntry(entry);
        }
        return ms.ToArray();
    }

    static byte[] BuildSymlinkChainArchive(string linkTarget, string token, string sep, out string entryName)
    {
        entryName = $"link{sep}{token}";
        using var ms = new MemoryStream();
        using (var writer = new TarWriter(ms, leaveOpen: true))
        {
            var link = new PaxTarEntry(TarEntryType.SymbolicLink, "link") { LinkName = linkTarget };
            writer.WriteEntry(link);

            var payload = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("PAYLOAD"), writable: false)
            };
            writer.WriteEntry(payload);
        }
        return ms.ToArray();
    }

    static byte[] BuildHardlinkOverwriteArchive(string linkTarget, out string entryName)
    {
        entryName = "alias";
        string target = linkTarget.Replace("outside", "outside/target.txt", StringComparison.Ordinal);
        using var ms = new MemoryStream();
        using (var writer = new TarWriter(ms, leaveOpen: true))
        {
            var hard = new PaxTarEntry(TarEntryType.HardLink, entryName) { LinkName = target };
            writer.WriteEntry(hard);

            var overwrite = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes("CHANGED"), writable: false)
            };
            writer.WriteEntry(overwrite);
        }
        return ms.ToArray();
    }

    static void Save(string outDir, int id, byte[]? archive, Candidate candidate)
    {
        string stem = $"candidate-{id:D4}-{candidate.CaseIndex:D7}";
        if (archive is not null)
            File.WriteAllBytes(Path.Combine(outDir, stem + ".tar"), archive);
        File.WriteAllText(Path.Combine(outDir, stem + ".json"),
            JsonSerializer.Serialize(candidate, new JsonSerializerOptions { WriteIndented = true }));
    }

    static void Cleanup(string root)
    {
        try
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
        catch { }
    }
}
