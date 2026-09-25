using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using Microsoft.CodeAnalysis.Scripting.Hosting;

internal static class Program
{
    private const string VictimAssemblyName = "VictimLib";
    private static readonly DateTime FixedTimestampUtc =
        new(2026, 9, 25, 12, 34, 56, DateTimeKind.Utc);

    public static async Task<int> Main(string[] args)
    {
        string mode = args.Length == 0 ? "test-all" : args[0];
        string root = Environment.GetEnvironmentVariable("LAB_ROOT")
            ?? Path.Combine(Path.GetTempPath(), "roslyn-filekey-lab");

        Console.WriteLine($"MODE={mode}");
        Console.WriteLine($"LAB_ROOT={root}");
        Console.WriteLine($"OS={System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
        Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"MICROSOFT_CODEANALYSIS_ASSEMBLY={typeof(MetadataReference).Assembly.GetName().Version}");
        Console.WriteLine($"CSHARP_SCRIPTING_ASSEMBLY={typeof(CSharpScript).Assembly.GetName().Version}");

        try
        {
            return mode switch
            {
                "test-all" => await TestAllAsync(root),
                "process-prime" => ProcessPrime(root),
                "process-consume" => await ProcessConsumeAsync(root),
                _ => throw new ArgumentException($"Unknown mode: {mode}")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FATAL:");
            Console.Error.WriteLine(ex);
            return 99;
        }
    }

    private static async Task<int> TestAllAsync(string root)
    {
        ResetDirectory(root);

        bool positive = await RunScenarioAsync(
            Path.Combine(root, "positive"),
            trustedFileName: "A.dll",
            trustedTimestampOffsetSeconds: 0,
            prime: true,
            resetProviderAfterPrime: false,
            expectedResult: "ATTACKER",
            expectedCollision: true);

        bool timestampControl = await RunScenarioAsync(
            Path.Combine(root, "control-timestamp"),
            trustedFileName: "A.dll",
            trustedTimestampOffsetSeconds: 2,
            prime: true,
            resetProviderAfterPrime: false,
            expectedResult: "TRUSTED",
            expectedCollision: false);

        bool pathControl = await RunScenarioAsync(
            Path.Combine(root, "control-path"),
            trustedFileName: "B.dll",
            trustedTimestampOffsetSeconds: 0,
            prime: true,
            resetProviderAfterPrime: false,
            expectedResult: "TRUSTED",
            expectedCollision: false);

        bool cacheResetControl = await RunScenarioAsync(
            Path.Combine(root, "control-cache-reset"),
            trustedFileName: "A.dll",
            trustedTimestampOffsetSeconds: 0,
            prime: true,
            resetProviderAfterPrime: true,
            expectedResult: "TRUSTED",
            expectedCollision: false);

        bool noPrimeControl = await RunScenarioAsync(
            Path.Combine(root, "control-no-prime"),
            trustedFileName: "A.dll",
            trustedTimestampOffsetSeconds: 0,
            prime: false,
            resetProviderAfterPrime: false,
            expectedResult: "TRUSTED",
            expectedCollision: false);

        bool ok = positive && timestampControl && pathControl && cacheResetControl && noPrimeControl;
        Console.WriteLine($"TEST_ALL_OK={ok}");
        return ok ? 0 : 20;
    }

    private static int ProcessPrime(string root)
    {
        string dir = Path.Combine(root, "process-boundary");
        PreparePair(dir, "A.dll", trustedTimestampOffsetSeconds: 0);

        string attacker = Path.Combine(dir, "a.dll");
        string trusted = Path.Combine(dir, "A.dll");

        using var provider = CreateProvider(dir, "prime-process-shadow");
        _ = provider.GetMetadata(attacker, MetadataImageKind.Assembly);

        var aCopy = provider.GetMetadataShadowCopy(attacker, MetadataImageKind.Assembly)
            ?? throw new InvalidOperationException("Attacker file unexpectedly not shadow copied.");
        var bLookup = provider.GetMetadataShadowCopy(trusted, MetadataImageKind.Assembly)
            ?? throw new InvalidOperationException("Trusted file unexpectedly not shadow copied.");

        PrintCollisionEvidence("PROCESS_PRIME", attacker, trusted, aCopy, bLookup);
        Console.WriteLine("PROCESS_PRIME_COMPLETE=true");
        return 0;
    }

    private static async Task<int> ProcessConsumeAsync(string root)
    {
        string dir = Path.Combine(root, "process-boundary");
        string attacker = Path.Combine(dir, "a.dll");
        string trusted = Path.Combine(dir, "A.dll");
        if (!File.Exists(attacker) || !File.Exists(trusted))
        {
            throw new FileNotFoundException("Run process-prime first; original pair is missing.");
        }

        using var provider = CreateProvider(dir, "consume-process-shadow");
        string canary = Path.Combine(dir, "process-consume-canary.txt");
        string result = await ExecuteTrustedReferenceAsync(provider, trusted, canary);

        bool ok = result == "TRUSTED" && !File.Exists(canary);
        Console.WriteLine($"PROCESS_CONSUME_RESULT={result}");
        Console.WriteLine($"PROCESS_BOUNDARY_CACHE_SURVIVED={result == "ATTACKER"}");
        Console.WriteLine($"PROCESS_BOUNDARY_OK={ok}");
        return ok ? 0 : 21;
    }

    private static async Task<bool> RunScenarioAsync(
        string dir,
        string trustedFileName,
        int trustedTimestampOffsetSeconds,
        bool prime,
        bool resetProviderAfterPrime,
        string expectedResult,
        bool expectedCollision)
    {
        PreparePair(dir, trustedFileName, trustedTimestampOffsetSeconds);

        string attacker = Path.Combine(dir, "a.dll");
        string trusted = Path.Combine(dir, trustedFileName);
        string canary = Path.Combine(dir, "canary.txt");

        MetadataShadowCopyProvider? provider = null;
        try
        {
            provider = CreateProvider(dir, "shadow-1");

            if (prime)
            {
                // Metadata-only primer: no attacker assembly is loaded or executed here.
                _ = provider.GetMetadata(attacker, MetadataImageKind.Assembly);
                Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} METADATA_ONLY_PRIME=true");
            }

            if (resetProviderAfterPrime)
            {
                provider.Dispose();
                provider = CreateProvider(dir, "shadow-2");
                Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} PROVIDER_RESET=true");
            }

            var trustedLookup = provider.GetMetadataShadowCopy(trusted, MetadataImageKind.Assembly)
                ?? throw new InvalidOperationException("Trusted file unexpectedly not shadow copied.");

            bool collision;
            if (prime && !resetProviderAfterPrime)
            {
                var attackerLookup = provider.GetMetadataShadowCopy(attacker, MetadataImageKind.Assembly)
                    ?? throw new InvalidOperationException("Attacker file unexpectedly not shadow copied.");
                collision = ReferenceEquals(attackerLookup, trustedLookup);
                PrintCollisionEvidence(Path.GetFileName(dir), attacker, trusted, attackerLookup, trustedLookup);
            }
            else
            {
                collision = false;
                Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} TRUSTED_LOOKUP_ORIGINAL={trustedLookup.PrimaryModule.OriginalPath}");
                Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} TRUSTED_LOOKUP_HASH={HashFile(trustedLookup.PrimaryModule.FullPath)}");
            }

            string result = await ExecuteTrustedReferenceAsync(provider, trusted, canary);
            bool canaryExists = File.Exists(canary);
            string? canaryContents = canaryExists ? File.ReadAllText(canary) : null;

            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} EXPECTED_COLLISION={expectedCollision}");
            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} ACTUAL_COLLISION={collision}");
            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} EXPECTED_RESULT={expectedResult}");
            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} ACTUAL_RESULT={result}");
            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} CANARY_EXISTS={canaryExists}");
            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} CANARY_CONTENTS={canaryContents ?? "<none>"}");

            bool expectedCanary = expectedResult == "ATTACKER";
            bool ok =
                collision == expectedCollision &&
                result == expectedResult &&
                canaryExists == expectedCanary &&
                (!canaryExists || canaryContents == "ATTACKER_CANARY");

            Console.WriteLine($"SCENARIO={Path.GetFileName(dir)} OK={ok}");
            return ok;
        }
        finally
        {
            provider?.Dispose();
        }
    }

    private static MetadataShadowCopyProvider CreateProvider(string scenarioDir, string shadowName)
    {
        string shadowRoot = Path.Combine(scenarioDir, shadowName);
        Directory.CreateDirectory(shadowRoot);
        return new MetadataShadowCopyProvider(shadowRoot);
    }

    private static async Task<string> ExecuteTrustedReferenceAsync(
        MetadataShadowCopyProvider provider,
        string trustedPath,
        string canaryPath)
    {
        if (File.Exists(canaryPath))
        {
            File.Delete(canaryPath);
        }

        string? oldCanary = Environment.GetEnvironmentVariable("FILEKEY_CANARY");
        Environment.SetEnvironmentVariable("FILEKEY_CANARY", canaryPath);

        try
        {
            using var loader = new InteractiveAssemblyLoader(provider);
            var trustedReference = MetadataReference.CreateFromFile(trustedPath);
            var options = ScriptOptions.Default
                .AddReferences(trustedReference)
                .AddImports("VictimLib");

            var script = CSharpScript.Create<string>(
                "Marker.Get()",
                options: options,
                assemblyLoader: loader);

            var diagnostics = script.Compile();
            foreach (var diagnostic in diagnostics)
            {
                Console.WriteLine($"SCRIPT_DIAGNOSTIC={diagnostic}");
            }

            if (diagnostics.Any(d => d.Severity == DiagnosticSeverity.Error))
            {
                throw new InvalidOperationException("Script compilation failed.");
            }

            var state = await script.RunAsync();
            return state.ReturnValue ?? "<null>";
        }
        finally
        {
            Environment.SetEnvironmentVariable("FILEKEY_CANARY", oldCanary);
        }
    }

    private static void PreparePair(string dir, string trustedFileName, int trustedTimestampOffsetSeconds)
    {
        ResetDirectory(dir);

        string attacker = Path.Combine(dir, "a.dll");
        string trusted = Path.Combine(dir, trustedFileName);

        EmitLibrary(attacker, malicious: true);
        EmitLibrary(trusted, malicious: false);

        File.SetLastWriteTimeUtc(attacker, FixedTimestampUtc);
        File.SetLastWriteTimeUtc(trusted, FixedTimestampUtc.AddSeconds(trustedTimestampOffsetSeconds));

        if (string.Equals(attacker, trusted, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Paths unexpectedly identical.");
        }

        string attackerHash = HashFile(attacker);
        string trustedHash = HashFile(trusted);
        if (attackerHash == trustedHash)
        {
            throw new InvalidOperationException("Attacker and trusted files unexpectedly have identical content.");
        }

        Console.WriteLine($"PAIR_DIR={dir}");
        Console.WriteLine($"ATTACKER_PATH={attacker}");
        Console.WriteLine($"TRUSTED_PATH={trusted}");
        Console.WriteLine($"ORDINAL_EQUAL={string.Equals(attacker, trusted, StringComparison.Ordinal)}");
        Console.WriteLine($"ORDINAL_IGNORE_CASE_EQUAL={string.Equals(attacker, trusted, StringComparison.OrdinalIgnoreCase)}");
        Console.WriteLine($"ATTACKER_TIMESTAMP={File.GetLastWriteTimeUtc(attacker):O}");
        Console.WriteLine($"TRUSTED_TIMESTAMP={File.GetLastWriteTimeUtc(trusted):O}");
        Console.WriteLine($"TIMESTAMPS_EQUAL={File.GetLastWriteTimeUtc(attacker) == File.GetLastWriteTimeUtc(trusted)}");
        Console.WriteLine($"ATTACKER_SHA256={attackerHash}");
        Console.WriteLine($"TRUSTED_SHA256={trustedHash}");
        Console.WriteLine($"ATTACKER_MVID={ReadMvid(attacker)}");
        Console.WriteLine($"TRUSTED_MVID={ReadMvid(trusted)}");

        var fileKeyEvidence = GetRoslynFileKeyEvidence(attacker, trusted);
        Console.WriteLine($"ROSLYN_FILEKEY_TYPE={fileKeyEvidence.TypeName}");
        Console.WriteLine($"ROSLYN_FILEKEY_EQUALS={fileKeyEvidence.Equal}");
        Console.WriteLine($"ROSLYN_FILEKEY_HASH_A={fileKeyEvidence.HashA}");
        Console.WriteLine($"ROSLYN_FILEKEY_HASH_B={fileKeyEvidence.HashB}");
    }

    private static void EmitLibrary(string outputPath, bool malicious)
    {
        string body = malicious
            ? """
              using System;
              using System.IO;
              using System.Reflection;
              [assembly: AssemblyVersion("1.0.0.0")]
              namespace VictimLib
              {
                  public static class Marker
                  {
                      public static string Get()
                      {
                          var path = Environment.GetEnvironmentVariable("FILEKEY_CANARY");
                          if (!string.IsNullOrEmpty(path))
                          {
                              File.WriteAllText(path, "ATTACKER_CANARY");
                          }
                          return "ATTACKER";
                      }
                  }
              }
              """
            : """
              using System.Reflection;
              [assembly: AssemblyVersion("1.0.0.0")]
              namespace VictimLib
              {
                  public static class Marker
                  {
                      public static string Get() => "TRUSTED";
                  }
              }
              """;

        var syntaxTree = CSharpSyntaxTree.ParseText(body);
        var references = GetPlatformReferences();

        var compilation = CSharpCompilation.Create(
            VictimAssemblyName,
            new[] { syntaxTree },
            references,
            new CSharpCompilationOptions(
                OutputKind.DynamicallyLinkedLibrary,
                optimizationLevel: OptimizationLevel.Release,
                deterministic: true));

        using var stream = File.Create(outputPath);
        var emit = compilation.Emit(stream);
        if (!emit.Success)
        {
            throw new InvalidOperationException(
                "Victim library compilation failed:" + Environment.NewLine +
                string.Join(Environment.NewLine, emit.Diagnostics));
        }
    }

    private static IEnumerable<MetadataReference> GetPlatformReferences()
    {
        string? tpa = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string;
        if (string.IsNullOrEmpty(tpa))
        {
            throw new InvalidOperationException("TRUSTED_PLATFORM_ASSEMBLIES is unavailable.");
        }

        return tpa.Split(Path.PathSeparator)
            .Distinct(StringComparer.Ordinal)
            .Select(static p => MetadataReference.CreateFromFile(p));
    }

    private static (string TypeName, bool Equal, int HashA, int HashB) GetRoslynFileKeyEvidence(
        string attacker,
        string trusted)
    {
        var codeAnalysis = typeof(MetadataReference).Assembly;
        var type = codeAnalysis.GetType("Roslyn.Utilities.FileKey", throwOnError: true)
            ?? throw new InvalidOperationException("Roslyn.Utilities.FileKey type not found.");

        var create = type.GetMethod(
            "Create",
            BindingFlags.Public | BindingFlags.Static,
            binder: null,
            types: new[] { typeof(string) },
            modifiers: null)
            ?? throw new MissingMethodException(type.FullName, "Create(string)");

        object keyA = create.Invoke(null, new object[] { attacker })
            ?? throw new InvalidOperationException("FileKey.Create(attacker) returned null.");
        object keyB = create.Invoke(null, new object[] { trusted })
            ?? throw new InvalidOperationException("FileKey.Create(trusted) returned null.");

        return (type.AssemblyQualifiedName ?? type.FullName ?? type.Name, keyA.Equals(keyB), keyA.GetHashCode(), keyB.GetHashCode());
    }

    private static void PrintCollisionEvidence(
        string scenario,
        string attacker,
        string trusted,
        MetadataShadowCopy attackerLookup,
        MetadataShadowCopy trustedLookup)
    {
        string attackerOriginal = attackerLookup.PrimaryModule.OriginalPath;
        string trustedLookupOriginal = trustedLookup.PrimaryModule.OriginalPath;
        string attackerShadowHash = HashFile(attackerLookup.PrimaryModule.FullPath);
        string trustedLookupShadowHash = HashFile(trustedLookup.PrimaryModule.FullPath);

        Console.WriteLine($"SCENARIO={scenario} CACHE_REFERENCE_EQUAL={ReferenceEquals(attackerLookup, trustedLookup)}");
        Console.WriteLine($"SCENARIO={scenario} ATTACKER_LOOKUP_ORIGINAL={attackerOriginal}");
        Console.WriteLine($"SCENARIO={scenario} TRUSTED_REQUEST_PATH={trusted}");
        Console.WriteLine($"SCENARIO={scenario} TRUSTED_LOOKUP_ORIGINAL={trustedLookupOriginal}");
        Console.WriteLine($"SCENARIO={scenario} ATTACKER_LOOKUP_SHADOW={attackerLookup.PrimaryModule.FullPath}");
        Console.WriteLine($"SCENARIO={scenario} TRUSTED_LOOKUP_SHADOW={trustedLookup.PrimaryModule.FullPath}");
        Console.WriteLine($"SCENARIO={scenario} ATTACKER_LOOKUP_SHADOW_HASH={attackerShadowHash}");
        Console.WriteLine($"SCENARIO={scenario} TRUSTED_LOOKUP_SHADOW_HASH={trustedLookupShadowHash}");
        Console.WriteLine($"SCENARIO={scenario} ATTACKER_ORIGINAL_HASH={HashFile(attacker)}");
        Console.WriteLine($"SCENARIO={scenario} TRUSTED_ORIGINAL_HASH={HashFile(trusted)}");
    }

    private static Guid ReadMvid(string path)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        var reader = pe.GetMetadataReader();
        return reader.GetGuid(reader.GetModuleDefinition().Mvid);
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void ResetDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }

        Directory.CreateDirectory(path);
    }
}
