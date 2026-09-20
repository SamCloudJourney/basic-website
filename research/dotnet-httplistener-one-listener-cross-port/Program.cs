using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    private static readonly string SideEffectPath =
        Path.Combine(Path.GetTempPath(), "httplistener-one-listener-cross-port-4b19.txt");

    record Obs(
        string Name,
        string FirstLine,
        bool BasicChallenge,
        bool ContextDelivered,
        AuthenticationSchemes Selected,
        string UserHostName,
        string UrlAuthority,
        int LocalPort,
        string Path,
        bool Anonymous,
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

    static async Task<string> ReadWire(NetworkStream ns)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while (true)
            {
                int n = await ns.ReadAsync(buf, cts.Token);
                if (n == 0) break;
                await ms.WriteAsync(buf.AsMemory(0, n), cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    static async Task<Obs> RunCase(
        string name,
        int publicPort,
        int adminPort,
        int connectPort,
        string target,
        string host,
        bool executeAdminAction)
    {
        try { File.Delete(SideEffectPath); } catch { }

        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://app.test:{publicPort}/public/");
        listener.Prefixes.Add($"http://app.test:{adminPort}/admin/");
        listener.AuthenticationSchemes = AuthenticationSchemes.None;
        listener.Realm = "one-listener-cross-port";

        AuthenticationSchemes selected = AuthenticationSchemes.None;
        string selectorUserHost = "<not-called>";
        string selectorUrlAuthority = "<not-called>";

        listener.AuthenticationSchemeSelectorDelegate = request =>
        {
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlAuthority = request.Url?.Authority ?? "<null>";

            int colon = selectorUserHost.LastIndexOf(':');
            int seenPort = colon >= 0 &&
                int.TryParse(selectorUserHost[(colon + 1)..], out int parsed)
                    ? parsed : -1;

            selected = seenPort == publicPort
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"SELECTOR case={name} UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} SeenPort={seenPort} PublicPort={publicPort} AdminPort={adminPort} Selected={selected}");
            return selected;
        };

        listener.Start();
        Task<HttpListenerContext> contextTask = listener.GetContextAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, connectPort);
        using NetworkStream ns = client.GetStream();

        string method = executeAdminAction ? "POST" : "GET";
        string raw =
            $"{method} {target} HTTP/1.1\r\n" +
            $"Host: {host}\r\n" +
            (executeAdminAction ? "Content-Length: 0\r\n" : "") +
            "Connection: close\r\n\r\n";

        Console.WriteLine(
            $"RAW case={name} connectedPort={connectPort} requestTarget={target} Host={host}");

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        int localPort = -1;
        string path = "<none>";
        bool anonymous = false;

        Task handler = Task.Run(async () =>
        {
            Task first = await Task.WhenAny(contextTask, Task.Delay(4000));
            if (first != contextTask || !contextTask.IsCompletedSuccessfully)
                return;

            HttpListenerContext ctx = await contextTask;
            localPort = ctx.Request.LocalEndPoint.Port;
            path = ctx.Request.Url?.AbsolutePath ?? "<null>";
            anonymous = ctx.User is null;

            Console.WriteLine(
                $"CONTEXT case={name} LocalPort={localPort} UserHostName={ctx.Request.UserHostName} UrlAuthority={ctx.Request.Url?.Authority} Path={path} User={(anonymous ? "ANONYMOUS" : "AUTHENTICATED")}");

            byte[] body;
            if (executeAdminAction && localPort == adminPort && path == "/admin/action")
            {
                File.WriteAllText(SideEffectPath, "ONE_LISTENER_PROTECTED_ADMIN_CHANGE_EXECUTED");
                body = Encoding.ASCII.GetBytes("ONE_LISTENER_ADMIN_ACTION_EXECUTED_4b19\n");
            }
            else
            {
                body = Encoding.ASCII.GetBytes("PUBLIC_OK\n");
            }

            ctx.Response.StatusCode = 200;
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        });

        string wire = await ReadWire(ns);
        await Task.WhenAny(handler, Task.Delay(1000));

        string firstLine = wire.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)[0];
        bool basicChallenge =
            wire.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase);
        bool delivered = contextTask.IsCompletedSuccessfully;
        bool sideEffect = File.Exists(SideEffectPath);

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basicChallenge} context={delivered} selected={selected} selectorUserHost={selectorUserHost} selectorUrlAuthority={selectorUrlAuthority} localPort={localPort} path={path} anonymous={anonymous} sideEffect={sideEffect}");

        listener.Close();

        return new Obs(
            name, firstLine, basicChallenge, delivered, selected,
            selectorUserHost, selectorUrlAuthority, localPort, path,
            anonymous, sideEffect);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        int publicPort = FreePort();
        int adminPort = FreePort();
        while (adminPort == publicPort) adminPort = FreePort();

        Obs publicControl = await RunCase(
            "PUBLIC_CONTROL",
            publicPort, adminPort,
            connectPort: publicPort,
            target: "/public/ping",
            host: $"app.test:{publicPort}",
            executeAdminAction: false);

        Obs adminControl = await RunCase(
            "ADMIN_CONTROL",
            publicPort, adminPort,
            connectPort: adminPort,
            target: "/admin/action",
            host: $"app.test:{adminPort}",
            executeAdminAction: true);

        Obs attack = await RunCase(
            "CROSS_PORT_ATTACK",
            publicPort, adminPort,
            connectPort: adminPort,
            target: $"http://app.test:{publicPort}/admin/action",
            host: $"app.test:{publicPort}",
            executeAdminAction: true);

        Require(publicControl.FirstLine.Contains("200"),
            "public prefix control must succeed");
        Require(publicControl.Selected == AuthenticationSchemes.Anonymous &&
                publicControl.ContextDelivered &&
                publicControl.LocalPort == publicPort &&
                publicControl.Path == "/public/ping" &&
                publicControl.Anonymous &&
                !publicControl.SideEffect,
            "public control must remain anonymous and non-admin");

        Require(adminControl.FirstLine.Contains("401"),
            "admin prefix control without credentials must be 401");
        Require(adminControl.BasicChallenge &&
                adminControl.Selected == AuthenticationSchemes.Basic &&
                !adminControl.ContextDelivered &&
                !adminControl.SideEffect,
            "admin control must be blocked by Basic before context delivery");

        Require(attack.FirstLine.Contains("200"),
            "cross-port attack must succeed");
        Require(!attack.BasicChallenge,
            "cross-port attack must suppress Basic challenge");
        Require(attack.Selected == AuthenticationSchemes.Anonymous,
            "selector must downgrade cross-port attack to Anonymous");
        Require(attack.ContextDelivered &&
                attack.LocalPort == adminPort &&
                attack.Path == "/admin/action" &&
                attack.Anonymous,
            "framework must deliver anonymous context for the admin prefix/endpoint");
        Require(attack.UserHostName.EndsWith($":{publicPort}", StringComparison.Ordinal),
            "selector must observe public client-specified port");
        Require(attack.UrlAuthority.EndsWith($":{adminPort}", StringComparison.Ordinal),
            "framework Url must identify admin endpoint");
        Require(attack.SideEffect,
            "protected admin state change must execute");
        Require(File.ReadAllText(SideEffectPath) ==
                "ONE_LISTENER_PROTECTED_ADMIN_CHANGE_EXECUTED",
            "side effect marker must match");

        Console.WriteLine($"PUBLIC_PORT={publicPort}");
        Console.WriteLine($"ADMIN_PORT={adminPort}");
        Console.WriteLine($"SIDE_EFFECT_PATH={SideEffectPath}");
        Console.WriteLine("ONE_LISTENER_CROSS_PORT_AUTH_BYPASS=CONFIRMED");
    }
}
