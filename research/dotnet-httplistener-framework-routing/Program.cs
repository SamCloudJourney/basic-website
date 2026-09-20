using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

record CaseResult(
    string Name,
    string FirstLine,
    bool BasicChallenge,
    bool PublicContext,
    bool AdminContext,
    bool AdminSentinel,
    string SelectorUserHost,
    string SelectorUrlHost,
    AuthenticationSchemes SelectedScheme);

class Program
{
    private const string AdminSentinel = "FRAMEWORK_ADMIN_AUTH_BYPASS_SENTINEL_f31a";

    static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static async Task<string> ReadWire(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        byte[] buffer = new byte[4096];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while (true)
            {
                int n = await stream.ReadAsync(buffer, cts.Token);
                if (n <= 0) break;
                await ms.WriteAsync(buffer.AsMemory(0, n), cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception("ASSERTION_FAILED: " + message);
    }

    static async Task<CaseResult> RunCase(string name, Func<int,string> rawFactory)
    {
        int port = FreePort();

        using var publicListener = new HttpListener();
        using var adminListener = new HttpListener();

        publicListener.Prefixes.Add($"http://public.test:{port}/");
        adminListener.Prefixes.Add($"http://admin.test:{port}/");

        publicListener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;

        string selectorUserHost = "<not-called>";
        string selectorUrlHost = "<not-called>";
        AuthenticationSchemes selected = AuthenticationSchemes.None;

        adminListener.AuthenticationSchemes = AuthenticationSchemes.None;
        adminListener.Realm = "admin-research";
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

        string raw = rawFactory(port);
        Console.WriteLine($"SEND case={name} raw={raw.Replace("\r","<CR>").Replace("\n","<LF>")}");
        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> wireTask = ReadWire(ns);
        Task first = await Task.WhenAny(publicTask, adminTask, wireTask, Task.Delay(5000));

        bool publicContext = false;
        bool adminContext = false;

        if (first == publicTask && publicTask.IsCompletedSuccessfully)
        {
            publicContext = true;
            HttpListenerContext ctx = await publicTask;
            byte[] body = Encoding.ASCII.GetBytes("PUBLIC_CONTEXT\n");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }
        else if (first == adminTask && adminTask.IsCompletedSuccessfully)
        {
            adminContext = true;
            HttpListenerContext ctx = await adminTask;
            Console.WriteLine(
                $"ADMIN_CONTEXT case={name} UserHostName={ctx.Request.UserHostName} Url.Host={ctx.Request.Url?.Host} User={(ctx.User is null ? "ANONYMOUS" : "AUTHENTICATED")}");
            byte[] body = Encoding.ASCII.GetBytes(
                AdminSentinel + "\n" +
                "ADMIN_ACTION_EXECUTED=true\n");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }

        string wire = await wireTask;
        string firstLine = wire.Split(new[]{"\r\n","\n"}, StringSplitOptions.None)[0];
        bool basic = wire.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase);
        bool sentinel = wire.Contains(AdminSentinel, StringComparison.Ordinal);

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basic} publicContext={publicContext} adminContext={adminContext} adminSentinel={sentinel} selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} selected={selected}");

        publicListener.Close();
        adminListener.Close();

        // No authentication-rejected request may later materialize as a context.
        await Task.Delay(100);

        return new CaseResult(name, firstLine, basic, publicContext, adminContext, sentinel,
            selectorUserHost, selectorUrlHost, selected);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        CaseResult publicControl = await RunCase(
            "PUBLIC_CONTROL",
            p => $"GET / HTTP/1.1\r\nHost: public.test:{p}\r\nConnection: close\r\n\r\n");

        CaseResult adminControl = await RunCase(
            "ADMIN_CONTROL",
            p => $"GET / HTTP/1.1\r\nHost: admin.test:{p}\r\nConnection: close\r\n\r\n");

        CaseResult conflict = await RunCase(
            "ABSOLUTE_ADMIN_HOST_PUBLIC",
            p => $"GET http://admin.test:{p}/ HTTP/1.1\r\nHost: public.test:{p}\r\nConnection: close\r\n\r\n");

        Require(publicControl.FirstLine.Contains("200"), "public control must return 200");
        Require(publicControl.PublicContext && !publicControl.AdminContext, "public control must route to public listener");
        Require(!publicControl.BasicChallenge && !publicControl.AdminSentinel, "public control must not challenge or expose admin sentinel");

        Require(adminControl.FirstLine.Contains("401"), "ordinary admin authority must require authentication");
        Require(adminControl.BasicChallenge, "ordinary admin authority must include framework Basic challenge");
        Require(!adminControl.AdminContext, "unauthenticated ordinary admin request must not be delivered as admin context");
        Require(!adminControl.AdminSentinel, "ordinary unauthenticated admin request must not execute protected admin action");
        Require(adminControl.SelectedScheme == AuthenticationSchemes.Basic, "admin selector must choose Basic");

        if (OperatingSystem.IsWindows())
        {
            Require(conflict.FirstLine.Contains("401"), "Windows/http.sys must challenge conflicting request");
            Require(conflict.BasicChallenge, "Windows/http.sys must include Basic challenge");
            Require(!conflict.AdminContext && !conflict.AdminSentinel, "Windows/http.sys must not deliver protected admin context");
            Console.WriteLine("FRAMEWORK_PREFIX_WINDOWS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(conflict.FirstLine.Contains("200"), "managed HttpListener conflicting request must return 200");
            Require(!conflict.BasicChallenge, "managed conflict must omit Basic challenge");
            Require(conflict.AdminContext && !conflict.PublicContext,
                "framework prefix routing must bind conflicting request to ADMIN listener");
            Require(conflict.AdminSentinel, "protected admin action sentinel must reach unauthenticated client");
            Require(conflict.SelectedScheme == AuthenticationSchemes.Anonymous,
                "admin listener's selector must choose Anonymous from stale public Host");
            Require(conflict.SelectorUserHost.StartsWith("public.test", StringComparison.OrdinalIgnoreCase),
                "selector must see stale public Host authority");
            Require(string.Equals(conflict.SelectorUrlHost, "admin.test", StringComparison.OrdinalIgnoreCase),
                "same request must expose admin authority in Url.Host");

            Console.WriteLine("FRAMEWORK_PREFIX_ROUTING_AUTH_BYPASS=CONFIRMED");
        }
    }
}
