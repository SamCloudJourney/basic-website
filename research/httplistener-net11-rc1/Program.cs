using System.Net;
using System.Net.Sockets;
using System.Text;

static int ReservePort()
{
    using var t = new TcpListener(IPAddress.Loopback, 0);
    t.Start();
    return ((IPEndPoint)t.LocalEndpoint).Port;
}

static async Task<string> ReadWireAsync(NetworkStream stream)
{
    byte[] buffer = new byte[8192];
    using var ms = new MemoryStream();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try
    {
        while (true)
        {
            int n = await stream.ReadAsync(buffer, cts.Token);
            if (n == 0) break;
            await ms.WriteAsync(buffer.AsMemory(0, n), cts.Token);
        }
    }
    catch (OperationCanceledException) {}
    return Encoding.ASCII.GetString(ms.ToArray());
}

static async Task RunCase(string name, Func<int,string> makeRequest, bool expectUnixContext)
{
    int port = ReservePort();
    using var listener = new HttpListener();
    listener.Prefixes.Add($"http://*:{port}/");
    listener.AuthenticationSchemes = AuthenticationSchemes.None;
    listener.Realm = "admin-research";

    AuthenticationSchemes selected = AuthenticationSchemes.None;
    string selectorUserHost = "<not-called>";
    string selectorUrlHost = "<not-called>";
    listener.AuthenticationSchemeSelectorDelegate = request =>
    {
        selectorUserHost = request.UserHostName ?? "<null>";
        selectorUrlHost = request.Url?.Host ?? "<null>";
        selected = string.Equals(request.UserHostName, "public.test", StringComparison.OrdinalIgnoreCase)
            ? AuthenticationSchemes.Anonymous
            : AuthenticationSchemes.Basic;
        Console.WriteLine($"RC1_SELECTOR={name} USERHOST={selectorUserHost} URLHOST={selectorUrlHost} SELECTED={selected}");
        return selected;
    };
    listener.Start();

    Task<HttpListenerContext> contextTask = listener.GetContextAsync();
    using var client = new TcpClient();
    await client.ConnectAsync(IPAddress.Loopback, port);
    using NetworkStream stream = client.GetStream();
    await stream.WriteAsync(Encoding.ASCII.GetBytes(makeRequest(port)));
    await stream.FlushAsync();

    Task<string> wireTask = ReadWireAsync(stream);
    Task first = await Task.WhenAny(contextTask, wireTask).WaitAsync(TimeSpan.FromSeconds(5));

    bool isUnix = !OperatingSystem.IsWindows();
    if (expectUnixContext && isUnix)
    {
        if (!ReferenceEquals(first, contextTask))
            throw new Exception($"{name}: expected context first on managed Unix");
        HttpListenerContext ctx = await contextTask;
        if (ctx.User is not null) throw new Exception($"{name}: expected anonymous user");
        byte[] body = Encoding.ASCII.GetBytes("RC1_ADMIN_SENTINEL\n");
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentLength64 = body.Length;
        await ctx.Response.OutputStream.WriteAsync(body);
        ctx.Response.Close();
        string wire = await wireTask;
        if (!wire.Contains("200", StringComparison.Ordinal) || !wire.Contains("RC1_ADMIN_SENTINEL", StringComparison.Ordinal))
            throw new Exception($"{name}: expected 200 sentinel");
        Console.WriteLine($"RC1_CASE={name} RESULT=ANONYMOUS_CONTEXT USERHOST={selectorUserHost} URLHOST={selectorUrlHost} SELECTED={selected}");
    }
    else
    {
        if (!ReferenceEquals(first, wireTask))
            throw new Exception($"{name}: expected authentication response before context");
        string wire = await wireTask;
        if (!wire.Contains("401", StringComparison.Ordinal) ||
            !wire.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase))
            throw new Exception($"{name}: expected Basic 401");
        if (contextTask.IsCompletedSuccessfully)
            throw new Exception($"{name}: context should not be delivered");
        Console.WriteLine($"RC1_CASE={name} RESULT=BASIC_401 USERHOST={selectorUserHost} URLHOST={selectorUrlHost} SELECTED={selected} CONTEXT_DELIVERED={contextTask.IsCompletedSuccessfully}");
    }
}

Console.WriteLine($"OS={Environment.OSVersion}");
Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");

await RunCase(
    "ADMIN_ORIGIN",
    p => "GET /admin HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n",
    expectUnixContext: false);

await RunCase(
    "ABS_ADMIN_HOST_PUBLIC",
    p => $"GET http://admin.test:{p}/admin HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n",
    expectUnixContext: true);

await RunCase(
    "ABS_PUBLIC_HOST_ADMIN",
    p => $"GET http://public.test:{p}/public HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n",
    expectUnixContext: false);

Console.WriteLine("NET11_RC1_HTTP_LISTENER_AUTHORITY_MATRIX=PASS");
