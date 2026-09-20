using System.Net;
using System.Net.Sockets;
using System.Text;

static int ReservePort()
{
    using var t = new TcpListener(IPAddress.Loopback, 0);
    t.Start();
    return ((IPEndPoint)t.LocalEndpoint).Port;
}
static Socket Connect(int port)
{
    var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    s.Connect(IPAddress.Loopback, port); return s;
}
static async Task<string> ReadWire(Socket s)
{
    byte[] b=new byte[8192]; using var ms=new MemoryStream();
    using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try { while(true){int n=await s.ReceiveAsync(b.AsMemory(),SocketFlags.None,cts.Token); if(n==0)break; await ms.WriteAsync(b.AsMemory(0,n),cts.Token);} }
    catch(OperationCanceledException){}
    return Encoding.ASCII.GetString(ms.ToArray());
}

int listenPort=ReservePort();
int targetPort=ReservePort();
while(targetPort==listenPort) targetPort=ReservePort();

Console.WriteLine($"OS={Environment.OSVersion}");
Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"LISTEN_PORT={listenPort} TARGET_PORT={targetPort}");

using var pub=new HttpListener();
using var adm=new HttpListener();
pub.Prefixes.Add($"http://public.test:{listenPort}/");
adm.Prefixes.Add($"http://admin.test:{listenPort}/");
pub.AuthenticationSchemes=AuthenticationSchemes.None;
adm.AuthenticationSchemes=AuthenticationSchemes.None;

int pubCalls=0, admCalls=0;
string userHost="<not-called>", urlAuthority="<not-called>", rawUrl="<not-called>";
adm.AuthenticationSchemeSelectorDelegate=req=>{
    Interlocked.Increment(ref admCalls);
    userHost=req.UserHostName ?? "<null>";
    urlAuthority=req.Url?.Authority ?? "<null>";
    rawUrl=req.RawUrl ?? "<null>";
    var selected=string.Equals(req.UserHostName,"public.test",StringComparison.OrdinalIgnoreCase)
        ? AuthenticationSchemes.Anonymous : AuthenticationSchemes.Basic;
    Console.WriteLine($"PORT_SELECTOR=ADMIN USERHOST={userHost} URLAUTHORITY={urlAuthority} RAWURL={rawUrl} SELECTED={selected}");
    return selected;
};
pub.AuthenticationSchemeSelectorDelegate=req=>{Interlocked.Increment(ref pubCalls); return AuthenticationSchemes.Anonymous;};

pub.Start(); adm.Start();
Task<HttpListenerContext> pt=pub.GetContextAsync(), at=adm.GetContextAsync();
using var client=Connect(listenPort);

string request=
    $"GET http://admin.test:{targetPort}/port-proof HTTP/1.1\r\n"+
    "Host: public.test\r\nConnection: close\r\n\r\n";
await client.SendAsync(Encoding.ASCII.GetBytes(request),SocketFlags.None);

Task<string> wireTask=ReadWire(client);
Task first=await Task.WhenAny(pt,at,wireTask).WaitAsync(TimeSpan.FromSeconds(5));
if(OperatingSystem.IsWindows())
{
    string wire=await wireTask;
    string firstLine=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
    Console.WriteLine($"PORT_AUTHORITY_WINDOWS RESULT={firstLine} PUB_CALLS={pubCalls} ADMIN_CALLS={admCalls} USERHOST={userHost} URLAUTHORITY={urlAuthority} RAWURL={rawUrl}");
}
else
{
    if(!ReferenceEquals(first,at)) throw new Exception("Expected exact admin listener context on managed Unix");
    var ctx=await at;
    Console.WriteLine(
        $"PORT_AUTHORITY_UNIX ROUTED_LISTENER=ADMIN USERHOST={ctx.Request.UserHostName} " +
        $"URLHOST={ctx.Request.Url?.Host} URLPORT={ctx.Request.Url?.Port} URLAUTHORITY={ctx.Request.Url?.Authority} " +
        $"RAWURL={ctx.Request.RawUrl} LISTEN_PORT={listenPort} RAW_TARGET_PORT={targetPort} " +
        $"PUBLIC_SELECTOR_CALLS={pubCalls} ADMIN_SELECTOR_CALLS={admCalls} USER={(ctx.User is null?"ANONYMOUS":"AUTHENTICATED")}");
    ctx.Response.StatusCode=200; ctx.Response.Close();
    await wireTask;
}
Console.WriteLine("PORT_AUTHORITY_MATRIX=PASS");
