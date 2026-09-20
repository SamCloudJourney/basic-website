using System.Net;
using System.Text;

const int adminPort=46181;
const int publicPort=46182;
string ready=Path.Combine(Path.GetTempPath(),"httplistener-remote-ready");
string marker=Path.Combine(Path.GetTempPath(),"httplistener-remote-admin-marker");
try{File.Delete(ready);}catch{}
try{File.Delete(marker);}catch{}

AuthenticationSchemes Select(HttpListenerRequest r) =>
    string.Equals(r.UserHostName,$"service.test:{publicPort}",StringComparison.OrdinalIgnoreCase)
        ? AuthenticationSchemes.Anonymous : AuthenticationSchemes.Basic;

using var pub=new HttpListener();
using var adm=new HttpListener();
pub.Prefixes.Add($"http://*:{publicPort}/");
adm.Prefixes.Add($"http://*:{adminPort}/");
pub.AuthenticationSchemes=AuthenticationSchemes.None;
adm.AuthenticationSchemes=AuthenticationSchemes.None;
pub.AuthenticationSchemeSelectorDelegate=Select;
adm.AuthenticationSchemeSelectorDelegate=Select;
pub.Start();adm.Start();
await File.WriteAllTextAsync(ready,"ready");
Console.WriteLine($"REMOTE_SERVER_READY ADMIN_PORT={adminPort} PUBLIC_PORT={publicPort}");

Task<HttpListenerContext> publicTask=pub.GetContextAsync();
Task<HttpListenerContext> adminTask=adm.GetContextAsync();
HttpListenerContext ctx=await adminTask.WaitAsync(TimeSpan.FromSeconds(30));

string remote=ctx.Request.RemoteEndPoint?.ToString()??"<null>";
bool loopback=ctx.Request.RemoteEndPoint is not null && IPAddress.IsLoopback(ctx.Request.RemoteEndPoint.Address);
Console.WriteLine(
    $"REMOTE_ADMIN_CONTEXT REMOTE={remote} LOOPBACK={loopback} USERHOST={ctx.Request.UserHostName} " +
    $"URLAUTHORITY={ctx.Request.Url?.Authority} RAWURL={ctx.Request.RawUrl} USER={(ctx.User is null?"ANONYMOUS":"AUTHENTICATED")}");

if(loopback)throw new Exception("remote client unexpectedly arrived as loopback");
if(publicTask.IsCompletedSuccessfully)throw new Exception("public listener received attack");
if(ctx.User is not null)throw new Exception("expected anonymous protected context");
if(ctx.Request.Url?.Port!=adminPort)throw new Exception("protected admin port not selected");
if(!string.Equals(ctx.Request.UserHostName,$"service.test:{publicPort}",StringComparison.OrdinalIgnoreCase))
    throw new Exception("public authority not retained for selector");

string sentinel="REMOTE_UNAUTHENTICATED_ADMIN_STATE_CHANGED_f31b";
await File.WriteAllTextAsync(marker,sentinel);
byte[] body=Encoding.ASCII.GetBytes("REMOTE_ADMIN_ACTION_EXECUTED=true\n");
ctx.Response.StatusCode=200;ctx.Response.ContentLength64=body.Length;
await ctx.Response.OutputStream.WriteAsync(body);ctx.Response.Close();

Console.WriteLine(
    $"REMOTE_PORT_ONLY_AUTH_BYPASS=CONFIRMED REMOTE_NON_LOOPBACK={!loopback} " +
    $"WIRE_HOST_EQUALS_TARGET_AUTHORITY=True ROUTED_LISTENER=ADMIN USER=ANONYMOUS " +
    $"MARKER_EXISTS={File.Exists(marker)} MARKER_CONTENT={await File.ReadAllTextAsync(marker)}");
Console.WriteLine("REMOTE_PORT_ONLY_PROOF=PASS");
