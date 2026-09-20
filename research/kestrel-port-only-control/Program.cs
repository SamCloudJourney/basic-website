using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

static int Port(){using var t=new TcpListener(IPAddress.Loopback,0);t.Start();return((IPEndPoint)t.LocalEndpoint).Port;}
static async Task<string> Wire(NetworkStream s){byte[] b=new byte[8192];using var ms=new MemoryStream();using var c=new CancellationTokenSource(TimeSpan.FromSeconds(5));try{while(true){int n=await s.ReadAsync(b,c.Token);if(n==0)break;await ms.WriteAsync(b.AsMemory(0,n),c.Token);}}catch(OperationCanceledException){}return Encoding.ASCII.GetString(ms.ToArray());}
int admin=Port(), pub=Port(); while(pub==admin)pub=Port();
int dispatch=0; string seenHost="",seenLocal="";
var builder=WebApplication.CreateBuilder();
builder.WebHost.ConfigureKestrel(o=>{o.ListenLocalhost(admin);o.ListenLocalhost(pub);});
await using var app=builder.Build();
app.Run(async ctx=>{Interlocked.Increment(ref dispatch);seenHost=ctx.Request.Host.ToString();seenLocal=ctx.Connection.LocalPort.ToString();Console.WriteLine($"KESTREL_PORT_APP HOST={seenHost} LOCALPORT={seenLocal}");ctx.Response.StatusCode=200;await ctx.Response.WriteAsync("OK");});
await app.StartAsync();
using var c=new TcpClient();await c.ConnectAsync(IPAddress.Loopback,admin);using var s=c.GetStream();
string raw=$"GET http://127.0.0.1:{pub}/x HTTP/1.1\r\nHost: 127.0.0.1:{pub}\r\nConnection: close\r\n\r\n";
await s.WriteAsync(Encoding.ASCII.GetBytes(raw));await s.FlushAsync();
string wire=await Wire(s); string first=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
Console.WriteLine($"KESTREL_PORT_ONLY_CONTROL FIRSTLINE={first} DISPATCH={dispatch} HOST={seenHost} LOCALPORT={seenLocal} ADMIN_PORT={admin} PUBLIC_PORT={pub}");
await app.StopAsync();
