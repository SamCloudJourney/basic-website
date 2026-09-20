using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

record Observation(
    string Name,
    string FirstLine,
    bool BasicChallenge,
    bool ContextDelivered,
    string SelectorUserHost,
    string SelectorUrlHost,
    AuthenticationSchemes SelectedScheme,
    string ContextUserHost,
    string ContextUrlHost,
    bool ContextAnonymous,
    bool AdminSentinel);

class Program
{
    const string Sentinel = "DOCS_MODEL_ADMIN_CONTEXT_SENTINEL_98a4";

    static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p=((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static async Task<string> ReadWire(NetworkStream stream)
    {
        byte[] buffer=new byte[4096];
        using var ms=new MemoryStream();
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while(true)
            {
                int n=await stream.ReadAsync(buffer,cts.Token);
                if(n==0) break;
                await ms.WriteAsync(buffer.AsMemory(0,n),cts.Token);
            }
        }
        catch(OperationCanceledException) {}
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    static void Require(bool condition,string message)
    {
        if(!condition) throw new Exception("ASSERTION_FAILED: "+message);
    }

    static async Task<Observation> Run(string name, Func<int,string> build)
    {
        int port=FreePort();

        using var listener=new HttpListener();
        listener.Prefixes.Add($"http://public.test:{port}/");
        listener.Prefixes.Add($"http://admin.test:{port}/");
        listener.AuthenticationSchemes=AuthenticationSchemes.None;
        listener.Realm="docs-model-admin";

        string selectorUserHost="<not-called>";
        string selectorUrlHost="<not-called>";
        AuthenticationSchemes selected=AuthenticationSchemes.None;

        // This is the exact API model documented by Microsoft:
        // use AuthenticationSchemeSelectorDelegate when authentication should
        // differ based on request characteristics such as Url/UserHostName.
        listener.AuthenticationSchemeSelectorDelegate=request =>
        {
            selectorUserHost=request.UserHostName ?? "<null>";
            selectorUrlHost=request.Url?.Host ?? "<null>";
            string hostOnly=selectorUserHost.Split(':')[0];

            selected=string.Equals(hostOnly,"public.test",StringComparison.OrdinalIgnoreCase)
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"SELECTOR case={name} UserHostName={selectorUserHost} Url.Host={selectorUrlHost} Selected={selected}");
            return selected;
        };

        listener.Start();
        Task<HttpListenerContext> contextTask=listener.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,port);
        using NetworkStream ns=client.GetStream();

        await ns.WriteAsync(Encoding.ASCII.GetBytes(build(port)));
        await ns.FlushAsync();

        Task<string> wireTask=ReadWire(ns);
        Task first=await Task.WhenAny(contextTask,wireTask,Task.Delay(5000));

        bool contextDelivered=false;
        string contextUserHost="<none>";
        string contextUrlHost="<none>";
        bool contextAnonymous=false;

        if(first==contextTask && contextTask.IsCompletedSuccessfully)
        {
            contextDelivered=true;
            HttpListenerContext ctx=await contextTask;
            contextUserHost=ctx.Request.UserHostName ?? "<null>";
            contextUrlHost=ctx.Request.Url?.Host ?? "<null>";
            contextAnonymous=ctx.User is null;

            string bodyText=string.Equals(contextUrlHost,"admin.test",StringComparison.OrdinalIgnoreCase)
                ? Sentinel+"\n"
                : "PUBLIC_CONTEXT\n";

            byte[] body=Encoding.ASCII.GetBytes(bodyText);
            ctx.Response.StatusCode=200;
            ctx.Response.ContentLength64=body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }

        string wire=await wireTask;
        string firstLine=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        bool basic=wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase);
        bool sentinel=wire.Contains(Sentinel,StringComparison.Ordinal);

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basic} context={contextDelivered} " +
            $"selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} selected={selected} " +
            $"contextUserHost={contextUserHost} contextUrlHost={contextUrlHost} contextAnonymous={contextAnonymous} sentinel={sentinel}");

        listener.Close();
        return new Observation(name,firstLine,basic,contextDelivered,selectorUserHost,selectorUrlHost,
            selected,contextUserHost,contextUrlHost,contextAnonymous,sentinel);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        Observation publicControl=await Run(
            "PUBLIC_CONTROL",
            p=>$"GET / HTTP/1.1\r\nHost: public.test:{p}\r\nConnection: close\r\n\r\n");

        Observation adminControl=await Run(
            "ADMIN_CONTROL",
            p=>$"GET / HTTP/1.1\r\nHost: admin.test:{p}\r\nConnection: close\r\n\r\n");

        Observation conflict=await Run(
            "ABSOLUTE_ADMIN_HOST_PUBLIC",
            p=>$"GET http://admin.test:{p}/ HTTP/1.1\r\nHost: public.test:{p}\r\nConnection: close\r\n\r\n");

        Require(publicControl.FirstLine.Contains("200"),"public control must return 200");
        Require(publicControl.ContextDelivered && publicControl.ContextAnonymous,"public control must be delivered anonymously");
        Require(publicControl.SelectedScheme==AuthenticationSchemes.Anonymous,"public control selector must choose Anonymous");
        Require(!publicControl.BasicChallenge && !publicControl.AdminSentinel,"public control must not receive admin sentinel");

        Require(adminControl.FirstLine.Contains("401"),"admin control must return 401");
        Require(adminControl.BasicChallenge,"admin control must contain Basic challenge");
        Require(adminControl.SelectedScheme==AuthenticationSchemes.Basic,"admin control selector must choose Basic");
        Require(!adminControl.ContextDelivered && !adminControl.AdminSentinel,"ordinary unauthenticated admin request must not be returned as context");

        if(OperatingSystem.IsWindows())
        {
            Require(conflict.FirstLine.Contains("401"),"Windows conflict must return 401");
            Require(conflict.BasicChallenge,"Windows conflict must contain Basic challenge");
            Require(conflict.SelectedScheme==AuthenticationSchemes.Basic,"Windows conflict must select Basic");
            Require(!conflict.ContextDelivered && !conflict.AdminSentinel,"Windows conflict must not return admin context");
            Require(conflict.SelectorUserHost.StartsWith("admin.test",StringComparison.OrdinalIgnoreCase),
                "Windows must canonicalize selector authority to admin");
            Console.WriteLine("DOCS_MODEL_WINDOWS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(conflict.FirstLine.Contains("200"),"managed conflict must return 200");
            Require(!conflict.BasicChallenge,"managed conflict must omit Basic challenge");
            Require(conflict.SelectedScheme==AuthenticationSchemes.Anonymous,"managed conflict must select Anonymous");
            Require(conflict.ContextDelivered && conflict.ContextAnonymous,"managed conflict must deliver anonymous context");
            Require(conflict.SelectorUserHost.StartsWith("public.test",StringComparison.OrdinalIgnoreCase),
                "selector must see public Host authority");
            Require(string.Equals(conflict.SelectorUrlHost,"admin.test",StringComparison.OrdinalIgnoreCase),
                "selector must simultaneously see admin Url authority");
            Require(string.Equals(conflict.ContextUrlHost,"admin.test",StringComparison.OrdinalIgnoreCase),
                "delivered context must identify admin resource authority");
            Require(conflict.AdminSentinel,"admin context sentinel must reach unauthenticated client");

            Console.WriteLine("DOCS_MODEL_AUTHENTICATION_BYPASS=CONFIRMED");
        }
    }
}
