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
    private const string ExpectedUser="cross-port-admin";
    private const string ExpectedPassword="correct-cross-port-password";
    private static readonly string SideEffectPath=
        Path.Combine(Path.GetTempPath(),"httplistener-cross-port-credential-31ae.txt");

    record Obs(
        string Name,
        string FirstLine,
        bool BasicChallenge,
        bool PublicContext,
        bool AdminContext,
        AuthenticationSchemes Selected,
        string UserHostName,
        string UrlAuthority,
        bool ValidationRan,
        bool ValidationPassed,
        bool AdminOperation,
        bool SideEffect);

    static int FreePort()
    {
        using var l=new TcpListener(IPAddress.Loopback,0);
        l.Start();
        int p=((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static void Require(bool c,string m)
    {
        if(!c) throw new Exception("ASSERTION_FAILED: "+m);
    }

    static string Basic(string u,string p)=>
        Convert.ToBase64String(Encoding.ASCII.GetBytes(u+":"+p));

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
        Func<int,int,string> build)
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
        adminListener.Realm="cross-port-credential";
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
                $"SELECTOR case={name} UserHostName={selectorUserHost} UrlAuthority={selectorUrlAuthority} SeenPort={seenPort} PublicPort={publicPort} AdminPort={adminPort} Selected={selected}");

            return selected;
        };

        publicListener.Start();
        adminListener.Start();

        Task<HttpListenerContext> publicTask=publicListener.GetContextAsync();
        Task<HttpListenerContext> adminTask=adminListener.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,connectPort);
        using NetworkStream ns=client.GetStream();

        string raw=build(publicPort,adminPort);
        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> wireTask=ReadAll(ns);
        Task first=await Task.WhenAny(publicTask,adminTask,wireTask,Task.Delay(5000));

        bool publicContext=false;
        bool adminContext=false;
        bool validationRan=false;
        bool validationPassed=false;
        bool adminOperation=false;

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

            if(ctx.User?.Identity is HttpListenerBasicIdentity basic)
            {
                validationRan=true;
                validationPassed=
                    basic.Name==ExpectedUser &&
                    basic.Password==ExpectedPassword;

                Console.WriteLine(
                    $"APP_CREDENTIAL_VALIDATION case={name} username={basic.Name} passed={validationPassed}");

                if(!validationPassed)
                {
                    byte[] denied=Encoding.ASCII.GetBytes("INVALID_ADMIN_CREDENTIALS\n");
                    ctx.Response.StatusCode=403;
                    ctx.Response.ContentLength64=denied.Length;
                    await ctx.Response.OutputStream.WriteAsync(denied);
                    ctx.Response.Close();
                }
            }

            if(!validationRan || validationPassed)
            {
                adminOperation=true;
                File.WriteAllText(SideEffectPath,"CROSS_PORT_CREDENTIAL_PROTECTED_OPERATION_EXECUTED");

                byte[] body=Encoding.ASCII.GetBytes("CROSS_PORT_CREDENTIAL_ADMIN_OK\n");
                ctx.Response.StatusCode=200;
                ctx.Response.ContentLength64=body.Length;
                await ctx.Response.OutputStream.WriteAsync(body);
                ctx.Response.Close();
            }
        }

        string wire=await wireTask;
        string firstLine=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        bool basicChallenge=wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase);
        bool sideEffect=File.Exists(SideEffectPath);

        Console.WriteLine(
            $"RESULT case={name} connectPort={connectPort} first={firstLine} basicChallenge={basicChallenge} publicContext={publicContext} adminContext={adminContext} selected={selected} selectorUserHost={selectorUserHost} selectorUrlAuthority={selectorUrlAuthority} validationRan={validationRan} validationPassed={validationPassed} adminOperation={adminOperation} sideEffect={sideEffect}");

        publicListener.Close();
        adminListener.Close();

        return new Obs(
            name,firstLine,basicChallenge,publicContext,adminContext,selected,
            selectorUserHost,selectorUrlAuthority,validationRan,validationPassed,adminOperation,sideEffect);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        int publicPort=FreePort();
        int adminPort=FreePort();
        while(adminPort==publicPort) adminPort=FreePort();

        Obs noCred=await Run(
            "ADMIN_NO_CREDENTIALS",
            publicPort,adminPort,adminPort,
            (pub,adm)=>$"POST /admin/change HTTP/1.1\r\nHost: app.test:{adm}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Obs wrongCred=await Run(
            "ADMIN_WRONG_CREDENTIALS",
            publicPort,adminPort,adminPort,
            (pub,adm)=>$"POST /admin/change HTTP/1.1\r\nHost: app.test:{adm}\r\nAuthorization: Basic {Basic("wrong","wrong")}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Obs correctCred=await Run(
            "ADMIN_CORRECT_CREDENTIALS",
            publicPort,adminPort,adminPort,
            (pub,adm)=>$"POST /admin/change HTTP/1.1\r\nHost: app.test:{adm}\r\nAuthorization: Basic {Basic(ExpectedUser,ExpectedPassword)}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Obs attack=await Run(
            "CROSS_PORT_NO_CREDENTIALS_ATTACK",
            publicPort,adminPort,adminPort,
            (pub,adm)=>$"POST http://app.test:{pub}/admin/change HTTP/1.1\r\nHost: app.test:{pub}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Require(noCred.FirstLine.Contains("401"),"ordinary admin port without credentials must be 401");
        Require(noCred.BasicChallenge && noCred.Selected==AuthenticationSchemes.Basic,
            "ordinary admin port must choose Basic");
        Require(!noCred.AdminContext && !noCred.AdminOperation && !noCred.SideEffect,
            "no-credential admin control must not execute");

        Require(wrongCred.FirstLine.Contains("403"),"wrong admin credentials must be app-rejected");
        Require(wrongCred.AdminContext && wrongCred.ValidationRan && !wrongCred.ValidationPassed,
            "wrong credentials must reach and fail independent credential validation");
        Require(!wrongCred.AdminOperation && !wrongCred.SideEffect,
            "wrong credentials must not execute admin operation");

        Require(correctCred.FirstLine.Contains("200"),"correct admin credentials must succeed");
        Require(correctCred.ValidationRan && correctCred.ValidationPassed,
            "correct credentials must pass app validation");
        Require(correctCred.AdminOperation && correctCred.SideEffect,
            "valid credential control must execute admin operation");

        Require(attack.FirstLine.Contains("200"),"cross-port no-credential attack must return admin success");
        Require(!attack.BasicChallenge,"cross-port attack must omit Basic challenge");
        Require(!attack.PublicContext && attack.AdminContext,
            "framework must route physical admin-port request to admin listener");
        Require(attack.Selected==AuthenticationSchemes.Anonymous,
            "selector must classify target authority as public port");
        Require(attack.UserHostName.EndsWith($":{publicPort}",StringComparison.Ordinal),
            "selector must see public port");
        Require(attack.UrlAuthority.EndsWith($":{adminPort}",StringComparison.Ordinal),
            "Request.Url must expose physical admin port");
        Require(!attack.ValidationRan,
            "no-credential cross-port attack must bypass Basic credential-validation stage");
        Require(attack.AdminOperation && attack.SideEffect,
            "no-credential cross-port attack must execute operation wrong credentials cannot execute");

        Console.WriteLine($"PUBLIC_PORT={publicPort}");
        Console.WriteLine($"ADMIN_PORT={adminPort}");
        Console.WriteLine($"SIDE_EFFECT_PATH={SideEffectPath}");
        Console.WriteLine("CROSS_PORT_AUTHORITY_BYPASSES_CREDENTIAL_VALIDATION=CONFIRMED");
    }
}
