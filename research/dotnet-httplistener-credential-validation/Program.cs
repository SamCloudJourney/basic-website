using System;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    private const string ExpectedUser = "research-admin";
    private const string ExpectedPassword = "correct-research-password";
    private const string AdminSentinel = "CREDENTIAL_VALIDATION_BYPASS_ADMIN_OPERATION_c0d7";
    private static readonly string SideEffectPath =
        Path.Combine(Path.GetTempPath(), "httplistener-credential-validation-c0d7.txt");

    record Observation(
        string Name,
        string FirstLine,
        bool BasicChallenge,
        bool ContextDelivered,
        AuthenticationSchemes Selected,
        string SelectorUserHost,
        string SelectorUrlHost,
        bool UserNull,
        bool CredentialValidationRan,
        bool CredentialValidationPassed,
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

    static void Require(bool condition,string message)
    {
        if(!condition) throw new Exception("ASSERTION_FAILED: "+message);
    }

    static async Task<string> ReadAll(NetworkStream ns)
    {
        using var ms=new MemoryStream();
        byte[] buffer=new byte[4096];
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while(true)
            {
                int n=await ns.ReadAsync(buffer,cts.Token);
                if(n==0) break;
                await ms.WriteAsync(buffer.AsMemory(0,n),cts.Token);
            }
        }
        catch(OperationCanceledException) {}
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    static string BasicHeader(string user,string password) =>
        Convert.ToBase64String(Encoding.ASCII.GetBytes(user+":"+password));

    static async Task<Observation> Run(
        string name,
        Func<int,string> requestFactory)
    {
        int port=FreePort();
        try{File.Delete(SideEffectPath);}catch{}

        using var listener=new HttpListener();
        listener.Prefixes.Add($"http://public.test:{port}/");
        listener.Prefixes.Add($"http://admin.test:{port}/");
        listener.AuthenticationSchemes=AuthenticationSchemes.None;
        listener.Realm="credential-validation-research";

        AuthenticationSchemes selected=AuthenticationSchemes.None;
        string selectorUserHost="<not-called>";
        string selectorUrlHost="<not-called>";

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

        string raw=requestFactory(port);
        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> wireTask=ReadAll(ns);
        Task first=await Task.WhenAny(contextTask,wireTask,Task.Delay(5000));

        bool contextDelivered=false;
        bool userNull=true;
        bool credentialValidationRan=false;
        bool credentialValidationPassed=false;
        bool adminOperation=false;

        if(first==contextTask && contextTask.IsCompletedSuccessfully)
        {
            contextDelivered=true;
            HttpListenerContext ctx=await contextTask;
            userNull=ctx.User is null;

            // A separate application credential-validation layer validates every
            // Basic identity returned by HttpListener. Arbitrary Basic credentials
            // therefore do not authorize the protected operation.
            if(ctx.User?.Identity is HttpListenerBasicIdentity basic)
            {
                credentialValidationRan=true;
                credentialValidationPassed=
                    basic.Name==ExpectedUser &&
                    basic.Password==ExpectedPassword;

                Console.WriteLine(
                    $"APP_CREDENTIAL_VALIDATION case={name} username={basic.Name} passed={credentialValidationPassed}");

                if(!credentialValidationPassed)
                {
                    byte[] denied=Encoding.ASCII.GetBytes("APPLICATION_CREDENTIAL_VALIDATION_DENIED\n");
                    ctx.Response.StatusCode=403;
                    ctx.Response.ContentLength64=denied.Length;
                    await ctx.Response.OutputStream.WriteAsync(denied);
                    ctx.Response.Close();
                }
            }

            if(!credentialValidationRan || credentialValidationPassed)
            {
                // Resource/tenant selection uses the canonical Request.Url authority.
                if(string.Equals(ctx.Request.Url?.Host,"admin.test",StringComparison.OrdinalIgnoreCase))
                {
                    adminOperation=true;
                    File.WriteAllText(SideEffectPath,"CREDENTIAL_VALIDATION_PROTECTED_OPERATION_EXECUTED");

                    byte[] body=Encoding.ASCII.GetBytes(AdminSentinel+"\n");
                    ctx.Response.StatusCode=200;
                    ctx.Response.ContentLength64=body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body);
                    ctx.Response.Close();
                }
                else
                {
                    byte[] body=Encoding.ASCII.GetBytes("PUBLIC_RESOURCE\n");
                    ctx.Response.StatusCode=200;
                    ctx.Response.ContentLength64=body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body);
                    ctx.Response.Close();
                }
            }
        }

        string wire=await wireTask;
        string firstLine=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        bool basicChallenge=wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase);
        bool sideEffect=File.Exists(SideEffectPath);

        Console.WriteLine(
            $"RESULT case={name} first={firstLine} basicChallenge={basicChallenge} context={contextDelivered} selected={selected} selectorUserHost={selectorUserHost} selectorUrlHost={selectorUrlHost} userNull={userNull} credentialValidationRan={credentialValidationRan} credentialValidationPassed={credentialValidationPassed} adminOperation={adminOperation} sideEffect={sideEffect}");

        listener.Close();

        return new Observation(
            name,firstLine,basicChallenge,contextDelivered,selected,selectorUserHost,selectorUrlHost,
            userNull,credentialValidationRan,credentialValidationPassed,adminOperation,sideEffect);
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        Observation publicControl=await Run(
            "PUBLIC_CONTROL",
            p=>$"GET / HTTP/1.1\r\nHost: public.test:{p}\r\nConnection: close\r\n\r\n");

        Observation adminNoCredentials=await Run(
            "ADMIN_NO_CREDENTIALS",
            p=>$"POST /admin/change HTTP/1.1\r\nHost: admin.test:{p}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Observation adminWrongCredentials=await Run(
            "ADMIN_WRONG_CREDENTIALS",
            p=>$"POST /admin/change HTTP/1.1\r\nHost: admin.test:{p}\r\nAuthorization: Basic {BasicHeader("wrong-user","wrong-password")}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Observation adminCorrectCredentials=await Run(
            "ADMIN_CORRECT_CREDENTIALS",
            p=>$"POST /admin/change HTTP/1.1\r\nHost: admin.test:{p}\r\nAuthorization: Basic {BasicHeader(ExpectedUser,ExpectedPassword)}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Observation attack=await Run(
            "ABSOLUTE_ADMIN_HOST_PUBLIC_NO_CREDENTIALS",
            p=>$"POST http://admin.test:{p}/admin/change HTTP/1.1\r\nHost: public.test:{p}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        Require(publicControl.FirstLine.Contains("200"),"public control must be anonymous 200");
        Require(publicControl.Selected==AuthenticationSchemes.Anonymous && publicControl.UserNull,
            "public control must remain anonymous");
        Require(!publicControl.AdminOperation && !publicControl.SideEffect,
            "public control must not execute admin operation");

        Require(adminNoCredentials.FirstLine.Contains("401"),"admin without credentials must be 401");
        Require(adminNoCredentials.BasicChallenge,"admin without credentials must carry Basic challenge");
        Require(!adminNoCredentials.ContextDelivered && !adminNoCredentials.AdminOperation,
            "admin without credentials must not reach application");

        Require(adminWrongCredentials.FirstLine.Contains("403"),"wrong Basic credentials must be rejected by app validation");
        Require(adminWrongCredentials.ContextDelivered &&
                adminWrongCredentials.CredentialValidationRan &&
                !adminWrongCredentials.CredentialValidationPassed,
            "wrong Basic credentials must reach and fail application credential validation");
        Require(!adminWrongCredentials.AdminOperation && !adminWrongCredentials.SideEffect,
            "wrong credentials must not execute protected operation");

        Require(adminCorrectCredentials.FirstLine.Contains("200"),"correct Basic credentials must succeed");
        Require(adminCorrectCredentials.CredentialValidationRan &&
                adminCorrectCredentials.CredentialValidationPassed,
            "correct Basic credentials must pass application validation");
        Require(adminCorrectCredentials.AdminOperation && adminCorrectCredentials.SideEffect,
            "valid credential control must execute protected operation");

        if(OperatingSystem.IsWindows())
        {
            Require(attack.FirstLine.Contains("401"),"Windows conflict must be Basic 401");
            Require(attack.BasicChallenge && attack.Selected==AuthenticationSchemes.Basic,
                "Windows must canonicalize authority before selector");
            Require(!attack.ContextDelivered && !attack.AdminOperation && !attack.SideEffect,
                "Windows must not bypass credential gate");
            Console.WriteLine("CREDENTIAL_VALIDATION_WINDOWS_NEGATIVE_CONTROL=PASS");
        }
        else
        {
            Require(attack.FirstLine.Contains("200"),"managed conflict must return 200");
            Require(!attack.BasicChallenge,"managed conflict must omit Basic challenge");
            Require(attack.Selected==AuthenticationSchemes.Anonymous,
                "managed selector must classify attack as Anonymous");
            Require(attack.ContextDelivered && attack.UserNull,
                "attack must reach application with no authenticated Basic identity");
            Require(!attack.CredentialValidationRan,
                "attack must bypass application Basic credential-validation path entirely");
            Require(attack.SelectorUserHost.StartsWith("public.test",StringComparison.OrdinalIgnoreCase),
                "selector must see stale public Host");
            Require(string.Equals(attack.SelectorUrlHost,"admin.test",StringComparison.OrdinalIgnoreCase),
                "same request must expose canonical admin Url");
            Require(attack.AdminOperation && attack.SideEffect,
                "no-credential attack must execute operation that wrong credentials cannot execute");

            Console.WriteLine($"CREDENTIAL_VALIDATION_SIDE_EFFECT={SideEffectPath}");
            Console.WriteLine("HOST_AUTHORITY_CONFUSION_BYPASSES_CREDENTIAL_VALIDATION=CONFIRMED");
        }
    }
}
