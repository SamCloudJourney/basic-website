using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Program
{
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
        byte[] b=new byte[4096];
        var sb=new StringBuilder();
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while(true)
            {
                int n=await ns.ReadAsync(b,cts.Token);
                if(n==0) break;
                sb.Append(Encoding.ASCII.GetString(b,0,n));
            }
        }
        catch(OperationCanceledException){}
        return sb.ToString();
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        int publicPort=FreePort();
        int adminPort=FreePort();
        while(adminPort==publicPort) adminPort=FreePort();

        using var admin=new HttpListener();
        admin.Prefixes.Add($"http://app.test:{adminPort}/admin/");
        admin.AuthenticationSchemes=AuthenticationSchemes.None;
        admin.Realm="url-port-control";

        AuthenticationSchemes selected=AuthenticationSchemes.None;
        string userHost="<not-called>";
        string urlAuthority="<not-called>";

        admin.AuthenticationSchemeSelectorDelegate=request =>
        {
            userHost=request.UserHostName ?? "<null>";
            urlAuthority=request.Url?.Authority ?? "<null>";

            // Causal control: use the same canonical Url port that HttpListener
            // exposes for the listener/resource actually selected.
            selected=request.Url?.Port==publicPort
                ? AuthenticationSchemes.Anonymous
                : AuthenticationSchemes.Basic;

            Console.WriteLine(
                $"URL_SELECTOR UserHostName={userHost} UrlAuthority={urlAuthority} PublicPort={publicPort} AdminPort={adminPort} Selected={selected}");

            return selected;
        };

        admin.Start();
        Task<HttpListenerContext> contextTask=admin.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,adminPort);
        using NetworkStream ns=client.GetStream();

        string raw=
            $"POST http://app.test:{publicPort}/admin/change HTTP/1.1\r\n"+
            $"Host: app.test:{publicPort}\r\n"+
            "Content-Length: 0\r\n"+
            "Connection: close\r\n\r\n";

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        string wire=await ReadAll(ns);
        string first=wire.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        bool basic=wire.Contains("WWW-Authenticate: Basic",StringComparison.OrdinalIgnoreCase);

        Console.WriteLine(
            $"URL_SELECTOR_RESULT first={first} basicChallenge={basic} contextCompleted={contextTask.IsCompletedSuccessfully} selected={selected} UserHostName={userHost} UrlAuthority={urlAuthority}");

        Require(first.Contains("401"),"Url.Port selector control must restore 401");
        Require(basic,"Url.Port selector control must emit Basic challenge");
        Require(selected==AuthenticationSchemes.Basic,"Url.Port selector must choose Basic on physical admin port");
        Require(userHost.EndsWith($":{publicPort}",StringComparison.Ordinal),
            "control must preserve the original cross-port split");
        Require(urlAuthority.EndsWith($":{adminPort}",StringComparison.Ordinal),
            "Url authority must identify the physical admin port");
        Require(!contextTask.IsCompletedSuccessfully,
            "blocked request must not be delivered as application context");

        Console.WriteLine("URL_PORT_SELECTOR_CAUSAL_CONTROL=PASS");
        admin.Close();
    }
}
