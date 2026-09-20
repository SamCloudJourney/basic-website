using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
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

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        int localPort=FreePort();
        int targetPort=localPort==12345 ? 12346 : 12345;

        using var listener=new HttpListener();
        listener.Prefixes.Add($"http://*:{localPort}/");
        listener.Start();

        Task<HttpListenerContext> contextTask=listener.GetContextAsync();

        using var client=new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback,localPort);
        using NetworkStream ns=client.GetStream();

        string raw=
            $"GET http://admin.test:{targetPort}/port-check HTTP/1.1\r\n"+
            $"Host: public.test:{localPort}\r\n"+
            "Connection: close\r\n\r\n";

        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task first=await Task.WhenAny(contextTask,Task.Delay(3000));
        if(first==contextTask && contextTask.IsCompletedSuccessfully)
        {
            var ctx=await contextTask;
            Console.WriteLine(
                $"PORT_AUTHORITY_CONTEXT HostHeader={ctx.Request.Headers["Host"]} UserHostName={ctx.Request.UserHostName} UrlHost={ctx.Request.Url?.Host} UrlPort={ctx.Request.Url?.Port} UrlAuthority={ctx.Request.Url?.Authority} RawUrl={ctx.Request.RawUrl} LocalPort={localPort} TargetPort={targetPort}");
            ctx.Response.StatusCode=204;
            ctx.Response.Close();
        }
        else
        {
            byte[] b=new byte[4096];
            try
            {
                int n=await ns.ReadAsync(b).AsTask().WaitAsync(TimeSpan.FromSeconds(2));
                Console.WriteLine("PORT_AUTHORITY_RESPONSE="+Encoding.ASCII.GetString(b,0,n).Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0]);
            }
            catch(Exception ex)
            {
                Console.WriteLine("PORT_AUTHORITY_NO_CONTEXT="+ex.GetType().Name);
            }
        }

        listener.Close();
    }
}
