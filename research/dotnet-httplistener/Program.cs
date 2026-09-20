using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

record Case(string Name, Func<int,string> Request);

class Program
{
    static async Task<int> FreePort()
    {
        var t = new TcpListener(IPAddress.Loopback, 0);
        t.Start();
        int p = ((IPEndPoint)t.LocalEndpoint).Port;
        t.Stop();
        return p;
    }

    static async Task RunCase(Case c)
    {
        int port = await FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        Task<HttpListenerContext> contextTask = listener.GetContextAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();
        string raw = c.Request(port);
        byte[] bytes = Encoding.ASCII.GetBytes(raw);
        await ns.WriteAsync(bytes);
        await ns.FlushAsync();

        var responseTask = ReadSome(ns);
        Task first = await Task.WhenAny(contextTask, responseTask, Task.Delay(3000));

        if (first == contextTask && contextTask.IsCompletedSuccessfully)
        {
            var ctx = await contextTask;
            string[]? hosts = ctx.Request.Headers.GetValues("Host");
            Console.WriteLine($"CASE={c.Name} RESULT=CONTEXT HOST={ctx.Request.UserHostName} URLHOST={ctx.Request.Url?.Host} HOSTVALUES={string.Join("|", hosts ?? Array.Empty<string>())} METHOD={ctx.Request.HttpMethod} RAWURL={ctx.Request.RawUrl}");
            ctx.Response.StatusCode = 204;
            ctx.Response.Close();
        }
        else if (first == responseTask)
        {
            string response = await responseTask;
            string firstLine = response.Split(new[]{"\r\n","\n"}, StringSplitOptions.None)[0];
            Console.WriteLine($"CASE={c.Name} RESULT=RESPONSE FIRSTLINE={firstLine}");
        }
        else
        {
            Console.WriteLine($"CASE={c.Name} RESULT=TIMEOUT");
        }

        listener.Stop();
    }

    static async Task<string> ReadSome(NetworkStream ns)
    {
        var buffer = new byte[4096];
        try
        {
            int n = await ns.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(3));
            return Encoding.ASCII.GetString(buffer,0,n);
        }
        catch { return ""; }
    }

    static async Task Main()
    {
        Console.WriteLine($"OS={Environment.OSVersion}");
        Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");

        Case[] cases = {
            new("CONTROL_CRLF", p =>
                $"GET /control HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nConnection: close\r\n\r\n"),

            new("DUP_HOST_FIRST_ATTACKER_LAST_VALID", p =>
                $"GET /dup HTTP/1.1\r\nHost: attacker.invalid\r\nHost: 127.0.0.1:{p}\r\nConnection: close\r\n\r\n"),

            new("DUP_HOST_FIRST_VALID_LAST_ATTACKER", p =>
                $"GET /dup HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nHost: attacker.invalid\r\nConnection: close\r\n\r\n"),

            new("BARE_LF_ALL_LINES", p =>
                $"GET /lf HTTP/1.1\nHost: 127.0.0.1:{p}\nConnection: close\n\n"),

            new("BARE_LF_HIDDEN_HOST", p =>
                $"GET /lfhost HTTP/1.1\r\nHost: attacker.invalid\nHost: 127.0.0.1:{p}\r\nConnection: close\r\n\r\n"),

            new("TE_CL_BOTH", p =>
                $"POST /tecl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
        };

        foreach (var c in cases)
        {
            try { await RunCase(c); }
            catch(Exception ex) { Console.WriteLine($"CASE={c.Name} RESULT=EXCEPTION TYPE={ex.GetType().Name} MSG={ex.Message.Replace("\r"," ").Replace("\n"," ")}"); }
        }
    }
}
