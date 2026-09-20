using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

record TestCase(string Name, Func<int, byte[]> Build);

class Program
{
    static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    static byte[] A(string s) => Encoding.Latin1.GetBytes(s);

    static byte[] Cat(params byte[][] parts)
    {
        int len = 0;
        foreach (var p in parts) len += p.Length;
        byte[] r = new byte[len];
        int o = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p,0,r,o,p.Length); o += p.Length; }
        return r;
    }

    static string Second(int port) =>
        $"GET /smuggled HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n";

    static async Task<string> ReadResponse(NetworkStream ns)
    {
        using var ms = new MemoryStream();
        byte[] b = new byte[8192];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            while (true)
            {
                int n = await ns.ReadAsync(b, cts.Token);
                if (n <= 0) break;
                ms.Write(b,0,n);
            }
        }
        catch {}
        return Encoding.Latin1.GetString(ms.ToArray());
    }

    static async Task Run(TestCase tc)
    {
        int port = FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();

        Task<HttpListenerContext> c1Task = listener.GetContextAsync();
        byte[] raw = tc.Build(port);
        await ns.WriteAsync(raw);
        await ns.FlushAsync();

        var contexts = new List<string>();
        var bodies = new List<string>();
        var errors = new List<string>();

        Task first = await Task.WhenAny(c1Task, Task.Delay(2500));
        if (first == c1Task && c1Task.IsCompletedSuccessfully)
        {
            HttpListenerContext c1 = await c1Task;
            contexts.Add(c1.Request.RawUrl ?? "<null>");
            try
            {
                using var body = new MemoryStream();
                await c1.Request.InputStream.CopyToAsync(body).WaitAsync(TimeSpan.FromSeconds(2));
                bodies.Add(Encoding.Latin1.GetString(body.ToArray()));
            }
            catch(Exception ex)
            {
                bodies.Add("<READ_ERROR:"+ex.GetType().Name+">");
            }

            try
            {
                c1.Response.StatusCode=204;
                c1.Response.KeepAlive=true;
                c1.Response.Close();
            }
            catch {}

            Task<HttpListenerContext> c2Task = listener.GetContextAsync();
            Task second = await Task.WhenAny(c2Task, Task.Delay(1500));
            if (second == c2Task && c2Task.IsCompletedSuccessfully)
            {
                HttpListenerContext c2 = await c2Task;
                contexts.Add(c2.Request.RawUrl ?? "<null>");
                try
                {
                    using var body2=new MemoryStream();
                    await c2.Request.InputStream.CopyToAsync(body2).WaitAsync(TimeSpan.FromSeconds(1));
                    bodies.Add(Encoding.Latin1.GetString(body2.ToArray()));
                }
                catch(Exception ex){ bodies.Add("<READ_ERROR:"+ex.GetType().Name+">");}
                try { c2.Response.StatusCode=204; c2.Response.Close(); } catch {}
            }
        }

        string response = await ReadResponse(ns);
        string firstLine = response.Split(new[]{"\r\n","\n"},StringSplitOptions.None)[0];
        Console.WriteLine(
            $"FRAME_CASE={tc.Name} contexts={contexts.Count} urls=[{string.Join("|",contexts)}] " +
            $"bodies=[{string.Join("|",bodies).Replace("\r","<CR>").Replace("\n","<LF>")}] " +
            $"wireFirst={firstLine}");
        listener.Stop();
    }

    static async Task Main()
    {
        Console.WriteLine($"FRAMEWORK={RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS={RuntimeInformation.OSDescription}");

        var cases = new List<TestCase>
        {
            new("CONTROL_CL", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nHELLO" + Second(p))),

            new("DUP_CL_SAME", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 5\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nHELLO" + Second(p))),

            new("CL_COMMA_SAME", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 5, 5\r\nConnection: keep-alive\r\n\r\nHELLO" + Second(p))),

            new("CL_PLUS", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: +5\r\nConnection: keep-alive\r\n\r\nHELLO" + Second(p))),

            new("CL_LEADING_ZERO", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 0005\r\nConnection: keep-alive\r\n\r\nHELLO" + Second(p))),

            new("TE_CL", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CL_TE", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("TE_CHUNKED_TRAILING_SPACE", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked \r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("TE_CHUNKED_PARAM", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked;foo=bar\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_EXT_VALID", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5;foo=bar\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_EXT_EMPTY", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5;\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_EXT_DOUBLE_SEMI", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5;;foo=bar\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_EXT_UNTERM_QUOTE", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5;foo=\"unterminated\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_EXT_SPACE_VALUE", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5;foo=bar baz\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_EXT_TAB", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5;\tfoo=bar\r\nHELLO\r\n0\r\n\r\n" + Second(p))),

            new("CHUNK_TRAILER", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\nX-Trailer: yes\r\n\r\n" + Second(p))),

            new("CHUNK_TRAILER_CL", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\nContent-Length: 999\r\n\r\n" + Second(p))),

            new("CHUNK_ZERO_EXTRA_CR", p => A(
                $"POST /first HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\r\n" + Second(p))),
        };

        foreach(var tc in cases)
        {
            try { await Run(tc); }
            catch(Exception ex){ Console.WriteLine($"FRAME_CASE={tc.Name} EX={ex.GetType().Name}:{ex.Message.Replace("\r"," ").Replace("\n"," ")}"); }
        }
    }
}
