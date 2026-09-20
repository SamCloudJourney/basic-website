using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

static int ReservePort()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    return ((IPEndPoint)listener.LocalEndpoint).Port;
}

static async Task<string> ReadWireAsync(NetworkStream stream)
{
    byte[] buffer = new byte[8192];
    using var ms = new MemoryStream();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try
    {
        while (true)
        {
            int n = await stream.ReadAsync(buffer, cts.Token);
            if (n == 0) break;
            await ms.WriteAsync(buffer.AsMemory(0, n), cts.Token);
        }
    }
    catch (OperationCanceledException)
    {
    }

    return Encoding.ASCII.GetString(ms.ToArray());
}

static async Task RunCase(bool allowOverride)
{
    int port = ReservePort();
    int appDispatches = 0;
    string appHost = "<not-dispatched>";

    var builder = WebApplication.CreateBuilder();
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ListenLocalhost(port);
        options.AllowHostHeaderOverride = allowOverride;
    });

    await using var app = builder.Build();
    app.Run(async context =>
    {
        Interlocked.Increment(ref appDispatches);
        appHost = context.Request.Host.ToString();
        Console.WriteLine($"KESTREL_APP_DISPATCH override={allowOverride} Host={appHost} Path={context.Request.Path}");
        context.Response.StatusCode = 200;
        await context.Response.WriteAsync($"APP_HOST={appHost}\n");
    });

    await app.StartAsync();

    using var client = new TcpClient();
    await client.ConnectAsync(IPAddress.Loopback, port);
    using NetworkStream stream = client.GetStream();

    string raw =
        $"GET http://admin.test:{port}/authority HTTP/1.1\r\n" +
        $"Host: public.test:{port}\r\n" +
        "Connection: close\r\n" +
        "\r\n";

    await stream.WriteAsync(Encoding.ASCII.GetBytes(raw));
    await stream.FlushAsync();

    string wire = await ReadWireAsync(stream);
    string firstLine = wire.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)[0];

    if (!allowOverride)
    {
        if (!firstLine.Contains("400", StringComparison.Ordinal))
            throw new Exception($"Expected default Kestrel to reject authority mismatch, got: {firstLine}");
        if (Volatile.Read(ref appDispatches) != 0)
            throw new Exception("Default Kestrel dispatched mismatched request to app");

        Console.WriteLine(
            $"KESTREL_DEFAULT_AUTHORITY_MISMATCH=REJECTED FIRSTLINE={firstLine} " +
            $"APP_DISPATCHES={Volatile.Read(ref appDispatches)}");
    }
    else
    {
        if (!firstLine.Contains("200", StringComparison.Ordinal))
            throw new Exception($"Expected override Kestrel case to dispatch, got: {firstLine}");
        if (Volatile.Read(ref appDispatches) != 1)
            throw new Exception($"Expected exactly one app dispatch, got {Volatile.Read(ref appDispatches)}");
        if (!string.Equals(appHost, $"admin.test:{port}", StringComparison.OrdinalIgnoreCase))
            throw new Exception($"Expected canonical request-target authority in Host, got {appHost}");

        Console.WriteLine(
            $"KESTREL_EXPLICIT_OVERRIDE=CANONICALIZED FIRSTLINE={firstLine} " +
            $"APP_HOST={appHost} APP_DISPATCHES={Volatile.Read(ref appDispatches)}");
    }

    await app.StopAsync();
}

Console.WriteLine($".NET={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
await RunCase(allowOverride: false);
await RunCase(allowOverride: true);
Console.WriteLine("KESTREL_AUTHORITY_CONTROL_MATRIX=PASS");
