using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, 0);
});

var app = builder.Build();

app.MapMethods("/admin/action", new[] { "GET", "POST" }, async context =>
{
    await WriteObservation(context, "ADMIN_ACTION");
}).WithDisplayName("ADMIN_ACTION");

app.Map("/{**rest}", async context =>
{
    await WriteObservation(context, "CATCH_ALL");
}).WithDisplayName("CATCH_ALL");

await app.StartAsync();

var server = app.Services.GetRequiredService<IServer>();
var address = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
var listenUri = new Uri(address);
var port = listenUri.Port;

Console.WriteLine($"KESTREL_PORT={port}");
Console.WriteLine($"RUNTIME={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");

string[] candidates =
[
    "/admin/action",
    "/./admin/action",
    "/a/../admin/action",
    "/%2e/admin/action",
    "/%2E%2E/admin/action",
    "/a/%2e%2e/admin/action",
    "/%252e/admin/action",
    "/a/%252e%252e/admin/action",
    "//admin/action",
    "///admin/action",
    "/%2fadmin/action",
    "/%2Fadmin/action",
    "/%252fadmin/action",
    "/a%2fb",
    "/a%252fb",
    "/a%3Fb",
    "/a%253Fb",
    "/a%23b",
    "/a%2523b",
    "/a#b",
    "/admin/action#ignored",
    "/public#../admin/action",
    "/a%5Cb",
    "/a%255Cb",
    "/a%7Cb",
    "/a%5Eb",
    "/a%60b",
    "/a%7Bb",
    "/a%7Db",
    "/a%3Cb",
    "/a%3Eb",
    "/a%22b",
    "/a;b",
    "/a:b",
    "/a@b",
    "/a//b",
    "/a/%2F/../admin/action",
    "/a/%252F/../admin/action",
    "/a/%2e%2e/%2fadmin/action",
    "/a/%2e%2e/%252fadmin/action",
];

var differences = new List<object>();

foreach (var candidate in candidates)
{
    var origin = await SendRawAsync(port, candidate);
    var absoluteTarget = $"http://localhost:{port}{candidate}";
    var absolute = await SendRawAsync(port, absoluteTarget);

    var originSig = Signature(origin);
    var absoluteSig = Signature(absolute);
    var differs = originSig != absoluteSig;

    Console.WriteLine("CASE_BEGIN");
    Console.WriteLine($"CANDIDATE={Escape(candidate)}");
    Console.WriteLine($"ORIGIN_STATUS={origin.StatusLine}");
    Console.WriteLine($"ORIGIN_BODY={Escape(origin.Body)}");
    Console.WriteLine($"ABSOLUTE_STATUS={absolute.StatusLine}");
    Console.WriteLine($"ABSOLUTE_BODY={Escape(absolute.Body)}");
    Console.WriteLine($"SEMANTIC_DIFFERENTIAL={differs}");
    Console.WriteLine("CASE_END");

    if (differs)
    {
        differences.Add(new
        {
            candidate,
            OriginStatus = origin.StatusLine,
            Origin = TryParseObservation(origin.Body),
            AbsoluteStatus = absolute.StatusLine,
            Absolute = TryParseObservation(absolute.Body),
            originBody = origin.Body,
            absoluteBody = absolute.Body,
        });
    }
}

Console.WriteLine($"TOTAL_CASES={candidates.Length}");
Console.WriteLine($"DIFFERENTIAL_COUNT={differences.Count}");
Console.WriteLine("DIFFERENTIALS_JSON=" + JsonSerializer.Serialize(differences));

await app.StopAsync();

static async Task WriteObservation(HttpContext context, string selected)
{
    var feature = context.Features.Get<IHttpRequestFeature>();
    var observation = new Observation(
        feature?.RawTarget ?? string.Empty,
        context.Request.Path.Value ?? string.Empty,
        context.Request.QueryString.Value ?? string.Empty,
        selected,
        context.Request.RouteValues.ToDictionary(kvp => kvp.Key, kvp => kvp.Value?.ToString()));
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(JsonSerializer.Serialize(observation));
}

static async Task<RawResponse> SendRawAsync(int port, string target)
{
    using var client = new TcpClient();
    await client.ConnectAsync(IPAddress.Loopback, port);
    await using NetworkStream stream = client.GetStream();

    var request =
        $"GET {target} HTTP/1.1\r\n" +
        $"Host: localhost:{port}\r\n" +
        "Connection: close\r\n" +
        "\r\n";

    byte[] bytes = Encoding.ASCII.GetBytes(request);
    await stream.WriteAsync(bytes);
    await stream.FlushAsync();

    using var memory = new MemoryStream();
    byte[] buffer = new byte[8192];
    while (true)
    {
        int read;
        try
        {
            read = await stream.ReadAsync(buffer);
        }
        catch (IOException)
        {
            break;
        }

        if (read == 0)
        {
            break;
        }

        await memory.WriteAsync(buffer.AsMemory(0, read));
    }

    var response = Encoding.UTF8.GetString(memory.ToArray());
    var split = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
    var headers = split >= 0 ? response[..split] : response;
    var body = split >= 0 ? response[(split + 4)..] : string.Empty;
    var statusLineEnd = headers.IndexOf("\r\n", StringComparison.Ordinal);
    var statusLine = statusLineEnd >= 0 ? headers[..statusLineEnd] : headers;

    // Kestrel may use chunked transfer encoding. Decode the simple one-body case.
    if (headers.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
    {
        body = DecodeChunked(body);
    }

    return new RawResponse(statusLine, body);
}

static string DecodeChunked(string body)
{
    var cursor = 0;
    var output = new StringBuilder();
    while (cursor < body.Length)
    {
        var lineEnd = body.IndexOf("\r\n", cursor, StringComparison.Ordinal);
        if (lineEnd < 0)
        {
            break;
        }

        var sizeText = body[cursor..lineEnd].Split(';')[0];
        if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size))
        {
            return body;
        }

        cursor = lineEnd + 2;
        if (size == 0)
        {
            break;
        }

        if (cursor + size > body.Length)
        {
            return body;
        }

        output.Append(body, cursor, size);
        cursor += size + 2;
    }

    return output.ToString();
}

static Observation? TryParseObservation(string body)
{
    try
    {
        return JsonSerializer.Deserialize<Observation>(body);
    }
    catch
    {
        return null;
    }
}

static string Signature(RawResponse response)
{
    var obs = TryParseObservation(response.Body);
    if (obs is null)
    {
        return response.StatusLine + "|" + response.Body;
    }

    return string.Join("|",
        response.StatusLine,
        obs.Path,
        obs.Query,
        obs.Selected,
        JsonSerializer.Serialize(obs.RouteValues));
}

static string Escape(string value) =>
    value.Replace("\\", "\\\\", StringComparison.Ordinal)
         .Replace("\r", "\\r", StringComparison.Ordinal)
         .Replace("\n", "\\n", StringComparison.Ordinal);

internal sealed record Observation(
    string RawTarget,
    string Path,
    string Query,
    string Selected,
    Dictionary<string, string?> RouteValues);

internal sealed record RawResponse(string StatusLine, string Body);
