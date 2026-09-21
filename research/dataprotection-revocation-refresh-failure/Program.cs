using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging.Abstractions;

Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"OS={Environment.OSVersion}");

string keyDirectory = Path.Combine(Path.GetTempPath(), "dp-refresh-failure-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(keyDirectory);

int port = ReservePort();
int protectedExecutions = 0;
var repository = new FaultOnceFileSystemXmlRepository(new DirectoryInfo(keyDirectory));

try
{
    var builder = WebApplication.CreateBuilder();
    builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

    builder.Services
        .AddDataProtection()
        .SetApplicationName("MSRC-DataProtection-Refresh-Failure")
        .AddKeyManagementOptions(options => options.XmlRepository = repository);

    builder.Services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            options.Cookie.Name = "RefreshFailureAuth";
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

    builder.Services.AddAuthorization();

    await using var app = builder.Build();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapGet("/login", async context =>
    {
        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.Name, "research-admin"),
                new Claim(ClaimTypes.Role, "Admin")
            },
            CookieAuthenticationDefaults.AuthenticationScheme);

        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));

        await context.Response.WriteAsync("LOGIN_OK");
    });

    app.MapGet("/protected", () =>
    {
        int n = Interlocked.Increment(ref protectedExecutions);
        return Results.Text($"PROTECTED_ADMIN_ACTION_EXECUTED={n}");
    })
    .RequireAuthorization(new AuthorizeAttribute { Roles = "Admin" });

    await app.StartAsync();

    using var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false };
    using var client = new HttpClient(handler) { BaseAddress = new Uri($"http://127.0.0.1:{port}") };

    using HttpResponseMessage login = await client.GetAsync("/login");
    login.EnsureSuccessStatusCode();

    string cookiePair = login.Headers.GetValues("Set-Cookie")
        .Single(v => v.StartsWith("RefreshFailureAuth=", StringComparison.Ordinal))
        .Split(';', 2)[0];

    async Task<(HttpStatusCode Status, string Body)> SendProtectedAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.TryAddWithoutValidation("Cookie", cookiePair);
        using HttpResponseMessage response = await client.SendAsync(request);
        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    var baseline = await SendProtectedAsync();
    if (baseline.Status != HttpStatusCode.OK)
    {
        throw new Exception("Baseline cookie failed.");
    }
    Console.WriteLine($"BASELINE_STATUS={(int)baseline.Status}");

    int baselineExecutions = Volatile.Read(ref protectedExecutions);

    IKeyManager keyManager = app.Services.GetRequiredService<IKeyManager>();
    Guid keyId = keyManager.GetAllKeys().Single().KeyId;

    repository.ArmSingleReadFailure();
    keyManager.RevokeKey(keyId, "MSRC transient repository failure after revocation");

    int revocationFiles = Directory.GetFiles(keyDirectory, "revocation-*.xml").Length;
    Console.WriteLine($"REVOKE_RETURNED=True KEY={keyId}");
    Console.WriteLine($"REVOCATION_FILE_COUNT={revocationFiles}");

    if (revocationFiles != 1)
    {
        throw new Exception("Revocation was not persisted before replay.");
    }

    // First post-revocation request schedules an async refresh but consumes the stale ring.
    var first = await SendProtectedAsync();
    Console.WriteLine($"FIRST_POST_REVOKE_STATUS={(int)first.Status}");
    Console.WriteLine($"FIRST_POST_REVOKE_BODY={first.Body}");

    if (first.Status != HttpStatusCode.OK)
    {
        throw new Exception("Expected first stale-ring replay to be accepted.");
    }

    if (!repository.FailureObserved.Wait(TimeSpan.FromSeconds(10)))
    {
        throw new Exception("Background refresh did not hit the injected transient repository failure.");
    }

    Console.WriteLine("POST_REVOKE_REFRESH_FAILURE_OBSERVED=True");

    // The next call consumes the faulted refresh task. Depending on the auth pipeline,
    // this may surface as 401 or 500. The important follow-up is that product code
    // temporarily extends the old stale ring after this failure.
    var faultConsumer = await SendProtectedAsync();
    Console.WriteLine($"FAULT_CONSUMER_STATUS={(int)faultConsumer.Status}");
    Console.WriteLine($"FAULT_CONSUMER_BODY={faultConsumer.Body}");

    // Subsequent requests occur after the refresh failure has been observed.
    // CacheableKeyRing.WithTemporaryExtendedLifetime() disconnects the cancelled
    // token and extends the stale ring for two minutes.
    const int FollowupCount = 8;
    int accepted = 0;
    for (int i = 0; i < FollowupCount; i++)
    {
        var result = await SendProtectedAsync();
        Console.WriteLine($"POST_FAILURE_REPLAY_{i + 1}_STATUS={(int)result.Status}");
        if (result.Status == HttpStatusCode.OK)
        {
            accepted++;
        }
        await Task.Delay(100);
    }

    int protectedAfterRevoke = Volatile.Read(ref protectedExecutions) - baselineExecutions;
    Console.WriteLine($"POST_FAILURE_REPLAY_COUNT={FollowupCount}");
    Console.WriteLine($"POST_FAILURE_REPLAY_200_COUNT={accepted}");
    Console.WriteLine($"PROTECTED_EXECUTIONS_AFTER_REVOKE={protectedAfterRevoke}");

    if (accepted != FollowupCount)
    {
        throw new Exception($"Expected all {FollowupCount} post-failure replays to be accepted from temporarily extended stale ring; got {accepted}.");
    }

    if (protectedAfterRevoke < FollowupCount + 1)
    {
        throw new Exception("Protected endpoint did not execute for expected revoked-cookie replays.");
    }

    Console.WriteLine("TRANSIENT_REFRESH_FAILURE_EXTENDS_REVOKED_COOKIE_ACCEPTANCE=CONFIRMED");
    Console.WriteLine("TEMPORARY_STALE_RING_EXTENSION_SOURCE_DURATION=2_MINUTES");
    Console.WriteLine("REVOCATION_REFRESH_FAILURE_AMPLIFICATION=PASS");

    await app.StopAsync();
}
finally
{
    try { Directory.Delete(keyDirectory, recursive: true); } catch { }
}

static int ReservePort()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    return ((IPEndPoint)listener.LocalEndpoint).Port;
}

sealed class FaultOnceFileSystemXmlRepository : FileSystemXmlRepository
{
    private int _failNextRead;
    public ManualResetEventSlim FailureObserved { get; } = new(false);

    public FaultOnceFileSystemXmlRepository(DirectoryInfo directory)
        : base(directory, NullLoggerFactory.Instance)
    {
    }

    public void ArmSingleReadFailure()
    {
        FailureObserved.Reset();
        Interlocked.Exchange(ref _failNextRead, 1);
    }

    public override IReadOnlyCollection<System.Xml.Linq.XElement> GetAllElements()
    {
        if (Interlocked.Exchange(ref _failNextRead, 0) == 1)
        {
            Console.WriteLine("REPOSITORY_GET_ALL_ELEMENTS=INJECTING_SINGLE_TRANSIENT_FAILURE");
            FailureObserved.Set();
            throw new IOException("MSRC deterministic one-shot repository read failure");
        }

        return base.GetAllElements();
    }
}
