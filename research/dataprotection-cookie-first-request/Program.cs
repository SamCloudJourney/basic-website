using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

bool expectSafe = args.Contains("--expect-safe", StringComparer.Ordinal);
bool revokeAll = args.Contains("--revoke-all", StringComparer.Ordinal);
Console.WriteLine($"MODE={(expectSafe ? "EXPECT_SAFE" : "EXPECT_STALE_FIRST")}");
Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"OS={Environment.OSVersion}");

string keyDirectory = Path.Combine(Path.GetTempPath(), "dp-first-request-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(keyDirectory);

int port = ReservePort();
int protectedExecutions = 0;

try
{
    var builder = WebApplication.CreateBuilder();
    builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

    builder.Services
        .AddDataProtection()
        .SetApplicationName("MSRC-DataProtection-First-Request")
        .PersistKeysToFileSystem(new DirectoryInfo(keyDirectory));

    builder.Services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            options.Cookie.Name = "RevocationFirstRequestAuth";
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

    using var handler = new HttpClientHandler
    {
        UseCookies = false,
        AllowAutoRedirect = false
    };
    using var client = new HttpClient(handler)
    {
        BaseAddress = new Uri($"http://127.0.0.1:{port}")
    };

    HttpResponseMessage login = await client.GetAsync("/login");
    login.EnsureSuccessStatusCode();

    string setCookie = login.Headers.GetValues("Set-Cookie")
        .Single(value => value.StartsWith("RevocationFirstRequestAuth=", StringComparison.Ordinal));
    string cookiePair = setCookie.Split(';', 2)[0];

    async Task<(HttpStatusCode Status, string Body)> SendProtectedAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.TryAddWithoutValidation("Cookie", cookiePair);
        using HttpResponseMessage response = await client.SendAsync(request);
        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    var baseline = await SendProtectedAsync();
    Console.WriteLine($"BASELINE_STATUS={(int)baseline.Status}");
    Console.WriteLine($"BASELINE_BODY={baseline.Body}");

    if (baseline.Status != HttpStatusCode.OK)
    {
        throw new Exception("Baseline authentication cookie was not accepted.");
    }

    int baselineExecutions = Volatile.Read(ref protectedExecutions);

    IKeyManager keyManager = app.Services.GetRequiredService<IKeyManager>();
    var keys = keyManager.GetAllKeys();
    if (keys.Count != 1)
    {
        throw new Exception($"Expected one initial key, got {keys.Count}.");
    }

    Guid keyId = keys.Single().KeyId;
    Console.WriteLine($"KEY_ID={keyId}");
    Console.WriteLine($"KEY_FILES_BEFORE_REVOKE={Directory.GetFiles(keyDirectory, "*.xml").Length}");

    var stopwatch = Stopwatch.StartNew();
    if (revokeAll)
    {
        keyManager.RevokeAllKeys(
            DateTimeOffset.UtcNow.AddMinutes(1),
            "MSRC built-in repository emergency mass-revocation validation");
    }
    else
    {
        keyManager.RevokeKey(keyId, "MSRC built-in repository first-request validation");
    }
    long revokeReturnedAtMs = stopwatch.ElapsedMilliseconds;

    string[] revocationFiles = Directory.GetFiles(keyDirectory, "revocation-*.xml");
    Console.WriteLine($"REVOCATION_MODE={(revokeAll ? "ALL_KEYS" : "SINGLE_KEY")}");
    Console.WriteLine($"REVOKE_RETURNED=True ELAPSED_MS={revokeReturnedAtMs}");
    Console.WriteLine($"REVOCATION_FILE_COUNT={revocationFiles.Length}");

    if (revocationFiles.Length != 1)
    {
        throw new Exception("Expected persisted revocation XML before replay.");
    }

    // No artificial repository delay, custom repository, lock, or injected fault exists here.
    // This is simply the very first request using the old cookie after RevokeKey() returns.
    var firstAfterRevoke = await SendProtectedAsync();
    long firstCompletedAtMs = stopwatch.ElapsedMilliseconds;

    Console.WriteLine($"FIRST_POST_REVOKE_STATUS={(int)firstAfterRevoke.Status}");
    Console.WriteLine($"FIRST_POST_REVOKE_BODY={firstAfterRevoke.Body}");
    Console.WriteLine($"FIRST_POST_REVOKE_COMPLETED_MS_AFTER_REVOKE={firstCompletedAtMs - revokeReturnedAtMs}");
    Console.WriteLine($"PROTECTED_EXECUTIONS_AFTER_FIRST_REPLAY={Volatile.Read(ref protectedExecutions) - baselineExecutions}");

    if (expectSafe)
    {
        if (firstAfterRevoke.Status != HttpStatusCode.Unauthorized ||
            Volatile.Read(ref protectedExecutions) != baselineExecutions)
        {
            throw new Exception("Expected safe release to reject first revoked-cookie replay.");
        }

        Console.WriteLine("FIRST_POST_REVOKE_COOKIE_REJECTED=True");
        Console.WriteLine("BUILTIN_REPOSITORY_SAFE_CONTROL=PASS");
    }
    else
    {
        if (firstAfterRevoke.Status != HttpStatusCode.OK ||
            !firstAfterRevoke.Body.Contains("PROTECTED_ADMIN_ACTION_EXECUTED=", StringComparison.Ordinal))
        {
            throw new Exception("Expected first post-revocation cookie replay to reach protected endpoint.");
        }

        Console.WriteLine("FIRST_POST_REVOKE_COOKIE_ACCEPTED=CONFIRMED");

        // Allow the already-scheduled background reread to complete, then retry the exact cookie.
        await Task.Delay(1000);

        var secondAfterRevoke = await SendProtectedAsync();

        Console.WriteLine($"SECOND_POST_REVOKE_STATUS={(int)secondAfterRevoke.Status}");
        Console.WriteLine($"SECOND_POST_REVOKE_BODY={secondAfterRevoke.Body}");
        Console.WriteLine($"KEY_FILES_AFTER_REFRESH={Directory.GetFiles(keyDirectory, "*.xml").Length}");

        if (secondAfterRevoke.Status != HttpStatusCode.Unauthorized)
        {
            throw new Exception("Old cookie was not rejected after background key-ring refresh completed.");
        }

        Console.WriteLine("SECOND_POST_REVOKE_COOKIE_REJECTED=True");
        Console.WriteLine("BUILTIN_REPOSITORY_FIRST_REQUEST_WINDOW=PASS");
    }

    await app.StopAsync();
}
finally
{
    try
    {
        Directory.Delete(keyDirectory, recursive: true);
    }
    catch
    {
    }
}

static int ReservePort()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    return ((IPEndPoint)listener.LocalEndpoint).Port;
}
