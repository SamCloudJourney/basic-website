using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Xml.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;

const string SyncSwitch = "Microsoft.AspNetCore.DataProtection.KeyManagement.DisableAsyncKeyRingUpdate";
bool syncGuard = args.Contains("--sync", StringComparer.Ordinal);
bool expectSafeDefault = args.Contains("--expect-safe-default", StringComparer.Ordinal);
bool expectBlocking = syncGuard || expectSafeDefault;
AppContext.SetSwitch(SyncSwitch, syncGuard);

Console.WriteLine($"MODE={(syncGuard ? "SYNC_GUARD" : expectSafeDefault ? "DEFAULT_SAFE" : "DEFAULT_ASYNC")}");
Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"OS={Environment.OSVersion}");

int port = ReservePort();
var repository = new BlockingXmlRepository();
int protectedExecutions = 0;

var builder = WebApplication.CreateBuilder();
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

builder.Services
    .AddDataProtection()
    .SetApplicationName("MSRC-Cookie-Revocation-Race")
    .AddKeyManagementOptions(options => options.XmlRepository = repository);

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "RevocationRaceAuth";
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
    int execution = Interlocked.Increment(ref protectedExecutions);
    return Results.Text($"PROTECTED_ADMIN_ACTION_EXECUTED={execution}");
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
    .Single(value => value.StartsWith("RevocationRaceAuth=", StringComparison.Ordinal));
string cookiePair = setCookie.Split(';', 2)[0];

Console.WriteLine($"LOGIN_COOKIE_ISSUED=True COOKIE_NAME={cookiePair.Split('=', 2)[0]}");

async Task<HttpResponseMessage> SendProtectedAsync()
{
    var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
    request.Headers.TryAddWithoutValidation("Cookie", cookiePair);
    return await client.SendAsync(request);
}

using (HttpResponseMessage baseline = await SendProtectedAsync())
{
    string body = await baseline.Content.ReadAsStringAsync();
    Console.WriteLine($"BASELINE_PROTECTED_STATUS={(int)baseline.StatusCode}");
    Console.WriteLine($"BASELINE_PROTECTED_BODY={body}");

    if (baseline.StatusCode != HttpStatusCode.OK ||
        !body.Contains("PROTECTED_ADMIN_ACTION_EXECUTED=", StringComparison.Ordinal))
    {
        throw new Exception("Baseline authenticated cookie did not reach the protected Admin endpoint.");
    }
}

int baselineExecutions = Volatile.Read(ref protectedExecutions);

IKeyManager keyManager = app.Services.GetRequiredService<IKeyManager>();
var keys = keyManager.GetAllKeys();
if (keys.Count != 1)
{
    throw new Exception($"Expected one Data Protection key before revocation, got {keys.Count}.");
}
Guid keyId = keys.Single().KeyId;

repository.BlockNextRead();
keyManager.RevokeKey(keyId, "MSRC deterministic cookie revocation test");

Console.WriteLine($"REVOKE_RETURNED=True KEY={keyId}");
Console.WriteLine($"REVOCATION_PERSISTED={repository.HasRevocationElement}");

if (!repository.HasRevocationElement)
{
    throw new Exception("Revocation record was not persisted.");
}

// This is the first authenticated request after IKeyManager.RevokeKey returned.
// The repository blocks the authoritative key-ring reread so the behavior of
// requests during the refresh window is deterministic.
Task<HttpResponseMessage> firstAfterRevoke = SendProtectedAsync();

if (!repository.RefreshReadEntered.Wait(TimeSpan.FromSeconds(10)))
{
    repository.ReleaseBlockedRead();
    throw new Exception("Post-revocation key-ring refresh never reached the repository.");
}

Console.WriteLine("POST_REVOKE_REFRESH_READ=ENTERED_AND_BLOCKED");

Task firstWinner = await Task.WhenAny(firstAfterRevoke, Task.Delay(TimeSpan.FromSeconds(3)));
bool firstCompletedWhileBlocked = ReferenceEquals(firstWinner, firstAfterRevoke);

Console.WriteLine($"FIRST_COOKIE_REQUEST_COMPLETED_WHILE_REFRESH_BLOCKED={firstCompletedWhileBlocked}");

if (!expectBlocking)
{
    if (!firstCompletedWhileBlocked)
    {
        repository.ReleaseBlockedRead();
        throw new Exception("Default async path did not complete the cookie request while refresh was blocked.");
    }

    using HttpResponseMessage firstResponse = await firstAfterRevoke;
    string firstBody = await firstResponse.Content.ReadAsStringAsync();

    Console.WriteLine($"FIRST_POST_REVOKE_COOKIE_STATUS={(int)firstResponse.StatusCode}");
    Console.WriteLine($"FIRST_POST_REVOKE_COOKIE_BODY={firstBody}");

    if (firstResponse.StatusCode != HttpStatusCode.OK ||
        !firstBody.Contains("PROTECTED_ADMIN_ACTION_EXECUTED=", StringComparison.Ordinal))
    {
        repository.ReleaseBlockedRead();
        throw new Exception("Revoked auth cookie did not reproduce against protected endpoint.");
    }

    // Keep the authoritative refresh blocked and send a burst of additional
    // requests using the same cookie. This checks whether the condition is a
    // one-request race or a window that remains open for all callers while the
    // backing key repository is slow/unavailable.
    const int BurstCount = 12;
    Task<HttpResponseMessage>[] burstTasks =
        Enumerable.Range(0, BurstCount).Select(_ => SendProtectedAsync()).ToArray();

    Task<HttpResponseMessage[]> allBurst = Task.WhenAll(burstTasks);
    Task burstWinner = await Task.WhenAny(allBurst, Task.Delay(TimeSpan.FromSeconds(5)));

    if (!ReferenceEquals(burstWinner, allBurst))
    {
        repository.ReleaseBlockedRead();
        throw new Exception("Burst requests did not complete while key-ring refresh was blocked.");
    }

    HttpResponseMessage[] burstResponses = await allBurst;
    try
    {
        int okCount = burstResponses.Count(r => r.StatusCode == HttpStatusCode.OK);
        Console.WriteLine($"REVOKED_COOKIE_BURST_COUNT={BurstCount}");
        Console.WriteLine($"REVOKED_COOKIE_BURST_200_COUNT={okCount}");

        if (okCount != BurstCount)
        {
            repository.ReleaseBlockedRead();
            throw new Exception($"Only {okCount}/{BurstCount} revoked-cookie requests were authorized.");
        }
    }
    finally
    {
        foreach (var response in burstResponses)
        {
            response.Dispose();
        }
    }

    int postRevokeExecutions =
        Volatile.Read(ref protectedExecutions) - baselineExecutions;

    Console.WriteLine($"PROTECTED_EXECUTIONS_WHILE_REFRESH_BLOCKED={postRevokeExecutions}");

    if (postRevokeExecutions < BurstCount + 1)
    {
        repository.ReleaseBlockedRead();
        throw new Exception("Expected every revoked-cookie request to execute protected Admin handler.");
    }

    Console.WriteLine("REVOKED_AUTH_COOKIE_ACCEPTED_WHILE_REFRESH_BLOCKED=CONFIRMED");

    repository.ReleaseBlockedRead();

    if (!repository.PostRevocationKeyStored.Wait(TimeSpan.FromSeconds(10)))
    {
        throw new Exception("Post-revocation key-ring refresh did not generate a replacement key.");
    }

    await Task.Delay(300);

    using HttpResponseMessage afterRefresh = await SendProtectedAsync();
    string afterRefreshBody = await afterRefresh.Content.ReadAsStringAsync();

    Console.WriteLine($"AFTER_REFRESH_OLD_COOKIE_STATUS={(int)afterRefresh.StatusCode}");
    Console.WriteLine($"AFTER_REFRESH_OLD_COOKIE_BODY={afterRefreshBody}");

    if (afterRefresh.StatusCode != HttpStatusCode.Unauthorized)
    {
        throw new Exception("Old cookie was still authorized after refreshed key ring observed revocation.");
    }

    Console.WriteLine("AFTER_REFRESH_OLD_COOKIE_REJECTED=True");
    Console.WriteLine("COOKIE_REVOCATION_WINDOW_E2E=PASS");
}
else
{
    if (firstCompletedWhileBlocked)
    {
        using HttpResponseMessage early = await firstAfterRevoke;
        repository.ReleaseBlockedRead();
        throw new Exception($"Sync guard unexpectedly completed while refresh blocked with HTTP {(int)early.StatusCode}.");
    }

    string safePrefix = syncGuard ? "SYNC_GUARD" : "DEFAULT_SAFE";
    Console.WriteLine($"{safePrefix}_COOKIE_REQUEST_BLOCKED_UNTIL_REFRESH=True");

    repository.ReleaseBlockedRead();

    using HttpResponseMessage response =
        await firstAfterRevoke.WaitAsync(TimeSpan.FromSeconds(10));
    string body = await response.Content.ReadAsStringAsync();

    Console.WriteLine($"{safePrefix}_POST_REFRESH_STATUS={(int)response.StatusCode}");
    Console.WriteLine($"{safePrefix}_POST_REFRESH_BODY={body}");

    int executionsAfterRevoke =
        Volatile.Read(ref protectedExecutions) - baselineExecutions;
    Console.WriteLine($"{safePrefix}_PROTECTED_EXECUTIONS_AFTER_REVOKE={executionsAfterRevoke}");

    if (response.StatusCode != HttpStatusCode.Unauthorized ||
        executionsAfterRevoke != 0)
    {
        throw new Exception("Blocking control failed to reject revoked authentication cookie.");
    }

    Console.WriteLine($"{safePrefix}_REVOKED_COOKIE_REJECTED=True");
    Console.WriteLine(syncGuard ? "COOKIE_REVOCATION_SYNC_CONTROL=PASS" : "COOKIE_REVOCATION_DEFAULT_SAFE_CONTROL=PASS");
}

await app.StopAsync();

static int ReservePort()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    return ((IPEndPoint)listener.LocalEndpoint).Port;
}

sealed class BlockingXmlRepository : IXmlRepository
{
    private readonly object _lock = new();
    private readonly List<XElement> _elements = new();
    private int _blockNextRead;
    private bool _revocationSeen;
    private ManualResetEventSlim _releaseRefreshRead = new(false);

    public ManualResetEventSlim RefreshReadEntered { get; } = new(false);
    public ManualResetEventSlim PostRevocationKeyStored { get; } = new(false);

    public bool HasRevocationElement
    {
        get
        {
            lock (_lock)
            {
                return _elements.Any(
                    e => string.Equals(e.Name.LocalName, "revocation", StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    public void BlockNextRead()
    {
        RefreshReadEntered.Reset();
        _releaseRefreshRead.Dispose();
        _releaseRefreshRead = new ManualResetEventSlim(false);
        Interlocked.Exchange(ref _blockNextRead, 1);
    }

    public void ReleaseBlockedRead() => _releaseRefreshRead.Set();

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        if (Interlocked.Exchange(ref _blockNextRead, 0) == 1)
        {
            Console.WriteLine("REPOSITORY_GET_ALL_ELEMENTS=BLOCKING_POST_REVOKE_REFRESH");
            RefreshReadEntered.Set();

            if (!_releaseRefreshRead.Wait(TimeSpan.FromSeconds(30)))
            {
                throw new TimeoutException("Controlled key-ring repository refresh timed out.");
            }

            Console.WriteLine("REPOSITORY_GET_ALL_ELEMENTS=POST_REVOKE_REFRESH_RELEASED");
        }

        lock (_lock)
        {
            return _elements.Select(e => new XElement(e)).ToArray();
        }
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        XElement clone = new(element);
        bool postRevocationKey = false;

        lock (_lock)
        {
            _elements.Add(clone);

            if (string.Equals(clone.Name.LocalName, "revocation", StringComparison.OrdinalIgnoreCase))
            {
                _revocationSeen = true;
            }
            else if (_revocationSeen &&
                     string.Equals(clone.Name.LocalName, "key", StringComparison.OrdinalIgnoreCase))
            {
                postRevocationKey = true;
            }
        }

        Console.WriteLine($"REPOSITORY_STORE NAME={friendlyName} ELEMENT={clone.Name.LocalName}");

        if (postRevocationKey)
        {
            PostRevocationKeyStored.Set();
        }
    }
}
