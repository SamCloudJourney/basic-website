# Proposed minimal remediation for managed HttpListener authority confusion

Research hypothesis only; this is not a Microsoft patch.

## Current managed behavior

File:

`src/libraries/System.Net.HttpListener/src/System/Net/Managed/HttpListenerRequest.Managed.cs`

Current logic in `FinishInitialization()`:

```csharp
ReadOnlySpan<char> host = UserHostName;
...
if (MaybeUri(_rawUrl!.ToLowerInvariant()) && Uri.TryCreate(_rawUrl, UriKind.Absolute, out raw_uri))
    path = raw_uri.PathAndQuery;
else
    path = _rawUrl;

...
if (raw_uri != null)
    host = raw_uri.Host;
```

This updates only the local variable used to construct `Request.Url`.

The public Host-facing state remains based on the received Host field:

```csharp
public string UserHostName => Headers[HttpKnownHeaderNames.Host]!;
```

That allows:

```text
UserHostName = public.test
Url.Host     = admin.test
```

for one absolute-form request.

## Minimal canonicalization hypothesis

When an absolute-form request target is accepted, canonicalize the Host field to the
request-target authority before authentication selection:

```diff
 if (raw_uri != null)
-    host = raw_uri.Host;
+{
+    host = raw_uri.Host;
+    Headers.Set(HttpKnownHeaderNames.Host, raw_uri.Authority);
+}
```

Expected result:

```text
UserHostName = admin.test:<port>
Headers["Host"] = admin.test:<port>
Url.Host = admin.test
```

Then the documented authentication selector:

```csharp
listener.AuthenticationSchemeSelectorDelegate = request =>
    request.UserHostName.StartsWith("public.test")
        ? AuthenticationSchemes.Anonymous
        : AuthenticationSchemes.Basic;
```

selects `Basic` for the malicious absolute-form request, causing a framework 401
challenge rather than delivering an anonymous admin context.

## Why canonicalization rather than rejecting absolute-form

RFC 9112 section 3.2.2 says an origin server must accept absolute-form and must ignore
the received Host field in favor of the authority in the request-target.

The Windows/http.sys implementation already produces the canonicalized behavior in the
research control:

```text
selectorUserHost=admin.test:<port>
selectorUrlHost=admin.test
scheme=Basic
HTTP/1.1 401 Unauthorized
```

## Regression tests

A product fix should cover at least:

1. origin-form public + Host public -> selector Anonymous
2. origin-form admin + Host admin -> selector Basic / 401
3. absolute-form admin + Host public -> Host/UserHostName canonicalized to admin / Basic / 401
4. absolute-form with userinfo + Host public -> reject or canonicalize consistently according to URI validity
5. `Headers["Host"]`, `UserHostName`, and `Url.Authority` must not expose conflicting authorities after request initialization
6. Linux/macOS behavior should match the security invariant demonstrated by Windows/http.sys
