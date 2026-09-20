# MSRC report-quality checklist — HttpListener authority/authentication bypass

## Reproduction

- [x] Raw socket request; no production service
- [x] Synthetic loopback-only hostnames
- [x] Ordinary public control
- [x] Ordinary protected-admin control
- [x] Conflicting absolute-form attack request
- [x] Full response status captured
- [x] `WWW-Authenticate: Basic` presence/absence captured
- [x] Context-delivery presence/absence captured
- [x] `context.User is null` captured on vulnerable path
- [x] Protected admin sentinel returned only on bypass path
- [x] Windows/http.sys negative control

## Affected supported releases

- [x] .NET 8.0.31 Linux
- [x] .NET 9.0.20 Linux
- [x] .NET 10.0.12 Linux
- [x] .NET 10.0.12 macOS
- [x] .NET 10.0.12 Windows negative control
- [x] .NET 11.0.0-rc.1 Linux
- [x] .NET 11.0.0-rc.1 macOS
- [x] .NET 11.0.0-rc.1 Windows/http.sys negative control

## Independent proof shapes

- [x] Single HttpListener with public + admin prefixes using Microsoft's documented per-request selector model
  - Run 35528996700
- [x] Separate public/admin HttpListener instances with framework-owned prefix routing
  - Run 35528291290
- [x] Current-main source regression at commit 12921b1d8c6865a774232de9379133020ad23d79
  - vulnerable source regression already demonstrated in prior current-main run
  - deterministic patched-source causal run is separately tracked

## Root cause

- [x] `FinishInitialization()` starts from Host-derived `UserHostName`
- [x] absolute-form target updates only local host used to construct `Request.Url`
- [x] public `UserHostName` remains backed by received Host field
- [x] managed prefix router uses `Request.Url`
- [x] selected listener invokes `AuthenticationSchemeSelectorDelegate`
- [x] Basic failure path produces 401 + Basic challenge and withholds context

## Causal remediation hypothesis

Minimal managed-source experiment:

```diff
 if (raw_uri != null)
-    host = raw_uri.Host;
+{
+    host = raw_uri.Host;
+    Headers.Set(HttpKnownHeaderNames.Host, raw_uri.Authority);
+}
```

Required regression outcome:

- [ ] current-main vulnerable source: attack = Anonymous / 200 / context delivered
- [ ] patched current-main source: same attack = Basic / 401 / no context
- [ ] patched source: public control remains Anonymous / 200
- [ ] patched source: ordinary admin remains Basic / 401

These final four boxes should be checked only after the dedicated source workflow reports success.

## Standards + documentation

- [x] RFC 9112 §3.2.2 absolute-form authority rule
- [x] Microsoft AuthenticationSchemes documentation explicitly identifies `Url` / `UserHostName` as selector inputs
- [x] Microsoft docs say GetContext returns requests only if HttpListener successfully authenticates
- [x] Microsoft UserHostName docs define it as Host-header text
- [x] .NET bounty scope confirms current supported versions are in scope
- [x] .NET bounty table includes Security Feature Bypass

## Duplicate checks

- [x] GitHub issue search: AuthenticationSchemeSelectorDelegate + absolute-form + Host
- [x] GitHub issue search: UserHostName + absolute URI
- [x] GitHub issue search: request-target authority + Host
- [x] GitHub PR search variants
- [x] broader web search for exact vulnerability shape
- [x] no exact public duplicate identified

## Claims intentionally NOT made

- [x] No claim that every HttpListener application is exploitable
- [x] No claim of RCE
- [x] No claim of NTLM/Negotiate bypass on managed Linux/macOS
- [x] No claim of Extended Protection bypass
- [x] No claim that Basic passwords are validated against an external credential store by managed HttpListener
- [x] No Critical-severity assertion; severity is Microsoft's determination

## Submission framing

Primary mechanism:
- inconsistent absolute-form authority canonicalization

Security boundary:
- framework listener selection + framework per-request authentication selection

Demonstrated consequence:
- Basic-protected admin request that normally gets 401 is instead returned as an anonymous admin context

Suggested impact category:
- Security Feature Bypass / Authentication Bypass


## Strong credential-validation controls

- [x] Admin request without credentials -> Basic 401, no context
- [x] Wrong Basic credentials rejected by independent app validation -> 403, no side effect
- [x] Correct Basic credentials pass validation -> protected operation succeeds
- [x] Conflicting absolute-form request with no credentials -> Anonymous context, validation path skipped, same protected operation succeeds
- [x] Concrete temp-file side effect confirms operation execution
- [x] Windows/http.sys blocks the no-credential conflicting request before application context delivery
