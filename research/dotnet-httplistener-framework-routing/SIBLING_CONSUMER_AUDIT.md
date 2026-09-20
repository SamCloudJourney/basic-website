# HttpListener stale-authority sibling-consumer audit

Validated source commit:
`12921b1d8c6865a774232de9379133020ad23d79`

## Result

The most important sibling consumer is not another application callback. It is HttpListener's own managed prefix
router.

The framework consumes the two conflicting authority representations on opposite sides of the security boundary:

```text
absolute-form request-target
        |
        +--> Request.Url.Host = admin.test
        |       |
        |       +--> HttpEndPointListener.SearchListener()
        |               |
        |               +--> selects ADMIN HttpListener
        |
Host: public.test
        |
        +--> UserHostName = public.test
                |
                +--> ADMIN listener AuthenticationSchemeSelectorDelegate
                        |
                        +--> selects Anonymous
```

This removes the earlier application-router assumption.

## Direct UserHostName consumers in System.Net.HttpListener

Repository-wide source search of `src/libraries/System.Net.HttpListener/src` found the public `UserHostName`
property and the managed request initialization logic. No additional first-party managed security decision directly
reads `UserHostName`.

The security effect nevertheless occurs because Microsoft deliberately exposes the complete `HttpListenerRequest`
to `AuthenticationSchemeSelectorDelegate`, and Microsoft documents request properties as supported selector inputs.

## Prefix routing

`HttpEndPointListener.BindContext()` calls:

```csharp
SearchListener(req.Url, out prefix)
```

`SearchListener()` consumes `uri.Host`, `uri.Port`, and `uri.AbsolutePath` to select the exact registered
`HttpListener`.

This was validated end-to-end with separate `public.test` and `admin.test` listener instances on the same local
endpoint. The conflicting request is delivered to the ADMIN listener, not the PUBLIC listener.

This is the strongest sibling security consumer found.

## ExtendedProtectionSelectorDelegate

`ExtendedProtectionSelectorDelegate` also receives an `HttpListenerRequest`, but the substantive selector and
Extended Protection authentication path is implemented in the Windows/http.sys-specific HttpListener code.

The managed Linux/macOS authentication path under test does not invoke that Extended Protection selector.

Windows/http.sys canonicalizes the absolute-form authority before the authentication callbacks in the tested
request, so this does not provide a second vulnerable sink on the affected managed platforms.

Conclusion: do not inflate the report by claiming an Extended Protection bypass.

## Managed authentication support

The managed `ListenerAsyncResult` security path directly handles Anonymous and Basic. Other requested schemes are
rejected in that managed path.

The demonstrated security boundary should therefore be framed precisely as a per-request
Anonymous-versus-Basic authentication selection bypass, not as a demonstrated NTLM/Negotiate bypass on Linux/macOS.

## Broader networking audit

Searches were also performed for analogous raw-Host-versus-canonical-URI decisions in adjacent System.Net components
including HttpWebRequest, SocketsHttpHandler authentication, proxy routing, credential selection, and diagnostics.

No second vulnerability with the same concrete remote chain was established during this pass.

This negative result is useful: the report can remain tightly scoped to the managed HttpListener authority model
rather than claiming a System.Net-wide authority bug.
