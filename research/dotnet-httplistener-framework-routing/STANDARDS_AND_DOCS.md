# Standards and Microsoft documentation evidence

## RFC 9112 — absolute-form authority handling

RFC 9112 §3.2.2:

> "the origin server MUST ignore the received Host header field"

when the request-target is absolute-form, and the server must use the request-target host information instead.

Source:
https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2

This is exactly the invariant violated by the managed implementation's simultaneous:

```text
UserHostName = received Host
Url.Host     = absolute-form request-target host
```

## Microsoft — AuthenticationSchemes

Microsoft's HttpListener.AuthenticationSchemes documentation states:

> "The GetContext and EndGetContext methods return an incoming client request only if the HttpListener successfully authenticates the request."

It also explicitly says applications may choose different authentication mechanisms from request characteristics,
including the request's `Url` or `UserHostName`.

Source:
https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistener.authenticationschemes?view=net-10.0

This makes the proof's host-based selector a documented API usage model rather than an invented unsupported pattern.

## Microsoft — AuthenticationSchemeSelectorDelegate

Microsoft documents the property as:

> "Gets or sets the delegate called to determine the protocol used to authenticate clients."

It further states that if a request cannot be authenticated, HttpListener automatically returns 401.

Source:
https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistener.authenticationschemeselectordelegate?view=net-10.0

## Microsoft — AuthenticationSchemeSelector

Microsoft documents the delegate as selecting the authentication scheme for an HttpListener instance and says the
delegate is passed the HttpListenerRequest for incoming unauthenticated requests.

Source:
https://learn.microsoft.com/en-us/dotnet/api/system.net.authenticationschemeselector?view=net-10.0

## Microsoft — UserHostName

Microsoft documents `HttpListenerRequest.UserHostName` as:

> "A String value that contains the text of the request's Host header."

Source:
https://learn.microsoft.com/en-us/dotnet/api/system.net.httplistenerrequest.userhostname?view=net-10.0

That API contract explains why current managed code returns the attacker-controlled Host value. The security defect is
that absolute-form handling canonicalizes `Request.Url` for listener routing but does not canonicalize the Host-facing
state before the framework invokes the authentication selector.

## Bounty impact category

The current Microsoft .NET bounty table explicitly includes Security Feature Bypass. As of this research date, the
published award table lists up to $30,000 for Critical / high-quality Security Feature Bypass and $10,000 for Important /
high-quality Security Feature Bypass.

Source:
https://www.microsoft.com/en-us/msrc/bounty-dot-net-core

Severity and bounty classification remain Microsoft's determination; the report should present demonstrated impact
rather than assert an award tier.
