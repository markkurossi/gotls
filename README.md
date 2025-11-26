# TLS 1.3 in Go - Lightweight, Standalone, Dependency-Free

A modern, pure Go implementation of TLS 1.3 — no external
dependencies, no legacy baggage. This library supports both client and
server modes and fully implements the essential "MUST" requirements
from [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html).

Built for developers who want a minimal, transparent, and auditable
TLS 1.3 stack that's easy to embed, test, or extend.

## Testing TLS Server

OpenSSL:

``` shell
openssl s_client -connect localhost:8443 -debug -msg -tlsextdebug -servername ephemelier.com -CAfile server-cert.pem
```

``` shell
openssl s_server -accept 8443 -cert server-cert.pem -key server-key.pem
```
