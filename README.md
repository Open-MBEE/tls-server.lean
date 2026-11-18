# tls-server.lean

A Lean 4 TLS server over OpenSSL, for testing and mocking https endpoints.

`TlsServer` is the server side that an https client (curl, libcurl, a browser) talks to: a listening
socket, a server context from a certificate and its key, connections accepted, read and written, and
a self-signed certificate made on the spot. It is meant for tests and mocks served over https on the
loopback, not for production serving. The TLS protocol itself is OpenSSL's; this library is a thin
Lean interface to it (`native/leantls.cpp`, about 250 lines of C++) plus a small verified model of
how the interface may be used.

It began as `Curl.Tls` in a fork of [leanCurl](https://github.com/bergmannjg/leanCurl) and moved here
because it depends on OpenSSL, not on libcurl.

## Use

Requirements: Linux (the shim uses POSIX sockets; other systems are untested), a C++ compiler, and OpenSSL's headers and libraries (`libssl-dev` on
Debian/Ubuntu). In your `lakefile.lean`:

```lean
require TlsServer from git "https://github.com/Open-MBEE/tls-server.lean" @ "<commit>"

lean_exe myserver where
  moreLinkArgs := #["-lssl", "-lcrypto"]   -- every executable that uses TlsServer links OpenSSL
```

```lean
import TlsServer

open scoped TlsServer in   -- lifts TlsIO (EIO String: the error is a message) into IO
def main : IO Unit := do
    TlsServer.selfSigned "localhost" "IP:127.0.0.1,DNS:localhost" 1 "cert.pem" "key.pem"
    let ctx ← TlsServer.serverContext "cert.pem" "key.pem"
    let l ← TlsServer.listen "127.0.0.1" 8443   -- port 0: any free one, read back with TlsServer.port l
    let c ← TlsServer.accept ctx l            -- the handshake done
    let request ← TlsServer.read c            -- bytes; empty once the peer has closed
    TlsServer.write c "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello".toUTF8
    TlsServer.close c
```

Then `curl --cacert cert.pem https://127.0.0.1:8443/` answers `hello`.

`lake build` builds the library; `lake test` runs the round trip below (it needs the `curl` program).

## The protocol, as types and as a model

`TlsServer.withConnection ctx l body` accepts one connection, hands `body` an `Open` handle whose only
operations are `Open.read` and `Open.write`, and closes the connection when `body` ends, by return or by
error. Within the bracket nothing can close the connection (`Open` has no `close`, its connection is
private, only `withConnection` makes one), so every read and write there is on an open connection. Lean
has no linear types, so a body that returns or stores its handle keeps a name for a closed connection:
a later `Open.read`/`Open.write` on it fails with "connection closed" — an error, never a crash. Keep
handles inside their bracket.

Every definition's docstring in `TlsServer` names the RFC and section it follows (TLS 1.3 RFC 8446,
TLS 1.2 RFC 5246, X.509 RFC 5280, PEM RFC 7468, https identity RFC 2818 §3.1 / RFC 6125 §6.4), or says
that it follows none — sockets, and the library's own contract.

`TlsServer.Protocol` is the same protocol as a model: `Cmd` the calls, `step` which ones the shim answers
and which it refuses ("connection closed", "listener closed"), `run` a trace. Theorems:
`read_after_close_stuck`, `write_after_close_stuck`, `accept_after_closeListener_stuck`, `close_idem`,
`closeListener_idem`, and `withConnection_runs` — on a listening state, the trace of `withConnection`
with any body runs with no stuck call and ends with the connection closed. These are about programs
written against the shim's contract (which `lake test` checks); they say nothing about OpenSSL.

## Concurrency

Every `TlsServer` call blocks the calling thread until the kernel or OpenSSL answers (`accept` until a
client connects and its handshake ends, `read` until bytes or the peer's close arrive). Run a serving
loop in a task of its own, `IO.asTask … Task.Priority.dedicated`, so it does not hold one of Lean's
pool threads; `Task.spawn`/plain `IO.asTask` are for short work.

What may be shared between tasks and what may not:

* a `Context` may be shared: `accept` on it from several tasks at once is safe (OpenSSL's `SSL_CTX` is
  read-only after `serverContext`);
* a `Listener` may be shared: several tasks may `accept` on the same listener, each connection goes to
  exactly one of them (the kernel's `accept(2)` guarantee);
* a `Connection` belongs to one task at a time: a TLS session (`SSL`) has state that two concurrent
  `read`/`write` calls corrupt. Hand it over, do not share it;
* initialisation (OpenSSL, the external classes, SIGPIPE) runs once, under `pthread_once`, whichever
  task comes first;
* `TlsServer` sets `SIGPIPE` to ignored for the whole process at first use, so writing to a peer that
  has gone makes `write` fail with a message instead of ending the program. If the program relies on
  `SIGPIPE`, do not use `TlsServer` in it.

Lifetimes: a `Listener` closes its socket when dropped or at `closeListener` (which may be called from another task: an `accept` waiting for a connection or in its handshake then fails); a `Connection` closes at
`close` or when dropped; `close`/`closeListener` are idempotent; `read`/`write` after `close` and
`accept` after `closeListener` fail with a message (never a crash). Errors are `EIO String`, the
message OpenSSL's or `strerror`'s.

## The TLS flow and what is verified

The protocol is OpenSSL's: TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) or TLS 1.2
([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)), never below 1.2 (`SSL_CTX_set_min_proto_version`),
cipher suites and the exact ceiling from the system's `openssl.cnf`. Certificates are X.509 v3
([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)).

*Server* (`serverContext`, `accept`): presents one certificate chain (the file may hold the leaf and its
intermediates) and signs with its key; checks nothing about the client (`SSL_VERIFY_NONE` — no client
certificates, no SNI dispatch: one certificate for every name). A connection whose handshake fails is
an `accept` error and the listener goes on. `selfSigned` makes the test certificate as `openssl req
-x509` does: version 3, `subjectAltName` from the `san` argument (`IP:…`, `DNS:…`),
`basicConstraints critical,CA:TRUE`, a key identifier, RSA-2048, SHA-256, serial = creation time;
the key is written mode 0600, the certificate 0644.

*Client* (curl or libcurl, in the test and typically in use): verifies the server as RFC 5280 §6.1 path validation by
OpenSSL, with the trust anchors from `CAINFO` (a self-signed certificate given there is its own anchor
— the test's case) or the system store, then matches the host of the URL against the certificate's
`subjectAltName`: an IP literal against `IP:` entries as [RFC 2818](https://www.rfc-editor.org/rfc/rfc2818)
§3.1 says, a name against `DNS:` entries as [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) §6.4
describes (wildcards per §6.4.3). `SSL_VERIFYPEER 0` turns
the first check off — for a throwaway test only; hostname matching cannot be turned off from Lean (no
`SSL_VERIFYHOST` option is exposed, on purpose). Mutual TLS is not offered.

What is *verified* here and how:

* by test (`lake test`): the certificate is made, a connection served, fetched by
  curl with that certificate as its anchor, the key's mode 600, read and write after `close` refused, a client that does not trust the certificate refused, `accept` after `closeListener` refused, a common name over 64 bytes refused with no certificate written, an empty read when the client goes without `close_notify`, an empty read again after that, an `accept` waiting for a connection or in its handshake when another task calls `closeListener` refused;
* by construction in Lean: the API's types — `Context`, `Listener`, `Connection` are opaque, every
  operation is in `TlsIO`, so nothing but these functions touches the native state;
* **trusted, not verified**: OpenSSL (handshake, record layer, path validation), the client (hostname
  matching), the C shim `native/leantls.cpp` (≈250 lines, reviewed), the Lean runtime's external
  objects. No Lean theorem speaks about these, and none should be read as doing so.
