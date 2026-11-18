import TlsServer.Protocol

/-! `lake test`: a self-signed certificate, one connection served over https on the loopback and fetched
by the `curl` program with that certificate as its CA; then the key's mode and the refusals. -/

open scoped TlsServer

def check (what : String) (ok : Bool) : IO Unit := do
  IO.println s!"{if ok then "ok  " else "FAIL"} {what}"
  unless ok do throw (IO.userError s!"failed: {what}")

def refused (act : TlsServer.TlsIO α) : IO Bool :=
  (do let _ ← act; pure false) <|> pure true

def main : IO Unit := do
  let dir := ".lake/build/tls-test"
  IO.FS.createDirAll dir
  let cert := s!"{dir}/cert.pem"; let key := s!"{dir}/key.pem"
  TlsServer.selfSigned "localhost" "IP:127.0.0.1,DNS:localhost" 1 cert key
  let ctx ← TlsServer.serverContext cert key
  let l ← TlsServer.listen "127.0.0.1" 0
  let server ← IO.asTask (prio := .dedicated) <| TlsServer.withConnection ctx l fun o => do
    let request ← o.read
    o.write "HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".toUTF8
    pure (String.fromUTF8! request)
  let body ← IO.Process.run
    { cmd := "curl", args := #["--silent", "--show-error", "--cacert", cert, s!"https://127.0.0.1:{TlsServer.port l}/"] }
  let request ← IO.ofExcept (← IO.wait server)
  check "the client, trusting the certificate, reads the body 'hello'" (body == "hello")
  check "the server saw 'GET / HTTP/1.1'" (request.startsWith "GET / HTTP/1.1")
  let mode ← IO.Process.run { cmd := "stat", args := #["-c", "%a", key] }
  check "the key file is mode 600" (mode.trimAscii.toString == "600")
  -- a second connection, used directly: read and write after close are refused
  let direct ← IO.asTask (prio := .dedicated) <| (do
    let c ← TlsServer.accept ctx l
    let _ ← TlsServer.read c
    TlsServer.write c "HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n".toUTF8
    TlsServer.close c
    TlsServer.close c
    pure c : TlsServer.TlsIO _)
  let _ ← IO.Process.run
    { cmd := "curl", args := #["--silent", "--show-error", "--cacert", cert, s!"https://127.0.0.1:{TlsServer.port l}/"] }
  let c ← IO.ofExcept (← IO.wait direct)
  check "read after close is refused" (← refused (TlsServer.read c))
  check "write after close is refused" (← refused (TlsServer.write c "x".toUTF8))
  -- a client that does not trust the certificate fails its handshake; the listener goes on
  let failing ← IO.asTask (prio := .dedicated) <| refused (TlsServer.accept ctx l)
  let out ← IO.Process.output
    { cmd := "curl", args := #["--silent", s!"https://127.0.0.1:{TlsServer.port l}/"] }
  check "a client without the certificate as its CA is refused by curl" (out.exitCode != 0)
  check "its handshake is an accept error" (← IO.ofExcept (← IO.wait failing))
  TlsServer.closeListener l
  TlsServer.closeListener l
  check "accept after closeListener is refused" (← refused (TlsServer.accept ctx l))
