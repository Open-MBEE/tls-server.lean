import TlsServer.Protocol

/-! `lake test`: a self-signed certificate, one connection served over https on the loopback and fetched
by the `curl` program with that certificate as its CA; then the key's mode, the refusals, and the two ways a client can close. -/

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
  let longCn := String.ofList (List.replicate 65 'a')
  let longCert := s!"{dir}/long-cert.pem"
  -- an OpenSSL error left pending on the task does not turn a later clean close into a read error
  let l ← TlsServer.listen "127.0.0.1" 0
  let url := s!"https://127.0.0.1:{TlsServer.port l}/"
  let stale ← IO.asTask (prio := .dedicated) <| (do
    let c ← TlsServer.accept ctx l
    let _ ← TlsServer.read c
    TlsServer.write c "HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n".toUTF8
    let cnRefused ← (refused (TlsServer.selfSigned longCn "DNS:localhost" 1 longCert s!"{dir}/long-key.pem") : IO Bool)
    let atClose ← TlsServer.read c
    TlsServer.close c
    pure (cnRefused, atClose.size) : IO _)
  let _ ← IO.Process.run { cmd := "curl", args := #["--silent", "--show-error", "--cacert", cert, url] }
  let (cnRefused, atClose) ← IO.ofExcept (← IO.wait stale)
  check "a common name over 64 bytes is refused" cnRefused
  check "and no certificate is written for it" (!(← System.FilePath.pathExists longCert))
  check "the read at the client's close_notify that follows is empty" (atClose == 0)
  -- a client killed mid-request closes its TCP connection without close_notify
  let seen ← IO.mkRef false
  let gone ← IO.mkRef false
  let cut ← IO.asTask (prio := .dedicated) <| (do
    let c ← TlsServer.accept ctx l
    let _ ← TlsServer.read c
    seen.set true
    while !(← gone.get) do IO.sleep 20
    let atEof ← TlsServer.read c
    TlsServer.close c
    pure atEof.size : IO _)
  let child ← IO.Process.spawn { cmd := "curl", args := #["--silent", "--cacert", cert, url], stdout := .null, stderr := .null }
  while !(← seen.get) do IO.sleep 20
  child.kill
  let _ ← child.wait
  gone.set true
  check "the read after the client's TCP connection is gone is empty" ((← IO.ofExcept (← IO.wait cut)) == 0)
  -- closeListener from another task ends an accept that is waiting
  let waiting ← IO.asTask (prio := .dedicated) <| refused (TlsServer.accept ctx l)
  IO.sleep 200
  TlsServer.closeListener l
  check "an accept waiting when the listener is closed is refused" (← IO.ofExcept (← IO.wait waiting))
