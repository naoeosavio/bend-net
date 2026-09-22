# lib (wss_loopback): WSS echo over TLS loopback (self-signed).
# Server is single-shot WSS.serve_once on an ephemeral port (TLS accept
# with the test cert); client is WSS.client_echo_insecure masked Hi.
# Golden 111 (echo + fail-closed dial to port 0/1 via noalpn path).
import Base
import ../../lib/tls.bend as TLS
import ../../lib/wss.bend as WSS

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law echo_ok:
  for r: Result<&1, &1, U32 & String, String>
  U32

def echo_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, "Hi"))

law chk_echo:
  for chan: Chan(String)
  for r: Result<&1, &1, U32 & String, String>
  IO(U32)

def chk_echo(chan, r):
  match r:
    case Fail{e}:
      do IO<U32>:
        s : String <- IO.join(String, chan)
        return 0
    case Done{body}:
      do IO<U32>:
        s : String <- IO.join(String, chan)
        return echo_ok(r)

law is_fail:
  for r: Result<&1, &1, U32 & String, Socket>
  U32

def is_fail(r):
  match r:
    case Fail{e}:
      1
    case Done{s}:
      0

law server_down:
  for l: Listener
  for e: U32 & String
  IO(String)

def server_down(l, e):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

law server_talk:
  for l: Listener
  for sock: Socket
  IO(String)

def server_talk(l, sock):
  do IO<String>:
    u : Unit <- WSS.serve_once(sock)
    x : Unit <- Listener.close(l)
    return "up"

law server_conn:
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  IO(String)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      server_down(l, e)
    case Done{sock}:
      server_talk(l, sock)

law server_side:
  for l: Listener
  for cert: String
  for key: String
  IO(String)

def server_side(l, cert, key):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    server_conn(m)

law listen_retry:
  for port: U32
  for r: Result<&1, &1, U32 & String, Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

law listen_any:
  for tries: Nat
  for +port: U32
  IO(Listener & U32)

def listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem"))
    r : Result<&1, &1, U32 & String, String> <- WSS.client_echo_insecure("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    a : U32 <- chk_echo(chan, r)
    rb : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure("127.0.0.1", 0)
    rc : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure("127.0.0.1", 1)
    +total : U32 = (a * 100 + is_fail(rb) * 10 + is_fail(rc) : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19887)
    main_go(b)

#|111
