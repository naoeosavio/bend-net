# lib (lib_http_fetch): HTTP.fetch over loopback plus the fail-closed
# paths. The server is lib's echo handler on an ephemeral port (found
# by retry, as in tcp_loopback); the client fetches /echo and must
# read back the empty body. Port 0 dies in validation (400) and
# https dies with 501 (no TLS yet), both without touching the net.
import Base
import ../../lib/http.bend as HTTP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law is_fail:
  for r: Result<&1, &1, (U32 & String), String>
  U32

def is_fail(r):
  match r:
    case Fail{e}:
      1
    case Done{body}:
      0

law is_501:
  for r: Result<&1, &1, (U32 & String), String>
  U32

def is_501(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 501))
    case Done{body}:
      0

law chk_fail:
  for chan: Chan(String)
  IO(U32)

def chk_fail(chan):
  do IO<U32>:
    s : String <- IO.join(String, chan)
    return 0

law chk_done:
  for chan: Chan(String)
  for body: String
  IO(U32)

def chk_done(chan, body):
  do IO<U32>:
    s : String <- IO.join(String, chan)
    return b2u(String.is_empty(body))

law chk:
  for chan: Chan(String)
  for r: Result<&1, &1, (U32 & String), String>
  IO(U32)

def chk(chan, r):
  match r:
    case Fail{e}:
      chk_fail(chan)
    case Done{body}:
      chk_done(chan, body)

law listen_retry:
  for port: U32
  for r: Result<&1, &1, (U32 & String), Listener>
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
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

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
    u : Unit <- HTTP.serve_once(sock, req => HTTP.echo.body(req))
    x : Unit <- Listener.close(l)
    return "up"

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
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
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TCP.accept(l)
    server_conn(m)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r : Result<&1, &1, (U32 & String), String> <- HTTP.fetch("http://127.0.0.1:" ++ U32.show(port) ++ "/echo")
    a : U32 <- chk(chan, r)
    rb : Result<&1, &1, (U32 & String), String> <- HTTP.fetch("http://127.0.0.1:0/")
    rc : Result<&1, &1, (U32 & String), String> <- HTTP.fetch("https://127.0.0.1:443/")
    +total : U32 = (a * 100 + is_fail(rb) * 10 + is_501(rc) : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19587)
    main_go(b)

#|111
