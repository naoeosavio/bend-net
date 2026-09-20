# lib (ws_loopback): WS echo over loopback plus static guards.
# Server is single-shot WS.serve_once on an ephemeral port (retry like
# tcp_loopback); client is WS.client_echo masked Hi. Static checks are
# pure (no File) to stay under the gate timeout.
import Base
import ../../lib/ws.bend as WS
import ../../lib/static.bend as Static

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
    u : Unit <- WS.serve_once(sock)
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
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    server_conn(m)

law static_good:
  U32

def static_good():
  b2u(Static.is_safe("hello.txt"))

law static_bad:
  U32

def static_bad():
  b2u(Bool.not(Static.is_safe("../etc/passwd")))

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r : Result<&1, &1, U32 & String, String> <- WS.client_echo("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    a : U32 <- chk_echo(chan, r)
    +total : U32 = (a * 100 + static_good() * 10 + static_bad() : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19787)
    main_go(b)

#|111
