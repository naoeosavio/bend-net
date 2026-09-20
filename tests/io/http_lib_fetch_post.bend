# lib (http_lib_fetch_post): send_request — POST carries method, headers
# and body through show_request; the echo handler answers with the
# method glued to the request body plus the Host header, so the
# roundtrip proves all three (HTTP/1.1 needs Host, and send_request must
# inject it). A method with a space fails closed with 400 before
# touching the net.
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

law echo.handler:
  for req: String & String & List<&1, (String & String)> & String
  IO(U32 & List<&1, (String & String)> & String)

def echo.handler(req):
  (m, p, hs, b) = req
  IO.pure(U32 & List<&1, (String & String)> & String, (200, [], m ++ b ++ "|" ++ HTTP.get_header("", "Host", hs)))

law server_down:
  for l: Listener
  IO(Unit)

def server_down(l):
  do IO<Unit>:
    x : Unit <- Listener.close(l)
    return x

law server_talk:
  for l: Listener
  for sock: Socket
  IO(Unit)

def server_talk(l, sock):
  do IO<Unit>:
    u : Unit <- HTTP.serve_once(sock, echo.handler)
    x : Unit <- Listener.close(l)
    return x

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(Unit)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      server_down(l)
    case Done{sock}:
      server_talk(l, sock)

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TCP.accept(l)
    server_conn(m)

law chk_sync0:
  for chan: Chan(Unit)
  IO(U32)

def chk_sync0(chan):
  do IO<U32>:
    x : Unit <- IO.join(Unit, chan)
    return 0

law chk_sync_eq:
  for chan: Chan(Unit)
  for body: String
  for want: String
  IO(U32)

def chk_sync_eq(chan, body, want):
  do IO<U32>:
    x : Unit <- IO.join(Unit, chan)
    return b2u(String.eq(body, want))

law chk_eq:
  for chan: Chan(Unit)
  for want: String
  for r: Result<&1, &1, (U32 & String), String>
  IO(U32)

def chk_eq(chan, want, r):
  match r:
    case Fail{e}:
      chk_sync0(chan)
    case Done{body}:
      chk_sync_eq(chan, body, want)

law chk_bad:
  for r: Result<&1, &1, (U32 & String), String>
  IO(U32)

def chk_bad(r):
  match r:
    case Fail{(c, e)}:
      IO.pure(U32, b2u(U32.is_eq(c, 400)))
    case Done{body}:
      IO.pure(U32, 0)

law case_post:
  for b: Listener & U32
  IO(U32)

def case_post(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    r : Result<&1, &1, (U32 & String), String> <- HTTP.send_request("127.0.0.1", port, "/echo", "POST", [], "xyz")
    chk_eq(chan, "POSTxyz|127.0.0.1", r)

law case_get:
  for b: Listener & U32
  IO(U32)

def case_get(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    r : Result<&1, &1, (U32 & String), String> <- HTTP.send_request("127.0.0.1", port, "/echo", "GET", [("X-Note", "hi")], "")
    chk_eq(chan, "GET|127.0.0.1", r)

law case_bad:
  for b: Listener & U32
  IO(U32)

def case_bad(b):
  (l, port) = b
  do IO<U32>:
    r : Result<&1, &1, (U32 & String), String> <- HTTP.send_request("127.0.0.1", port, "/echo", "PO ST", [], "")
    v : U32 <- chk_bad(r)
    x : Unit <- Listener.close(l)
    return v

law main_go:
  for b1: Listener & U32
  for b2: Listener & U32
  for b3: Listener & U32
  IO(U32)

def main_go(b1, b2, b3):
  do IO<U32>:
    a : U32 <- case_post(b1)
    c : U32 <- case_get(b2)
    d : U32 <- case_bad(b3)
    +total : U32 = (a * 100 + c * 10 + d : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 19587)
    b2 : Listener & U32 <- listen_any(32n, 19587)
    b3 : Listener & U32 <- listen_any(32n, 19587)
    main_go(b1, b2, b3)

#|111
