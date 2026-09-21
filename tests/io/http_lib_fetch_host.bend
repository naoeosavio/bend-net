# lib (http_lib_fetch_host): HTTP.fetch over loopback BY NAME. The
# server answers the Host header it received; fetching
# http://localhost:PORT/echo must read back "localhost" (and the
# literal-IP fetch "127.0.0.1"), proving the invariant: DNS resolve
# changes the connect IP only — virtual hosting keeps the original
# host. Port 0 still dies in validation (400) before any dial.
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

law hit:
  for r: Result<&1, &1, (U32 & String), String>
  for want: String
  U32

def hit(r, want):
  match r:
    case Done{body}:
      b2u(String.eq(body, want))
    case Fail{e}:
      0

law is_400:
  for r: Result<&1, &1, (U32 & String), String>
  U32

def is_400(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))
    case Done{body}:
      0

law host_body:
  for req: String & String & List<&1, (String & String)> & String
  IO(U32 & List<&1, (String & String)> & String)

def host_body(req):
  (m, p, hs, body) = req
  IO.pure(U32 & List<&1, String & String> & String, (200, [], HTTP.get_header("", "Host", hs)))

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
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law server_close:
  for l: Listener
  IO(String)

def server_close(l):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

law server_last:
  for l: Listener
  for sock: Socket
  IO(String)

def server_last(l, sock):
  do IO<String>:
    u : Unit <- HTTP.serve_once(sock, req => host_body(req))
    x : Unit <- Listener.close(l)
    return "down"

law server_again:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(String)

def server_again(m):
  (l, r) = m
  match r:
    case Fail{e}:
      server_close(l)
    case Done{sock}:
      server_last(l, sock)

law server_talk:
  for l: Listener
  for sock: Socket
  IO(String)

def server_talk(l, sock):
  do IO<String>:
    u : Unit <- HTTP.serve_once(sock, req => host_body(req))
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    server_again(m)

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(String)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      server_close(l)
    case Done{sock}:
      server_talk(l, sock)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    server_conn(m)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r1 : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://localhost:" ++ U32.show(port) ++ "/echo")
    r2 : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://127.0.0.1:" ++ U32.show(port) ++ "/echo")
    r3 : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://localhost:0/")
    s : String <- IO.join(String, chan)
    +total : U32 = ((hit(r1, "localhost") * 100 + hit(r2, "127.0.0.1") * 10 : U32) + is_400(r3) : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19607)
    main_go(b)

#|111
