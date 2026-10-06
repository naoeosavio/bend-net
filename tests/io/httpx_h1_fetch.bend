# lib (lib_httpx_h1_fetch): HTTPX.fetch_insecure over loopback plus the
# fail-closed paths. The server is the httpx echo handler on an ephemeral
# port (found by retry, as in tcp_loopback) via server.on_h1_plain; the
# client fetches /echo and must read back the empty body. Port 0 dies in
# validation (400) and https dies on the TLS dial (refused, no listener),
# both without touching the net. Ported from the lib/http.bend text lane
# (task-036 phase 7): the 501 "tls missing" answer retired with it.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

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

law chk_fail:
  IO(U32)

def chk_fail():
  do IO<U32>:
    return 0

law chk_done:
  for body: String
  IO(U32)

def chk_done(body):
  do IO<U32>:
    return b2u(String.is_empty(body))

law chk:
  for r: Result<&1, &1, (U32 & String), String>
  IO(U32)

def chk(r):
  match r:
    case Fail{e}:
      chk_fail()
    case Done{body}:
      chk_done(body)

# Echo handler on the httpx shape: status 200, no headers, body back.
law echo_service:
  for req: HTTPX.Request
  IO(HTTPX.Response)

def echo_service(req):
  match req:
    case HTTPX.Request{method, path, headers, body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

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

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on_h1_plain(~echo_service, l)
    return "up"

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r : Result<&1, &1, (U32 & String), String> <- HTTPX.fetch_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/echo")
    a : U32 <- chk(r)
    rb : Result<&1, &1, (U32 & String), String> <- HTTPX.fetch_insecure("http://127.0.0.1:0/")
    rc : Result<&1, &1, (U32 & String), String> <- HTTPX.fetch_insecure("https://127.0.0.1:443/")
    +total : U32 = (a * 100 + is_fail(rb) * 10 + is_fail(rc) : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19587)
    main_go(b)

#|111
