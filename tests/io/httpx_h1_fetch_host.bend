# lib (lib_httpx_h1_fetch_host): HTTPX.fetch_insecure over loopback BY
# NAME. The server answers the Host header it received; fetching
# http://localhost:PORT/echo must read back "localhost:PORT" (and the
# literal-IP fetch "127.0.0.1:PORT"), proving the invariant: DNS resolve
# changes the connect IP only — virtual hosting keeps the original
# host (the httpx Host line carries host:port). Port 0 still dies in
# validation (400) before any dial.
# Ported from the lib/http.bend text lane (task-036 phase 7).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http1.bend as HTTP1
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

# Host header lookup over the contract header list (case-insensitive,
# first hit wins, default when absent).
law host_of:
  for hs: List<&2, HTTP.Hdr>
  for dflt: String
  String

def host_of(hs, dflt):
  match hs:
    case Nil{}:
      dflt
    case HTTP.Hdr{name, value} <> t:
      Bool.pick(String, HTTP1.x_h1.eq_ci(name, "host"), value, host_of(t, dflt))

law host_body:
  for req: HTTP.Request
  IO(HTTP.Response)

def host_body(req):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, HTTP.x_utf8_encode(host_of(headers, ""))})

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
    x : Unit <- HTTPX.server.on_h1_plain(~host_body, l)
    return "up"

# The httpx Host line carries host:port (the renderer synthesises it),
# so the want strings carry the port too — the invariant under test is
# the HOST part (localhost stays localhost after resolve).
law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r1 : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://localhost:" ++ U32.show(port) ++ "/echo")
    r2 : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/echo")
    r3 : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://localhost:0/")
    +total : U32 = ((hit(r1, "localhost:" ++ U32.show(port)) * 100 + hit(r2, "127.0.0.1:" ++ U32.show(port)) * 10 : U32) + is_400(r3) : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19607)
    main_go(b)

#|111
