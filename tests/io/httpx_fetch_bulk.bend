# io (httpx_fetch_bulk): fetch over TLS is not truncated at 64 KB.
#
# The security section of README.md claimed a 64 KB cap for fetch until
# task-057 phase 4 ("reads at most 8 x 8192 bytes, then truncates"). The
# code has no such cap: the H2 lane paces the body with flow control and
# the H1 lane answers 413 when its read fuel runs out, never a short body.
# This test pins the whole body: a response of BULK_LEN bytes, past the
# 65535-byte default stream window, comes back with every byte.
#
# The server is server.concurrent (TLS + h2), the client is
# fetch_insecure("https://127.0.0.1:port/bulk"). Golden 1 iff the body
# length is BULK_LEN.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def BULK_LEN() -> U32:
  70000

# Byte 97 repeated BULK_LEN times, tail-recursive (the shape
# tests/io/http_bytes.bend uses; the naive append overflows).
@unsafe
def fill.go(n: U32, acc: List<&2, U32>, +b: U32) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      fill.go((n - 1 : U32), b <> acc, b)

def bulk() -> List<&2, U32>:
  fill.go(BULK_LEN(), Nil{}, 97)

def bulk_service(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, bulk()})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# One check: the decoded body has every byte the server sent.
def score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{body}:
      b2u(U32.is_eq(U32.from_nat(String.length(body)), BULK_LEN()))

def client_url(+port: U32) -> String:
  "https://127.0.0.1:" ++ U32.show(port) ++ "/bulk"

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTPX.fetch_insecure(client_url(port))
    IO.pure(U32, score(r))

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <-
      HTTPX.server.concurrent(~bulk_service, l, "tests/io/tls_test_cert.pem",
        "tests/io/tls_test_key.pem")
    return "up"

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>,
  rest: IO(Listener & U32)) -> IO(Listener & U32):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

def main_go(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18460)
    main_go(b)

#|1
