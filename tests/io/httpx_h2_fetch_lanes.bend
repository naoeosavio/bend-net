# io (httpx_h2_fetch_lanes): the high-level entries of the H2 module
# (task-058 phase 4) against one h2 peer.
#
# The grid is pure: h2_url.read must answer the same https vectors as the
# facade reader (defaults, explicit port, empty port) and refuse a bad
# scheme, a bad port and a bad path with 400.
#
# The lanes dial and close:
#   - fetch_insecure: GET by URL, body as String.
#   - fetch_bytes_insecure: GET by URL, body as raw bytes.
#   - request_insecure: any method with a String body, body as String.
#   - request_bytes_insecure: any method with a raw body, body as bytes.
#   - client.once_insecure: the public name over the same shared body.
#   - fetch (verify): the loopback cert is self-signed, so the chain check
#     fails 614 before any request byte.
#   - fetch("http://..."): 400 bad scheme before any dial.
#   - request_insecure("", ...) and request_bytes_insecure(..., 0, ...):
#     400 bad request before any dial.
#
# Score: grid 6, lanes 9, golden 15.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18640

def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HOST() -> String:
  "127.0.0.1"

# This def answers the weight when the check passed, and zero otherwise.
def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

# URL grid (pure)
# ---------------------------------------------------------------------

def url_ok_tuple(t: Bool & String & U32 & String, +want_host: String, +want_port: U32, +want_path: String) -> U32:
  match t:
    case (s, h, p, pa):
      weigh(Bool.and(s, Bool.and(String.eq(h, want_host), Bool.and(U32.is_eq(p, want_port), String.eq(pa, want_path)))), 1)

def url_ok(r: Result<&1, &1, U32 & String, Bool & String & U32 & String>, +want_host: String, +want_port: U32, +want_path: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{t}:
      url_ok_tuple(t, want_host, want_port, want_path)

def url_bad(r: Result<&1, &1, U32 & String, Bool & String & U32 & String>, +want_code: U32) -> U32:
  match r:
    case Fail{e}:
      match e:
        case (+c, m):
          weigh(U32.is_eq(c, want_code), 1)
    case Done{t}:
      0

def url_grid() -> U32:
  +a : U32 = url_ok(HTTP2.h2_url.read("https://127.0.0.1"), "127.0.0.1", 443, "/")
  +b : U32 = url_ok(HTTP2.h2_url.read("https://127.0.0.1:8443/a/b"), "127.0.0.1", 8443, "/a/b")
  +c : U32 = url_ok(HTTP2.h2_url.read("https://127.0.0.1:"), "127.0.0.1", 443, "/")
  +d : U32 = url_bad(HTTP2.h2_url.read("http://127.0.0.1/"), 400)
  +e : U32 = url_bad(HTTP2.h2_url.read("https://127.0.0.1:abc/"), 400)
  +f : U32 = url_bad(HTTP2.h2_url.read("https://127.0.0.1/a b"), 400)
  (a + (b + (c + (d + (e + f)))) : U32)

# Lanes
# ---------------------------------------------------------------------

# The fetch lanes send GET with an empty body, so the peer answers hello.
# The request lanes send hello, so the peer echoes it.
def answer(+body: List<&2, U32>, is_empty: Bool) -> HTTP.Response:
  match is_empty:
    case True{}:
      HTTP.Response{200, Nil{}, HTTP.x_str_bytes("hello")}
    case False{}:
      HTTP.Response{200, Nil{}, body}

def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, answer(body, List.is_empty(&2, U32, body)))

def url_of(+path: String, port: U32) -> String:
  "https://127.0.0.1:" ++ U32.show(port) ++ path

def text_is(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      weigh(String.eq(body, want), 1)

def mul_eq(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      mul_eq(bytes_eq(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

def bytes_is(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: List<&2, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      weigh(U32.is_eq(bytes_eq(body, want), 1), 1)

def code_is_go(e: U32 & String, +want: U32) -> U32:
  match e:
    case (+c, m):
      weigh(U32.is_eq(c, want), 1)

def resp_text(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          weigh(Bool.and(U32.is_eq(status, 200), String.eq(HTTP.x_utf8_decode(body), want)), 1)

def text_code(r: Result<&1, &1, U32 & String, String>, +want: U32) -> U32:
  match r:
    case Fail{e}:
      code_is_go(e, want)
    case Done{+body}:
      0

def bytes_code(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: U32) -> U32:
  match r:
    case Fail{e}:
      code_is_go(e, want)
    case Done{+body}:
      0

def hello() -> String:
  "hello"

def hello_bytes() -> List<&2, U32>:
  [104, 101, 108, 108, 111]

law lane_fetch:
  for port: U32
  IO(U32)

def lane_fetch(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.fetch_insecure(url_of("/hello", port))
    IO.pure(U32, text_is(r, hello()))

law lane_fetch_bytes:
  for port: U32
  IO(U32)

def lane_fetch_bytes(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      HTTP2.fetch_bytes_insecure(url_of("/hello", port))
    IO.pure(U32, bytes_is(r, hello_bytes()))

law lane_request:
  for port: U32
  IO(U32)

def lane_request(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.request_insecure(HOST(), port, "/echo", "POST", Nil{}, hello())
    IO.pure(U32, text_is(r, hello()))

law lane_request_bytes:
  for port: U32
  IO(U32)

def lane_request_bytes(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      HTTP2.request_bytes_insecure(HOST(), port, "/echo", "POST", Nil{}, hello_bytes())
    IO.pure(U32, bytes_is(r, hello_bytes()))

law lane_once:
  for port: U32
  IO(U32)

def lane_once(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <-
      HTTP2.client.once_insecure(HOST(), port, HTTP.Request{"GET", "/hello", Nil{}, Nil{}})
    IO.pure(U32, resp_text(r, hello()))

law lane_verify:
  for port: U32
  IO(U32)

def lane_verify(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.fetch(url_of("/hello", port))
    IO.pure(U32, text_code(r, 614))

law lane_bad_scheme:
  IO(U32)

def lane_bad_scheme():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.fetch("http://127.0.0.1:1/hello")
    IO.pure(U32, text_code(r, 400))

law lane_bad_host:
  IO(U32)

def lane_bad_host():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.request_insecure("", 1, "/echo", "GET", Nil{}, "")
    IO.pure(U32, text_code(r, 400))

law lane_bad_port:
  IO(U32)

def lane_bad_port():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      HTTP2.request_bytes_insecure(HOST(), 0, "/echo", "GET", Nil{}, Nil{})
    IO.pure(U32, bytes_code(r, 400))

# Driver
# ---------------------------------------------------------------------

law lanes:
  for +port: U32
  IO(U32)

def lanes(port):
  do IO<U32>:
    +a : U32 <- lane_fetch(port)
    +b : U32 <- lane_fetch_bytes(port)
    +c : U32 <- lane_request(port)
    +d : U32 <- lane_request_bytes(port)
    +e : U32 <- lane_verify(port)
    +f : U32 <- lane_bad_scheme()
    +g : U32 <- lane_bad_host()
    +h : U32 <- lane_bad_port()
    +i : U32 <- lane_once(port)
    IO.pure(U32, (a + (b + (c + (d + (e + (f + (g + (h + i))))))) : U32))

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~echo, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

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

law main_go:
  for b: Listener & U32
  for grid: U32
  IO(U32)

def main_go(b, grid):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +laned : U32 <- lanes(port)
    +total : U32 = (grid + laned : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law drive:
  IO(U32)

def drive():
  do IO<U32>:
    +a : U32 = url_grid()
    b : Listener & U32 <- listen_any(TRIES(), PORT())
    main_go(b, a)

law main:
  IO(U32)

def main():
  do IO<U32>:
    drive()

#|15
