# httpx (lib_httpx_site): the library's own site, served three ways.
#
# docs/site/ holds the site (index.html + style.css, ASCII, each one
# under SITE_CAP). The whole-response handler reads the file per request
# with Static.read_bytes (fail-closed 400/404/413) and answers 200 with
# the file's content type; the pure streaming handler cannot read at all
# and answers the same markers from literals. Both shapes answer the
# SAME three routes with the SAME score, so switching the mode below
# never changes the golden.
#
# SWITCHING MODE — two of the three server entries are comments on
# purpose. Mode 1 and 2 speak plaintext; mode 3 needs TLS/h2, so its
# `site_scheme` twin below has to be switched with it.
#
#   mode 1 (active)  server.on_h1_plain  plain H1 keep-alive, IO handler
#   mode 2 (comment) server.stream_plain pure classifier, literal pages
#   mode 3 (comment) server.concurrent   TLS + h2, interleaved streams
#
# Golden 5: three wire vectors ("/" carries the index marker,
# "/style.css" the css marker, "/nope.txt" the missing marker in a 404
# body) plus two local handler vectors that pin the status and the
# content-type header of "/" (200, text/html) and "/style.css" (200,
# text/css) without a socket.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP
import ../../lib/static.bend as Static

# Named constants: the site root (relative to the repo root) and the read
# cap. The interpreter holds ~32 KB of byte list (task-040 D2), so the
# cap is 16 KB — past it the reader refuses, it never truncates.
def SITE_ROOT() -> String:
  "docs/site/"

def SITE_CAP() -> U32:
  16384

def INDEX_MARKER() -> String:
  "bend-net"

def CSS_MARKER() -> String:
  "font-family"

def MISSING_MARKER() -> String:
  "not found"

# The scheme the client dials: plain for modes 1/2, TLS for mode 3.
# Modes 1/2 (plaintext): keep this def, comment the https twin below.
def site_scheme() -> String:
  "http://"

# Mode 3 (TLS): comment the http def above and uncomment this one.
# def site_scheme() -> String:
#   "https://"

# Route to file name: "/" is the index, anything else is a file under the
# root. Static.is_safe refuses "..", absolute paths and control bytes, so
# the mapping does not have to (the leading "/" has to go, though).
def site_file.slash(+path: String, has_slash: Bool) -> String:
  match has_slash:
    case True{}:
      String.drop(path, 1n)
    case False{}:
      path

def site_file.root(+path: String, is_root: Bool) -> String:
  match is_root:
    case True{}:
      "index.html"
    case False{}:
      site_file.slash(path, String.starts_with(path, "/"))

def site_file(+path: String) -> String:
  site_file.root(path, String.eq(path, "/"))

# Headers of a served file: the lane stamps the length, the content type
# comes from the extension.
def site_headers(+path: String) -> List<&2, HTTP.Hdr>:
  HTTP.Hdr{"content-type", Static.content_type(path)} <> Nil{}

def site_error_headers() -> List<&2, HTTP.Hdr>:
  HTTP.Hdr{"content-type", "text/html"} <> Nil{}

# The reader's codes (400 bad path, 404 missing, 413 too large) travel to
# the client unchanged; the body is one readable line either way.
def site_error_body() -> List<&2, U32>:
  HTTP.x_str_bytes("<h1>404 not found</h1>\n")

# The answer for a file whose bytes are known, as a pure def so the
# handler's header choice can be scored without a socket (vectors 4/5).
# `file` — never the request path — decides the content type: passing the
# path here served "/" as application/octet-stream (task-040 D10).
def site_response(+file: String, r: Result<&1, &1, U32 & String, List<&2, U32>>) -> HTTP.Response:
  match r:
    case Fail{(code, msg)}:
      HTTP.Response{code, site_error_headers(), site_error_body()}
    case Done{+body}:
      HTTP.Response{200, site_headers(file), body}

# Mode 1/3 handler: IO is allowed, so the file is read per request. The
# mapped name is bound once and used for both the read and the answer.
def site_handler(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, +path, headers, body}:
      do IO<HTTP.Response>:
        +file : String = site_file(path)
        r : Result<&1, &1, U32 & String, List<&2, U32>> <- Static.read_bytes(SITE_ROOT(), file, SITE_CAP())
        IO.pure(HTTP.Response, site_response(file, r))

# Mode 2 pages. The streaming handler is pure (no IO) and `~H` is a
# closed template (task-040 D1), so it serves literals carrying the same
# markers the real files carry.
def stream_missing() -> List<&2, U32>:
  HTTP.x_str_bytes("<h1>404 not found</h1>\n")

def stream_css() -> List<&2, U32>:
  HTTP.x_str_bytes("body { font-family: monospace; }\n")

def stream_index() -> List<&2, U32>:
  HTTP.x_str_bytes("<h1>bend-net</h1><p>pure streaming mode</p>\n")

def stream_ans.css(+path: String, is_css: Bool) -> U32 & List<&2, U32>:
  match is_css:
    case True{}:
      (200, stream_css())
    case False{}:
      (404, stream_missing())

def stream_ans.root(+path: String, is_root: Bool) -> U32 & List<&2, U32>:
  match is_root:
    case True{}:
      (200, stream_index())
    case False{}:
      stream_ans.css(path, String.eq(path, "/style.css"))

def stream_ans(+path: String) -> U32 & List<&2, U32>:
  stream_ans.root(path, String.eq(path, "/"))

# The pair from stream_ans arrives as a parameter, never as a scrutinee:
# a destructuring let on a computed value is rejected (task-040 D9).
def stream_answer(ans: U32 & List<&2, U32>) -> HTTP.SrvOut:
  (code, +body) = ans
  HTTP.RespondEarly{HTTP.Response{code, Nil{}, body}}

def site_stream.head(head: HTTP.ReqHead) -> HTTP.SrvOut:
  match head:
    case HTTP.ReqHead{method, +path, headers}:
      stream_answer(stream_ans(path))

# Mode 2 handler: answer at the head, never drain the request body.
def site_stream(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      site_stream.head(head)
    case HTTP.SrvReqData{slot, chunk, fin}:
      HTTP.Continue{}

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    # mode 1 (active): plaintext H1 keep-alive, IO handler
    x : Unit <- HTTPX.server.on_h1_plain(~site_handler, l)
    # mode 2 (comment): pure classifier over literal pages
    # x : Unit <- HTTPX.server.stream_plain(~site_stream, l)
    # mode 3 (comment): TLS + h2, interleaved streams
    # x : Unit <- HTTPX.server.concurrent(~site_handler, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def site_url(+port: U32, +route: String) -> String:
  site_scheme() ++ "127.0.0.1:" ++ U32.show(port) ++ route

def site_ok(r: Result<&1, &1, U32 & String, String>, +marker: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      b2u(String.contains(body, marker))

def site_get(+port: U32, +route: String, +marker: String) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(site_url(port, route))
    IO.pure(U32, site_ok(r, marker))

# Vectors 4/5: the handler itself, no socket. The status and the
# content-type header of the answer are what the wire vectors cannot see.
# Header lookup: one self-recursive walk (mutual recursion is not
# allowed) carrying the answer, plus a two-step def for the name
# comparison, because a match may not scrutinize a computed value
# (task-040 D9).
def hdr_pick.go(is_want: Bool, +value: String, +found: String) -> String:
  match is_want:
    case True{}:
      value
    case False{}:
      found

def hdr_pick(+name: String, +value: String, +want: String, +found: String) -> String:
  hdr_pick.go(String.eq(name, want), value, found)

def hdr_lookup(+want: String, headers: List<&2, HTTP.Hdr>, +found: String) -> String:
  match headers:
    case Nil{}:
      found
    case HTTP.Hdr{+name, +value} <> rest:
      hdr_lookup(want, rest, hdr_pick(name, value, want, found))

def hdr_value(headers: List<&2, HTTP.Hdr>, +want: String) -> String:
  hdr_lookup(want, headers, "")

def resp_ok.both(is_status: Bool, is_ctype: Bool) -> U32:
  match is_status:
    case True{}:
      b2u(is_ctype)
    case False{}:
      0

def resp_ok.go(got: U32, headers: List<&2, HTTP.Hdr>, +status: U32, +ctype: String) -> U32:
  resp_ok.both(U32.is_eq(got, status), String.eq(hdr_value(headers, "content-type"), ctype))

def resp_ok(resp: HTTP.Response, +status: U32, +ctype: String) -> U32:
  match resp:
    case HTTP.Response{got, headers, body}:
      resp_ok.go(got, headers, status, ctype)

def handler_check(+route: String, +status: U32, +ctype: String) -> IO(U32):
  do IO<U32>:
    resp : HTTP.Response <- site_handler(HTTP.Request{"GET", route, Nil{}, Nil{}})
    IO.pure(U32, resp_ok(resp, status, ctype))

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    a : U32 <- site_get(port, "/", INDEX_MARKER())
    b : U32 <- site_get(port, "/style.css", CSS_MARKER())
    c : U32 <- site_get(port, "/nope.txt", MISSING_MARKER())
    d : U32 <- handler_check("/", 200, "text/html")
    e : U32 <- handler_check("/style.css", 200, "text/css")
    IO.pure(U32, (a + b + c + d + e : U32))

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
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 49250)
    main_go(b)

#|5
