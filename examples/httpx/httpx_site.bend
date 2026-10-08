# The library's own site, in a browser: docs/site/ on two ports at once.
#
#   http://127.0.0.1:8080/     server.on_h1_plain — plaintext H1 keep-alive
#   https://127.0.0.1:8443/    server.on_alpn    — TLS, ALPN split
#
# Both lanes feed the SAME whole-response handler, which reads the file
# per request with Static.read_bytes: 400 for a path is_safe refuses, 404
# for a missing file, 413 past the cap — never a truncated page. The
# certificate is the test PEM (CN 127.0.0.1, self-signed), so the browser
# warns once on the TLS port; that is what the second port is for, not a
# bug. `/` is index.html, any other path is a file under the root, and
# `/style.css` is what the page asks for next.
#
# Manual only: both ports are fixed and the run blocks until Ctrl-C.
#   bend examples/httpx/httpx_site.bend
#
# Mirror of tests/io/httpx_site.bend, the gated proof of the same handler
# (its mode 1 and mode 3 are exactly these two lanes, one at a time).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/static.bend as Static

# Named constants: the site root (relative to the repo root), the read
# cap (the interpreter holds ~32 KB of byte list, so 16 KB is safe) and
# the two ports.
def SITE_ROOT() -> String:
  "docs/site/"

def SITE_CAP() -> U32:
  16384

def SITE_PLAIN_PORT() -> U32:
  8080

def SITE_TLS_PORT() -> U32:
  8443

def TLS_CERT() -> String:
  "tests/io/tls_test_cert.pem"

def TLS_KEY() -> String:
  "tests/io/tls_test_key.pem"

# Route to file name: "/" is the index, anything else is a file under the
# root (the leading "/" goes; Static.is_safe refuses ".." and controls).
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
def site_headers(+path: String) -> List<&2, HTTPX.Hdr>:
  HTTPX.Hdr{"content-type", Static.content_type(path)} <> Nil{}

def site_error_headers() -> List<&2, HTTPX.Hdr>:
  HTTPX.Hdr{"content-type", "text/html"} <> Nil{}

def site_error_body() -> List<&2, U32>:
  HTTPX.x_str_bytes("<h1>404 not found</h1>\n")

# The answer for a file whose bytes are known, as a pure def. `file` —
# never the request path — decides the content type: passing the path
# here served "/" as application/octet-stream (task-040 D10).
def site_response(+file: String, r: Result<&1, &1, U32 & String, List<&2, U32>>) -> HTTPX.Response:
  match r:
    case Fail{(code, msg)}:
      HTTPX.Response{code, site_error_headers(), site_error_body()}
    case Done{+body}:
      HTTPX.Response{200, site_headers(file), body}

# The mapped name is bound once and used for both the read and the answer.
def site_handler(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{method, +path, headers, body}:
      do IO<HTTPX.Response>:
        +file : String = site_file(path)
        r : Result<&1, &1, U32 & String, List<&2, U32>> <- Static.read_bytes(SITE_ROOT(), file, SITE_CAP())
        IO.pure(HTTPX.Response, site_response(file, r))

def server_plain(l: Listener) -> IO(String):
  do IO<String>:
    w : Unit <- IO.print("SITE http://127.0.0.1:" ++ U32.show(SITE_PLAIN_PORT()) ++ "/")
    x : Unit <- HTTPX.server.on_h1_plain(~site_handler, l)
    return "plain lane down"

def server_tls(l: Listener) -> IO(String):
  do IO<String>:
    w : Unit <- IO.print("SITE https://127.0.0.1:" ++ U32.show(SITE_TLS_PORT()) ++ "/ (self-signed cert)")
    x : Unit <- HTTPX.server.on_alpn(~site_handler, l, TLS_CERT(), TLS_KEY())
    return "tls lane down"

# A busy port is reported, not retried: the URL printed above has to be
# the URL the browser opens.
def listen_or_die.go(r: Result<&1, &1, U32 & String, Listener>, port: U32) -> IO(Listener):
  match r:
    case Fail{e}:
      IO.die(Listener, 1, "port busy: " ++ U32.show(port))
    case Done{l}:
      IO.pure(Listener, l)

def listen_or_die(+port: U32) -> IO(Listener):
  do IO<Listener>:
    r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
    listen_or_die.go(r, port)

def main() -> IO(Unit):
  do IO<Unit>:
    plain : Listener <- listen_or_die(SITE_PLAIN_PORT())
    tls : Listener <- listen_or_die(SITE_TLS_PORT())
    c1 : Chan(String) <- IO.fork(String, server_plain(plain))
    c2 : Chan(String) <- IO.fork(String, server_tls(tls))
    # Both lanes answer until the process is killed, so joining the first
    # one is what keeps main (and the second fiber) alive.
    s : String <- IO.join(String, c1)
    return Unit{}
