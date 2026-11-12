# io (httpx_h2_head_decode): the HPACK block decoder and the response
# head rule (task-062 phase 4, findings 4, 5 and 7).
#
# Pure checks, no IO:
#   * the table-size update [32] no longer becomes a phantom Hdr{"", ""}:
#     [32, 130, 132, 64, 1, 120, 1, 121] decodes to method GET, path / and
#     exactly the field x: y;
#   * [32, 130] has :method but no :path, so the request decode fails;
#   * [135, 130, 132] carries :scheme, which is not a field: the header
#     list stays empty;
#   * a response head needs :status, and only a trailer may omit it.
#
# Live check: a canned server answers HEADERS with a field and no
# :status, and HTTPX.client.once_insecure must fail 502 "head decode"
# instead of handing back an empty answer with status 0.
#
# Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18551

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# --- pure: the block decoder ---

# 0x20 = table-size update 32, 0x82 = :method GET, 0x84 = :path /,
# 0x40 = literal with indexing, then x and y.
def block_phantom() -> List<&2, U32>:
  [32, 130, 132, 64, 1, 120, 1, 121]

# :method GET, no :path.
def block_no_path() -> List<&2, U32>:
  [32, 130]

# 0x87 = :scheme https, then :method GET and :path /.
def block_scheme() -> List<&2, U32>:
  [135, 130, 132]

def hdr_eq(a: HTTP.Hdr, b: HTTP.Hdr) -> Bool:
  match a:
    case HTTP.Hdr{n1, v1}:
      match b:
        case HTTP.Hdr{n2, v2}:
          Bool.and(String.eq(n1, n2), String.eq(v1, v2))

def hdrs_eq(xs: List<&2, HTTP.Hdr>, ys: List<&2, HTTP.Hdr>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Nil{} _:
      False{}
    case _ Nil{}:
      False{}
    case h1 <> t1 h2 <> t2:
      Bool.and(hdr_eq(h1, h2), hdrs_eq(t1, t2))

def one_xy() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"x", "y"}]

def none_hdr() -> List<&2, HTTP.Hdr>:
  Nil{}

# A decoded request head against the wanted method, path and fields.
def reql_ok(head: HTTP.ReqHead, is_ok: Bool, +want_hdrs: List<&2, HTTP.Hdr>, +want_meth: String, +want_path: String) -> U32:
  match head:
    case HTTP.ReqHead{+method, +path, +headers}:
      U32.mul(b2u(is_ok), U32.mul(b2u(String.eq(method, want_meth)), U32.mul(b2u(String.eq(path, want_path)), b2u(hdrs_eq(headers, want_hdrs)))))

def decode_ok(dec: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>, +want_hdrs: List<&2, HTTP.Hdr>, +want_meth: String, +want_path: String) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+head, t)}:
      reql_ok(head, True{}, want_hdrs, want_meth, want_path)

# The phantom case: method, path and exactly one field.
def phantom_ok() -> U32:
  decode_ok(HTTP2.x_req.decode(block_phantom(), HTTP2.x_tab.empty()), one_xy(), "GET", "/")

# A block without :path fails the decode.
def no_path_go(got: HTTP.ReqHead & Bool & HTTP.Tab) -> U32:
  match got:
    case (h, +ok, t):
      b2u(Bool.not(ok))

def no_path_ok(dec: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> U32:
  no_path_go(HTTP2.x_req.got(dec))

def no_path_t() -> U32:
  no_path_ok(HTTP2.x_req.decode(block_no_path(), HTTP2.x_tab.empty()))

# :scheme is a pseudo-header, so it never lands in headers.
def scheme_t() -> U32:
  decode_ok(HTTP2.x_req.decode(block_scheme(), HTTP2.x_tab.empty()), none_hdr(), "GET", "/")

# A response head needs :status; a trailer block may omit it.
def status_ok() -> U32:
  +no_status : U32 = b2u(Bool.not(HTTP2.client.resp.head_ok(True{}, False{}, 0)))
  +with_status : U32 = b2u(HTTP2.client.resp.head_ok(True{}, False{}, 200))
  +trailer : U32 = b2u(HTTP2.client.resp.head_ok(True{}, True{}, 0))
  +failed : U32 = b2u(Bool.not(HTTP2.client.resp.head_ok(False{}, False{}, 200)))
  U32.mul(no_status, U32.mul(with_status, U32.mul(trailer, failed)))

# --- live: a status-less answer fails the call ---

def field_block() -> List<&2, U32>:
  [64, 1, 120, 1, 121]

def score(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{(code, msg)}:
      U32.mul(b2u(U32.is_eq(code, 502)), b2u(String.eq(msg, "head decode")))
    case Done{resp}:
      0

def sent_sock(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# Read until the client closes: the peer answers nothing else.
@unsafe
def srv_idle(got: Socket & HTTP.Got) -> IO(Unit):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      TLS.tls_close(s)
    case HTTP.GotOk{+frame, +buf2}:
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s, buf2)
        srv_idle(got2)

def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle((s, HTTP.GotErr{0, "next"}))

def srv_go(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    set : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    flags : U32 = (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32)
    head : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sent_sock(set), HTTP2.x_t_headers(), flags, 1, field_block())
    srv_idle_from(head)

def live(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <-
      HTTPX.client.once_insecure(HOST(), port, HTTP.Request{"GET", "/x", Nil{}, Nil{}})
    IO.pure(U32, score(r))

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
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

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(String):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(String, "up")
    case Done{sock}:
      do IO<String>:
        x : Unit <- srv_go(sock)
        return "up"

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    srv_conn(m)

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +phantom : U32 = phantom_ok()
    +no_path : U32 = no_path_t()
    +scheme : U32 = scheme_t()
    +status : U32 = status_ok()
    +live_score : U32 <- live(port)
    +total : U32 = (phantom + no_path + scheme + status + live_score : U32)
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    +total : U32 <- run(b)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|5
