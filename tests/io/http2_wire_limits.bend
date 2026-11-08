# io (httpx_h2_wire_limits): what a request puts on the wire (task-062
# phase 5, findings 6, 12 and 15).
#
# Pure checks:
#   * the hop-by-hop fields (connection, keep-alive, proxy-connection,
#     transfer-encoding, upgrade, te) and :authority leave
#     client.req.drop, and a normal field stays;
#   * x_send_block.fuel slices one 16384-byte HEADERS frame and one
#     CONTINUATION per full slice after it, so a block of exactly one
#     slice needs no CONTINUATION.
#
# Live check: the peer is a canned H2 server. It reads the request of the
# real client frame by frame and answers 200 only when the shape is
# sliced (first HEADERS of 16384 bytes without END_HEADERS, then
# CONTINUATIONs with END_HEADERS on the last), the block decodes, the
# 40000-byte field x-big arrives intact and no hop-by-hop field is in it.
# A wrong shape closes the connection and the client scores 0.
#
# Golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18552

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def BIG_LEN() -> Nat:
  40000n

def BIG_NAME() -> String:
  "x-big"

# Frames the peer reads before it gives up: the client SETTINGS, the
# HEADERS and two CONTINUATIONs.
def FUEL() -> Nat:
  12n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# --- pure: the dropped fields ---

def hop_list() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{":authority", "h"},
    HTTP.Hdr{"connection", "close"},
    HTTP.Hdr{"keep-alive", "timeout=5"},
    HTTP.Hdr{"proxy-connection", "keep-alive"},
    HTTP.Hdr{"transfer-encoding", "chunked"},
    HTTP.Hdr{"upgrade", "h2c"},
    HTTP.Hdr{"te", "trailers"},
    HTTP.Hdr{"x-keep", "1"}]

def kept_names() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"x-keep", "1"}]

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

def drop_ok() -> U32:
  b2u(hdrs_eq(HTTP2.client.req.drop(hop_list()), kept_names()))

# --- pure: the slice count ---

def fuel_ok() -> U32:
  +zero : U32 = b2u(Nat.is_eq(HTTP2.x_send_block.fuel(0), 0n))
  +one : U32 = b2u(Nat.is_eq(HTTP2.x_send_block.fuel(16384), 0n))
  +two : U32 = b2u(Nat.is_eq(HTTP2.x_send_block.fuel(16385), 1n))
  +more : U32 = b2u(Nat.is_eq(HTTP2.x_send_block.fuel(40000), 2n))
  U32.mul(zero, U32.mul(one, U32.mul(two, more)))

# --- live: the sliced request ---

def big_go(+n: Nat, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      big_go(p, String.append(acc, "a"))

def big_value(+n: Nat) -> String:
  big_go(n, "")

def big_req() -> HTTP.Request:
  HTTP.Request{"GET", "/big",
    [HTTP.Hdr{BIG_NAME(), big_value(BIG_LEN())}, HTTP.Hdr{"connection", "close"}, HTTP.Hdr{"te", "trailers"}],
    Nil{}}

def has_name(+hs: List<&2, HTTP.Hdr>, +want: String) -> Bool:
  match hs:
    case Nil{}:
      False{}
    case HTTP.Hdr{n, v} <> t:
      Bool.or(String.eq(n, want), has_name(t, want))

def value_len_go(is_want: Bool, +v: String, rest: Nat) -> Nat:
  match is_want:
    case True{}:
      String.length(v)
    case False{}:
      rest

def value_len(+hs: List<&2, HTTP.Hdr>, +want: String) -> Nat:
  match hs:
    case Nil{}:
      0n
    case HTTP.Hdr{n, v} <> t:
      value_len_go(String.eq(n, want), v, value_len(t, want))

def head_fields_ok(+headers: List<&2, HTTP.Hdr>) -> Bool:
  Bool.and(Nat.is_eq(value_len(headers, BIG_NAME()), BIG_LEN()),
    Bool.and(Bool.not(has_name(headers, "connection")), Bool.not(has_name(headers, "te"))))

def block_ok(dec: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> Bool:
  match dec:
    case Fail{e}:
      False{}
    case Done{(+head, t)}:
      match head:
        case HTTP.ReqHead{+method, +path, +headers}:
          head_fields_ok(headers)

# The block ends on the frame that carries END_HEADERS: 2 stops the loop.
def srv_route_hdr(endh: U32) -> U32:
  match endh:
    case 4:
      2
    case _:
      0

def srv_route(+typ: U32, +flags: U32) -> U32:
  match typ:
    case 1:
      srv_route_hdr(HTTP2.x_fin_hdr(flags))
    case 9:
      srv_route_hdr(HTTP2.x_fin_hdr(flags))
    case _:
      0

def shape_ok(+n: Nat, +endh: U32, +first_big: U32) -> Bool:
  Bool.and(U32.is_ge(U32.from_nat(n), 2), Bool.and(U32.is_eq(endh, HTTP2.x_f_end_headers()), U32.is_eq(first_big, 1)))

def srv_acc(+typ: U32, +payload: List<&2, U32>, +acc: List<&2, U32>) -> List<&2, U32>:
  match typ:
    case 1:
      HTTP.x_rev_push(payload, acc)
    case 9:
      HTTP.x_rev_push(payload, acc)
    case _:
      acc

def srv_count(+typ: U32, +n: Nat) -> Nat:
  match typ:
    case 1:
      (n + 1n : Nat)
    case 9:
      (n + 1n : Nat)
    case _:
      n

# END_HEADERS of the last block frame; every other frame leaves it.
def srv_endh(+typ: U32, +flags: U32, +endh: U32) -> U32:
  match typ:
    case 1:
      HTTP2.x_fin_hdr(flags)
    case 9:
      HTTP2.x_fin_hdr(flags)
    case _:
      endh

# The first HEADERS frame must fill one full slice and stop there.
def srv_big(+typ: U32, +payload: List<&2, U32>, +first_big: U32) -> U32:
  match typ:
    case 1:
      b2u(U32.is_eq(HTTP.x_len32(payload), HTTP2.x_max_send()))
    case _:
      first_big

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

# A send becomes the read seed the loop starts from.
def srv_acked(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = m
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle((s, HTTP.GotErr{0, "next"}))

def answer(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    flags : U32 = (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32)
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), flags, 1, HTTP2.x_block([HTTP.Hdr{":status", "200"}]))
    srv_idle_from(sent)

def finish_dec(s: Socket, is_ok: Bool) -> IO(Unit):
  match is_ok:
    case True{}:
      answer(s)
    case False{}:
      TLS.tls_close(s)

def finish_block(s: Socket, shape: Bool, +acc: List<&2, U32>) -> IO(Unit):
  match shape:
    case True{}:
      finish_dec(s, block_ok(HTTP2.x_req.decode(HTTP.x_cat(acc), HTTP2.x_tab.empty())))
    case False{}:
      TLS.tls_close(s)

def finish(got: Socket & HTTP.Got, +acc: List<&2, U32>, +n: Nat, +endh: U32, +first_big: U32) -> IO(Unit):
  (s, g) = got
  finish_block(s, shape_ok(n, endh, first_big), acc)

# Frame loop of the canned server. Phases: 0 read, 1 route, 2 stop.
@unsafe
def srv(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: List<&2, U32>, +n: Nat, +endh: U32, +first_big: U32) ->
  IO(Unit):
  match fuel:
    case 0n:
      finish(got, acc, n, endh, first_big)
    case 1n+p:
      match ph:
        case 0:
          (s0, g0) = got
          do IO<Unit>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            srv(p, 1, got2, buf, acc, n, endh, first_big)
        case 1:
          (s1, g1) = got
          match g1:
            case HTTP.GotErr{code, msg}:
              TLS.tls_close(s1)
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid,+flen, +payload}:
                  srv(p, srv_route(typ, flags), (s1, HTTP.GotOk{frame, buf2}), buf2,
                    srv_acc(typ, payload, acc), srv_count(typ, n), srv_endh(typ, flags, endh), srv_big(typ, payload, first_big))
        case _:
          finish(got, acc, n, endh, first_big)

# The preface is not a frame: consume its 24 bytes, then send SETTINGS.
@unsafe
def srv_pre(phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          srv_pre(1, (s0, Done{chunk}), acc2, HTTP2.x_preface_ok(acc2), U32.is_lt(HTTP.x_len32(acc2), 24))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            srv_pre(0, r2, acc, 0, False{})
        case False{}:
          srv_pre(2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <-
              HTTP2.x_send_frame(s2, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
            srv(FUEL(), 0, srv_acked(sent), HTTP.x_drop32(24, acc), Nil{}, 0n, 0, 0)
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def srv_start(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    srv_pre(0, r1, Nil{}, 0, False{})

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- srv_start(sock)
        return l

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    l2 : Listener <- srv_conn(m)
    return "up"

def client_score(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(U32.is_eq(status, 200))

def live(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTPX.client.once_insecure(HOST(), port, big_req())
    IO.pure(U32, client_score(r))

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

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +drop_score : U32 = drop_ok()
    +fuel_score : U32 = fuel_ok()
    +live_score : U32 <- live(port)
    +total : U32 = (drop_score + fuel_score + live_score : U32)
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    +total : U32 <- run(b)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|3
