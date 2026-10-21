# io (httpx_h2_trailers_cont): the END_STREAM of the last CONTINUATION
# belongs to the response (task-042 phase 3c, the drain-lane gap the
# phase-3b fix left behind).
#
# The peer is a canned H2 server: TLS accept, preface consumed, SETTINGS
# out, then hand-built frames, one shape per connection:
#   scen 0: HEADERS(:status 200, no END_HEADERS) + CONTINUATION
#           (END_HEADERS|END_STREAM): a fragmented head that closes the
#           response with an empty body;
#   scen 1: HEADERS(:status 200, END_HEADERS), DATA("hi", no END_STREAM)
#           and a fragmented trailer (HEADERS without END_HEADERS plus
#           CONTINUATION with END_STREAM) — the shape node's
#           stream.sendTrailers() puts on the wire when the trailer block
#           does not fit one frame.
#
# client.on.cont_read collected the fragments but never carried the
# END_STREAM of the frame that completed the block, so drain_conted
# decided with the HEADERS frame's end — always 0 in a fragmented block:
# head_act(0, ok, 0) = 0 kept the drain reading for scen 0 (the peer's
# close failed it) and trailer_act(0) = 5 failed scen 1 as a protocol
# error. Now the Cont carries the flag and both close the response: 200
# with an empty body and 200 with "hi", golden 2.
#
# Score: 1 per connection iff status 200 and the expected body, golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18566

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HI() -> List<&2, U32>:
  [104, 105]

def head_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":status", "200"}])

def trailer_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{"x-sum", "3"}])

# Blocks are split at 6 bytes to force the CONTINUATION path.
def head_first() -> List<&2, U32>:
  HTTP.x_take32(6, head_block())

def head_rest() -> List<&2, U32>:
  HTTP.x_drop32(6, head_block())

def trailer_first() -> List<&2, U32>:
  HTTP.x_take32(6, trailer_block())

def trailer_rest() -> List<&2, U32>:
  HTTP.x_drop32(6, trailer_block())

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def score(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: List<&2, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          U32.mul(b2u(U32.is_eq(status, 200)), HTTP.x_eq(body, want))

def client_exch(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +want: List<&2, U32>) -> IO(U32):
  (s, r, st) = got
  do IO<U32>:
    +sc : U32 = score(r, want)
    x : Unit <- TLS.tls_close(s)
    return sc

def client_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +port: U32, +path: String, +want: List<&2, U32>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTPX.client.request(sock, st, HOST(), port, HTTP.Request{"GET", path, Nil{}, Nil{}})
        client_exch(got, want)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    c0 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    s0 : U32 <- client_conn(c0, port, "/empty", Nil{})
    c1 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    s1 : U32 <- client_conn(c1, port, "/trailer", HI())
    IO.pure(U32, (s0 + s1 : U32))

def srv_close(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  TLS.tls_close(s)

# Answers are out: a real H2 peer keeps the connection (it does not close
# without GOAWAY), so read until the client closes. Closing right here
# would race the credit the client sends for the DATA it just read: the
# write hits a dead socket, the peer answers RST and the frames still in
# flight are lost.
@unsafe
def srv_idle(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        srv_idle(1, got2, buf)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTP.GotOk{+frame, +buf2}:
          srv_idle(0, (s1, HTTP.GotOk{frame, buf2}), buf2)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle(0, (s, HTTP.GotErr{0, "next"}), Nil{})


# scen 0 tail: CONTINUATION completes the head and closes the response.
def srv_head_cont(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_cont(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, head_rest())
        srv_idle_from(sent)

# scen 1 tail: fragmented trailer, END_STREAM on the CONTINUATION.
def srv_tr_cont(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_cont(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, trailer_rest())
        srv_idle_from(sent)

def srv_tr_frag(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), 0, 1, trailer_first())
        srv_tr_cont(sent)

def srv_data(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_data(), 0, 1, HI())
        srv_tr_frag(sent)

# The answer on the request HEADERS: fragmented head only (scen 0) or
# head + body + fragmented trailer (scen 1).
def srv_answer(sock: Socket, scen: U32) -> IO(Unit):
  match scen:
    case 0:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), 0, 1, head_first())
        srv_head_cont(sent)
    case _:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head_block())
        srv_data(sent)

def srv_is_request(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTP2.x_t_headers())

def srv_act(is_req: Bool) -> U32:
  match is_req:
    case True{}:
      2
    case False{}:
      0

def srv_sock(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

# Frame budget loop: read until the request HEADERS shows up, then answer
# (the mold tests/io/httpx_h2_trailers.bend uses).
@unsafe
def srv(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +typ: U32, +scen: U32, act: U32) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        srv(1, got2, buf, 0, scen, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +payload2}:
              srv(2, (s1, HTTP.GotOk{frame, buf2}), buf2, typ2, scen, srv_act(srv_is_request(typ2)))
    case 2:
      match act:
        case 2:
          srv_answer(srv_sock(got), scen)
        case _:
          srv(0, got, buf, typ, scen, 4)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

def srv_acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTP.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTP.GotErr{0, "next"})

def srv_set(got: Socket & HTTP.Got) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    IO.pure(Socket & HTTP.Got, srv_acked(sent))

# The client preface is not a frame: consume its 24 bytes first (mold
# tests/io/httpx_client_cont.bend; @unsafe for the same reason: the phase
# ping-pong does not shrink a structural argument), then hand the leftover
# to the frame loop.
@unsafe
def srv_pre(phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool, +scen: U32) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          srv_pre(1, (s0, Done{chunk}), acc2, HTTP2.x_preface_ok(acc2), U32.is_lt(HTTP.x_len32(acc2), 24), scen)
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            srv_pre(0, r2, acc, 0, False{}, scen)
        case False{}:
          srv_pre(2, rs, acc, ok, short, scen)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            got : Socket & HTTP.Got <- srv_set((s2, HTTP.GotErr{0, "next"}))
            srv(0, got, HTTP.x_drop32(24, acc), 0, scen, 4)
        case _:
          do IO<Unit>:
            TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def srv_start(sock: Socket, +scen: U32) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    srv_pre(0, r1, Nil{}, 0, False{}, scen)

# Two accepts, one per scenario, in client call order: the client dials
# the second connection only after the first exchange is answered and
# closed, so the backlog holds it until this loop comes back.
def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +scen: U32) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- srv_start(sock, scen)
        return l

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    m0 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    l1 : Listener <- srv_conn(m0, 0)
    m1 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l1, CERT(), KEY())
    l2 : Listener <- srv_conn(m1, 1)
    return "up"

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

def run(l: Listener, +port: U32) -> IO(U32):
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|2
