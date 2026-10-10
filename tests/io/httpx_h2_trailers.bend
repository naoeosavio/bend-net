# io (httpx_h2_trailers): a trailer block must not become the response
# (task-042 phase 3, bug 3 of the audit).
#
# The peer is a canned H2 server: TLS accept, then hand-built frames —
# SETTINGS, HEADERS(:status 200, END_HEADERS), DATA("hi", no END_STREAM)
# and HEADERS(x-sum: 3, END_HEADERS|END_STREAM), the shape node's
# stream.sendTrailers() puts on the wire. The request itself is read
# first (the loop answers on the request HEADERS) so the client is never
# writing into a closed socket.
#
# Before the fix the trailer block decoded to Head{0, ...} (x_resp.decode
# answers status 0 when no :status is present), replaced the stored head
# in client.on.drain and its END_STREAM turned it into the answer, so the
# client handed back Response{0, ...}. Now the block is recognized as a
# trailer: the stored head and body ride out and the response is 200
# with "hi" intact.
#
# Score: 1 iff status 200 and body "hi", golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def PORT() -> U32:
  18563

def HOST() -> String:
  "127.0.0.1"

def HI() -> List<&2, U32>:
  [104, 105]

# Head block: :status 200 only, so the response head is a real head.
def head_hdrs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{":status", "200"}]

# Trailer block: no pseudo-header at all, the shape that decodes to
# status 0 and used to be mistaken for a head.
def trailer_hdrs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"x-sum", "3"}]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Canned server: read frames until the request HEADERS shows up, then
# answer with head, data and trailers. Fuel is the frame budget; the
# phase ping-pong keeps one self-recursive def.
def srv_act(+typ: U32) -> U32:
  match typ:
    case 1:
      2
    case _:
      3

def srv_last(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      TLS.tls_close(s)

# Answers are out: a real H2 peer keeps the connection (it does not close
# without GOAWAY), so read until the client closes. Closing right here
# would race the credit the client sends for the DATA it just read: the
# write hits a dead socket, the peer answers RST and the frames still in
# flight are lost.
@unsafe
def srv_idle(phase: U32, got: Socket & HTTPX.Got, +buf: List<&2, U32>) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTPX.Got <- HTTPX.x_read_frame(s0, buf)
        srv_idle(1, got2, buf)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTPX.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTPX.GotOk{+frame, +buf2}:
          srv_idle(0, (s1, HTTPX.GotOk{frame, buf2}), buf2)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle(0, (s, HTTPX.GotErr{0, "next"}), Nil{})

# Trailer is out: keep the connection until the client closes (see
# srv_idle).
def srv_sent3(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  srv_idle_from(m)

# Data is out: send the trailer with END_STREAM.
def srv_sent2(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_headers(), (HTTPX.x_f_end_headers() + HTTPX.x_f_end_stream() : U32), 1, HTTPX.x_block(trailer_hdrs()))
        srv_sent3(sent)

# Head is out: send the body WITHOUT END_STREAM (the trailer ends it).
def srv_sent1(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_data(), 0, 1, HI())
        srv_sent2(sent)

# SETTINGS is out: send the response head.
def srv_sent0(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_headers(), HTTPX.x_f_end_headers(), 1, HTTPX.x_block(head_hdrs()))
        srv_sent1(sent)

def srv_answer(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(sock, HTTPX.x_t_settings(), 0, 0, HTTPX.x_settings_initial_pay())
    srv_sent0(sent)

def srv(fuel: Nat, ph: U32, got: Socket & HTTPX.Got, +buf: List<&2, U32>, +typ: U32) -> IO(Unit):
  match fuel:
    case 0n:
      (s0, g0) = got
      TLS.tls_close(s0)
    case 1n+p:
      match ph:
        case 0:
          (s1, g1) = got
          do IO<Unit>:
            got2 : Socket & HTTPX.Got <- HTTPX.x_read_frame(s1, buf)
            srv(p, 1, got2, buf, 0)
        case 1:
          (s2, g2) = got
          match g2:
            case HTTPX.GotErr{code, msg}:
              TLS.tls_close(s2)
            case HTTPX.GotOk{+frame, +buf2}:
              match frame:
                case HTTPX.Frame{+typ2, +flags2, +sid2, +payload2}:
                  srv(p, srv_act(typ2), (s2, HTTPX.GotOk{frame, buf2}), buf2, typ2)
        case 2:
          (s3, g3) = got
          srv_answer(s3)
        case _:
          (s4, g4) = got
          srv(p, 0, (s4, HTTPX.GotErr{0, "next"}), buf, 0)

# The client preface is not a frame: consume its 24 bytes first (the
# pattern tests/io/httpx_client_cont.bend uses, @unsafe for the same
# reason: the phase ping-pong does not shrink a structural argument),
# then hand the leftover to the frame loop.
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
          srv_pre(1, (s0, Done{chunk}), acc2, HTTPX.x_preface_ok(acc2), U32.is_lt(HTTPX.x_len32(acc2), 24))
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
          srv(16n, 0, (s2, HTTPX.GotErr{0, "next"}), HTTPX.x_drop32(24, acc), 0)
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def srv_start(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    srv_pre(0, r1, Nil{}, 0, False{})

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{sock}:
      srv_start(sock)

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    x : Unit <- srv_conn(m)
    return "up"

# Client: one request over the keep-alive dial (the drain lane).
def resp_score(r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTPX.Response{+status, +headers, +body}:
          U32.mul(b2u(U32.is_eq(status, 200)), HTTPX.x_eq(body, HI()))

def client_done(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt) -> IO(U32):
  (s, r, st) = got
  do IO<U32>:
    +score : U32 = resp_score(r)
    x : Unit <- TLS.tls_close(s)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def client_conn(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <- HTTPX.client.request(sock, st, HOST(), port, HTTPX.Request{"GET", "/trailer", Nil{}, Nil{}})
        client_done(got)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    client_conn(conn, port)

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
    score : U32 <- client(port)
    return score

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|1
