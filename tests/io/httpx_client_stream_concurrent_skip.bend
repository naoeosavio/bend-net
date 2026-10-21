# io (httpx_client_stream_concurrent_skip): the frames a dropped stream
# leaves in flight, against a canned peer (task-054 phase 3).
#
# The peer is a hand-built H2 server: it reads the three pipelined
# request HEADERS, then plays one script of frames that arrives
# interleaved for three streams. The client is
# HTTPX.client.stream_concurrent_insecure with a pure handler that
# cancels stream 1 at its response head.
#
# The script:
#   * HEADERS(1) :status 200          the head the handler cancels on
#   * DATA(1) END_STREAM              in flight after the reset
#   * HEADERS(1) x-sum END_STREAM     a trailer for the dropped stream
#   * HEADERS(3) :status 200
#   * HEADERS(5) :status 200
#   * DATA(5) END_STREAM              interleaved with stream 3
#   * HEADERS(3) x-sum END_STREAM     a trailer for a live stream, after
#                                     the frames of another stream
#
# One point: the answer is Done{(1, 2)}. The byte of stream 1 is skipped
# and its head block never reaches the handler (a second cancel would
# drop the pending count to zero early and answer Done{(0, 1)}), while
# the trailer of stream 3 is recognized from the ledger and closes it
# without a handler event.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18582

def HOST() -> String:
  "127.0.0.1"

def OK_HDRS() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{":status", "200"}]

def TRAILER_HDRS() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"x-sum", "3"}]

def Z_BYTES() -> List<&2, U32>:
  [90]

def A_BYTES() -> List<&2, U32>:
  [65]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The client handler: the first stream is cancelled at its head, and any
# head that is not a real response head (status 0, the shape a trailer
# decodes to) is cancelled too. The status rule is what makes a wrong
# trailer decision fail the golden instead of hanging it.
def h_cli_real(is_real: Bool, +slot: U32) -> HTTP.CStreamOut:
  match is_real:
    case True{}:
      HTTP.CStreamContinue{slot}
    case False{}:
      HTTP.CStreamCancel{slot}

def h_cli_status(head: HTTP.Head, +slot: U32) -> HTTP.CStreamOut:
  match head:
    case HTTP.Head{+status, +headers}:
      h_cli_real(U32.is_eq(status, 200), slot)

def h_cli_head(slot: U32, head: HTTP.Head) -> HTTP.CStreamOut:
  match slot:
    case 1:
      HTTP.CStreamCancel{1}
    case _:
      h_cli_status(head, slot)

def h_cli(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  match ev:
    case HTTP.CStreamHead{slot, head}:
      h_cli_head(slot, head)
    case HTTP.CStreamData{slot, +chunk, fin}:
      HTTP.CStreamContinue{slot}

def reqs() -> List<&2, HTTP.Request>:
  [HTTP.Request{"GET", "/one", Nil{}, Nil{}},
    HTTP.Request{"GET", "/three", Nil{}, Nil{}},
    HTTP.Request{"GET", "/five", Nil{}, Nil{}}]

def counts_ok(counts: U32 & U32) -> U32:
  (total, fins) = counts
  b2u(Bool.and(U32.is_eq(total, 1), U32.is_eq(fins, 2)))

def score(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      counts_ok(counts)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_concurrent_insecure(~h_cli, HOST(), port, reqs())
    IO.pure(U32, score(r))

# Canned peer: the request side first (SETTINGS plus three HEADERS), then
# the script. A count of the HEADERS frames is the trigger, because the
# client pipelines the three requests before it drains.
# ---------------------------------------------------------------------

def srv_heads(+typ: U32, +heads: U32) -> U32:
  match typ:
    case 1:
      (heads + 1 : U32)
    case _:
      heads

# 2 plays the script, 0 reads one more frame.
def srv_ph(+heads2: U32) -> U32:
  match heads2:
    case 3:
      2
    case _:
      0

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

# The script is out: read until the client closes (the credit and the
# reset it sends still arrive). Closing here would drop the answer.
def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle(0, (s, HTTP.GotErr{0, "next"}), Nil{})

# Frame 8 of 8: the trailer of stream 3 closes it.
def srv_sent7(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 3, HTTP2.x_block(TRAILER_HDRS()))
        srv_idle_from(sent)

# Frame 7 of 8: the data of stream 5, interleaved before stream 3 ends.
def srv_sent6(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 5, A_BYTES())
        srv_sent7(sent)

# Frame 6 of 8: the head of stream 5.
def srv_sent5(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 5, HTTP2.x_block(OK_HDRS()))
        srv_sent6(sent)

# Frame 5 of 8: the head of stream 3, which stays live.
def srv_sent4(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 3, HTTP2.x_block(OK_HDRS()))
        srv_sent5(sent)

# Frame 4 of 8: the head block of the dropped stream 1, in flight after
# the client's reset (a trailer, the shape node's sendTrailers puts on the
# wire).
def srv_sent3(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, HTTP2.x_block(TRAILER_HDRS()))
        srv_sent4(sent)

# Frame 3 of 8: the data of the dropped stream 1, in flight after the
# reset. Its one byte must not reach the answer.
def srv_sent2(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, Z_BYTES())
        srv_sent3(sent)

# Frame 2 of 8: the head the client cancels on.
def srv_sent1(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, HTTP2.x_block(OK_HDRS()))
        srv_sent2(sent)

# Frame 1 of 8: SETTINGS, then the script.
def srv_play(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    srv_sent1(sent)

@unsafe
def srv(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +typ: U32, +heads: U32) -> IO(Unit):
  match fuel:
    case 0n:
      (s0, g0) = got
      TLS.tls_close(s0)
    case 1n+p:
      match ph:
        case 0:
          (s1, g1) = got
          do IO<Unit>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
            srv(p, 1, got2, buf, 0, heads)
        case 1:
          (s2, g2) = got
          match g2:
            case HTTP.GotErr{code, msg}:
              TLS.tls_close(s2)
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ2, +flags2, +sid2, +payload2}:
                  srv(p, srv_ph(srv_heads(typ2, heads)), (s2, HTTP.GotOk{frame, buf2}), buf2, typ2, srv_heads(typ2, heads))
        case 2:
          (s3, g3) = got
          srv_play(s3)
        case _:
          (s4, g4) = got
          srv(p, 0, (s4, HTTP.GotErr{0, "next"}), buf, 0, heads)

# The client preface is not a frame: consume its 24 bytes first (the
# pattern tests/io/httpx_h2_trailers.bend uses), then hand the leftover to
# the frame loop.
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
          srv(16n, 0, (s2, HTTP.GotErr{0, "next"}), HTTP.x_drop32(24, acc), 0, 0)
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

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    x : Unit <- srv_conn(m)
    return "up"

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
    +total : U32 <- client(port)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    main_go(b)

#|1
