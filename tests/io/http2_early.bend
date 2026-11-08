# io (httpx_h2_early): an early answer must not leak the connection
# window (task-042 phase 2, bug 4 of the audit).
#
# The peer is a canned H2 client: it upgrades through
# HTTPX.client.connect_insecure (preface + SETTINGS + ALPN check) and
# then, by hand, sends HEADERS(POST /early, no END_STREAM), one
# 65535-byte DATA frame -- the whole default connection window of RFC
# 9113 section 6.9.2, so the peer wants to send more and cannot -- and a
# second request HEADERS(GET /after, END_STREAM) on the same connection.
# The server handler answers every head with RespondEarly, so the body of
# the first request is discarded by httpx_stream (act 8 of the DATA
# dispatch).
#
# What the peer must read back, in order: the early response
# (HEADERS sid 1), the RST_STREAM(sid 1) that stops a body the server
# will not read (RFC 9113 section 8.1: complete response first, then the
# reset), a connection-level WINDOW_UPDATE for the 65535 discarded bytes
# (without it the peer sits at a zero window forever -- the deadlock the
# audit found) and the answer to the second request (HEADERS sid 3),
# which proves the connection stayed usable.
#
# Score: early x1000 + rst x100 + wu x10 + alive, golden 1111. Before the
# fix the peer reads the two responses only and scores 1001.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18561

# RFC 9113 section 6.9.2 default connection window, and the exact number
# of body bytes this peer gets to send before it needs credit back.
def WINDOW() -> U32:
  65535

# Bytes per DATA frame: one TLS record, the slice x_max_send uses.
def SLICE() -> U32:
  16384

# Hops the body sender needs: two per frame (WINDOW / SLICE = 4 frames).
def BODY_FUEL() -> Nat:
  8n

def HOST() -> String:
  "127.0.0.1"

def FIRST_PATH() -> String:
  "/early"

def SECOND_PATH() -> String:
  "/after"

# Frames the peer is willing to read before giving up: the expected
# answer is 5 frames (SETTINGS, early head, reset, credit, second head),
# so 32 leaves room for a peer that splits them.
def FUEL() -> Nat:
  32n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Body bytes: position-independent filler, 65535 one-byte nodes built
# tail-recursively and reversed once by x_cat (the pattern
# tests/io/wsm_bulk_frame.bend uses for its 128 KB frame).
def body_go(+n: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      body_go(p, 46 <> acc)

def body(+n: Nat) -> List<&2, U32>:
  HTTP.x_cat(body_go(n, Nil{}))

# Sends the body as SLICE-byte DATA frames, the record-sized slice the
# library's own senders use: the interp's frame reader copies the buffer
# it accumulates (x_read.done appends onto it) and a single 65535-byte
# frame overflows the machine stack around 26k nodes. fuel counts the
# hops left (two per frame: send, then continue); ph 0 continues after a
# send, ph 1 sends the next slice. One self-recursive def, no mutual
# recursion, and the fuel shrinks first, so termination is structural.
def body_send(fuel: Nat, ph: U32, m: Socket & Result<&1, &1, U32 & String, Unit>, +body: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match fuel:
    case 0n:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, m)
    case 1n+p:
      match ph:
        case 0:
          (s0, r0) = m
          match r0:
            case Fail{e}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s0, Fail{e}))
            case Done{u}:
              body_send(p, 1, (s0, Done{Unit{}}), body)
        case _:
          (s1, r1) = m
          match r1:
            case Fail{e}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s1, Fail{e}))
            case Done{u}:
              do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
                sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s1, HTTP2.x_t_data(), 0, 1, HTTP.x_take32(SLICE(), body))
                body_send(p, 0, sent, HTTP.x_drop32(SLICE(), body))

# Server: answer every head early. The body of the first request is
# discarded by the loop, never handed to this handler.
def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, Nil{}}}
    case HTTP.SrvReqData{slot, chunk, fin}:
      HTTP.Continue{}

# Peer ledger: which of the four answers were seen, and how much
# connection credit came back.
type Acc is Data:
  Acc{early: U32, rst: U32, wu: U32, alive: U32}

def acc0() -> Acc:
  Acc{0, 0, 0, 0}

def bump_early(acc: Acc) -> Acc:
  match acc:
    case Acc{early, rst, wu, alive}:
      Acc{1, rst, wu, alive}

def bump_rst(acc: Acc) -> Acc:
  match acc:
    case Acc{early, rst, wu, alive}:
      Acc{early, 1, wu, alive}

def bump_alive(acc: Acc) -> Acc:
  match acc:
    case Acc{early, rst, wu, alive}:
      Acc{early, rst, wu, 1}

# Connection credit: only a well-formed WINDOW_UPDATE (RFC 9113 section
# 6.9: 4 bytes, non-zero increment) adds to the ledger.
def bump_wu_ok(early: U32, rst: U32, wu: U32, alive: U32, +payload: List<&2, U32>, ok: Bool) -> Acc:
  match ok:
    case True{}:
      Acc{early, rst, (wu + HTTP2.x_flow_wu_inc(payload) : U32), alive}
    case False{}:
      Acc{early, rst, wu, alive}

def bump_wu_go(acc: Acc, +payload: List<&2, U32>, ok: Bool) -> Acc:
  match acc:
    case Acc{early, rst, wu, alive}:
      bump_wu_ok(early, rst, wu, alive, payload, ok)

def bump_wu(acc: Acc, +payload: List<&2, U32>) -> Acc:
  bump_wu_go(acc, payload, HTTP2.x_wu_ok(payload))

def score_of(acc: Acc) -> U32:
  match acc:
    case Acc{early, rst, wu, alive}:
      (early * 1000 + rst * 100 + b2u(U32.is_eq(wu, WINDOW())) * 10 + alive : U32)

def score_alive(acc: Acc) -> U32:
  score_of(bump_alive(acc))

# Frame routing: which phase the loop runs next. 2 SETTINGS needing an
# ACK, 3 the early response (HEADERS sid 1), 4 the second response
# (HEADERS sid 3, the stop signal), 5 RST_STREAM, 6 WINDOW_UPDATE on the
# connection, 7 PING, 0 anything else.
def ack_phase(+flags: U32) -> U32:
  match flags:
    case 1:
      0
    case _:
      2

def act_of(+typ: U32, +sid: U32, +flags: U32) -> U32:
  match typ sid:
    case 1 1:
      3
    case 1 3:
      4
    case 3 _:
      5
    case 8 0:
      6
    case 6 _:
      7
    case 4 _:
      ack_phase(flags)
    case _ _:
      0

# A send triple becomes the seed the read loop starts from: a failed
# write stops the run with the code the TLS lane reported.
def sent_seed(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = m
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

# The stop leaves: score with or without the second response seen.
def stop_at(got: Socket & HTTP.Got, acc: Acc) -> Socket & U32:
  (s, g) = got
  (s, score_of(acc))

def stop_alive(got: Socket & HTTP.Got, acc: Acc) -> Socket & U32:
  (s, g) = got
  (s, score_alive(acc))

# Collect loop, one self-recursive def: the fuel is the first argument
# and shrinks on every hop, so termination is structural and the phase
# arms (0 read, 1 route, 2 ACK SETTINGS, 3 early head, 4 second head =
# stop, 5 reset, 6 credit, 7 PING ACK, 0/other keep reading) can hop
# freely. Every phase body is a single term; the IO leaves never call
# back into the loop.
def coll(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, acc: Acc) -> IO(Socket & U32):
  match fuel:
    case 0n:
      IO.pure(Socket & U32, stop_at(got, acc))
    case 1n+p:
      match ph:
        case 0:
          (s0, g0) = got
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            coll(p, 1, got2, buf, acc)
        case 1:
          (s1, g1) = got
          match g1:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, acc))
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid, +payload}:
                  coll(p, act_of(typ, sid, flags), (s1, HTTP.GotOk{frame, buf2}), buf2, acc)
        case 2:
          (s2, g2) = got
          do IO<Socket & U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s2, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
            coll(p, 0, sent_seed(sent), buf, acc)
        case 3:
          (s3, g3) = got
          coll(p, 0, (s3, HTTP.GotErr{0, "next"}), buf, bump_early(acc))
        case 4:
          (s4, g4) = got
          IO.pure(Socket & U32, stop_alive(got, acc))
        case 5:
          (s5, g5) = got
          coll(p, 0, (s5, HTTP.GotErr{0, "next"}), buf, bump_rst(acc))
        case 6:
          (s6, g6) = got
          match g6:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, acc))
            case HTTP.GotOk{+frame, +buf6}:
              match frame:
                case HTTP.Frame{+typ6, +flags6, +sid6, +payload6}:
                  coll(p, 0, (s6, HTTP.GotErr{0, "next"}), buf6, bump_wu(acc, payload6))
        case 7:
          (s7, g7) = got
          match g7:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, acc))
            case HTTP.GotOk{+frame, +buf7}:
              match frame:
                case HTTP.Frame{+typ7, +flags7, +sid7, +payload7}:
                  do IO<Socket & U32>:
                    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s7, HTTP2.x_t_ping(), HTTP2.x_f_ack(), 0, payload7)
                    coll(p, 0, sent_seed(sent), buf7, acc)
        case _:
          (s9, g9) = got
          coll(p, 0, (s9, HTTP.GotErr{0, "next"}), buf, acc)

def peer_done(m: Socket & U32) -> IO(U32):
  (s, +score) = m
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

# Second request is out: start the read loop.
def peer_h3_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        res : Socket & U32 <- coll(FUEL(), 1, got, Nil{}, acc0())
        peer_done(res)

# First request body is out: send the second request on the same
# connection (HEADERS never consume the connection window, so this is
# legal even at a zero window).
def peer_body_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +port: U32) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 3, HTTP2.client.on.req_block(HOST(), port, "GET", SECOND_PATH(), Nil{}))
        peer_h3_sent(sent)

# First request head is out: send the whole window of body.
def peer_head_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +port: U32) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- body_send(BODY_FUEL(), 1, (s, Done{Unit{}}), body(U32.to_nat(WINDOW())))
        peer_body_sent(sent, port)

def peer_start(sock: Socket, +port: U32) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, HTTP2.client.on.req_block(HOST(), port, "POST", FIRST_PATH(), Nil{}))
    peer_head_sent(sent, port)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_start(sock, port)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    peer_conn(conn, port)

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.stream(~h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
    score : U32 <- client(port)
    return score

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|1111
