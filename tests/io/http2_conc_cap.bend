# io (http2_conc_cap): a batch reads the peer preferences before it sends
# (task-069 phase 5).
#
# RFC 9113 section 5.1.2 lets the peer cap the open streams of a
# connection, and section 6.5.2 carries the cap in SETTINGS id 3 and the
# initial window in id 4. The concurrent client used to send the whole
# batch at once, so a batch past the cap lost its streams to RST_STREAM 7
# and the whole call failed. It also seeded the first stream of a batch
# from the RFC default window, so a peer with a smaller window saw an
# oversized DATA frame. The batch now reads the peer preface first: a
# batch that fits sends, a batch past the cap fails with 503 "batch past
# the peer cap" before any stream opens, and the first send uses the peer
# window.
#
# Six pure checks read the cap, the window and the gate. Three live runs
# follow on one listener. The first peer announces a cap of 2 and a batch
# of 3: the client reads the preface, takes its ACK and closes with no
# HEADERS. The second peer announces a cap of 100 and the same batch:
# three HEADERS arrive, the peer answers them, and the client folds three
# responses. The third peer announces an initial window of 16384 and takes
# one 20000-byte upload: no DATA frame passes the window, and the body
# arrives whole.
#
# Golden 16.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18971

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The cap the first peer announces, the cap the second one announces, and
# the requests a batch opens.
def CAP_LOW() -> U32:
  2

def CAP_HIGH() -> U32:
  100

def BATCH() -> U32:
  3

# The window the third peer announces, and the body it takes.
def WIN_SMALL() -> U32:
  16384

def BODY() -> U32:
  20000

# The client preface is 24 bytes of magic and is not a frame.
def PREFACE_LEN() -> U32:
  24

# Frames the peer reads before it stops.
def FUEL() -> Nat:
  256n

# The stage of the peer: 0 on the low cap, 1 on the high cap, 2 on the
# small window.
def STAGE_LOW() -> U32:
  0

def STAGE_HIGH() -> U32:
  1

def STAGE_BODY() -> U32:
  2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# A SETTINGS payload with MAX_CONCURRENT_STREAMS only, and one with
# INITIAL_WINDOW_SIZE only.
def cap_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(3), HTTP.x_be32(v))

def win_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

# --- the pure part -----------------------------------------------------

# The cap is read from id 3, the window from id 4, the hold is the smaller
# of the cap and x_max_streams(), and the gate takes a batch of three
# against both caps.
def pure_score() -> U32:
  +read : U32 = b2u(U32.is_eq(HTTP2.x_settings.mcs_of(cap_pay(CAP_LOW()), HTTP2.x_max_streams()), CAP_LOW()))
  +win : U32 = b2u(U32.is_eq(HTTP2.x_settings.iw_of(win_pay(WIN_SMALL()), HTTP2.x_init_window()), WIN_SMALL()))
  +low : U32 = b2u(U32.is_eq(HTTP2.client_conc.hold(CAP_LOW()), CAP_LOW()))
  +high : U32 = b2u(U32.is_eq(HTTP2.client_conc.hold(4096), HTTP2.x_max_streams()))
  +over : U32 = b2u(Bool.not(HTTP2.client_conc.fits(BATCH(), CAP_LOW())))
  +fits : U32 = b2u(HTTP2.client_conc.fits(BATCH(), CAP_HIGH()))
  U32.add(read, U32.add(win, U32.add(low, U32.add(high, U32.add(over, fits)))))

# --- the client: one rejected batch, one served batch, one upload -------

def one_req() -> HTTP.Request:
  HTTP.Request{"GET", "/x", Nil{}, Nil{}}

def reqs_go(fuel: Nat, +acc: List<&2, HTTP.Request>) -> List<&2, HTTP.Request>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      reqs_go(f, one_req() <> acc)

def reqs() -> List<&2, HTTP.Request>:
  reqs_go(U32.to_nat(BATCH()), Nil{})

def body_go(fuel: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      body_go(f, 97 <> acc)

# One upload of BODY bytes on one stream.
def uploads() -> List<&2, HTTP.Request>:
  HTTP.Request{"POST", "/up", Nil{}, body_go(U32.to_nat(BODY()), Nil{})} <> Nil{}

def one_resp(resp: HTTP.Response) -> U32:
  1

def cli_first(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      match e:
        case (code, msg):
          b2u(U32.is_eq(code, 503))
    case Done{u}:
      0

def cli_second(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      b2u(U32.is_eq(total, BATCH()))

def cli_third(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      b2u(U32.is_eq(total, 1))

def cli_go(+port: U32) -> IO(U32):
  do IO<U32>:
    low : Result<&1, &1, U32 & String, U32> <- HTTP2.client.concurrent_insecure(~one_resp, HOST(), port, reqs())
    +b1 : U32 = cli_first(low)
    high : Result<&1, &1, U32 & String, U32> <- HTTP2.client.concurrent_insecure(~one_resp, HOST(), port, reqs())
    +b2 : U32 = cli_second(high)
    up : Result<&1, &1, U32 & String, U32> <- HTTP2.client.concurrent_insecure(~one_resp, HOST(), port, uploads())
    IO.pure(U32, U32.add(b1, U32.add(b2, cli_third(up))))

# --- the raw peer ------------------------------------------------------

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

def peer_answer(s: Socket, +sid: U32) -> IO(Socket):
  send1(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), sid, HTTP2.x_block([HTTP.Hdr{":status", "200"}]))

def peer_wu(s: Socket, +sid: U32, +inc: U32) -> IO(Socket):
  send1(s, HTTP2.x_t_wu(), 0, sid, HTTP.x_be32(inc))

# The credit of one DATA frame: the stream window and the connection
# window both take the frame length.
def peer_credit(s: Socket, +sid: U32, +inc: U32) -> IO(Socket):
  do IO<Socket>:
    s1 : Socket <- peer_wu(s, sid, inc)
    peer_wu(s1, 0, inc)

# True when a frame is the ACK of our SETTINGS.
def is_ack(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, HTTP2.x_t_settings()), U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 1))

# The phase of one frame. 1 answers a HEADERS at once, 2 answers after the
# body, 3 counts a SETTINGS ACK, 4 reads a DATA frame of the upload, 5
# credits it and 0 ignores the frame.
def peer_phase(acked: Bool, +stage: U32, +typ: U32) -> U32:
  +heads : U32 = HTTP2.x_pick(U32.is_eq(typ, HTTP2.x_t_headers()), HTTP2.x_pick(U32.is_eq(stage, STAGE_BODY()), 0, 2), 0)
  +data : U32 = HTTP2.x_pick(Bool.and(U32.is_eq(typ, HTTP2.x_t_data()), U32.is_eq(stage, STAGE_BODY())), 4, 0)
  +ack : U32 = HTTP2.x_pick(Bool.and(U32.is_eq(typ, HTTP2.x_t_settings()), acked), 3, 0)
  U32.add(heads, U32.add(data, ack))

# The phase after a DATA frame: the answer when the body is whole, the
# credit when it is not.
def peer_data_phase(+total: U32) -> U32:
  HTTP2.x_pick(U32.is_ge(total, BODY()), 2, 5)

# --- the preface -------------------------------------------------------

@unsafe
def peer_app(r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>) -> Socket & List<&2, U32>:
  match r:
    case (s, Fail{e}):
      (s, acc)
    case (s, Done{+chunk}):
      (s, List.append(&2, U32, acc, chunk))

def is_pre_whole(+acc: List<&2, U32>) -> Bool:
  U32.is_ge(HTTP.x_len32(acc), PREFACE_LEN())

@unsafe
def peer_pre(fuel: Nat, got: Socket & List<&2, U32>) -> IO(Socket & List<&2, U32>):
  match got:
    case (s, +acc):
      peer_pre_go(fuel, is_pre_whole(acc), s, acc)

@unsafe
def peer_pre_go(fuel: Nat, whole: Bool, s: Socket, +acc: List<&2, U32>) -> IO(Socket & List<&2, U32>):
  match fuel whole:
    case _ True{}:
      IO.pure(Socket & List<&2, U32>, (s, HTTP.x_drop32(PREFACE_LEN(), acc)))
    case 0n _:
      IO.pure(Socket & List<&2, U32>, (s, acc))
    case 1n+f _:
      do IO<Socket & List<&2, U32>>:
        r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s, 16384)
        peer_pre(f, peer_app(r, acc))

# The close of one connection. On the low cap the score is 1 for no
# HEADERS and 1 for the ACK the preface read must send. On the high cap it
# is 1 for three HEADERS and 1 for the ACK. On the small window it is 1
# for every frame at or below the window, 1 for the whole body and 1 for
# the ACK.
def peer_done(s: Socket, l: Listener, +stage: U32, +heads: U32, +acks: U32, +total: U32, +ok: U32) -> IO(Listener & U32):
  match stage:
    case 0:
      do IO<Listener & U32>:
        x : Unit <- TLS.tls_close(s)
        +held : U32 = b2u(U32.is_eq(heads, 0))
        +ack_bit : U32 = b2u(U32.is_eq(acks, 1))
        IO.pure(Listener & U32, (l, U32.add(held, ack_bit)))
    case 1:
      do IO<Listener & U32>:
        x : Unit <- TLS.tls_close(s)
        +served : U32 = b2u(U32.is_eq(heads, BATCH()))
        +ack_bit : U32 = b2u(U32.is_eq(acks, 1))
        IO.pure(Listener & U32, (l, U32.add(served, ack_bit)))
    case _:
      do IO<Listener & U32>:
        x : Unit <- TLS.tls_close(s)
        +whole : U32 = b2u(U32.is_eq(total, BODY()))
        +ack_bit : U32 = b2u(U32.is_eq(acks, 1))
        IO.pure(Listener & U32, (l, U32.add(ok, U32.add(whole, ack_bit))))

def s_of(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

# The frame walk. Phase 0 reads, phase 1 dispatches, phase 2 answers,
# phase 3 counts an ACK, phase 4 reads a DATA frame of the upload and
# phase 5 credits it. @unsafe: the phase ping-pong does not shrink a
# structural argument; FUEL bounds it.
@unsafe
def peer(ph: U32, +stage: U32, fuel: Nat, l: Listener, got: Socket & HTTP.Got, +buf: List<&2, U32>, +heads: U32, +acks: U32, +total: U32, +ok: U32, +sid: U32, +flen: U32) -> IO(Listener & U32):
  match ph fuel:
    case 0 0n:
      peer_done(s_of(got), l, stage, heads, acks, total, ok)
    case 0 _:
      do IO<Listener & U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s_of(got), buf)
        peer(1, stage, Nat.sub(fuel, 1n), l, got2, buf, heads, acks, total, ok, sid, flen)
    case 1 _:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_done(s1, l, stage, heads, acks, total, ok)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid2, +flen2, +payload}:
              peer(peer_phase(is_ack(typ, flags), stage, typ), stage, fuel, l, (s1, HTTP.GotOk{frame, buf2}), buf2, heads, acks, total, ok, sid2, flen2)
    case 2 _:
      (s2, g2) = got
      do IO<Listener & U32>:
        s3 : Socket <- peer_answer(s2, sid)
        peer(0, stage, fuel, l, (s3, HTTP.GotErr{0, "next"}), buf, (heads + 1 : U32), acks, total, ok, sid, flen)
    case 3 _:
      (s4, g4) = got
      peer(0, stage, fuel, l, (s4, HTTP.GotErr{0, "next"}), buf, heads, (acks + 1 : U32), total, ok, sid, flen)
    case 4 _:
      (s5, g5) = got
      +ok2 : U32 = U32.and(ok, b2u(U32.is_le(flen, WIN_SMALL())))
      +total2 : U32 = U32.add(total, flen)
      peer(peer_data_phase(total2), stage, fuel, l, (s5, HTTP.GotErr{0, "next"}), buf, heads, acks, total2, ok2, sid, flen)
    case _ _:
      (s6, g6) = got
      do IO<Listener & U32>:
        s7 : Socket <- peer_credit(s6, sid, flen)
        peer(0, stage, fuel, l, (s7, HTTP.GotErr{0, "next"}), buf, heads, acks, total, ok, sid, flen)

# The frame walk after the preface: the seed of the preface read rides as
# the read buffer, and the socket starts at the read phase.
def peer_seed(l: Listener, pre: Socket & List<&2, U32>, +stage: U32) -> IO(Listener & U32):
  (s, +acc) = pre
  peer(0, stage, FUEL(), l, (s, HTTP.GotErr{0, "next"}), acc, 0, 0, 0, 1, 0, 0)

# One connection: announce the settings, drop the client preface, read
# frames.
def peer_conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +stage: U32, +pay: List<&2, U32>) -> IO(Listener & U32):
  match m:
    case (l2, Fail{e}):
      IO.pure(Listener & U32, (l2, 0))
    case (l2, Done{sock}):
      do IO<Listener & U32>:
        s1 : Socket <- send1(sock, HTTP2.x_t_settings(), 0, 0, pay)
        pre : Socket & List<&2, U32> <- peer_pre(64n, (s1, Nil{}))
        peer_seed(l2, pre, stage)

# --- the run -----------------------------------------------------------

# The third connection, then the sum of the three scores.
def peer_sum(body: Listener & U32, +two: U32) -> IO(U32):
  (l3, +body_bits) = body
  IO.pure(U32, U32.add(two, body_bits))

def peer_body(l: Listener, +two: U32) -> IO(U32):
  do IO<U32>:
    m3 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    body : Listener & U32 <- peer_conn(m3, STAGE_BODY(), win_pay(WIN_SMALL()))
    peer_sum(body, two)

def peer_high(l: Listener & U32, +one: U32) -> IO(U32):
  (l2, +two) = l
  peer_body(l2, U32.add(one, two))

def peer_next(low: Listener & U32) -> IO(U32):
  (l1, +one) = low
  do IO<U32>:
    m2 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l1, CERT(), KEY())
    high : Listener & U32 <- peer_conn(m2, STAGE_HIGH(), cap_pay(CAP_HIGH()))
    peer_high(high, one)

def peer_start(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    low : Listener & U32 <- peer_conn(m, STAGE_LOW(), cap_pay(CAP_LOW()))
    peer_next(low)

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

def main_go(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, cli_go(port))
    +peer_bits : U32 <- peer_start(l)
    +cli_bits : U32 <- IO.join(U32, chan)
    +score : U32 = U32.add(pure_score(), U32.add(peer_bits, cli_bits))
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    main_go(b)

#|16
