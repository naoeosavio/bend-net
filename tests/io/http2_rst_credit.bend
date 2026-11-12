# io (httpx_h2_rst_credit): a DATA frame of a stream the handler cancels
# still credits the connection window (task-063 phase 6b, defect found
# when the receive credit moved to the batch).
#
# The server is HTTP2.server.stream.once; the handler answers Continue
# on the head and Cancel on the body. The peer sends HEADERS(POST
# /cancel, no END_STREAM) and two DATA frames of 16384 bytes on stream 1.
# The first frame makes the handler cancel, so the server answers
# RST_STREAM 8 (CANCEL); its 16384 bytes still count against the
# connection window (RFC 9113 section 6.9.1). The second frame is stray
# (the stream is gone), so it credits the connection too, and the two
# credits cross x_wu_half() together: one connection WINDOW_UPDATE of
# 32768. Before the fix the reset path answered no credit at all, so the
# peer window leaked one frame for each cancelled stream and this body
# showed no WU.
#
# Checks: the increment 32768 on the connection, the RST 8 on the
# stream, 1 WU, 0 stream WUs, and no other frame. Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18792

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The body: two frames of 16384, below the 65535 window of the peer.
def BODY() -> U32:
  16384

# The credit the two frames add: the cancelled frame and the stray one.
def WU_INC() -> U32:
  32768

# The frames the peer reads: the server SETTINGS, the SETTINGS ACK, the
# reset and the WU.
def READS() -> U32:
  4

# CANCEL, the RST_STREAM code of a stream the handler drops.
def CANCEL() -> U32:
  8

def ACC_WU() -> U32:
  1

def ACC_RST() -> U32:
  2

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(+n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# The connection WU of the cancelled frame: sid 0 and the whole credit.
def conn_bit(+sid: U32, +payload: List<&2, U32>) -> U32:
  +is_conn : Bool = U32.is_eq(sid, 0)
  +is_inc : Bool = U32.is_eq(HTTP2.x_be32_rd(payload), WU_INC())
  weigh(Bool.and(is_conn, is_inc), ACC_WU())

# The RST of the stream, and the CANCEL code of RFC 9113 section 6.4.
def rst_bit(+sid: U32, +payload: List<&2, U32>) -> U32:
  +is_sid : Bool = U32.is_eq(sid, 1)
  +is_code : Bool = U32.is_eq(HTTP2.x_be32_rd(payload), CANCEL())
  weigh(Bool.and(is_sid, is_code), ACC_RST())

def frame_bit(+typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      conn_bit(sid, payload)
    case 3:
      rst_bit(sid, payload)
    case _:
      0

# A frame of a type this body must not see: an answer, a GOAWAY or a
# DATA frame. The two handshake frames (SETTINGS and the ACK) pass.
def bad_of(+typ: U32) -> U32:
  match typ:
    case 4:
      0
    case 8:
      0
    case 3:
      0
    case _:
      1

def wu_count(+typ: U32, +sid: U32) -> U32:
  match typ:
    case 8:
      weigh(U32.is_eq(sid, 0), 1)
    case _:
      0

def wu_stream(+typ: U32, +sid: U32) -> U32:
  match typ:
    case 8:
      weigh(U32.is_eq(sid, 1), 1)
    case _:
      0

# The next phase: read on until the fuel is spent, then stop.
def ph_next(+fuel: U32) -> U32:
  match fuel:
    case 1:
      2
    case _:
      0

def peer_stop(s: Socket, +wus: U32, +wus1: U32, +bad: U32, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(weigh(bit_ok(acc, ACC_WU()), 1), weigh(bit_ok(acc, ACC_RST()), 1))
    +counts : U32 = U32.add(weigh(U32.is_eq(wus, 1), 1), U32.add(weigh(U32.is_eq(wus1, 0), 1), weigh(U32.is_eq(bad, 0), 1)))
    IO.pure(U32, (bits + counts : U32))

# Phase 0 reads one frame, phase 1 scores it, and the fuel bounds the
# count: the reset comes first, the WU behind it.
# shortcut: @unsafe, because the phases do not shrink one argument.
@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +fuel: U32, +wus: U32, +wus1: U32, +bad: U32, +acc: U32) ->
  IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, fuel, wus, wus1, bad, acc)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, wus, wus1, bad, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              +wus2 : U32 = (wus + wu_count(typ, sid) : U32)
              +wus12 : U32 = (wus1 + wu_stream(typ, sid) : U32)
              +bad2 : U32 = (bad + bad_of(typ) : U32)
              +acc2 : U32 = U32.or(acc, frame_bit(typ, sid, payload))
              peer_read(ph_next(fuel), (s1, HTTP.GotOk{frame, buf2}), buf2, (fuel - 1 : U32), wus2, wus12, bad2, acc2)
    case _:
      (s2, g2) = got
      peer_stop(s2, wus, wus1, bad, acc)

def peer_tail(sock: Socket) -> IO(U32):
  do IO<U32>:
    up : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_data(), 0, 1, fill(BODY(), 97))
    up2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock_of(up), HTTP2.x_t_data(), 0, 1, fill(BODY(), 98))
    peer_read(0, (sock_of(up2), HTTP.GotErr{0, "next"}), Nil{}, READS(), 0, 0, 0, 0)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.req.block(HOST(), PORT(), "POST", "/cancel", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head)
    peer_tail(sock_of(sent))

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_go(sock)

def peer(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# --- the server side: cancel the body -------------------------------

def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, chunk, fin}:
      HTTP.Cancel{}

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.stream.once(~h, l, CERT(), KEY())
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

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +score : U32 <- peer(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|5
