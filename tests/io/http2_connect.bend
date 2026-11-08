# io (http2_connect): a CONNECT block answers 501 and the connection
# stays open (task-069 phase 7).
#
# RFC 9113 section 8.5 gives a CONNECT request :method CONNECT and
# :authority and no :path. The decode used to refuse the block, and the
# server closed the connection with no frame. The decode now accepts it
# and the server answers 501 with no body; the lane serves no tunnel.
#
# The peer is a raw H2 client and the server is HTTP2.server.concurrent.
# The peer sends CONNECT on stream 1, then a PING. Two checks read the
# answer: the 501 head on stream 1, and the PING ack that proves the
# connection stayed open. Two pure checks pin the decode: a CONNECT block
# passes and a path-less block without CONNECT still fails.
#
# Golden 4.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18954

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Frames the peer reads before it stops.
def FUEL() -> Nat:
  32n

def ACC_HEAD() -> U32:
  1

def ACC_PING() -> U32:
  2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

# --- the pure part: the decode of a CONNECT block --------------------

def connect_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "CONNECT"}, HTTP.Hdr{":authority", "127.0.0.1:18954"}])

def nopath_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":authority", "127.0.0.1:18954"}])

def pure_bits() -> U32:
  +conn_ok : Bool = HTTP2.x_req.ok(HTTP2.x_req.decode(connect_block(), HTTP2.x_tab.empty()))
  +nopath_ok : Bool = Bool.not(HTTP2.x_req.ok(HTTP2.x_req.decode(nopath_block(), HTTP2.x_tab.empty())))
  U32.add(weigh(conn_ok, 1), weigh(nopath_ok, 1))

# --- the raw peer ----------------------------------------------------

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def send_frame(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  HTTP2.x_send_frame(s, typ, flags, sid, pay)

# The answer head is a 501 on stream 1.
def head_bit_go(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+head, t)}:
      match head:
        case HTTP.Head{+status, +headers}:
          weigh(U32.is_eq(status, 501), ACC_HEAD())

def head_bit(payload: List<&2, U32>) -> U32:
  head_bit_go(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty()))

def is_ping_ack(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 6), U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 1))

def frame_bits(+typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 1:
      U32.mul(b2u(U32.is_eq(sid, 1)), head_bit(payload))
    case 6:
      U32.mul(b2u(is_ping_ack(typ, flags)), ACC_PING())
    case _:
      0

def stop_of(+typ: U32, +flags: U32) -> Bool:
  is_ping_ack(typ, flags)

# 3 stops the read, 0 keeps it.
def ph_of(done: Bool) -> U32:
  match done:
    case True{}:
      3
    case False{}:
      0

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, U32.add(weigh(bit_ok(acc, ACC_HEAD()), 1), weigh(bit_ok(acc, ACC_PING()), 1)))

def is_settle(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 4), U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 0))

# A fresh SETTINGS gets an ACK, so the peer answers the server preface.
def peer_ack(s: Socket) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  send_frame(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})

@unsafe
def peer_read(ph: U32, settle: Bool, +done: Bool, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_stop(s0, acc)
        case 1n+f:
          (s0, g0) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer_read(1, False{}, False{}, f, got2, buf, acc)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              +acc2 : U32 = U32.or(acc, frame_bits(typ, flags, sid, payload))
              peer_read(2, is_settle(typ, flags), stop_of(typ, flags), fuel, (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
    case 2:
      match settle:
        case True{}:
          do IO<U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- peer_ack(s_of(got))
            peer_read(0, False{}, False{}, fuel, (sock_of(sent), HTTP.GotErr{0, "next"}), buf, acc)
        case False{}:
          peer_read(ph_of(done), settle, done, fuel, got, buf, acc)
    case _:
      (s2, g2) = got
      peer_stop(s2, acc)

def s_of(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

def case_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      send_frame(sock, HTTP2.x_t_headers(), U32.add(HTTP2.x_f_end_headers(), HTTP2.x_f_end_stream()), 1, connect_block())
    ping : Socket & Result<&1, &1, U32 & String, Unit> <-
      send_frame(sock_of(sent), HTTP2.x_t_ping(), 0, 0, HTTP.x_be32(20261105))
    peer_read(0, False{}, False{}, FUEL(), (sock_of(ping), HTTP.GotErr{0, "next"}), Nil{}, 0)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      case_go(sock)

def peer(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# --- the server side: a handler that must never run ------------------

def never_h(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~never_h, l, CERT(), KEY())
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
    +wire : U32 <- peer(port)
    +score : U32 = U32.add(pure_bits(), wire)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|4
