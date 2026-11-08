# io (http2_body_pad_cap): the buffered body cap counts the body without
# padding (task-069 phase 6).
#
# The ledger keeps the body without padding and adds the declared DATA
# length, so the old cap counted bytes that never reached memory and a
# peer that sent padding alone filled it. The count is now the body, and
# the credit keeps the declared length (RFC 9113 section 6.9.1).
#
# The peer is a raw H2 client and the server is HTTP2.server.concurrent
# with a handler that answers the body length. One connection sends 257
# padded DATA frames of 65535 bytes: the declared total passes the cap by
# 65279 bytes and the body stays 256 bytes below it, so a cap that counts
# the declared length refuses the body and a cap that counts the body
# accepts it. Three pure checks pin the strip, the edge at the cap and the
# declared total of the frames.
#
# Checks: pure 3 (padding is not body, padding does not pass the cap, the
# declared total passes it), wire 2 (the 200 head, the body count).
# Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18953

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The cap, the widest DATA frame, and the padding the peer adds to it.
def CAP() -> U32:
  HTTP2.x_max_body()

def FRAME() -> U32:
  65535

def PAD() -> U32:
  254

# The body of one padded frame: the length minus the pad-length byte and
# the padding.
def BODY() -> U32:
  U32.sub(U32.sub(FRAME(), PAD()), 1)

# Frames that pass the declared cap and stay below the body cap.
def FRAMES() -> U32:
  257

def PADDED() -> U32:
  8

# Acc bits, one per check.
def ACC_HEAD() -> U32:
  1

def ACC_BODY() -> U32:
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

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(+n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

# A padded DATA payload: the pad length, the body, then that many pad
# bytes (RFC 9113 section 6.1).
def pad_pay(+body: List<&2, U32>, +pad: U32) -> List<&2, U32>:
  List.append(&2, U32, [pad], List.append(&2, U32, body, fill(pad, 0)))

# --- the pure checks -------------------------------------------------

def pure_bits() -> U32:
  +strip_ok : Bool = U32.is_eq(HTTP.x_len32(HTTP2.x_data_body(pad_pay([1, 2, 3], PAD()), PADDED())), 3)
  +edge_ok : Bool = Bool.not(HTTP2.x_body_over(CAP(), 0))
  +over_ok : Bool = U32.is_gt(U32.mul(FRAMES(), FRAME()), CAP())
  U32.add(weigh(strip_ok, 1), U32.add(weigh(edge_ok, 1), weigh(over_ok, 1)))

# --- the raw peer ----------------------------------------------------

# The byte at position I of the padded payload: the pad length first, then
# the body, then the padding.
def pad_body_byte(is_data: Bool) -> U32:
  match is_data:
    case True{}:
      97
    case False{}:
      0

def pad_byte.go(is_len: Bool, is_data: Bool) -> U32:
  match is_len:
    case True{}:
      PAD()
    case False{}:
      pad_body_byte(is_data)

def pad_byte(+i: U32) -> U32:
  pad_byte.go(U32.is_eq(i, 1), U32.is_le(i, U32.add(BODY(), 1)))

# Builds one body frame backwards, so one frame costs one pass and no
# deep append (List.append recurses on its first list). @unsafe: the loop
# counts down in U32, which the checker cannot see as a decrease.
@unsafe
def pad_go(+left: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0:
      acc
    case _:
      +b : U32 = pad_byte(left)
      pad_go((left - 1 : U32), b <> acc)

# One body frame, built once and reused: the sender copies it per write.
def chunk() -> List<&2, U32>:
  pad_go(FRAME(), Nil{})

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# The last frame also ends the stream.
def last_flags(is_last: Bool) -> U32:
  U32.add(PADDED(), U32.mul(b2u(is_last), HTTP2.x_f_end_stream()))

@unsafe
def send_frames(+left: U32, +chunk: List<&2, U32>, sock: Socket) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match left:
    case 0:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case _:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        +flags : U32 = last_flags(U32.is_eq(left, 1))
        sent : Socket & Result<&1, &1, U32 & String, Unit> <-
          HTTP2.x_send_frame(sock, HTTP2.x_t_data(), flags, 1, chunk)
        send_frames((left - 1 : U32), chunk, sock_of(sent))

# --- scoring ---------------------------------------------------------

def is_end(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 0), U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream()))

def head_bit_go(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+head, t)}:
      match head:
        case HTTP.Head{+status, +headers}:
          weigh(U32.is_eq(status, 200), ACC_HEAD())

def head_bit(payload: List<&2, U32>) -> U32:
  head_bit_go(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty()))

# The count the handler saw, as four bytes, on the END_STREAM frame.
def body_bit(+flags: U32, +flen: U32, +payload: List<&2, U32>) -> U32:
  +end : Bool = U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())
  weigh(Bool.and(end, U32.is_eq(flen, 4)), weigh(U32.is_eq(HTTP2.x_be32_rd(payload), U32.mul(FRAMES(), BODY())), ACC_BODY()))

def frame_bits(+typ: U32, +flags: U32, +flen: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 1:
      head_bit(payload)
    case 0:
      body_bit(flags, flen, payload)
    case _:
      0

# 2 stops the read, 0 keeps it.
def ph_of(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, U32.add(weigh(bit_ok(acc, ACC_HEAD()), 1), weigh(bit_ok(acc, ACC_BODY()), 1)))

@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, acc)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              +acc2 : U32 = U32.or(acc, frame_bits(typ, flags, flen, sid, payload))
              peer_read(ph_of(is_end(typ, flags)), (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
    case _:
      (s2, g2) = got
      peer_stop(s2, acc)

def case_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    +head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT(), "POST", "/pad", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head)
    up : Socket & Result<&1, &1, U32 & String, Unit> <- send_frames(FRAMES(), chunk(), sock_of(sent))
    peer_read(0, (sock_of(up), HTTP.GotErr{0, "next"}), Nil{}, 0)

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

# --- the server side: count the body it saw -------------------------

# The handler answers the body count it saw, as four bytes.
def count_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, HTTP.x_be32(HTTP.x_len32(body))})

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~count_h, l, CERT(), KEY())
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

#|5
