# io (h2_settings_mid): a SETTINGS that arrives while a send waits for
# credit reaches the loop ledger, so the next stream starts from the new
# initial window (task-068 phase 6).
#
# The peer announces a stream window of WIN1 bytes and grants only the
# connection window, so the 4096-byte answer of stream 1 stops after WIN1.
# The peer then announces WIN2 = 4096 while the send is parked. The pump
# shifts its own window and stores the frame in the read seed; the loop
# reads the stored frame, acks it and takes the new value for its ledger.
# The peer then asks for stream 3: with the fix the whole 4096-byte body
# rides one DATA frame, because the loop seeds the send with 4096. Without
# the fix the loop keeps WIN1 and the body rides WIN1-byte frames.
#
# Checks: the 4096-byte body of stream 1, the first DATA frame of stream 3
# at 4096 bytes, and the 4096-byte body of stream 3. Golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18852

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The announced initial window of the first and the second SETTINGS, and
# the body the handler answers.
def WIN1() -> U32:
  1024

def WIN2() -> U32:
  4096

def BODY() -> U32:
  4096

def FUEL() -> Nat:
  48n

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

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def is_end(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())

def set_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def srv_body() -> List<&2, U32>:
  fill_go(U32.to_nat(BODY()), 120, Nil{})

def srv(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, srv_body()})

def req_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":path", "/body"}, HTTP.Hdr{":scheme", "https"}])

def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

def send_pref(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, HTTP2.x_preface())
    IO.pure(Socket, sock_of(w))

# The score of one stream: the whole body, and the first DATA frame of
# stream 3 at the second window.
def bits(+acc: U32, +t1: U32, +first3: U32, +t3: U32, done1: Bool, done3: Bool) -> U32:
  +b1 : U32 = weigh(Bool.and(done1, U32.is_eq(t1, BODY())), 1)
  +f3 : U32 = weigh(U32.is_eq(first3, WIN2()), 2)
  +b3 : U32 = weigh(Bool.and(done3, U32.is_eq(t3, BODY())), 4)
  U32.or(acc, U32.or(b1, U32.or(f3, b3)))

def popcount(+acc: U32) -> U32:
  U32.add(U32.and(acc, 1), U32.add(U32.and(U32.shrn(acc, 1n), 1), U32.add(U32.and(U32.shrn(acc, 2n), 1), U32.and(U32.shrn(acc, 3n), 1))))

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, popcount(acc))

# The peer loop: phase 0 reads, phase 1 dispatches, phase 2 handles DATA.
# The state is the byte totals, the first frame of stream 3, the second
# SETTINGS flag and the finished flags of the two streams.
@unsafe
def peer_loop(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +t1: U32, +t3: U32, +first3: U32, +sent2: U32, +sent3: U32, +done1: U32, +done3: U32, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_stop(s0, acc)
        case 1n+f:
          (s1, g1) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
            peer_disp(f, got2, buf, t1, t3, first3, sent2, sent3, done1, done3, acc)
    case _:
      (s9, g9) = got
      peer_stop(s9, acc)

# The frames the peer reads: SETTINGS is acked, DATA is counted, and the
# request of stream 3 leaves after the answer of stream 1.
@unsafe
def peer_disp(fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +t1: U32, +t3: U32, +first3: U32, +sent2: U32, +sent3: U32, +done1: U32, +done3: U32, +acc: U32) -> IO(U32):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      peer_stop(s, acc)
    case HTTP.GotOk{+frame, +buf2}:
      match frame:
        case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
          match typ:
            case 4:
              do IO<U32>:
                s2 : Socket <- ack_settings(s, flags)
                peer_loop(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf2, t1, t3, first3, sent2, sent3, done1, done3, acc)
            case 0:
              do IO<U32>:
                s2 : Socket <- data_go(s, sid, flags, payload, t1, t3, first3, sent2)
                +t1b : U32 = total1(sid, t1, payload)
                +t3b : U32 = total3(sid, t3, payload)
                +f3 : U32 = first3_of(sid, first3, payload)
                +sd : U32 = sent2_go(sid, t1b, sent2)
                +s3 : U32 = sent3_go(sid, t3b, sent3)
                +d1 : U32 = done1_go(sid, done1, flags)
                +d3 : U32 = done3_go(sid, done3, flags)
                +acc2 : U32 = bits(acc, t1b, f3, t3b, U32.is_eq(d1, 1), U32.is_eq(d3, 1))
                peer_after(s2, U32.is_eq(d3, 1), acc2, fuel, buf2, t1b, t3b, f3, sd, s3, d1, d3)
            case _:
              peer_loop(0, fuel, (s, HTTP.GotErr{0, "next"}), buf2, t1, t3, first3, sent2, sent3, done1, done3, acc)

# The end of the batch: the second stream closes the cell.
@unsafe
def peer_after(s: Socket, is_done: Bool, +acc: U32, fuel: Nat, +buf: List<&2, U32>, +t1: U32, +t3: U32, +first3: U32, +sent2: U32, +sent3: U32, +done1: U32, +done3: U32) -> IO(U32):
  match is_done:
    case True{}:
      peer_stop(s, acc)
    case False{}:
      peer_loop(0, fuel, (s, HTTP.GotErr{0, "next"}), buf, t1, t3, first3, sent2, sent3, done1, done3, acc)

def ack_go(s: Socket, is_fresh: Bool) -> IO(Socket):
  match is_fresh:
    case True{}:
      send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
    case False{}:
      IO.pure(Socket, s)

def ack_settings(s: Socket, +flags: U32) -> IO(Socket):
  ack_go(s, U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 0))

def total1(+sid: U32, +t1: U32, +pay: List<&2, U32>) -> U32:
  match sid:
    case 1:
      (t1 + HTTP.x_len32(pay) : U32)
    case _:
      t1

def total3(+sid: U32, +t3: U32, +pay: List<&2, U32>) -> U32:
  match sid:
    case 3:
      (t3 + HTTP.x_len32(pay) : U32)
    case _:
      t3

def first3_step(is_zero: Bool, +first3: U32, +pay: List<&2, U32>) -> U32:
  match is_zero:
    case True{}:
      HTTP.x_len32(pay)
    case False{}:
      first3

def first3_of(+sid: U32, +first3: U32, +pay: List<&2, U32>) -> U32:
  match sid:
    case 3:
      first3_step(U32.is_eq(first3, 0), first3, pay)
    case _:
      first3

def sent2_step(is_full: Bool, +sent2: U32) -> U32:
  match is_full:
    case True{}:
      1
    case False{}:
      sent2

def sent2_go(+sid: U32, +t1: U32, +sent2: U32) -> U32:
  match sid:
    case 1:
      sent2_step(U32.is_ge(t1, WIN1()), sent2)
    case _:
      sent2

def sent3_step(is_full: Bool, +sent3: U32) -> U32:
  match is_full:
    case True{}:
      1
    case False{}:
      sent3

def sent3_go(+sid: U32, +t3: U32, +sent3: U32) -> U32:
  match sid:
    case 3:
      sent3_step(U32.is_ge(t3, WIN1()), sent3)
    case _:
      sent3

def done_step(fin: Bool, +done: U32) -> U32:
  match fin:
    case True{}:
      1
    case False{}:
      done

def done1_go(+sid: U32, +done1: U32, +flags: U32) -> U32:
  match sid:
    case 1:
      done_step(is_end(flags), done1)
    case _:
      done1

def done3_go(+sid: U32, +done3: U32, +flags: U32) -> U32:
  match sid:
    case 3:
      done_step(is_end(flags), done3)
    case _:
      done3

# The side effects of one DATA frame: the second SETTINGS leaves after the
# peer has WIN1 bytes of stream 1, and the request of stream 3 leaves after
# the answer of stream 1 ends.
# The stream-3 credit: the peer grants the second window after WIN1 bytes,
# so a send that keeps WIN1 finishes in WIN1-byte frames and the cell
# answers a number instead of a timeout.
def data3_go(s: Socket, is_full: Bool) -> IO(Socket):
  match is_full:
    case True{}:
      send1(s, HTTP2.x_t_wu(), 0, 3, HTTP.x_be32(WIN2()))
    case False{}:
      IO.pure(Socket, s)

def data1_go(s: Socket, is_send2: Bool, fin: Bool) -> IO(Socket):
  match is_send2:
    case True{}:
      send1(s, HTTP2.x_t_settings(), 0, 0, set_pay(WIN2()))
    case False{}:
      match fin:
        case True{}:
          send1(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 3, req_block())
        case False{}:
          IO.pure(Socket, s)

def data_go(s: Socket, +sid: U32, +flags: U32, +pay: List<&2, U32>, +t1: U32, +t3: U32, +first3: U32, +sent2: U32) -> IO(Socket):
  match sid:
    case 3:
      data3_go(s, U32.is_ge((t3 + HTTP.x_len32(pay) : U32), WIN1()))
    case 1:
      +next1 : U32 = (t1 + HTTP.x_len32(pay) : U32)
      data1_go(s, Bool.and(U32.is_ge(next1, WIN1()), U32.is_eq(sent2, 0)), is_end(flags))
    case _:
      IO.pure(Socket, s)

# The handshake: preface, a SETTINGS with WIN1, the connection credit and
# the request of stream 1.
def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_pref(sock)
    s2 : Socket <- send1(s1, HTTP2.x_t_settings(), 0, 0, set_pay(WIN1()))
    s3 : Socket <- send1(s2, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(65535))
    s4 : Socket <- send1(s3, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, req_block())
    peer_loop(0, FUEL(), (s4, HTTP.GotErr{0, "next"}), Nil{}, 0, 0, 0, 0, 0, 0, 0, 0)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      peer_go(sock)

def peer(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    peer_conn(conn)

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~srv, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +score : U32 <- peer(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

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

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|3
