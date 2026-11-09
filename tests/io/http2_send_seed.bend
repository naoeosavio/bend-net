# io (httpx_h2_send_seed): the response sender must start from the bytes
# the loop already read (task-063 phase 7d).
#
# The peer sends one burst of three frames on one connection: HEADERS(1)
# with END_STREAM, HEADERS(3), and a DATA(3) of ECHO bytes with
# END_STREAM. The burst is wider than one 16384-byte read, so the server
# loop reads the head of stream 1 and leaves a partial DATA(3) frame in
# its buffer, with the rest of that frame still on the socket.
#
# The server answers stream 1 with BIG bytes, one byte past the connection
# window, so its send pump parks and reads. Before the fix the pump
# started with an empty buffer, read the socket from the middle of
# DATA(3), took its payload for a frame header and answered 413, then the
# connection went down with GOAWAY 6 -- both bodies lost. The pump now
# starts from the loop buffer, stashes HEADERS(3) and DATA(3), and the
# loop answers stream 3 after the first body.
#
# Checks: stream 1 holds BIG bytes of its fill, stream 3 holds the echo
# of ECHO bytes, no DATA byte passes the credit the peer granted, and both
# streams end. Golden 4.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18795

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The answer of stream 1: one byte past the initial connection window.
def BIG() -> U32:
  65536

def BIG_B() -> U32:
  97

# The body of stream 3 and so its echo: one whole frame, so the burst
# passes the 16384-byte read chunk and leaves a partial frame behind.
def ECHO() -> U32:
  16384

def ECHO_B() -> U32:
  120

def INIT_WIN() -> U32:
  65535

# Acc bits, one per check.
def ACC_BIG() -> U32:
  1

def ACC_ECHO() -> U32:
  2

def ACC_WIN() -> U32:
  4

def ACC_END() -> U32:
  8

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

@unsafe
def fill_go(n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

# Tail-recursive: a BIG-byte body is past the machine stack for a plain
# Bool.and recursion.
def bytes_go(+pay: List<&2, U32>, +b: U32, ok: Bool) -> Bool:
  match pay:
    case Nil{}:
      ok
    case +h <> t:
      bytes_go(t, b, Bool.and(ok, U32.is_eq(h, b)))

# RFC 9113 section 6.9.1: a frame never holds more than the credit the
# peer granted.
def win_ok(+total: U32, +allowed: U32, +len: U32) -> Bool:
  Bool.and(U32.is_le(total, allowed), U32.is_le(len, U32.sub(allowed, total)))

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

# A response head answers status 200.
def head_ok(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> Bool:
  match dec:
    case Fail{e}:
      False{}
    case Done{value}:
      match value:
        case (head, tab):
          match head:
            case HTTP.Head{+status, +headers}:
              U32.is_eq(status, 200)

# The acc bits one stream-1 DATA frame proves: the window and the bytes.
def acc_b1(+flags: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  +len : U32 = HTTP.x_len32(pay)
  +allowed : U32 = (INIT_WIN() + total : U32)
  +win : Bool = win_ok(total, allowed, len)
  +bod : Bool = bytes_go(pay, BIG_B(), True{})
  +fin : Bool = U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())
  U32.add(U32.mul(b2u(win), ACC_WIN()), U32.add(U32.mul(b2u(bod), ACC_BIG()), U32.mul(b2u(fin), ACC_END())))

# The acc bits one stream-3 DATA frame proves: the window, the bytes and
# the end of stream 3.
def acc_b3(+flags: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  +len : U32 = HTTP.x_len32(pay)
  +allowed : U32 = (INIT_WIN() + total : U32)
  +win : Bool = win_ok(total, allowed, len)
  +bod : Bool = bytes_go(pay, ECHO_B(), True{})
  +fin : Bool = U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())
  U32.add(U32.mul(b2u(win), ACC_WIN()), U32.add(U32.mul(b2u(bod), ACC_ECHO()), U32.mul(b2u(fin), ACC_END())))


# The response head of stream 3 carries no extra check; the head of
# stream 1 must answer 200.
def acc_head1(+sid: U32, +pay: List<&2, U32>) -> U32:
  match sid:
    case 3:
      0
    case _:
      U32.mul(b2u(head_ok(HTTP2.x_resp.decode(pay, HTTP2.x_tab.empty()))), ACC_END())

# A response HEADERS of stream 1 answers 200.
def acc_head(+typ: U32, +sid: U32, +pay: List<&2, U32>) -> U32:
  match typ:
    case 1:
      acc_head1(sid, pay)
    case _:
      0

# The credit of one DATA frame: the connection and the stream go out at
# once, so a parked sender never waits on a held batch. The last frame of
# a stream sends no stream credit (the sender is done with it).
def peer_credit(sock: Socket, +sid: U32, +len: U32, is_end: Bool) -> IO(Socket):
  match is_end:
    case True{}:
      do IO<Socket>:
        w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(len))
        IO.pure(Socket, sock_of(w))
    case False{}:
      do IO<Socket>:
        w1 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(len))
        w2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock_of(w1), HTTP2.x_t_wu(), 0, sid, HTTP.x_be32(len))
        IO.pure(Socket, sock_of(w2))

# The stop: close and turn the acc into the score.
def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(b2u(bit_ok(acc, ACC_BIG())), U32.add(b2u(bit_ok(acc, ACC_ECHO())), U32.add(b2u(bit_ok(acc, ACC_WIN())), b2u(bit_ok(acc, ACC_END())))))
    IO.pure(U32, bits)


# The DATA arm, per stream: stream 1 holds the big body, stream 3 the
# echo.
def peer_data(+sid: U32, +flags: U32, +len: U32, +end: Bool, +pay: List<&2, U32>, +tot1: U32, +tot3: U32, +acc: U32, sock: Socket) ->
  IO(U32):
  match sid:
    case 1:
      do IO<U32>:
        s1 : Socket <- peer_credit(sock, 1, len, end)
        IO.pure(U32, U32.or(acc, acc_b1(flags, pay, tot1)))
    case _:
      do IO<U32>:
        s3 : Socket <- peer_credit(sock, sid, len, end)
        IO.pure(U32, U32.or(acc, acc_b3(flags, pay, tot3)))

# One frame: the window check, the byte check and the credit. Answers the
# acc bits; the stream totals are pure math in the caller.
def peer_frame(+typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>, +tot1: U32, +tot3: U32, +acc: U32, sock: Socket) ->
  IO(U32):
  match typ:
    case 0:
      +len : U32 = HTTP.x_len32(pay)
      +end : Bool = U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())
      peer_data(sid, flags, len, end, pay, tot1, tot3, acc, sock)
    case 1:
      IO.pure(U32, U32.or(acc, acc_head(typ, sid, pay)))
    case _:
      IO.pure(U32, acc)


def total_go(same: Bool, +total: U32, +pay: List<&2, U32>) -> U32:
  match same:
    case True{}:
      (total + HTTP.x_len32(pay) : U32)
    case False{}:
      total

# The stream total after one frame: the DATA bytes of the stream, nothing
# else.
def total_add(+total: U32, +typ: U32, +sid: U32, +pay: List<&2, U32>, +want: U32) -> U32:
  match typ:
    case 0:
      match sid:
        case 1:
          +want1 : Bool = U32.is_eq(want, 1)
          total_go(want1, total, pay)
        case _:
          +want3 : Bool = U32.is_eq(want, 3)
          total_go(want3, total, pay)
    case _:
      total

# 1 keeps reading, 2 stops: both bodies are in.
def next_ph_go(done: Bool, +t1: U32, +t3: U32) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

def next_ph(+t1: U32, +t3: U32) -> U32:
  +done : Bool = Bool.and(U32.is_eq(t1, BIG()), U32.is_eq(t3, ECHO()))
  next_ph_go(done, t1, t3)

# The read loop. It stops when both streams end, or when the connection
# fails.
@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +tot1: U32, +tot3: U32, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, tot1, tot3, acc)
    case 1:
      (+s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              do IO<U32>:
                c2 : U32 <- peer_frame(typ, flags, sid, payload, tot1, tot3, acc, s1)
                +t1 : U32 = total_add(tot1, typ, sid, payload, 1)
                +t3 : U32 = total_add(tot3, typ, sid, payload, 3)
                peer_read(next_ph(t1, t3), (s1, HTTP.GotOk{frame, buf2}), buf2, t1, t3, c2)
    case _:
      (s9, g9) = got
      peer_stop(s9, acc)

# The burst: HEADERS(1, END_STREAM), HEADERS(3), DATA(3, END_STREAM).
# One write, so the read of the loop ends in the middle of DATA(3).
def burst() -> List<&2, U32>:
  +b1 : List<&2, U32> = HTTP2.x_frame_write(HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, HTTP2.client.on.req_block(HOST(), PORT(), "GET", "/big", Nil{}))
  +b3 : List<&2, U32> = HTTP2.x_frame_write(HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 3, HTTP2.client.on.req_block(HOST(), PORT(), "POST", "/echo", [HTTP.Hdr{"content-length", U32.show(ECHO())}]))
  +d3 : List<&2, U32> = HTTP2.x_frame_write(HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 3, fill(ECHO(), ECHO_B()))
  HTTP.x_cat.go(List.reverse(&2, U32, b1), HTTP.x_cat.go(List.reverse(&2, U32, b3), HTTP.x_cat.go(List.reverse(&2, U32, d3), Nil{})))

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, burst())
    peer_read(0, (sock_of(sent), HTTP.GotErr{0, "next"}), Nil{}, 0, 0, 0)

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

# --- the server side: a big answer and an echo -----------------------

def pick_resp(is_big: Bool, +body: List<&2, U32>) -> HTTP.Response:
  match is_big:
    case True{}:
      HTTP.Response{200, Nil{}, fill(BIG(), BIG_B())}
    case False{}:
      HTTP.Response{200, Nil{}, body}

def handler(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, pick_resp(String.eq(path, "/big"), body))

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~handler, l, CERT(), KEY())
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

#|4
