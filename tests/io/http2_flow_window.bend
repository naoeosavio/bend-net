# io (httpx_h2_flow_window): what a DATA frame costs the flow window and
# what a WINDOW_UPDATE may say (task-062 phase 6, findings 8 and 9).
#
# Scenario A: the peer is a raw H2 client and the server is
# HTTPX.server.concurrent. The peer sends a padded DATA frame on a parked
# request: pad length 200, the body "hi" and 200 padding octets, so the
# declared frame length is 203 while the body is 2. The server must
# credit 203 (the declared length, RFC 9113 section 6.9.1) and answer
# with the body "hi", which proves the padding was stripped before the
# handler saw it.
#
# Scenario B: the peer is a canned server that answers the client with a
# WINDOW_UPDATE of 2^31. The increment field is 31 bits, so the client
# must fail 502 "bad window_update" instead of crediting it.
#
# The delta rule of a peer SETTINGS (scenario C of task-062) moved to
# `tests/io/http2_settings_window.bend` in task-068 phase 8, which pins it
# at a non-default base and on the debt. This file keeps the two wire
# scenarios.
#
# Golden 4.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT_A() -> U32:
  18553

def PORT_B() -> U32:
  18554

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The padded frame: pad length 200, the body "hi", 200 padding octets.
def PAD() -> U32:
  200

def DECLARED() -> U32:
  203

# Frames the peer reads before it gives up.
def FUEL() -> Nat:
  16n

# Acc bits of scenario A: the credit, the 200 head, the body.
def ACC_WU() -> U32:
  1

def ACC_HEAD() -> U32:
  2

def ACC_BODY() -> U32:
  4

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# --- scenario A: the padded DATA frame ---

def pad_bytes_go(+n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      pad_bytes_go(p, 0 <> acc)

def pad_bytes(+n: Nat) -> List<&2, U32>:
  pad_bytes_go(n, Nil{})

# pad length byte, then "hi", then the padding octets.
def padded(+data: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, [PAD()], data), pad_bytes(U32.to_nat(PAD())))

def sent_seed(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = m
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

def acc_full() -> U32:
  (ACC_WU() + ACC_HEAD() + ACC_BODY() : U32)

def is_full(+acc: U32) -> Bool:
  U32.is_eq(U32.and(acc, acc_full()), acc_full())

def next_phase(is_done: Bool) -> U32:
  match is_done:
    case True{}:
      2
    case False{}:
      0

# One point per bit seen: the credit of the declared length, the 200 head
# and the two body bytes.
def score_of(+acc: U32) -> U32:
  U32.add(b2u(U32.is_eq(U32.and(acc, ACC_WU()), ACC_WU())), U32.add(b2u(U32.is_eq(U32.and(acc, ACC_HEAD()), ACC_HEAD())), b2u(U32.is_eq(U32.and(acc, ACC_BODY()), ACC_BODY()))))

# WINDOW_UPDATE on the stream, increment DECLARED.
def wu_ok(+sid: U32, +payload: List<&2, U32>) -> U32:
  U32.mul(b2u(U32.is_eq(sid, 1)), b2u(U32.is_eq(HTTP2.x_be32_rd(payload), DECLARED())))

def head_ok(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+head, t)}:
      match head:
        case HTTP.Head{+status, +headers}:
          b2u(U32.is_eq(status, 200))

def body_ok(+payload: List<&2, U32>) -> U32:
  b2u(U32.is_eq(HTTP.x_eq(payload, HTTP.x_str_bytes("hi")), 1))

def acc_add(+acc: U32, +typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      (acc + wu_ok(sid, payload) : U32)
    case 1:
      (acc + head_ok(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty())) : U32)
    case 0:
      (acc + body_ok(payload) : U32)
    case _:
      acc

def stop_at(got: Socket & HTTP.Got, +acc: U32) -> Socket & U32:
  (s, g) = got
  (s, score_of(acc))

def peer_read(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) ->
  IO(Socket & U32):
  match fuel:
    case 0n:
      IO.pure(Socket & U32, stop_at(got, acc))
    case 1n+p:
      match ph:
        case 0:
          (s0, g0) = got
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer_read(p, 1, got2, buf, acc)
        case 1:
          (s1, g1) = got
          match g1:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, acc))
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid,+flen, +payload}:
                  +acc2 : U32 = U32.or(acc, acc_add(acc, typ, sid, payload))
                  peer_read(p, next_phase(is_full(acc2)), (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
        case _:
          (s9, g9) = got
          IO.pure(Socket & U32, stop_at(got, acc))

def peer_done(m: Socket & U32) -> IO(U32):
  (s, +score) = m
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    return score

def peer_go(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        res : Socket & U32 <- peer_read(FUEL(), 1, got, Nil{}, 0)
        peer_done(res)

# The padded DATA frame: PADDED and END_STREAM.
def peer_data(sock: Socket) -> IO(U32):
  do IO<U32>:
    flags : U32 = (8 + HTTP2.x_f_end_stream() : U32)
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_data(), flags, 1, padded(HTTP.x_str_bytes("hi")))
    peer_go(sent)

def httpxs_sock(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def peer_start(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT_A(), "POST", "/pad", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head)
    peer_data(httpxs_sock(sent))

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_start(sock)

def peer(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# --- scenario B: a WINDOW_UPDATE past 2^31 - 1 ---

# 2^31 as the increment: one bit past the 31-bit field.
@unsafe
def srv_idle(got: Socket & HTTP.Got) -> IO(Unit):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      TLS.tls_close(s)
    case HTTP.GotOk{+frame, +buf2}:
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s, buf2)
        srv_idle(got2)

def srv_idle_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle((s, HTTP.GotErr{0, "next"}))

def bad_wu_payload() -> List<&2, U32>:
  [128, 0, 0, 0]

def sent_settings(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        wu : Socket & Result<&1, &1, U32 & String, Unit> <-
          HTTP2.x_send_frame(s, HTTP2.x_t_wu(), 0, 1, bad_wu_payload())
        srv_idle_sent(wu)

def srv_go(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    sent_settings(sent)

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- srv_go(sock)
        return l

def server_b(l: Listener) -> IO(String):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    l2 : Listener <- srv_conn(m)
    return "up"

def want_bad_wu(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{(code, msg)}:
      U32.mul(b2u(U32.is_eq(code, 502)), b2u(String.eq(msg, "bad window_update")))
    case Done{resp}:
      0

def client_b(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTPX.client.once_insecure(HOST(), port, HTTP.Request{"GET", "/wu", Nil{}, Nil{}})
    IO.pure(U32, want_bad_wu(r))

# --- scenario A server: the real buffered concurrent lane ---

def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def server_a(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~echo, l, CERT(), KEY())
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

def run_a(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_a(l))
    +score : U32 <- peer(port)
    return score

def run_b(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_b(l))
    +score : U32 <- client_b(port)
    return score

def main() -> IO(U32):
  do IO<U32>:
    ba : Listener & U32 <- listen_any(32n, PORT_A())
    bb : Listener & U32 <- listen_any(32n, PORT_B())
    +a : U32 <- run_a(ba)
    +b : U32 <- run_b(bb)
    +total : U32 = (a + b : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|4
