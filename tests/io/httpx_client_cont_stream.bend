# lib (httpx_client_cont_stream): fragmented response HEADERS against the
# streaming client (mold httpx_client_cont: server raw, client real).
# Server answers HEADERS (sid 1, no END_HEADERS) + CONT (END_HEADERS) +
# DATA (END_STREAM "hello"). Client is HTTP2.client.stream.once_insecure
# POST "hello" with a pure Continue handler. Golden 1 iff total bytes 5
# and fins 1 — proves client.on.sdrop reassembles CONT without
# re-delivering StreamHead (phase 7 rejoins phase 4 handler-free).
# Pre-fix behavior: Fail 502 "fragmented".
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def hello_bytes() -> List<&2, U32>:
  HTTP.x_str_bytes("hello")

def resp_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":status", "200"}])

def frag_first() -> List<&2, U32>:
  HTTP.x_take32(6, resp_block())

def frag_rest() -> List<&2, U32>:
  HTTP.x_drop32(6, resp_block())

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def h(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  match ev:
    case HTTP.StreamHead{head}:
      HTTP.StreamContinue{}
    case HTTP.StreamData{chunk, fin}:
      HTTP.StreamContinue{}

def client_score_counts(counts: U32 & U32) -> U32:
  (total, fins) = counts
  b2u(Bool.and(U32.is_eq(total, 5), U32.is_eq(fins, 1)))

def client_score(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      client_score_counts(counts)

def client(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP2.client.stream.once_insecure(~h, "127.0.0.1", port, "POST", "/echo", Nil{}, hello_bytes())
    IO.pure(U32, client_score(r))

# Raw server: preface (magic 24 via tls_recv_bytes) + SETTINGS send, then
# frame loop until client DATA END_STREAM, then fragmented answer.
def srv_acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTP.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTP.GotErr{0, "next"})

def srv_ack(got: Socket & HTTP.Got) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
    IO.pure(Socket & HTTP.Got, srv_acked(sent))

def srv_pinged(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTP.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTP.GotErr{0, "next"})

def srv_ping(got: Socket & HTTP.Got, +payload: List<&2, U32>) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_ping(), HTTP2.x_f_ack(), 0, payload)
    IO.pure(Socket & HTTP.Got, srv_pinged(sent))

def srv_is_settings_ack(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, HTTP2.x_t_settings()), U32.is_eq(flags, 1))

def srv_is_settings(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTP2.x_t_settings())

def srv_is_data_end(+typ: U32, +end: U32) -> Bool:
  Bool.and(U32.is_eq(typ, HTTP2.x_t_data()), U32.is_eq(end, 1))

def srv_act_data(is_end: Bool) -> U32:
  match is_end:
    case True{}:
      2
    case False{}:
      0

def srv_act_mid(is_set: Bool, +typ: U32, +end: U32) -> U32:
  match is_set:
    case True{}:
      1
    case False{}:
      srv_act_data(srv_is_data_end(typ, end))

def srv_act_go(is_ack: Bool, +typ: U32, +flags: U32, +end: U32) -> U32:
  match is_ack:
    case True{}:
      0
    case False{}:
      srv_act_mid(srv_is_settings(typ), typ, end)

def srv_act(+typ: U32, +flags: U32, +end: U32) -> U32:
  srv_act_go(srv_is_settings_ack(typ, flags), typ, flags, end)

def srv_done(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s4, r) = sent
  TLS.tls_close(s4)

def srv_send_data(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s3, r) = sent
  match r:
    case Fail{e}:
      TLS.tls_close(s3)
    case Done{u}:
      do IO<Unit>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s3, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, hello_bytes())
        srv_done(sent2)

def srv_send_cont(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, r) = sent
  match r:
    case Fail{e}:
      TLS.tls_close(s2)
    case Done{u}:
      do IO<Unit>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s2, HTTP2.x_t_cont(), HTTP2.x_f_end_headers(), 1, frag_rest())
        srv_send_data(sent2)

def srv_answer(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), 0, 1, frag_first())
    srv_send_cont(sent)

@unsafe
def srv(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +end: U32, act: U32) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        srv(1, got2, buf, 0, 0, 0, Nil{}, 0, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +payload2}:
              srv(2, (s1, HTTP.GotOk{frame, buf2}), buf2, typ2, flags2, sid2, payload2, U32.and(flags2, HTTP2.x_f_end_stream()), srv_act(typ2, flags2, U32.and(flags2, HTTP2.x_f_end_stream())))
    case 2:
      match act:
        case 1:
          do IO<Unit>:
            got2 : Socket & HTTP.Got <- srv_ack(got)
            srv(0, got2, buf, 0, 0, 0, Nil{}, 0, 4)
        case 2:
          srv_answer(srv_sock(got))
        case _:
          srv(3, got, buf, typ, flags, sid, payload, end, 4)
    case 3:
      match typ:
        case 6:
          do IO<Unit>:
            gotp : Socket & HTTP.Got <- srv_ping(got, payload)
            srv(0, gotp, buf, 0, 0, 0, Nil{}, 0, 4)
        case _:
          srv(0, got, buf, 0, 0, 0, Nil{}, 0, 4)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

def srv_sock(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

def srv_set(got: Socket & HTTP.Got) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    IO.pure(Socket & HTTP.Got, srv_acked(sent))

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
          do IO<Unit>:
            got : Socket & HTTP.Got <- srv_set((s2, HTTP.GotErr{0, "next"}))
            srv(0, got, HTTP.x_drop32(24, acc), 0, 0, 0, Nil{}, 0, 4)
        case _:
          do IO<Unit>:
            TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def srv_start(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    srv_pre(0, r1, Nil{}, 0, False{})

def srv_spawn_go(sock: Socket) -> IO(Unit):
  srv_start(sock)

def srv_spawn(sock: Socket, l: Listener) -> IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, srv_spawn_go(sock))
    return l

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      srv_spawn(sock, l)

@unsafe
def server_side_go(l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    l2 : Listener <- srv_conn(m)
    x : Unit <- server_side_go(l2)
    return x

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    l2 : Listener <- srv_conn(m)
    x : Unit <- server_side_go(l2)
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
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
