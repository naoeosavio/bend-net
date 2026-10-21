# lib (httpx_server_cont): fragmented request HEADERS against the real
# HTTPX.server.stream (mold httpx_interop, inverted: client raw, server
# real). Client pipelines HEADERS (sid 1, no END_HEADERS) + CONT
# (END_HEADERS) + DATA (END_STREAM "hi") raw via HTTP2.x_send_frame; the
# server must park the fragment (fends), finish on CONT (phase 6) and
# answer 200 echoing "hi" via the streaming handler. Golden 1 iff the
# single 200 head plus the "hi" body are collected. Pre-fix behavior:
# close on the partial HEADERS (no 200, score 0).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def hi_bytes() -> List<&2, U32>:
  HTTP.x_str_bytes("hi")

def req_block(+port: U32) -> List<&2, U32>:
  HTTP2.client.on.req_block("127.0.0.1", port, "POST", "/echo", Nil{})

def frag_first(+port: U32) -> List<&2, U32>:
  HTTP.x_take32(10, req_block(port))

def frag_rest(+port: U32) -> List<&2, U32>:
  HTTP.x_drop32(10, req_block(port))

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Server handler: plain echo (Head buffers, Data answers 200 immediately).
def h2(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

# Raw client collector: single stream, counts one 200 head + "hi" body.
def cc_acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTP.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTP.GotErr{0, "next"})

def cc_ack(got: Socket & HTTP.Got) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
    IO.pure(Socket & HTTP.Got, cc_acked(sent))

def cc_act_settings_ack(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, HTTP2.x_t_settings()), U32.is_eq(flags, 1))

def cc_act_settings(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTP2.x_t_settings())

def cc_act_head(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTP2.x_t_headers())

def cc_act_data(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTP2.x_t_data())

def cc_act_data_go(is_data: Bool) -> U32:
  match is_data:
    case True{}:
      3
    case False{}:
      0

def cc_act_head_go(is_head: Bool, +typ: U32) -> U32:
  match is_head:
    case True{}:
      2
    case False{}:
      cc_act_data_go(cc_act_data(typ))

def cc_act_mid(is_set: Bool, is_head: Bool, +typ: U32) -> U32:
  match is_set:
    case True{}:
      1
    case False{}:
      cc_act_head_go(is_head, typ)

def cc_act_go(is_ack: Bool, +typ: U32) -> U32:
  match is_ack:
    case True{}:
      0
    case False{}:
      cc_act_mid(cc_act_settings(typ), cc_act_head(typ), typ)

def cc_act(+typ: U32, +flags: U32) -> U32:
  cc_act_go(cc_act_settings_ack(typ, flags), typ)

def cc_status(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+h, t)}:
      match h:
        case HTTP.Head{status, headers}:
          status

def cc_hit(+status: U32, +sid: U32) -> Bool:
  Bool.and(U32.is_eq(status, 200), U32.is_eq(sid, 1))

def cc_bump(hit: Bool, +n: U32) -> U32:
  match hit:
    case True{}:
      (n + 1 : U32)
    case False{}:
      n

def cc_body_ok(+payload: List<&2, U32>, +end: U32) -> Bool:
  Bool.and(U32.is_eq(end, 1), U32.is_eq(HTTP.x_eq(payload, hi_bytes()), 1))

def cc_bok_add(hit: Bool, +bokn: U32) -> U32:
  match hit:
    case True{}:
      (bokn + 1 : U32)
    case False{}:
      bokn

def cc_fin_u(+n: U32, +bokn: U32) -> Bool:
  Bool.and(U32.is_eq(n, 1), U32.is_eq(bokn, 1))

def cc_score_go(fin: Bool) -> U32:
  match fin:
    case True{}:
      1
    case False{}:
      0

def cc_score(+n: U32, +bokn: U32) -> U32:
  cc_score_go(cc_fin_u(n, bokn))

def cc_done_got(got: Socket & HTTP.Got, +n: U32, +bokn: U32) -> Socket & U32:
  (s, g) = got
  (s, cc_score(n, bokn))

@unsafe
def cc(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +n: U32, +bokn: U32, fin: Bool) ->
  IO(Socket & U32):
  match phase:
    case 0:
      match fin:
        case True{}:
          IO.pure(Socket & U32, cc_done_got(got, n, bokn))
        case False{}:
          cc(1, got, buf, 0, 0, 0, Nil{}, n, bokn, fin)
    case 1:
      (s1, g1) = got
      do IO<Socket & U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
        cc(5, got2, buf, 0, 0, 0, Nil{}, n, bokn, fin)
    case 2:
      cc_dispat(cc_act(typ, flags), got, buf, typ, flags, sid, payload, n, bokn, fin)
    case 3:
      cc(0, got, buf, 0, 0, 0, Nil{}, cc_bump(cc_hit(cc_status(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty())), sid), n), bokn, cc_fin_u(cc_bump(cc_hit(cc_status(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty())), sid), n), bokn))
    case 4:
      cc(0, got, buf, 0, 0, 0, Nil{}, n, cc_bok_add(cc_body_ok(payload, U32.and(flags, HTTP2.x_f_end_stream())), bokn), cc_fin_u(n, cc_bok_add(cc_body_ok(payload, U32.and(flags, HTTP2.x_f_end_stream())), bokn)))
    case 5:
      (s5, g5) = got
      match g5:
        case HTTP.GotErr{code5, msg5}:
          match code5:
            case 0:
              cc(1, got, buf, 0, 0, 0, Nil{}, n, bokn, fin)
            case _:
              IO.pure(Socket & U32, (s5, cc_score(n, bokn)))
        case HTTP.GotOk{+frame5, +buf5}:
          match frame5:
            case HTTP.Frame{+typ5, +flags5, +sid5, +payload5}:
              cc_dispat(cc_act(typ5, flags5), (s5, HTTP.GotOk{frame5, buf5}), buf5, typ5, flags5, sid5, payload5, n, bokn, fin)
    case _:
      (s8, g8) = got
      IO.pure(Socket & U32, (s8, cc_score(n, bokn)))

def cc_dispat(act: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +n: U32, +bokn: U32, fin: Bool) ->
  IO(Socket & U32):
  match act:
    case 1:
      do IO<Socket & U32>:
        got2 : Socket & HTTP.Got <- cc_ack(got)
        cc(0, got2, buf, 0, 0, 0, Nil{}, n, bokn, cc_fin_u(n, bokn))
    case 2:
      cc(3, got, buf, typ, flags, sid, payload, n, bokn, fin)
    case 3:
      cc(4, got, buf, typ, flags, sid, payload, n, bokn, fin)
    case _:
      cc(1, got, buf, 0, 0, 0, Nil{}, n, bokn, fin)

def client_collect_done(done: Socket & U32) -> IO(U32):
  (s2, score) = done
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    return score

def client_collect(sock: Socket) -> IO(U32):
  do IO<U32>:
    got : Socket & HTTP.Got <- HTTP2.x_read_frame(sock, Nil{})
    done : Socket & U32 <- cc(5, got, Nil{}, 0, 0, 0, Nil{}, 0, 0, False{})
    client_collect_done(done)

# Raw pipelined sends: HEADERS(1, no END_HEADERS, frag) + CONT(1,
# END_HEADERS, rest) + DATA(1, END_STREAM, "hi").
def client_send3(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s3, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s3)
        IO.pure(U32, 0)
    case Done{u}:
      client_collect(s3)

def client_send2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +port: U32) -> IO(U32):
  (s2, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent3 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s2, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, hi_bytes())
        client_send3(sent3)

def client_send1(sent: Socket & Result<&1, &1, U32 & String, Unit>, +port: U32) -> IO(U32):
  (s1, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s1, HTTP2.x_t_cont(), HTTP2.x_f_end_headers(), 1, frag_rest(port))
        client_send2(sent2, port)

def client_fire(sock: Socket, +port: U32) -> IO(U32):
  do IO<U32>:
    sent1 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), 0, 1, frag_first(port))
    client_send1(sent1, port)

def client_conn(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      client_fire(sock, port)

law client:
  for +port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    c : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure("127.0.0.1", port)
    conn : Result<&1, &1, U32 & String, Socket> <- HTTPX.client.on.h2_only(c)
    client_conn(conn, port)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.stream(~h2, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
