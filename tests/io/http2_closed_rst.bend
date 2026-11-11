# io (http2_closed_rst): HEADERS em stream fechada responde GOAWAY 5.
#
# HEADERS numa stream fechada após troca limpa é erro de conexão
# (RFC 9113 5.1: MAY tratar como connection error STREAM_CLOSED, e a
# stream fechada não aceita non-PRIORITY). O loop responde GOAWAY 5 e
# fecha. O peer abre a stream 1, repete a HEADERS na stream 1 e vê a
# primeira resposta 200, o GOAWAY 5 e o fim da conexão. Golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18955

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Bits da resposta: primeira 200, GOAWAY 5, fim da conexão.
def ACC_FIRST() -> U32:
  1

def ACC_GOWAY() -> U32:
  2

def ACC_CLOSED() -> U32:
  4

def WANT1() -> U32:
  ACC_FIRST()

def WANT_ALL() -> U32:
  (WANT1() + ACC_GOWAY() + ACC_CLOSED() : U32)

def HFLAGS() -> U32:
  (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32)

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

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def head_block() -> List<&2, U32>:
  HTTP2.client.req.block(HOST(), PORT(), "GET", "/a", Nil{})

def send_head(sock: Socket, +sid: U32) -> IO(Socket):
  do IO<Socket>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HFLAGS(), sid, head_block())
    IO.pure(Socket, sock_of(sent))

def is_200_go(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> Bool:
  match dec:
    case Fail{e}:
      False{}
    case Done{(+head, t)}:
      match head:
        case HTTP.Head{+status, +headers}:
          U32.is_eq(status, 200)

def is_200(+pay: List<&2, U32>) -> Bool:
  is_200_go(HTTP2.x_resp.decode(pay, HTTP2.x_tab.empty()))

def head_bits(+sid: U32, +pay: List<&2, U32>) -> U32:
  weigh(Bool.and(U32.is_eq(sid, 1), is_200(pay)), ACC_FIRST())

def goway_bits(+sid: U32, +pay: List<&2, U32>) -> U32:
  weigh(Bool.and(U32.is_eq(sid, 0), U32.is_eq(HTTP2.x_be32_rd(HTTP.x_drop32(4, pay)), 5)), ACC_GOWAY())

def frame_bits(+typ: U32, +flags: U32, +sid: U32, +flen: U32, +pay: List<&2, U32>) -> U32:
  match typ:
    case 7:
      goway_bits(sid, pay)
    case 1:
      head_bits(sid, pay)
    case _:
      0

def drain_have(+acc: U32, +want: U32) -> Bool:
  U32.is_eq(U32.and(acc, want), want)

def drain_pick(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

def drain(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +want: U32, +acc: U32) ->
  IO(Socket & U32):
  match fuel ph:
    case 0n _:
      (s0, g0) = got
      IO.pure(Socket & U32, (s0, acc))
    case 1n+f 0:
      (s0, g0) = got
      do IO<Socket & U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        drain(f, 1, got2, buf, want, acc)
    case 1n+f 2:
      (s2, g2) = got
      IO.pure(Socket & U32, (s2, acc))
    case 1n+f _:
      (s, g) = got
      match g:
        case HTTP.GotErr{code, msg}:
          IO.pure(Socket & U32, (s, U32.or(acc, ACC_CLOSED())))
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +pay}:
              +acc2 : U32 = U32.or(acc, frame_bits(typ, flags, sid, flen, pay))
              drain(f, drain_pick(drain_have(acc2, want)), (s, HTTP.GotErr{0, "next"}), buf2, want, acc2)

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +total : U32 = U32.add(weigh(bit_ok(acc, ACC_FIRST()), 1), U32.add(weigh(bit_ok(acc, ACC_GOWAY()), 1), weigh(bit_ok(acc, ACC_CLOSED()), 1)))
    IO.pure(U32, total)

def peer_end(drained: Socket & U32) -> IO(U32):
  match drained:
    case (s5, acc):
      peer_stop(s5, acc)

def peer_mid(drained: Socket & U32) -> IO(U32):
  match drained:
    case (s3, acc1):
      do IO<U32>:
        s4 : Socket <- send_head(s3, 1)
        drained2 : Socket & U32 <- drain(24n, 0, (s4, HTTP.GotErr{0, "next"}), Nil{}, WANT_ALL(), acc1)
        peer_end(drained2)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_head(sock, 1)
    drained : Socket & U32 <- drain(24n, 0, (s1, HTTP.GotErr{0, "next"}), Nil{}, WANT1(), 0)
    peer_mid(drained)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_go(sock)

def peer(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# O handler responde 200 sem corpo.
def ok_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~ok_h, l, CERT(), KEY())
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

#|3
