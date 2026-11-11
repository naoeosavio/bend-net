# io (http2_trailer_length): trailer com corpo além do content-length.
#
# O trailer fecha o pedido com o corpo do ledger. O caso 12 chamava o
# handler sem checar o content-length. Um corpo de 100 octetos passava
# com content-length 200. O ato 17 responde RST_STREAM 1 e segue na
# conexão. O peer sobe 100 octetos com content-length 200 e um trailer,
# vê o RST 1 na stream 1 e a resposta 200 da stream 3. O handler nunca
# roda para a stream 1. Golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18956

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Bits da resposta: 200 na 1 (ausente), RST 1 na 1, 200 na 3.
def ACC_FIRST() -> U32:
  1

def ACC_RST() -> U32:
  2

def ACC_SECOND() -> U32:
  4

def WANT_ALL() -> U32:
  (ACC_RST() + ACC_SECOND() : U32)

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

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(+n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

def head_full() -> List<&2, U32>:
  HTTP2.client.req.block(HOST(), PORT(), "POST", "/up", [HTTP.Hdr{"content-length", "200"}])

def head_plain() -> List<&2, U32>:
  HTTP2.client.req.block(HOST(), PORT(), "GET", "/b", Nil{})

def trailer_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{"x-t", "1"}])

def send_hblock(sock: Socket, +sid: U32, +flags: U32, +blk: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), flags, sid, blk)
    IO.pure(Socket, sock_of(sent))

def send_data(sock: Socket, +sid: U32, +body: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_data(), 0, sid, body)
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
  U32.or(weigh(Bool.and(U32.is_eq(sid, 1), is_200(pay)), ACC_FIRST()), weigh(Bool.and(U32.is_eq(sid, 3), is_200(pay)), ACC_SECOND()))

def rst_bits(+sid: U32, +pay: List<&2, U32>) -> U32:
  weigh(Bool.and(U32.is_eq(sid, 1), U32.is_eq(HTTP2.x_be32_rd(pay), 1)), ACC_RST())

def frame_bits(+typ: U32, +flags: U32, +sid: U32, +flen: U32, +pay: List<&2, U32>) -> U32:
  match typ:
    case 3:
      rst_bits(sid, pay)
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
          IO.pure(Socket & U32, (s, acc))
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +pay}:
              +acc2 : U32 = U32.or(acc, frame_bits(typ, flags, sid, flen, pay))
              drain(f, drain_pick(drain_have(acc2, want)), (s, HTTP.GotErr{0, "next"}), buf2, want, acc2)

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +total : U32 = U32.add(weigh(bit_ok(acc, ACC_RST()), 1), U32.add(weigh(bit_ok(acc, ACC_SECOND()), 1), weigh(Bool.not(bit_ok(acc, ACC_FIRST())), 1)))
    IO.pure(U32, total)

def peer_end(drained: Socket & U32) -> IO(U32):
  match drained:
    case (s5, acc):
      peer_stop(s5, acc)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_hblock(sock, 1, 4, head_full())
    s2 : Socket <- send_data(s1, 1, fill(100, 97))
    s3 : Socket <- send_hblock(s2, 1, 5, trailer_block())
    s4 : Socket <- send_hblock(s3, 3, 5, head_plain())
    drained : Socket & U32 <- drain(32n, 0, (s4, HTTP.GotErr{0, "next"}), Nil{}, WANT_ALL(), 0)
    peer_end(drained)

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
