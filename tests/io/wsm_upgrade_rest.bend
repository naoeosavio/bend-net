# wsm (wsm_upgrade_rest): the handshake's rest feeds the frame loop.
# A raw client writes head + one masked frame in a single write. The
# server (on_h1_open_plain, echo ~K) must read the frame out of rest —
# never re-asked from the socket — echo it back and close: the client
# sees the exact 101 head, the exact echo, then EOF. serve_once_plain
# gets the same rest-seeded proof through client_echo_plain.
# Golden 3 = 2 (head + echo, EOF) + 1 (serve_once echo).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP
import ../../lib/wsm.bend as WSM

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def up_hs() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="}, HTTP.Hdr{"Sec-WebSocket-Version", "13"}]

def req_bytes(+port: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_str_bytes("GET /chat HTTP/1.1\r\nHost: 127.0.0.1:"), List.append(&2, U32, HTTP.x_str_bytes(U32.show(port)), List.append(&2, U32, HTTP.x_str_bytes("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n"), [129, 130, 1, 2, 3, 4, 73, 107])))

def want_stream() -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_str_bytes("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"), [129, 2, 72, 105])

def srv_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}], Nil{}})

def srv_k(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  WSM.wsm_echo_one(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, rest)

def srv_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.on_h1_open_plain(~srv_h, ~srv_k, l)
    IO.pure(U32, 0)

def cli_eof_got(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, b2u(WSM.wsm_eq_bytes(acc, want_stream())))
    case Done{+part}:
      match part:
        case Nil{}:
          do IO<U32>:
            x : Unit <- Socket.close(s)
            IO.pure(U32, (b2u(WSM.wsm_eq_bytes(acc, want_stream())) + 1 : U32))
        case h <> t:
          do IO<U32>:
            x : Unit <- Socket.close(s)
            IO.pure(U32, 0)

def cli_eof(sock: Socket, +acc: List<&2, U32>) -> IO(U32):
  do IO<U32>:
    got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(sock, 4096)
    cli_eof_got(got, acc)

@unsafe
def cli_acc(phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +want_len: U32, done: Bool) -> IO(U32):
  match phase:
    case 0:
      (s0, r0) = got
      match r0:
        case Fail{e}:
          do IO<U32>:
            x : Unit <- Socket.close(s0)
            IO.pure(U32, 0)
        case Done{+part}:
          +acc2 : List<&2, U32> = List.append(&2, U32, acc, part)
          cli_acc(1, (s0, Done{Nil{}}), acc2, want_len, U32.is_eq(U32.from_nat(List.length(&2, U32, acc2)), want_len))
    case 1:
      (s1, r1) = got
      match done:
        case True{}:
          cli_eof(s1, acc)
        case False{}:
          do IO<U32>:
            got2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s1, 4096)
            cli_acc(0, got2, acc, want_len, False{})
    case _:
      (s9, r9) = got
      do IO<U32>:
        x : Unit <- Socket.close(s9)
        IO.pure(U32, 0)

def cli_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want_len: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s, 4096)
        cli_acc(0, got, Nil{}, want_len, False{})

def cli_sock(sock: Socket, +port: U32) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(sock, req_bytes(port))
    cli_sent(sent, U32.from_nat(List.length(&2, U32, want_stream())))

def cli_conn(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      cli_sock(sock, port)

def run_raw(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, srv_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    cli_conn(conn, port)

def once_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l2, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l2)
        IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        x : Unit <- WSM.serve_once_plain(sock)
        y : Unit <- Listener.close(l2)
        IO.pure(U32, 0)

def once_side(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    once_conn(m)

def echo_ok(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, "Hi"))

def run_once(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, once_side(l))
    r : Result<&1, &1, U32 & String, String> <- WSM.client_echo_plain("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    IO.pure(U32, echo_ok(r))

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

law main:
  IO(U32)

def main():
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 18533)
    +raw : U32 <- run_raw(b1)
    b2 : Listener & U32 <- listen_any(32n, 18534)
    +one : U32 <- run_once(b2)
    +total : U32 = (raw + one : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|3
