# wsm (wsm_loopback): one handler, three lanes, same echo.
# server_on_plain / server_on / server_on(+insecure client) each serve
# the echo handler over loopback; client_echo_plain / client_echo /
# client_echo_insecure each expect "Hi" back. Golden 3 = 1 + 1 + 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/wsm.bend as WSM

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def echo_h(ev: WSM.WSEv) -> IO(WSM.WSOut):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      IO.pure(WSM.WSOut, WSM.OutMsg{msg})
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSBin{pay}})
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.OutOp{8, pay})
    case WSM.EvError{code, msg}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})

def echo_ok(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, "Hi"))

def plain_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- WSM.server_on_plain(~echo_h, l)
    IO.pure(U32, 0)

def run_plain(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, plain_side(l))
    r : Result<&1, &1, U32 & String, String> <- WSM.client_echo_plain("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    IO.pure(U32, echo_ok(r))

def tls_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- WSM.server_on(~echo_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

def run_tls(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, tls_side(l))
    r : Result<&1, &1, U32 & String, String> <- WSM.client_echo_insecure("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    IO.pure(U32, echo_ok(r))

def once_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        x : Unit <- WSM.serve_once(sock)
        IO.pure(U32, 0)

def once_side(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    once_conn(m)

def run_once(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, once_side(l))
    r : Result<&1, &1, U32 & String, String> <- WSM.client_echo_insecure("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
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
    b1 : Listener & U32 <- listen_any(32n, 18530)
    +a : U32 <- run_plain(b1)
    b2 : Listener & U32 <- listen_any(32n, 18531)
    +b : U32 <- run_tls(b2)
    b3 : Listener & U32 <- listen_any(32n, 18532)
    +c : U32 <- run_once(b3)
    +total : U32 = (a + b + c : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|3
