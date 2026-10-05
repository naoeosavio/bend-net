# lib (wsm_server_on): WSM.server_on — generic persistent server over
# TLS. The handler echoes text (OutRaw{[]} on open/ping policy like
# WS). One client_echo_insecure drives handshake + one frame; golden 1.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/wsm.bend as WSM

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law h.echo:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.echo(ev):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSText{text}})
        case WSM.WSBin{data}:
          IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSBin{data}})
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close(pay))
    case WSM.EvError{code, msg}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    z : Unit <- WSM.server_on(~h.echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

law echo_ok:
  for r: Result<&1, &1, U32 & String, String>
  U32

def echo_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, "Hi"))

law listen_retry:
  for port: U32
  for r: Result<&1, &1, U32 & String, Listener>
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
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r : Result<&1, &1, U32 & String, String> <- WSM.client_echo_insecure("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    +a : U32 = echo_ok(r)
    r2 : Result<&1, &1, U32 & String, String> <- WSM.client_echo_insecure("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    +total : U32 = (a * echo_ok(r2) : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19691)
    main_go(b)

#|1
