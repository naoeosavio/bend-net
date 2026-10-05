# lib (wsm_client_coalesce): 101 + first frame coalesced in one TLS write.
# The canned server reads the upgrade, then answers the 101 and an
# unmasked "hello" text frame in a SINGLE tls_send, so both ride one
# TLS record / TCP segment; the client (WSM.client_on_insecure) must
# split head from frame exactly (task-020 phase 0 off-by-3 guard).
# The client prints 1 on the hello echo and closes; the server answers
# the close and shuts. Golden 1. Self-contained loopback: the Node
# peer (examples/wss_hello_server.js) covers the manual matrix.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/wsm.bend as WSM
import ../../lib/tcp.bend as TCP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

# Canned wire bytes: the 101 for the fixed test key plus one unmasked
# "hello" text frame, sent as a single TLS write below.

law canned_101:
  String

def canned_101():
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

law canned_hi:
  List<&2, U32>

def canned_hi():
  [129, 5, 104, 101, 108, 108, 111]

law canned_all:
  List<&2, U32>

def canned_all():
  List.append(&2, U32, WSM.wsm_utf8_encode(canned_101()), canned_hi())

law close_wire:
  List<&2, U32>

def close_wire():
  [136, 0]

# Server side: accept -> read upgrade -> single coalesced write ->
# read client close -> answer close -> shut. One leaf per step.

law srv.sent_close:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  IO(Unit)

def srv.sent_close(m):
  (s, r) = m
  TLS.tls_close(s)

law srv.got_close:
  for m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>
  IO(Unit)

def srv.got_close(m):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{bs}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, close_wire())
        srv.sent_close(m2)

law srv.sent_hi:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  IO(Unit)

def srv.sent_hi(m):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s, 8192)
        srv.got_close(m2)

law srv.got_req:
  for m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>
  IO(Unit)

def srv.got_req(m):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{req}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, canned_all())
        srv.sent_hi(m2)

law srv.accepted:
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  IO(Unit)

def srv.accepted(m):
  (l, r) = m
  match r:
    case Fail{e}:
      Listener.close(l)
    case Done{sock}:
      do IO<Unit>:
        x : Unit <- Listener.close(l)
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 8192)
        srv.got_req(m2)

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    srv.accepted(m)

# Client side: silent on open, print 1 on the hello echo, 0 on anything
# unexpected (stale off-by-3 split lands here as EvError).

law cl.text_go:
  for ok: Bool
  IO(WSM.WSOut)

def cl.text_go(ok):
  match ok:
    case True{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("1")
        return WSM.wsm_out_close([])
    case False{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("0")
        return WSM.wsm_out_close([])

law cl.text:
  for +txt: String
  IO(WSM.WSOut)

def cl.text(txt):
  cl.text_go(String.eq(txt, "hello"))

law cl.bin:
  IO(WSM.WSOut)

def cl.bin():
  do IO<WSM.WSOut>:
    w : Unit <- IO.print("0")
    return WSM.wsm_out_close([])

law cl.err:
  IO(WSM.WSOut)

def cl.err():
  do IO<WSM.WSOut>:
    w : Unit <- IO.print("0")
    return WSM.wsm_out_close([])

law h.cl:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.cl(ev):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          cl.text(text)
        case WSM.WSBin{data}:
          cl.bin()
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close([]))
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvError{code, msg}:
      cl.err()

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
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    done : Unit <- WSM.client_on_insecure(~h.cl, "127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19787)
    main_go(b)

#|1
