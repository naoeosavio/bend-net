# io (wsm_bulk_frame): one 128 KB binary WebSocket frame over the
# loopback, both directions. The client (client_on_plain) sends the
# pattern in a single WSBin message; the server (server_on_plain) echoes
# it; the client checks the echo. 131072 bytes = 16 recvs of 8192, so the
# frame spans many reads on both sides.
#
# This is the wsm_fill lane: it used to append every recv onto a growing
# buffer (List.append(buf, bs)) and re-split the whole buffer from the
# head, which is O(n) per recv and linear-recursive past ~48 KB -- the
# interp machine stack overflowed. The chunks now ride consed and the
# buffer is flattened and split once, when the missing bytes arrive.
#
# The pattern is position-dependent (byte i is i mod 251), so the same
# bulk def builds the expected prefix on either side. Score: length x100
# + prefix x10 + checksum; golden 111.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/wsm.bend as WSM

def BULK_LEN() -> U32:
  131072

def BULK_PREFIX() -> U32:
  1024

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bulk_go(+n: Nat, +i: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      bulk_go(p, Nat.add(i, 1n), U32.from_nat(Nat.mod(i, 251n)) <> acc)

def bulk(+n: Nat) -> List<&2, U32>:
  HTTPX.x_cat(bulk_go(n, 0n, Nil{}))

def pattern_sum_go(+n: Nat, +i: Nat, +acc: U32) -> U32:
  match n:
    case 0n:
      acc
    case 1n+p:
      pattern_sum_go(p, Nat.add(i, 1n), U32.add(acc, U32.from_nat(Nat.mod(i, 251n))))

def pattern_sum(+n: Nat) -> U32:
  pattern_sum_go(n, 0n, 0)

def body_sum(+bs: List<&2, U32>, +acc: U32) -> U32:
  match bs:
    case Nil{}:
      acc
    case b <> t:
      body_sum(t, U32.add(acc, b))

def bulk_score(+body: List<&2, U32>) -> U32:
  +len_ok = b2u(U32.is_eq(HTTPX.x_len32(body), BULK_LEN()))
  +pre_ok = HTTPX.x_eq(HTTPX.x_take32(BULK_PREFIX(), body), bulk(U32.to_nat(BULK_PREFIX())))
  +sum_ok = b2u(U32.is_eq(body_sum(body, 0), pattern_sum(U32.to_nat(BULK_LEN()))))
  U32.add(U32.add(U32.mul(len_ok, 100), U32.mul(pre_ok, 10)), sum_ok)

# Server: echo every message back (text or binary), answer controls.
def h.srv(ev: WSM.WSEv) -> IO(WSM.WSOut):
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

# Client: send the 128 KB frame on open, score the echo, then close.
def cl_check(+data: List<&2, U32>) -> IO(WSM.WSOut):
  do IO<WSM.WSOut>:
    total : U32 = bulk_score(data)
    w : Unit <- IO.print(U32.show(total))
    return WSM.wsm_out_close([])

def h.cl(ev: WSM.WSEv) -> IO(WSM.WSOut):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSBin{bulk(U32.to_nat(BULK_LEN()))}})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          IO.pure(WSM.WSOut, WSM.wsm_out_close([]))
        case WSM.WSBin{+data}:
          cl_check(data)
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvError{code, msg}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})

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

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    z : Unit <- WSM.server_on_plain(~h.srv, l)
    return z

def run(l: Listener, port: U32) -> IO(Unit):
  do IO<Unit>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    done : Unit <- WSM.client_on_plain(~h.cl, "127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return z

def run_bound(b: Listener & U32) -> IO(Unit):
  (l, port) = b
  run(l, port)

def main() -> IO(Unit):
  do IO<Unit>:
    b : Listener & U32 <- listen_any(32n, 19590)
    run_bound(b)

#|111
