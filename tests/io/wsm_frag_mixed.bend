# io (wsm_frag_mixed): a whole data message that arrives while a
# fragment is still open must not be delivered (task-042 phase 1, the
# InMsg arm of the loop).
#
# RFC 6455 section 5.4: after an opening fragment (fin=0) every data
# frame until the final one must be a continuation (op 0). The frame
# decoder answers a complete data frame as InMsg, so the interleaved
# message never reaches the reassembly fold, which does own that rule
# (wsm_frag_got -> Fail 400 "mixed fragment"). The loop used to hand the
# message to the handler and drop the open fragment in silence; it now
# raises the same 400 the fold raises, and the session fails closed.
#
# The peer writes the opening fragment, pauses (so the server has parked
# in recv and the two frames cannot coalesce), then writes a complete
# TEXT(fin=1,"yo") of its own. A delivered message scores 0; the closed
# session scores 1.
#
# Score: 1 when the second frame is refused (read fails), golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/wsm.bend as WSM

def PORT() -> U32:
  19594

# Milliseconds between the opening fragment and the interleaved message:
# on the loopback the server is parked in recv by then, so this only
# keeps the two writes in separate segments.
def SYNC_MS() -> U32:
  100

def CLI_PATH() -> String:
  "/chat"

def CLI_KEY() -> String:
  "dGhlIHNhbXBsZSBub25jZQ=="

# Pinned mask key: this peer builds its frames by hand, so the key is
# fixed instead of drawn from the entropy pool.
def FX_KEY() -> WSM.WSMask:
  WSM.WSMask{1, 2, 3, 4}

def TEXT_HEAD() -> List<&2, U32>:
  [104, 101]

# A complete message of its own: the interleave that must be refused.
def TEXT_WHOLE() -> List<&2, U32>:
  [121, 111]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Print the score and stop the run: the forked server parks in accept, so
# every server_on test exits through IO.die (code 0, no extra line).
def cli_dead(s: Socket, score: U32) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- Socket.close(s)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return z

# A step before the socket exists (dial or head builder failed): print
# the failing score so the golden diff shows it, then stop.
def cli_none() -> IO(Unit):
  do IO<Unit>:
    w : Unit <- IO.print("0")
    z : Unit <- IO.die(Unit, 0, "")
    return z

# The interleaved message is out. A reply means it was delivered; a read
# failure means the session refused it and closed, which is the answer
# this test wants.
def cli_reply(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Unit):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli_dead(s, 1)
    case Done{t}:
      cli_dead(s, 0)

# The interleaved message is out: read the answer.
def cli_second_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_client_framed_plain(s, [])
        cli_reply(m2)

# The opening fragment is out: pause, then interleave a whole message.
def cli_pause(s: Socket) -> IO(Unit):
  do IO<Unit>:
    w : Unit <- IO.sleep(SYNC_MS())
    two : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(True{}, 1, TEXT_WHOLE(), FX_KEY()))
    m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, two)
    cli_second_sent(m)

def cli_first_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      cli_pause(s)

# Upgrade accepted: open the fragmented message.
def cli_send_first(s: Socket) -> IO(Unit):
  do IO<Unit>:
    one : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(False{}, 1, TEXT_HEAD(), FX_KEY()))
    m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, one)
    cli_first_sent(m)

# The 101 head arrived; only a validated upgrade moves on.
def cli_hs_ok(s: Socket, ok: U32) -> IO(Unit):
  match ok:
    case 1:
      cli_send_first(s)
    case _:
      cli_dead(s, 0)

def cli_hs(m: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{resp}:
      cli_hs_ok(s, b2u(String.contains(resp, "101")))

# The upgrade request is out: read the head.
def cli_hs_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        cli_hs(got)

def cli_open(conn: Result<&1, &1, U32 & String, Socket>, req_txt: String) -> IO(Unit):
  match conn:
    case Fail{e}:
      cli_none()
    case Done{sock}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        cli_hs_sent(m)

def cli_start(host: String, port: U32, req: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match req:
    case Fail{e}:
      cli_none()
    case Done{req_txt}:
      do IO<Unit>:
        conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
        cli_open(conn, req_txt)

# Server: echo every data message, answer controls, close on close. The
# interleaved message never reaches EvMsg once the loop refuses it.
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

def run(l: Listener, +port: U32) -> IO(Unit):
  do IO<Unit>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    done : Unit <- cli_start("127.0.0.1", port, WSM.wsm_client_head("127.0.0.1", port, CLI_PATH(), CLI_KEY()))
    z : Unit <- IO.die(Unit, 0, "")
    return z

def run_bound(b: Listener & U32) -> IO(Unit):
  (l, port) = b
  run(l, port)

def main() -> IO(Unit):
  do IO<Unit>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|1
