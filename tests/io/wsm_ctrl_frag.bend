# io (wsm_ctrl_frag): a control frame between two fragments of one
# message must not drop the reassembly accumulator (task-042 phase 0,
# bug 1 of the audit).
#
# The peer is a raw socket that speaks the protocol by hand: after the
# upgrade it writes a masked TEXT(fin=0,"he"), waits for the pong of a
# masked PING("p"), then writes a masked CONT(fin=1,"llo"). The session
# must answer PONG "p" and then echo the stitched "hello" on the SAME
# connection.
#
# The three frames ride three separate writes, and the pong is read
# before the continuation is written, so the test cannot fall into the
# neighboring bug its sibling file covers (bytes buffered past a
# fragment are dropped by the loop) and really isolates the accumulator
# loss. The sleep after the opening fragment keeps the first two frames
# from coalescing in the kernel.
#
# Every frame comes from the library's own masked writer
# (WSM.wsm_show_masked_key with a pinned key), so the peer never
# re-implements the codec.
#
# Score: pong x echo, golden 1. While wsm_loop hands FragIdle to the
# control arms, the continuation reaches the idle accumulator, fails 400
# "not data" and the session closes: the second read fails and the score
# is 0.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/http.bend as HTTP
import ../../lib/wsm.bend as WSM

def PORT() -> U32:
  19591

# Milliseconds between the opening fragment and the control frame: on
# the loopback the server is already parked in recv, so this only keeps
# the two writes in separate segments.
def SYNC_MS() -> U32:
  100

def CLI_PATH() -> String:
  "/chat"

def CLI_KEY() -> String:
  "dGhlIHNhbXBsZSBub25jZQ=="

# Pinned mask key: this peer builds its frames by hand, so the key is
# fixed instead of drawn from the entropy pool (the library's
# wsm_show_masked_random is the other half of the same surface).
def FX_KEY() -> WSM.WSMask:
  WSM.WSMask{1, 2, 3, 4}

def TEXT_HEAD() -> List<&2, U32>:
  [104, 101]

def TEXT_TAIL() -> List<&2, U32>:
  [108, 108, 111]

def TEXT_ALL() -> List<&2, U32>:
  List.append(&2, U32, TEXT_HEAD(), TEXT_TAIL())

def PING_PAY() -> List<&2, U32>:
  [112]

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

# Second reply: the echo of the stitched message. Score = pong x echo.
def cli_echo(pong: U32, m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Unit):
  (s2, r, rest) = m
  match r:
    case Fail{e}:
      cli_dead(s2, 0)
    case Done{t}:
      (fin, op, pay) = t
      echo : U32 = U32.mul(b2u(U32.is_eq(op, 1)), HTTP.x_eq(pay, TEXT_ALL()))
      cli_dead(s2, U32.mul(pong, echo))

# The continuation is out: read the echo.
def cli_cont_sent(pong: U32, m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_client_framed_plain(s, [])
        cli_echo(pong, m2)

# The pong arrived: write the continuation that closes the message.
def cli_cont(pong: U32, s: Socket) -> IO(Unit):
  do IO<Unit>:
    thr : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(True{}, 0, TEXT_TAIL(), FX_KEY()))
    m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, thr)
    cli_cont_sent(pong, m)

# First reply: the pong the loop owes the mid-message ping.
def cli_pong_ok(s: Socket, op: U32, pay: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    pong : U32 = U32.mul(b2u(U32.is_eq(op, 10)), HTTP.x_eq(pay, PING_PAY()))
    cli_cont(pong, s)

def cli_pong(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Unit):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{t}:
      (fin, op, pay) = t
      cli_pong_ok(s, op, pay)

# The ping is out: read the pong before writing the continuation.
def cli_ping_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_client_framed_plain(s, [])
        cli_pong(m2)

# The opening fragment is out: pause, then inject the ping.
def cli_open_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        w : Unit <- IO.sleep(SYNC_MS())
        two : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(True{}, 9, PING_PAY(), FX_KEY()))
        m2 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, two)
        cli_ping_sent(m2)

# Upgrade accepted: open the fragmented message.
def cli_send_open(s: Socket) -> IO(Unit):
  do IO<Unit>:
    one : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(False{}, 1, TEXT_HEAD(), FX_KEY()))
    m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, one)
    cli_open_sent(m)

# The 101 head arrived; only a validated upgrade moves on.
def cli_hs_ok(s: Socket, ok: U32) -> IO(Unit):
  match ok:
    case 1:
      cli_send_open(s)
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

# Server: echo every data message, answer controls, close on close.
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
