# io (httpx_h2_credit_rate): the count of WINDOW_UPDATE frames and TLS
# writes per MiB of received body (task-063 phase 6c).
#
# The count of writes is a pure property of the credit step: one step
# answers at most one byte list, and the loop writes that list once. So
# this test runs the step leaves over a body and counts the two numbers
# the wire cannot show: the frames and the writes.
#
# Case A is one stream and 1 MiB in 64 DATA frames of 16384 bytes. The
# batch flushes the pair every two frames: 32 writes and 63 frames, 32
# on the connection and 31 on the stream (the last frame ends the body,
# so it sends the connection remainder alone).
#
# Case B is the multi-stream shape that a per-stream threshold alone
# misses: four frames of 16384 on four streams leave every stream
# pending below the half window, so only the connection counter can
# answer. It flushes 2 connection frames and no stream frame.
#
# Checks: 32 writes, 63 frames, the connection pending 0 after the body,
# the stream entry pruned at the end, 2 writes on case B, 2 frames, the
# connection pending 0, and every stream pending still 16384. Golden 8.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

# The body size, its frame size and the frame count of case A.
def BODY() -> U32:
  1048576

def FULL() -> U32:
  16384

def FRAMES() -> Nat:
  64n

# The bytes of one WINDOW_UPDATE frame: the 9-byte header and the
# 4-byte increment.
def WU_LEN() -> U32:
  13

# What the batch writes for 1 MiB: one write every two frames, and the
# connection frame of the pair plus the remainder of the last frame.
def WANT_WRITES() -> U32:
  32

def WANT_FRAMES() -> U32:
  63

# What case B writes: the connection crosses the half window twice.
def ROT_WRITES() -> U32:
  2

def ROT_FRAMES() -> U32:
  2

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

# One write for a step that has bytes to send, zero for an empty step.
def writes_go(is_empty: Bool) -> U32:
  match is_empty:
    case True{}:
      0
    case False{}:
      1

def writes_of(+bytes: List<&2, U32>) -> U32:
  writes_go(List.is_empty(&2, U32, bytes))

# Case A: FRAMES() frames of FULL() bytes on one stream. The last frame
# carries END_STREAM. The loop scores the run when the fuel ends.
def run_go(+n: Nat, +sid: U32, +is_last: Bool, +cpend: U32, +spend: List<&2, HTTP2.Pnd>, +writes: U32, +nb: U32) ->
  U32:
  match n:
    case 0n:
      +s1 : U32 = weigh(U32.is_eq(writes, WANT_WRITES()), 1)
      +s2 : U32 = weigh(U32.is_eq(nb, U32.mul(WANT_FRAMES(), WU_LEN())), 1)
      +s3 : U32 = weigh(U32.is_eq(cpend, 0), 1)
      +s4 : U32 = weigh(U32.is_eq(HTTP2.x_wu.of(spend, sid), 0), 1)
      (s1 + (s2 + (s3 + s4)) : U32)
    case 1n+m:
      +fin : Bool = Bool.and(is_last, Nat.is_eq(m, 0n))
      +w : U32 = writes_of(HTTP2.x_wu.bytes(cpend, spend, sid, FULL(), fin))
      +nb2 : U32 = (nb + HTTP.x_len32(HTTP2.x_wu.bytes(cpend, spend, sid, FULL(), fin)) : U32)
      run_go(m, sid, is_last, HTTP2.x_wu.next_cpend(cpend, FULL(), fin), HTTP2.x_wu.next_spend(spend, sid, FULL(), fin), (writes + w : U32), nb2)

# Case B: one frame on each of the four streams 1, 3, 5 and 7. Every
# stream pending stays below the half window; only the connection
# counter flushes.
def rot_go(+n: Nat, +sid: U32, +cpend: U32, +spend: List<&2, HTTP2.Pnd>, +writes: U32, +nb: U32) ->
  U32:
  match n:
    case 0n:
      +s1 : U32 = weigh(U32.is_eq(writes, ROT_WRITES()), 1)
      +s2 : U32 = weigh(U32.is_eq(nb, U32.mul(ROT_FRAMES(), WU_LEN())), 1)
      +s3 : U32 = weigh(U32.is_eq(cpend, 0), 1)
      +s4 : U32 = weigh(U32.is_eq(HTTP2.x_wu.of(spend, 7), FULL()), 1)
      (s1 + (s2 + (s3 + s4)) : U32)
    case 1n+m:
      +w : U32 = writes_of(HTTP2.x_wu.bytes(cpend, spend, sid, FULL(), False{}))
      +nb2 : U32 = (nb + HTTP.x_len32(HTTP2.x_wu.bytes(cpend, spend, sid, FULL(), False{})) : U32)
      rot_go(m, (sid + 2 : U32), HTTP2.x_wu.next_cpend(cpend, FULL(), False{}), HTTP2.x_wu.next_spend(spend, sid, FULL(), False{}), (writes + w : U32), nb2)

def main() -> IO(Unit):
  do IO<Unit>:
    a : U32 = run_go(FRAMES(), 1, True{}, 0, Nil{}, 0, 0)
    b : U32 = rot_go(4n, 1, 0, Nil{}, 0, 0)
    s : Unit <- IO.print(U32.show((a + b : U32)))
    IO.pure(Unit, s)

# The score: eight checks of the 1 MiB run and the interleaved run.
#|8
