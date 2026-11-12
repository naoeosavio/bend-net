# lib (lib_httpx_rst): RST_STREAM + GOAWAY wire shapes and the control-frame
# class table the 3 server loops and the 3 client drains dispatch on. Pure
# layer, no IO: every control frame type must land on its own class (a loop
# that misroutes one silently drops or doubles a stream), the client must
# ignore a DATA/HEADERS that is not its stream, and the two payload builders
# must be byte-exact. Ported from h2_rst.bend (same intent, mini-H2 class
# numbers) when the old H2 codec was retired; the IO half of the original
# (abort stream 1, finish stream 3, then GOAWAY) is covered behaviourally by
# httpx_client_stream's cancel golden and httpx_concurrent_cont. Golden 1 iff all
# 12 vectors score.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bytes_eq.go(acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      bytes_eq.go(bytes_eq(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

# Server side: the loop reads Got and dispatches on x_cls, with
# cls_fix demoting an already-acked SETTINGS to the skip class.

def cls_go(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      HTTP2.x_cls(typ, sid, flags, payload)

def cls(frame: HTTP.Frame) -> U32:
  cls_go(frame)

def v_rst() -> U32:
  b2u(U32.is_eq(HTTP2.httpx.cls_fix(cls(HTTP.Frame{3, 0, 1, 0, [0, 0, 0, 8]}), 0), 2))

def v_goaway() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{7, 0, 0, 0, [0, 0, 0, 3, 0, 0, 0, 0]}), 5))

def v_ping() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{6, 0, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]}), 4))

def v_settings_ack() -> U32:
  b2u(U32.is_eq(HTTP2.httpx.cls_fix(cls(HTTP.Frame{4, 1, 0, 0, Nil{}}), 1), 0))

def v_cont() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{9, 0, 1, 0, [1, 2, 3]}), 8))

# A control frame that needs a stream id but arrives with 0 is skipped, not
# acted on: RST_STREAM and CONTINUATION on sid 0 are both connection errors.

def v_rst_sid0() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{3, 0, 0, 0, [0, 0, 0, 8]}), 0))

def v_cont_sid0() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{9, 0, 0, 0, [1, 2, 3]}), 0))

# WINDOW_UPDATE: the increment field is exactly 4 bytes and strictly inside
# (0, 2^31); anything else is class 9 = fail-closed 502 (RFC 9113 6.9). The
# length rule came from the h2_rst port: x_wu_ok used to stop after 4 bytes
# and ignore the tail, letting a 5-byte frame through as a valid credit.

def v_wu_ok() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{8, 0, 0, 0, [0, 0, 0, 1]}), 7))

def v_wu_zero() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{8, 0, 0, 0, [0, 0, 0, 0]}), 9))

def v_wu_short() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{8, 0, 0, 0, [0, 0, 1]}), 9))

def v_wu_long() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{8, 0, 0, 0, [0, 0, 0, 1, 0]}), 9))

def v_wu_reserved_bit() -> U32:
  b2u(U32.is_eq(cls(HTTP.Frame{8, 0, 0, 0, [255, 255, 255, 255]}), 9))

# Client side: the drain only treats a stream frame as actionable when the sid
# is the one it opened, so a multiplexed RST of a sibling stays invisible.

def v_mine_rst() -> U32:
  b2u(U32.is_eq(HTTP2.client.route.mine.cls(cls(HTTP.Frame{3, 0, 1, 0, [0, 0, 0, 8]}), 1, 1), 2))

def v_mine_data() -> U32:
  b2u(U32.is_eq(HTTP2.client.route.mine.cls(cls(HTTP.Frame{0, 1, 1, 0, [104, 105]}), 1, 1), 6))

def v_foreign_data() -> U32:
  b2u(U32.is_eq(HTTP2.client.route.mine.cls(cls(HTTP.Frame{0, 1, 3, 0, [104, 105]}), 3, 1), 0))

# A sibling's RST_STREAM is legitimate (node:http2 resets a stream it
# already answered while the request body is still coming; a pushed stream
# is reset freely), so the drain must not act on it: only RST_STREAM for
# the sid it opened is ours. Before TASK-042 phase 5 the sid filter only
# covered DATA/HEADERS and a sibling RST failed the request with a bare
# 502 "rst_stream".
def v_foreign_rst() -> U32:
  b2u(U32.is_eq(HTTP2.client.route.mine.cls(cls(HTTP.Frame{3, 0, 3, 0, [0, 0, 0, 8]}), 3, 1), 0))

# Wire shapes: RST_STREAM carries the 4-byte error code, GOAWAY the last-sid
# then the code (RFC 9113 section 6.8 / 6.9).

def v_rst_pay() -> U32:
  bytes_eq(HTTP.x_be32(8), [0, 0, 0, 8])

def v_goaway_pay() -> U32:
  bytes_eq(HTTP2.x_send_goaway.pay(3, 1), [0, 0, 0, 3, 0, 0, 0, 1])

# Read side of the same two frames (TASK-042 phase 5): the GOAWAY
# last-stream-id is a 31-bit field (R bit is the MSB of the first byte) and
# the error code names the failure, so a Fail can say which error arrived
# and whether the stream was processed at all.

def go_pay() -> List<&2, U32>:
  [0, 0, 0, 3, 0, 0, 0, 0]

def go_r_pay() -> List<&2, U32>:
  [128, 0, 0, 3, 0, 0, 0, 0]

def go_short() -> List<&2, U32>:
  [0, 0, 0, 3]

def v_goaway_last() -> U32:
  (b2u(U32.is_eq(HTTP2.x_goaway.last(go_pay()), 3))
    + b2u(U32.is_eq(HTTP2.x_goaway.last(go_r_pay()), 3))
    + b2u(U32.is_eq(HTTP2.x_goaway.code(go_pay()), 0)) : U32)

# RFC 9113 8.7: above the last-stream-id the stream was not processed (503,
# safe to repeat); at or below it the peer may have acted (502, real).
def v_goaway_verdict() -> U32:
  (b2u(Bool.not(HTTP2.x_goaway.retry(go_pay(), 1)))
    + b2u(HTTP2.x_goaway.retry(go_pay(), 5))
    + b2u(U32.is_eq(HTTP2.x_goaway.status(go_pay(), 1), 502))
    + b2u(U32.is_eq(HTTP2.x_goaway.status(go_pay(), 5), 503)) : U32)

def v_goaway_reason() -> U32:
  b2u(String.eq(HTTP2.x_goaway.reason(go_pay(), 1), "goaway NO_ERROR(0) last=3 sid=1"))

# A GOAWAY shorter than the 8 bytes RFC 9113 6.8 requires is a connection
# error: the reader answers the fail-closed sentinel for the id (no stream
# is above it, so nothing looks safe to repeat) and FRAME_SIZE_ERROR (6).
def v_goaway_short() -> U32:
  (b2u(U32.is_eq(HTTP2.x_goaway.last(go_short()), 4294967295))
    + b2u(U32.is_eq(HTTP2.x_goaway.code(go_short()), 6))
    + b2u(U32.is_eq(HTTP2.x_goaway.status(go_short(), 1), 502))
    + b2u(String.eq(HTTP2.x_goaway.reason(go_short(), 1), "goaway FRAME_SIZE_ERROR(6) short sid=1")) : U32)

# REFUSED_STREAM (7) is the RST_STREAM "I did not process this" signal, the
# same safe-to-repeat verdict a GOAWAY above the sid gives; any other code
# (CANCEL 8 here) is a real failure.
def v_rst_verdict() -> U32:
  (b2u(U32.is_eq(HTTP2.x_rst.code([0, 0, 0, 7]), 7))
    + b2u(HTTP2.x_rst.retry([0, 0, 0, 7]))
    + b2u(U32.is_eq(HTTP2.x_rst.status([0, 0, 0, 7]), 503))
    + b2u(String.eq(HTTP2.x_rst.reason([0, 0, 0, 7]), "rst_stream REFUSED_STREAM(7)"))
    + b2u(Bool.not(HTTP2.x_rst.retry([0, 0, 0, 8])))
    + b2u(U32.is_eq(HTTP2.x_rst.status([0, 0, 0, 8]), 502))
    + b2u(String.eq(HTTP2.x_rst.reason([0, 0, 0, 8]), "rst_stream CANCEL(8)")) : U32)

def v_rst_short() -> U32:
  (b2u(U32.is_eq(HTTP2.x_rst.code([0, 0, 0, 7, 0]), 6))
    + b2u(U32.is_eq(HTTP2.x_rst.status([0, 0, 0, 7, 0]), 502)) : U32)

def v_err_name() -> U32:
  (b2u(String.eq(HTTP2.x_h2_err.name(0), "NO_ERROR"))
    + b2u(String.eq(HTTP2.x_h2_err.name(7), "REFUSED_STREAM"))
    + b2u(String.eq(HTTP2.x_h2_err.name(99), "UNKNOWN"))
    + b2u(String.eq(HTTP2.x_h2_err.text(8), "CANCEL(8)")) : U32)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (v_rst() + v_goaway() + v_ping() + v_settings_ack() + v_cont()
      + v_rst_sid0() + v_cont_sid0() + v_wu_ok() + v_wu_zero() + v_wu_short()
      + v_wu_long() + v_wu_reserved_bit() + v_mine_rst() + v_mine_data()
      + v_foreign_data() + v_rst_pay() + v_goaway_pay() + v_foreign_rst()
      + v_goaway_last() + v_goaway_verdict() + v_goaway_reason()
      + v_goaway_short() + v_rst_verdict() + v_rst_short() + v_err_name() : U32)
    +pass : U32 = b2u(U32.is_eq(total, 43))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
