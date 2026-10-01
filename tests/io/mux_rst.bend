# lib (lib_mux_rst): RST_STREAM + GOAWAY wire shapes and the control-frame
# class table the 3 server loops and the 3 client drains dispatch on. Pure
# layer, no IO: every control frame type must land on its own class (a loop
# that misroutes one silently drops or doubles a stream), the client must
# ignore a DATA/HEADERS that is not its stream, and the two payload builders
# must be byte-exact. Ported from h2_rst.bend (same intent, mini-H2 class
# numbers) when the http2.bend codec was retired; the IO half of the original
# (abort stream 1, finish stream 3, then GOAWAY) is covered behaviourally by
# mux_client_stream's cancel golden and mux_concurrent_cont. Golden 1 iff all
# 12 vectors score.
import Base
import ../../lib/httpx.bend as HTTPX

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

# Server side: the loop reads Got and dispatches on x_classify, with
# cls_fix demoting an already-acked SETTINGS to the skip class.

def v_rst() -> U32:
  b2u(U32.is_eq(HTTPX.httpx.cls_fix(HTTPX.x_classify(HTTPX.Frame{3, 0, 1, [0, 0, 0, 8]}), 0), 2))

def v_goaway() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{7, 0, 0, [0, 0, 0, 3, 0, 0, 0, 0]}), 5))

def v_ping() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{6, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]}), 4))

def v_settings_ack() -> U32:
  b2u(U32.is_eq(HTTPX.httpx.cls_fix(HTTPX.x_classify(HTTPX.Frame{4, 1, 0, Nil{}}), 1), 0))

def v_cont() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{9, 0, 1, [1, 2, 3]}), 8))

# A control frame that needs a stream id but arrives with 0 is skipped, not
# acted on: RST_STREAM and CONTINUATION on sid 0 are both connection errors.

def v_rst_sid0() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{3, 0, 0, [0, 0, 0, 8]}), 0))

def v_cont_sid0() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{9, 0, 0, [1, 2, 3]}), 0))

# WINDOW_UPDATE: the increment field is exactly 4 bytes and strictly inside
# (0, 2^31); anything else is class 9 = fail-closed 502 (RFC 9113 6.9). The
# length rule came from the h2_rst port: x_wu_ok used to stop after 4 bytes
# and ignore the tail, letting a 5-byte frame through as a valid credit.

def v_wu_ok() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{8, 0, 0, [0, 0, 0, 1]}), 7))

def v_wu_zero() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{8, 0, 0, [0, 0, 0, 0]}), 9))

def v_wu_short() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{8, 0, 0, [0, 0, 1]}), 9))

def v_wu_long() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{8, 0, 0, [0, 0, 0, 1, 0]}), 9))

def v_wu_reserved_bit() -> U32:
  b2u(U32.is_eq(HTTPX.x_classify(HTTPX.Frame{8, 0, 0, [255, 255, 255, 255]}), 9))

# Client side: the drain only treats a stream frame as actionable when the sid
# is the one it opened, so a multiplexed RST of a sibling stays invisible.

def v_mine_rst() -> U32:
  b2u(U32.is_eq(HTTPX.client_on.mine_cls(HTTPX.x_classify(HTTPX.Frame{3, 0, 1, [0, 0, 0, 8]}), 1, 1), 2))

def v_mine_data() -> U32:
  b2u(U32.is_eq(HTTPX.client_on.mine_cls(HTTPX.x_classify(HTTPX.Frame{0, 1, 1, [104, 105]}), 1, 1), 6))

def v_foreign_data() -> U32:
  b2u(U32.is_eq(HTTPX.client_on.mine_cls(HTTPX.x_classify(HTTPX.Frame{0, 1, 3, [104, 105]}), 3, 1), 0))

# Wire shapes: RST_STREAM carries the 4-byte error code, GOAWAY the last-sid
# then the code (RFC 9113 section 6.8 / 6.9).

def v_rst_pay() -> U32:
  bytes_eq(HTTPX.x_be32(8), [0, 0, 0, 8])

def v_goaway_pay() -> U32:
  bytes_eq(HTTPX.x_send_goaway.pay(3, 1), [0, 0, 0, 3, 0, 0, 0, 1])

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (v_rst() + v_goaway() + v_ping() + v_settings_ack() + v_cont()
      + v_rst_sid0() + v_cont_sid0() + v_wu_ok() + v_wu_zero() + v_wu_short()
      + v_wu_long() + v_wu_reserved_bit() + v_mine_rst() + v_mine_data()
      + v_foreign_data() + v_rst_pay() + v_goaway_pay() : U32)
    +pass : U32 = b2u(U32.is_eq(total, 17))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
