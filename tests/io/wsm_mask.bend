# lib (lib_wsm_mask): Phase 7 client masking key + one-shot echo policy.
# RFC 6455 section 5.3 asks every client frame for a masking key from a
# strong entropy source; the library used the constant 1,2,3,4 on all
# eight client send paths. The key now rides IO.random_u32 (getrandom /
# arc4random), and this test pins:
#   - the pure key packing (two draws -> four key bytes, fail-closed
#     fallback) and that the packed key is the one on the wire;
#   - that two draws for the same payload do NOT produce the same frame
#     (a fixed key makes this check fail);
#   - the one-shot echo policy: text/binary/close echo, ping answers a
#     pong, a fragment or an unsolicited pong closes (they used to put
#     op 0 / op 10 on the wire).
import Base
import ../../lib/wsm.bend as WSM

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def same(a: U32, b: U32) -> U32:
  b2u(U32.is_eq(a, b))

# Two draws fill the four key bytes, low byte first (0x12345678 /
# 0xDECDAB89 -> 78 56 34 89); the fallback key only fires when the
# entropy source fails. Match order follows parameter order.
def key_score(m: WSM.WSMask, fallback: Bool) -> U32:
  match m:
    case WSM.WSMask{k0, k1, k2, k3}:
      match fallback:
        case True{}:
          (same(k0, 1) + same(k1, 2) + same(k2, 3) + same(k3, 4) : U32)
        case False{}:
          (same(k0, 120) + same(k1, 86) + same(k2, 52) + same(k3, 221) : U32)

def chk_key_pack() -> U32:
  (key_score(WSM.wsm_mask_key.go(Done{305419896}, Done{3742277141}), False{})
   + key_score(WSM.wsm_mask_key.go(Fail{(1, "no entropy")}, Done{0}), True{}) : U32)

# The wire carries the key we handed in: the same payload masked with
# two different keys gives two frames of the same length with different
# bytes.
def key_frames(m: WSM.WSMask) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  WSM.wsm_show_masked_key(True{}, 1, [104, 105], m)

def frame_len(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Done{bs}:
      U32.from_nat(List.length(&2, U32, bs))
    case Fail{e}:
      0

def frames_differ(
  a: Result<&1, &1, U32 & String, List<&2, U32>>,
  b: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match a b:
    case Done{x} Done{y}:
      b2u(Bool.not(WSM.wsm_eq_bytes(x, y)))
    case _ _:
      0

def chk_key_on_wire() -> U32:
  (b2u(U32.is_eq(frame_len(key_frames(WSM.WSMask{1, 2, 3, 4})), 8))
   + b2u(U32.is_eq(frame_len(key_frames(WSM.WSMask{9, 9, 9, 9})), 8))
   + frames_differ(key_frames(WSM.WSMask{1, 2, 3, 4}), key_frames(WSM.WSMask{9, 9, 9, 9})) : U32)

# Two draws for the same payload must not produce the same frame; with
# the old fixed key this check would be 0.
def chk_key_varies() -> IO(U32):
  do IO<U32>:
    a : Result<&1, &1, U32 & String, List<&2, U32>> <- WSM.wsm_show_masked_random(True{}, 1, [104, 105])
    b : Result<&1, &1, U32 & String, List<&2, U32>> <- WSM.wsm_show_masked_random(True{}, 1, [104, 105])
    return frames_differ(a, b)

# One-shot echo policy: 0 close, 1 echo, 2 answer a ping with a pong;
# a fragment never answers (the one-shot path has no reassembly).
def chk_echo_op() -> U32:
  (same(WSM.wsm_echo_op(True{}, 1), 1)
   + same(WSM.wsm_echo_op(True{}, 2), 1)
   + same(WSM.wsm_echo_op(True{}, 8), 1)
   + same(WSM.wsm_echo_op(True{}, 9), 2)
   + same(WSM.wsm_echo_op(True{}, 0), 0)
   + same(WSM.wsm_echo_op(True{}, 10), 0)
   + same(WSM.wsm_echo_op(True{}, 3), 0)
   + same(WSM.wsm_echo_op(False{}, 1), 0) : U32)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +vary : U32 <- chk_key_varies()
    +total : U32 = (chk_key_pack() + chk_key_on_wire() + chk_echo_op() + vary : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|19
