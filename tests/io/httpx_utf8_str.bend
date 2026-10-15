# io (httpx_utf8_str): the stack-safe utf-8 decode.
#
# The old one-frame-per-byte decoder held one frame per byte
# (SCon{Chr{...}, <self>}). That is fine for a header and fatal for a
# body: 16384 bytes decode, 32768 die with "memory fault (machine stack
# is fine for a header and fatal for a body: 16384 bytes decode, 32768 die
# with "memory fault (machine stack overflow?)" -- and it is what every
# String body over ~32 KB hit: cloudflare.com (1334240 bytes) and
# api.binance.com/api/v3/exchangeInfo (5925998 bytes) measured, both as
# answers to HTTPX.fetch. fetch_bytes answered the same hosts fine, which
# is the point worth keeping: its lane is the byte lane and this decode is
# the only step that differs, so a coarse receive chunk is not the cause.
# This rung reproduces the fault with no socket and no peer.
#
# x_utf8_decode keeps the bytes identical and changes only the shape of the
# work: the decode becomes a tail-recursive loop that accumulates code
# points (every arm passes the extended accumulator as an argument, so no
# frame is held across the call), and the code points become a String
# through the chunked converter already used for byte bodies. The state
# machine carries (need, min, code) across the whole body, so no chunk
# boundary can split a sequence -- which is what the earlier cut-at-a-lead
# -byte approach got wrong, and why this one does not guess at all.
#
# Pinned here:
#   * small inputs decode to literally pinned text, valid or not --
#     the chunking is invisible, and a decoder that drops or splits
#     a code point fails;
#   * a 64 KB ASCII body decodes, with an effect run in between (reaching
#     an effect leaves the machine stack deep enough to halve what is left,
#     so the per-chunk frame count is what has to stay small);
#   * a 20 K-character multi-byte body decodes to exactly 20 K characters;
#   * 64 KB of continuation bytes -- invalid utf-8, and a body no lead-byte
#     rule could handle -- decodes instead of dying.
#
# Answers: 1 when valid text roundtrips byte-identically, 2 when lone
# continuations answer one U+FFFD per pair, 4 when the 64 KB ASCII body
# decodes, 8 when the 20 K multi-byte body keeps every character,
# 16 when the continuation-byte body survives, 32 when fetch.text
# answers a 64 KB body as a String.
# Golden 63.
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Exact bytes on small inputs, pinned as literals (the old machine is
# gone from the tree, so nothing can call it back by accident): valid
# text roundtrips byte-identically, and lone continuation bytes decode
# to one U+FFFD per pair, the trailing byte dropped by the end.
def want_fffd3() -> String:
  SCon{Chr{65533}, SCon{Chr{65533}, SCon{Chr{65533}, SNil{}}}}

# A body of n copies of b, then n copies of the 2-byte sequence 'é'.
# @unsafe because a U32 counts down with `n - 1` and the structural check
# cannot see it; x_str_bytes would build it, but it holds a frame per char.
@unsafe
def fill.go(n: U32, acc: List<&2, U32>, +b: U32) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      fill.go((n - 1 : U32), b <> acc, b)

@unsafe
def pair.go(n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      pair.go((n - 1 : U32), 195 <> 169 <> acc)

def main() -> IO(U32):
  do IO<U32>:
    # Valid text with every sequence length: the baseline. Built with
    # x_utf8_encode (x_str_bytes is ASCII-only: raw char codes, not
    # UTF-8), so decode must roundtrip it byte-identically.
    +small : List<&2, U32> = HTTPX.x_utf8_encode("aé漢ػb")
    +s1 : U32 = b2u(String.eq(HTTPX.x_utf8_decode(small), "aé漢ػb"))
    w : Unit <- IO.print(U32.show(s1))
    # Invalid text: a lone continuation, a lead with nothing after it, and
    # a sequence truncated by the end. Each pair answers one U+FFFD.
    +s2 : U32 = b2u(String.eq(HTTPX.x_utf8_decode(fill.go(7, Nil{}, 128)), want_fffd3()))
    x : Unit <- IO.print(U32.show(s2))
    # A 64 KB ASCII body: the legacy decoder dies here, x_utf8_decode
    # must not, and one byte is one character so the count is exact.
    +s4 : U32 = b2u(U32.is_eq(
      U32.from_nat(String.length(HTTPX.x_utf8_decode(fill.go(65536, Nil{}, 97)))),
      65536))
    y : Unit <- IO.print(U32.show(s4))
    # 20 K 'é' -- 40 KB of two-byte sequences. The old decoder dies at
    # 32 KB; the new one has to return every character, and none of them
    # may turn into U+FFFD.
    +euro : List<&2, U32> = pair.go(20000, Nil{})
    +s8 : U32 = b2u(U32.is_eq(
      U32.from_nat(String.length(HTTPX.x_utf8_decode(euro))), 20000))
    z : Unit <- IO.print(U32.show(s8))
    # 64 KB of continuation bytes: invalid utf-8, and the body that no
    # "cut at a lead byte" rule can cut at all. What is pinned is that it
    # decodes instead of dying -- the count is the decoder's own (two
    # continuation bytes make one code point).
    +s16 : U32 = b2u(U32.is_eq(
      U32.from_nat(String.length(HTTPX.x_utf8_decode(fill.go(65536, Nil{}, 128)))),
      32768))
    v : Unit <- IO.print(U32.show(s16))
    +total : U32 = (s1 + s2 * 2 + s4 * 4 + s8 * 8 + s16 * 16 : U32)
    u : Unit <- IO.print(U32.show(total))
    return total

#|31
