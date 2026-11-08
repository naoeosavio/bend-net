# io (httpx_h2_send_len): the length-passing frame write of task-065.
#
# x_frame_write walked the payload for its length on every steady DATA
# frame, while the pump already held that length in `ful`. x_frame_write_len
# takes the length from the caller, and x_send_frame_len carries it to the
# wire; x_frame_write stays as the walk for the callers that do not know it.
# The chunker passes `chunk` (x_chunk_of over ful), which equals the length
# of the part it sends: the whole head when the windows cover it, a take of
# it otherwise.
#
# Score: one point per check, golden 24.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def build_go(+n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      build_go(p, (i + 1 : U32), U32.and(i, 255) <> acc)

def build(+n: U32) -> List<&2, U32>:
  build_go(U32.to_nat(n), 0, Nil{})

# The three length bytes of one frame decode back to the passed length.
def hdr_ok(+len: U32) -> U32:
  +hdr : List<&2, U32> = HTTP2.x_frame_write.hdr(len, 0, 0, 1)
  b2u(Bool.and(U32.is_eq(HTTP.x_len32(hdr), 9), U32.is_eq(HTTP.x_len32(HTTP.x_drop32(6, hdr)), 3)))

def len_bytes_ok(+len: U32) -> U32:
  +f : List<&2, U32> = HTTP2.x_frame_write_len(0, 0, 1, build(len), len)
  b2u(U32.is_eq(HTTP.x_len32(f), (len + 9 : U32)))

# The explicit length answers the same bytes as the walk.
def equiv_ok(+n: U32) -> U32:
  +pay : List<&2, U32> = build(n)
  b2u(U32.is_eq(HTTP.x_eq(HTTP2.x_frame_write(0, 0, 1, pay), HTTP2.x_frame_write_len(0, 0, 1, pay, HTTP.x_len32(pay))), 1))

# The steady part carries `chunk` bytes: whole head when covered, take else.
def part_ok(+h: List<&2, U32>, +ful: U32, +chunk: U32) -> U32:
  +full : Bool = U32.is_eq(chunk, ful)
  +part : List<&2, U32> = HTTP2.x_flow_part(full, chunk, h)
  b2u(Bool.and(U32.is_eq(HTTP.x_len32(part), chunk), U32.is_eq(HTTP2.x_chunk_of(65535, 65535, ful), ful)))

def rest_true_ok() -> U32:
  b2u(List.is_empty(&2, List<&2, U32>, HTTP2.x_flow_rest(True{}, 10, build(10), Nil{})))

def rest_false_go(+r: List<&2, List<&2, U32>>) -> U32:
  match r:
    case Nil{}:
      0
    case +h <> t:
      b2u(U32.is_eq(HTTP.x_len32(h), 6))

def rest_false_ok() -> U32:
  rest_false_go(HTTP2.x_flow_rest(False{}, 4, build(10), Nil{}))

# Pre-framing saves nine cells only: the consed header answers the same
# nine bytes as the header list the append copies.
def framed_hdr_ok(+len: U32) -> U32:
  +hdr : List<&2, U32> = HTTP2.x_frame_write.hdr(len, 0, 0, 0)
  +consed : List<&2, U32> = U32.and(U32.shrn(len, 16n), 255) <> U32.and(U32.shrn(len, 8n), 255) <> U32.and(len, 255) <> 0 <> 0 <> 0 <> 0 <> 0 <> 0 <> Nil{}
  b2u(U32.is_eq(HTTP.x_eq(hdr, consed), 1))

# The facade keeps its own copy of the frame write: the bytes must stay
# identical, or the two lanes diverge on the wire.
def facade_equiv_ok(+n: U32) -> U32:
  +pay : List<&2, U32> = build(n)
  b2u(U32.is_eq(HTTP.x_eq(HTTP2.x_frame_write(0, 0, 1, pay), HTTPX.x_frame_write(0, 0, 1, pay)), 1))

def main() -> IO(U32):
  do IO<U32>:
    a : U32 = hdr_ok(0)
    b : U32 = hdr_ok(1)
    c : U32 = hdr_ok(HTTP2.x_max_send())
    d : U32 = len_bytes_ok(0)
    e : U32 = len_bytes_ok(1)
    f : U32 = len_bytes_ok(1000)
    g : U32 = len_bytes_ok(HTTP2.x_max_send())
    h : U32 = equiv_ok(0)
    i : U32 = equiv_ok(1)
    j : U32 = equiv_ok(1000)
    k : U32 = equiv_ok(HTTP2.x_max_send())
    l : U32 = part_ok(build(10), 10, 10)
    m : U32 = part_ok(build(10), 10, 4)
    n : U32 = part_ok(build(HTTP2.x_max_send()), HTTP2.x_max_send(), HTTP2.x_max_send())
    o : U32 = part_ok(build(HTTP2.x_max_send()), HTTP2.x_max_send(), 4000)
    p : U32 = b2u(U32.is_eq(HTTP2.x_chunk_of(50, 65535, HTTP2.x_max_send()), 50))
    q : U32 = b2u(U32.is_eq(HTTP2.x_chunk_of(65535, 65535, 1000), 1000))
    r : U32 = b2u(U32.is_eq(HTTP.x_len32(HTTP2.x_frame_write_len(0, 0, 1, build(16384), 16384)), 16393))
    s : U32 = b2u(U32.is_eq(HTTP.x_eq(HTTP2.x_frame_write(0, 8, 3, [1, 2, 3]), HTTP2.x_frame_write_len(0, 8, 3, [1, 2, 3], 3)), 1))
    t : U32 = b2u(U32.is_eq(HTTP.x_len32(HTTP2.x_frame_write_len(0, 0, 1, Nil{}, 0)), 9))
    u : U32 = b2u(Bool.not(U32.is_eq(HTTP.x_len32(HTTP2.x_frame_write_len(0, 0, 1, build(10), 10)), HTTP.x_len32(build(10)))))
    v : U32 = b2u(U32.is_eq(HTTP2.x_frame.len3(0, 64, 0), 16384))
    w : U32 = rest_true_ok()
    x : U32 = rest_false_ok()
    y2 : U32 = framed_hdr_ok(0)
    z2 : U32 = framed_hdr_ok(16384)
    a3 : U32 = facade_equiv_ok(0)
    b3 : U32 = facade_equiv_ok(1000)
    +total : U32 = (a + b + c + d + e + f + g + h + i + j + k + l + m + n + o + p + q + r + s + t + u + v + w + x + y2 + z2 + a3 + b3 : U32)
    y : Unit <- IO.print(U32.show(total))
    return total

#|28
