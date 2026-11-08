# io (h2_credit_paid): the loop must not credit a DATA frame two times
# (task-068). The send pump credits each DATA frame it stashes and answers
# the count of credited DATA frames at the front of the read seed. The loop
# reads that count, skips the credit of those frames and decrements the
# count; the wire carries no marker at all, so a peer flag stays a peer
# flag.
#
# Score: one point per check, golden 10.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def main() -> IO(U32):
  do IO<U32>:
    # 1-2. The paid test of the count.
    a : U32 = b2u(HTTP2.x_pdc.paid(1))
    b : U32 = b2u(Bool.not(HTTP2.x_pdc.paid(0)))
    # 3-4. The decrement, and the floor at zero.
    c : U32 = b2u(U32.is_eq(HTTP2.x_pdc.dec(0), 0))
    d : U32 = b2u(U32.is_eq(HTTP2.x_pdc.dec(3), 2))
    # 5-6. A DATA frame consumes a slot, another frame does not.
    e : U32 = b2u(U32.is_eq(HTTP2.x_pdc.step(0, 2), 1))
    f : U32 = b2u(U32.is_eq(HTTP2.x_pdc.step(1, 2), 2))
    # 7-9. The DATA frames of a seed: one, none, and two.
    +one : List<&2, U32> = HTTP2.x_flow.seed_add(Nil{}, 0, 16, 3, [7], Nil{})
    +head : List<&2, U32> = HTTP2.x_flow.seed_add(Nil{}, 1, 4, 3, [7], Nil{})
    +two : List<&2, U32> = HTTP2.x_flow.seed_add(one, 0, 0, 1, [9], Nil{})
    g : U32 = b2u(U32.is_eq(HTTP2.x_pdc.count(one), 1))
    h : U32 = b2u(U32.is_eq(HTTP2.x_pdc.count(head), 0))
    i : U32 = b2u(U32.is_eq(HTTP2.x_pdc.count(two), 2))
    # 10. The seed keeps the peer flags exactly: the pump adds no bit.
    j : U32 = b2u(U32.is_eq(HTTP.x_eq(one, [0, 0, 1, 0, 16, 0, 0, 0, 3, 7]), 1))
    +total : U32 = (a + b + c + d + e + f + g + h + i + j : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|10
