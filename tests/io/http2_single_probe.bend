# io (httpx_h2_single_probe): the single-frame question stops at the cap
# and at the caller window (task-063 phase 7d and phase 8).
#
# The send picks the one-frame lane when the body fits one DATA frame and
# the caller's connection window covers it. Before phase 8 the question
# walked the whole body with x_len32; x_send_single asks x_has_at_least at
# x_send_probe, a walk bounded by the cap. Before 7d the question ignored
# the window, so the lane wrote a body past the credit it had and the
# window answer wrapped below zero in U32; x_send_probe takes the smaller
# of the cap and the window, so such a body takes the chunk path.
#
# Checks: 0 bytes, exactly x_max_send(), one byte more and 1 MiB with a
# full window; then the window edge at the cap, one byte under it, a body
# past a small window, and an empty body with no credit. Golden 8.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def WIN() -> U32:
  65535

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

@unsafe
def build(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      build(p, 7 <> acc)

def main() -> IO(U32):
  do IO<U32>:
    +cap : U32 = HTTP2.x_max_send()
    +full : List<&2, U32> = build(U32.to_nat(cap), Nil{})
    +over : List<&2, U32> = build(U32.to_nat((cap + 1 : U32)), Nil{})
    +million : List<&2, U32> = build(1048576n, Nil{})
    +small : List<&2, U32> = build(200n, Nil{})
    +under : List<&2, U32> = build(U32.to_nat((cap - 1 : U32)), Nil{})
    +empty_ok : Bool = HTTP2.x_send_single(WIN(), Nil{})
    +cap_ok : Bool = HTTP2.x_send_single(WIN(), full)
    +over_ok : Bool = Bool.not(HTTP2.x_send_single(WIN(), over))
    +million_ok : Bool = Bool.not(HTTP2.x_send_single(WIN(), million))
    +edge_ok : Bool = HTTP2.x_send_single(cap, full)
    +under_ok : Bool = Bool.not(HTTP2.x_send_single((cap - 1 : U32), full))
    +window_ok : Bool = Bool.not(HTTP2.x_send_single(60, small))
    +nocredit_ok : Bool = HTTP2.x_send_single(0, Nil{})
    +score : U32 = U32.add(b2u(empty_ok), U32.add(b2u(cap_ok), U32.add(b2u(over_ok), U32.add(b2u(million_ok), U32.add(b2u(edge_ok), U32.add(b2u(under_ok), U32.add(b2u(window_ok), b2u(nocredit_ok))))))))
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    IO.pure(U32, score)

#|8
