# io (httpx_h2_seed_join): the read seed is appended with a tail pass
# (task-063 phase 7d).
#
# The flow pump keeps the frames it read while a big answer waited for
# credit in a read seed, and the seed grows to one whole upload (64 KiB on
# each of two streams). The old List.append recursed on its first list, so
# that seed killed the process with a machine stack overflow (measured on
# the two-stream cell: one 64 KiB upload stashed during a 64 KiB answer).
# x_flow_join reverses the seed and pushes it onto the tail: two tail
# passes, the same bytes.
#
# Checks: the empty seed, the small order, the 131072-byte length and the
# boundary between seed and tail, golden 4.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def SEED_N() -> U32:
  100000

def TAIL_N() -> U32:
  31072

def SEED_B() -> U32:
  7

def TAIL_B() -> U32:
  9

# Tail builder: n copies of b.
@unsafe
def fill_go(n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

# Tail count.
def len_go(+xs: List<&2, U32>, acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case h <> t:
      len_go(t, (acc + 1 : U32))

def count(xs: List<&2, U32>) -> U32:
  len_go(xs, 0)

# Tail check: every byte holds b.
def all_go(+xs: List<&2, U32>, +b: U32, ok: Bool) -> Bool:
  match xs:
    case Nil{}:
      ok
    case h <> t:
      all_go(t, b, Bool.and(ok, U32.is_eq(h, b)))

def all(xs: List<&2, U32>, +b: U32) -> Bool:
  all_go(xs, b, True{})

# Structural equality on short lists.
def eq_go(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case h1 <> t1 h2 <> t2:
      Bool.and(U32.is_eq(h1, h2), eq_go(t1, t2))
    case _ _:
      False{}

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Checks: 1 empty, 2 small order, 3 big length, 4 boundary intact.
def run() -> IO(U32):
  do IO<U32>:
    +seed : List<&2, U32> = fill(SEED_N(), SEED_B())
    +tail : List<&2, U32> = fill(TAIL_N(), TAIL_B())
    +joined : List<&2, U32> = HTTP2.x_flow_join(seed, tail)
    +empty : Bool = U32.is_eq(count(HTTP2.x_flow_join(Nil{}, Nil{})), 0)
    +small : Bool = eq_go(HTTP2.x_flow_join([1, 2], [3, 4]), [1, 2, 3, 4])
    +big : Bool = U32.is_eq(count(joined), (SEED_N() + TAIL_N() : U32))
    +edge : Bool = Bool.and(U32.is_eq(count(HTTP.x_drop32(SEED_N(), joined)), TAIL_N()), all(HTTP.x_drop32(SEED_N(), joined), TAIL_B()))
    IO.pure(U32, U32.add(b2u(empty), U32.add(b2u(small), U32.add(b2u(big), b2u(edge)))))

def main() -> IO(U32):
  do IO<U32>:
    +score : U32 <- run()
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

#|4
