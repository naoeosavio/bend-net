# lib (io_sleep): IO.sleep parks the computation on the loop's timer
# alone -- no fd is involved -- and the runtime still goes through
# select() with an empty fd_set, so every host has to make a bare
# timeout work (the Node preload answers it without ever starting a
# socket worker). Each round must come back no earlier than the
# requested milliseconds: select's timeout is a lower bound, and
# io_wait re-parks a waiter whose deadline has not passed yet.
# Rounds count in U32 and convert once, the shape test.bend measured
# as the fast one for a counter that only feeds an add. Golden 3:
# every round slept long enough.
import Base

# Sleeps per run; three is enough to catch a timer that fires once.
def ROUNDS() -> U32:
  3

# Milliseconds per sleep: short enough to keep the suite fast, long
# enough that a host busy-looping cannot pass the "not early" check.
def SLEEP_MS() -> U32:
  20

# Counts a Bool as 0 or 1 without branching at the call site.
def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Counts one round as 1 when the sleep lasted at least SLEEP_MS.
def slept_enough(t0: Nat, t1: Nat) -> U32:
  b2u(U32.is_le(SLEEP_MS(), U32.from_nat(Nat.sub(t1, t0))))

# Sleeps `n` times, counting the rounds that slept long enough.
# The fuel is Nat -- the termination checker wants a structural subterm --
# and the accumulator is U32, the faster counter shape in test.bend.
def rounds(n: Nat, acc: U32) -> IO(U32):
  match n:
    case 0n:
      IO.pure(U32, acc)
    case 1n+p:
      do IO<U32>:
        t0 : Nat <- IO.now()
        w : Unit <- IO.sleep(SLEEP_MS())
        t1 : Nat <- IO.now()
        rounds(p, (acc + slept_enough(t0, t1) : U32))

def main() -> IO(Unit):
  do IO<Unit>:
    ok : U32 <- rounds(U32.to_nat(ROUNDS()), 0)
    IO.print(U32.show(ok))

#|3
