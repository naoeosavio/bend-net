# io (http2_perf): the two hot loops must stay inside twice the budget of
# docs/perf.md (task-070 phase 3).
#
# The box is the one the budget names (AMD Ryzen 7 5800H, 8 cores). The
# test builds 1 MiB of DATA frames and times two shapes:
#   recv: x_parse, x_frame_of, x_data_body and x_len32 over 64 frames of
#         16384 bytes, which is one receive turn per frame;
#   send: the shipped x_chunks split of one 1 MiB body.
# A shape scores when its time is at most twice the budget value.
#
# The budget is a ceiling, not a target: a slower box fails the test, and
# that is the point — the gate then reports the new number instead of
# hiding a regression. Set BEND_TIMEOUT higher on a loaded box.
#
# Golden 2.
import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as HTTP2

def SIZE() -> U32:
  1048576

def FRAME() -> U32:
  16384

def FRAMES() -> Nat:
  64n

def CHUNKS() -> Nat:
  64n

# Twice the values of docs/perf.md (2026-11-07): recv_turn 169 ms/MiB and
# send_chunks 173 ms/MiB.

def RECV_MAX() -> Nat:
  338n

def SEND_MAX() -> Nat:
  346n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bytes.go(n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      bytes.go(p, b, b <> acc)

def bytes(n: Nat, +b: U32) -> List<&2, U32>:
  bytes.go(n, b, Nil{})

def body() -> List<&2, U32>:
  bytes(U32.to_nat(SIZE()), 120)

def unit() -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_data(), 0, 1, bytes(U32.to_nat(FRAME()), 97))

# One receive turn: parse the frame, read the record, strip the body.

def first_byte(+xs: List<&2, U32>) -> U32:
  match xs:
    case Nil{}:
      0
    case b <> t:
      b

def turn_rec(f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      first_byte(HTTP2.x_data_body(payload, flags))

# FRAMES turns over the same unit, which is 1 MiB of payload.

def turn_go(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{+u, +fin, +rest}:
      turn_rec(HTTP2.x_frame_of(u))
    case HTTP.NeedMore{+missing, +rest}:
      0
    case HTTP.Bad{+code, +msg}:
      0
    case HTTP.End{+rest}:
      0

def turn(+unit: List<&2, U32>) -> U32:
  +out : HTTP.UnitOut = HTTP2.x_parse(unit)
  turn_go(out)

def recv_go(fuel: Nat, +u: List<&2, U32>, acc: U32) -> U32:
  match fuel:
    case 0n:
      acc
    case 1n+p:
      recv_go(p, u, (acc + turn(u) : U32))

def recv_all(+u: List<&2, U32>) -> U32:
  recv_go(FRAMES(), u, 0)

def split_len(xs: List<&2, List<&2, U32>>, acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case h <> t:
      split_len(t, (acc + 1 : U32))

def split_all(+b: List<&2, U32>) -> U32:
  +xs : List<&2, List<&2, U32>> = HTTP2.x_chunks(CHUNKS(), b)
  split_len(xs, 0)

def run_kind(kind: U32, +b: List<&2, U32>) -> U32:
  match kind:
    case 0:
      recv_all(unit())
    case _:
      split_all(b)

def now() -> IO(Nat):
  IO.now()

def timed(kind: U32) -> IO(Nat & U32):
  do IO<Nat & U32>:
    +b : List<&2, U32> = body()
    t0 : Nat <- IO.now()
    +n : U32 = run_kind(kind, b)
    t1 : Nat <- IO.now()
    IO.pure(Nat & U32, (Nat.sub(t1, t0), n))

def within(kind: U32, ms: Nat) -> Bool:
  match kind:
    case 0:
      Nat.is_le(ms, RECV_MAX())
    case _:
      Nat.is_le(ms, SEND_MAX())

def note_go(first: Bool, is_in: Bool, +ms: Nat) -> U32:
  match first:
    case True{}:
      U32.mul(b2u(is_in), b2u(Nat.is_gt(ms, 1n)))
    case False{}:
      b2u(is_in)

def note(p: Nat & U32, +kind: U32, +first: Bool) -> IO(U32):
  match p:
    case (+ms, +n):
      do IO<U32>:
        a : Unit <- IO.print(Nat.show(ms))
        b : Unit <- IO.print(U32.show(n))
        IO.pure(U32, note_go(first, within(kind, ms), ms))

def run() -> IO(U32):
  do IO<U32>:
    p0 : Nat & U32 <- timed(0)
    a : Unit <- IO.print("recv")
    +c0 : U32 <- note(p0, 0, True{})
    p1 : Nat & U32 <- timed(1)
    b : Unit <- IO.print("send")
    +c1 : U32 <- note(p1, 1, False{})
    IO.pure(U32, (c0 + c1 : U32))

def main() -> IO(U32):
  do IO<U32>:
    +total : U32 <- run()
    x : Unit <- IO.print(U32.show(total))
    IO.pure(U32, total)

#|2

#|2
