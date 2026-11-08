# fuzz (h2_fuzz_frames): the pure H2 frame parser, byte by byte.
#
# Five seed frames cover the frame types the server reads: DATA, HEADERS,
# SETTINGS, WINDOW_UPDATE and RST_STREAM. The program picks a seed frame,
# one byte and one value with a small LCG, and calls x_parse on the
# mutant. A Got also calls x_frame_of and x_data_body, so the record and
# the body strip see the same bytes.
#
# The contract: every variant answers Got, NeedMore or Bad{1..502}. A
# variant that answers End, a Bad outside the range, or that kills the
# process breaks the run. The number printed is a rolling hash of the
# outcomes, so a change in the parser moves it, and the exit code is 1
# when one variant breaks the contract.
#
#   bend tests/fuzz/frames.bend [seed] [rounds]
#
# The gate runs the default seed and 400 rounds, which fits the per-file
# ceiling. `tests/fuzz/run.sh <seconds>` raises the round count.
import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as HTTP2

def SEED() -> U32:
  20261107

def ROUNDS() -> Nat:
  400n

def MASK() -> U32:
  2097151

def HASNAT() -> U32:
  4294967295

type Fz is Data:
  Fz{r: U32, h: U32, bad: U32}

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# One safe 16-bit LCG step: the product stays below 2^31.
def rnd(x: U32) -> U32:
  U32.and(((x * 25173 + 13849 : U32)), 65535)

def hash(h: U32, code: U32) -> U32:
  U32.and(((h * 33 + code : U32)), MASK())

# The five seed frames, as the writer builds them.
def seed_of(k: U32) -> List<&2, U32>:
  match k:
    case 0:
      HTTP2.x_frame_write(HTTP2.x_t_data(), 0, 1, [1, 2, 3, 4])
    case 1:
      HTTP2.x_frame_write(HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, [130, 134, 65, 7, 47])
    case 2:
      HTTP2.x_frame_write(HTTP2.x_t_settings(), 0, 0, [0, 2, 0, 0, 0, 0])
    case 3:
      HTTP2.x_frame_write(HTTP2.x_t_wu(), 0, 1, [0, 0, 0, 1])
    case _:
      HTTP2.x_frame_write(HTTP2.x_t_rst(), 0, 1, [0, 0, 0, 0])

# One byte replaced at countdown at. The sentinel moves past the rest.
def put.go(+v: U32, xs: List<&2, U32>, at: Nat) -> List<&2, U32>:
  match xs at:
    case Nil{} _:
      Nil{}
    case _ <> t 0n:
      v <> put.go(v, t, 1000000000n)
    case h <> t 1n+p:
      h <> put.go(v, t, p)

def put(v: U32, at: U32, xs: List<&2, U32>) -> List<&2, U32>:
  put.go(v, xs, U32.to_nat(at))

# The record of a unit that parsed: touching x_frame_of and x_data_body is
# the point, so both run and the answer is the success code.
def record_go(f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      b2u(U32.is_le(HTTP.x_len32(HTTP2.x_data_body(payload, flags)), flen))

def record(unit: List<&2, U32>) -> U32:
  record_go(HTTP2.x_frame_of(unit))

# 1 Got, 2 NeedMore, 3 a Bad inside the range, 0 anything else.
def outcome_go(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{+unit, +fin, +rest}:
      record(unit)
    case HTTP.NeedMore{+missing, +rest}:
      2
    case HTTP.Bad{+code, +msg}:
      U32.mul(b2u(Bool.and(U32.is_ge(code, 1), U32.is_le(code, 502))), 3)
    case HTTP.End{+rest}:
      0

def outcome(unit: List<&2, U32>) -> U32:
  outcome_go(HTTP2.x_parse(unit))

# 1 when the outcome is outside the contract.
def miss(code: U32) -> U32:
  match code:
    case 0:
      1
    case _:
      0

# One round: the state carries the LCG, the hash and the failures.
def step(fuel: Nat, st: Fz) -> Fz:
  match fuel:
    case 0n:
      st
    case 1n+f:
      match st:
        case Fz{+r, +h, +bad}:
          +r1 : U32 = rnd(r)
          +r2 : U32 = rnd(r1)
          +r3 : U32 = rnd(r2)
          +seed : List<&2, U32> = seed_of(U32.and(r1, 7))
          +at : U32 = U32.mod(r2, (HTTP.x_len32(seed) + 1 : U32))
          +v : U32 = U32.and(r3, 255)
          +code : U32 = outcome(put(v, at, seed))
          step(f, Fz{r3, hash(h, code), (bad + miss(code) : U32)})

def run(fuel: Nat, seed: U32) -> Fz:
  step(fuel, Fz{seed, 0, 0})

def st_hash(st: Fz) -> U32:
  match st:
    case Fz{r, h, bad}:
      h

def st_bad(st: Fz) -> U32:
  match st:
    case Fz{r, h, bad}:
      bad

def num_of(m: Maybe<&2, U32>, +dflt: U32) -> U32:
  match m:
    case None{}:
      dflt
    case Some{+v}:
      v

def arg1(xs: List<String>, +dflt: U32) -> U32:
  match xs:
    case Nil{}:
      dflt
    case h <> t:
      num_of(U32.read(h), dflt)

# The two arguments in one walk: <seed> <rounds>. Fz carries them.
def cfg2(+seed: U32, xs: List<String>) -> Fz:
  match xs:
    case Nil{}:
      Fz{seed, U32.from_nat(ROUNDS()), 0}
    case h <> t:
      Fz{seed, num_of(U32.read(h), U32.from_nat(ROUNDS())), 0}

def cfg(xs: List<String>) -> Fz:
  match xs:
    case Nil{}:
      Fz{SEED(), U32.from_nat(ROUNDS()), 0}
    case h <> t:
      cfg2(num_of(U32.read(h), SEED()), t)

def cfg_seed(c: Fz) -> U32:
  match c:
    case Fz{r, h, bad}:
      r

def cfg_rounds(c: Fz) -> Nat:
  match c:
    case Fz{r, h, bad}:
      U32.to_nat(h)

def bad_exit(bad: U32) -> IO(U32):
  match bad:
    case 0:
      IO.pure(U32, 0)
    case _:
      IO.die(U32, 1, "fuzz failure")

def report(+st: Fz) -> IO(U32):
  do IO<U32>:
    x : Unit <- IO.print(U32.show(st_hash(st)))
    bad_exit(st_bad(st))

def main() -> IO(U32):
  do IO<U32>:
    xs : List<String> <- IO.args()
    +c : Fz = cfg(xs)
    +st : Fz = run(cfg_rounds(c), cfg_seed(c))
    report(st)

#|1803377
