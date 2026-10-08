# lib (wsm_got_contra): TASK-040 contra-proof for the WSM got derivations.
# The new one-walk peel (wsm_frame_take) must answer exactly what the
# pre-TASK-040 path answered (x_take32 plus x_drop32, kept here as the
# reference A side), over Gots, NeedMores and Bads, and the got-B pair must
# agree with the projections it replaces.
# Self-failing on purpose: check.sh reads only the exit status and bend
# ignores the #| marker, so a wrong score halts with code 1 from contra_end.
import Base
import ../../lib/httpx.bend as HTTPX
import ../../lib/wsm.bend as WSM

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def same_bool(a: Bool, b: Bool) -> U32:
  match a:
    case True{}:
      b2u(b)
    case False{}:
      b2u(Bool.not(b))

def contra_end(is_ok: Bool, +score: U32) -> IO(U32):
  match is_ok:
    case True{}:
      do IO<U32>:
        w : Unit <- IO.print(U32.show(score))
        z : Unit <- IO.die(Unit, 0, "")
        return score
    case False{}:
      do IO<U32>:
        w : Unit <- IO.print("0")
        z : Unit <- IO.die(Unit, 1, "contra: score mismatch")
        return 0

# The pre-TASK-040 split path, copied as the reference answer.
def old_got_go(+bs: List<&2, U32>, +total: U32, eq: Bool, +missing: U32) ->
  HTTPX.UnitOut:
  match eq:
    case True{}:
      HTTPX.Got{HTTPX.x_take32(total, bs), False{}, HTTPX.x_drop32(total, bs)}
    case False{}:
      HTTPX.NeedMore{missing, bs}

def old_split_got(+bs: List<&2, U32>, +total: U32) -> HTTPX.UnitOut:
  +got = HTTPX.x_len_upto(total, bs)
  old_got_go(bs, total, U32.is_eq(got, total), U32.sub(total, got))

def old_split_res(bs: List<&2, U32>, need: Result<&1, &1, U32 & String, U32>) ->
  HTTPX.UnitOut:
  match need:
    case Fail{(c, e)}:
      HTTPX.Bad{c, e}
    case Done{total}:
      old_split_got(bs, total)

def old_split_hd(+bs: List<&2, U32>, unmasked_ok: Bool, missing: U32) ->
  HTTPX.UnitOut:
  match missing:
    case 0:
      old_split_res(bs, WSM.wsm_frame_need_go(bs, unmasked_ok))
    case _:
      HTTPX.NeedMore{missing, bs}

def old_split(+bs: List<&2, U32>, unmasked_ok: Bool) -> HTTPX.UnitOut:
  old_split_hd(bs, unmasked_ok,
    WSM.wsm_frame_hdr_go(bs, HTTPX.x_len_upto(10, bs)))

def new_split(+bs: List<&2, U32>, unmasked_ok: Bool) -> HTTPX.UnitOut:
  match unmasked_ok:
    case True{}:
      WSM.wsm_frame_split_unmasked(bs)
    case False{}:
      WSM.wsm_frame_split(bs)

# Structural equality of two split answers, 1 or 0.
def out_eq(a: HTTPX.UnitOut, b: HTTPX.UnitOut) -> U32:
  match a b:
    case HTTPX.Got{u1, f1, r1} HTTPX.Got{u2, f2, r2}:
      b2u(Bool.and(U32.is_eq(HTTPX.x_eq(u1, u2), 1),
        Bool.and(U32.is_eq(same_bool(f1, f2), 1),
          U32.is_eq(HTTPX.x_eq(r1, r2), 1))))
    case HTTPX.NeedMore{m1, r1} HTTPX.NeedMore{m2, r2}:
      b2u(Bool.and(U32.is_eq(m1, m2), U32.is_eq(HTTPX.x_eq(r1, r2), 1)))
    case HTTPX.Bad{c1, s1} HTTPX.Bad{c2, s2}:
      b2u(Bool.and(U32.is_eq(c1, c2), String.eq(s1, s2)))
    case HTTPX.End{r1} HTTPX.End{r2}:
      HTTPX.x_eq(r1, r2)
    case _ _:
      0

# One split vector: wire bytes plus the unmasked flag of the lane.
type SplitVec is Data:
  SplitVec{bs: List<&2, U32>, unmasked_ok: Bool}

# Unmasked frames ride the server lane (unmasked_ok=True), masked frames
# the client lane (unmasked_ok=False): complete text, complete plus trailing
# bytes, payload still missing, header missing, empty buffer, binary frame,
# masked on both lanes, medium header, invalid opcode, unmasked on the
# client lane (refused).
def vectors() -> List<&2, SplitVec>:
  [SplitVec{[129, 2, 72, 105], True{}},
    SplitVec{[129, 2, 72, 105, 1, 2], True{}},
    SplitVec{[129, 5, 72], True{}},
    SplitVec{[129], True{}},
    SplitVec{Nil{}, True{}},
    SplitVec{[130, 3, 72, 105, 33], True{}},
    SplitVec{[129, 130, 1, 2, 3, 4, 72, 105], True{}},
    SplitVec{[129, 130, 1, 2, 3, 4, 72, 105], False{}},
    SplitVec{[129, 126, 0, 5, 72, 105, 33, 44, 55], True{}},
    SplitVec{[131, 0], True{}},
    SplitVec{[129, 2, 72, 105], False{}}]

def vec_row(v: SplitVec) -> U32:
  match v:
    case SplitVec{+bs, +unmasked_ok}:
      out_eq(old_split(bs, unmasked_ok), new_split(bs, unmasked_ok))

def vec_sum(xs: List<&2, SplitVec>, acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case +h <> t:
      vec_sum(t, (acc + vec_row(h) : U32))

# Eleven vectors, one point each.
def split_all() -> U32:
  vec_sum(vectors(), 0)

# Explicit answers, so a wrong answer in both sides cannot pass silently.
def want_got(out: HTTPX.UnitOut, +unit: List<&2, U32>, +rest: List<&2, U32>) ->
  Bool:
  match out:
    case HTTPX.Got{u, f, r}:
      Bool.and(U32.is_eq(HTTPX.x_eq(u, unit), 1),
        U32.is_eq(HTTPX.x_eq(r, rest), 1))
    case _:
      False{}

def want_need(out: HTTPX.UnitOut, missing: U32, +rest: List<&2, U32>) -> Bool:
  match out:
    case HTTPX.NeedMore{m, r}:
      Bool.and(U32.is_eq(m, missing), U32.is_eq(HTTPX.x_eq(r, rest), 1))
    case _:
      False{}

def want_bad(out: HTTPX.UnitOut, code: U32) -> Bool:
  match out:
    case HTTPX.Bad{c, s}:
      U32.is_eq(c, code)
    case _:
      False{}

def want_all() -> U32:
  (b2u(want_got(WSM.wsm_frame_split_unmasked([129, 2, 72, 105]),
      [129, 2, 72, 105], Nil{}))
    + b2u(want_need(WSM.wsm_frame_split_unmasked([129, 5, 72]), 4,
      [129, 5, 72]))
    + b2u(want_need(WSM.wsm_frame_split(Nil{}), 1, Nil{}))
    + b2u(want_bad(WSM.wsm_frame_split_unmasked([131, 0]), 400)) : U32)

# The peel against the two projections it replaces: unit and rest must be
# the same bytes for n = 0, 2, 4, 6 over a six-byte buffer.
def got_units(out: HTTPX.UnitOut, +unit: List<&2, U32>, +rest: List<&2, U32>) ->
  Bool:
  match out:
    case HTTPX.Got{u, f, r}:
      Bool.and(U32.is_eq(HTTPX.x_eq(u, unit), 1),
        U32.is_eq(HTTPX.x_eq(r, rest), 1))
    case _:
      False{}

def peel_row(+bs: List<&2, U32>, +total: U32) -> U32:
  b2u(got_units(WSM.wsm_frame_take.got(WSM.wsm_frame_take(bs, total)),
    HTTPX.x_take32(total, bs), HTTPX.x_drop32(total, bs)))

def peel_all() -> U32:
  +bs : List<&2, U32> = [1, 2, 3, 4, 5, 6]
  (peel_row(bs, 0) + peel_row(bs, 2) + peel_row(bs, 4) + peel_row(bs, 6) : U32)

# Message projections: the single-match consumer over wsm_msg_of_frame must
# agree with wsm_recv_in_of (both are the same pick).
def msg_kind(msg: WSM.WSMessage) -> U32:
  match msg:
    case WSM.WSText{text}:
      1
    case WSM.WSBin{data}:
      2

def msg_score(r: Result<&1, &1, U32 & String, WSM.WSMessage>, +want: U32) ->
  U32:
  match r:
    case Fail{e}:
      b2u(U32.is_zero(want))
    case Done{msg}:
      b2u(U32.is_eq(msg_kind(msg), want))

def in_score(i: WSM.WSIn, +want: U32) -> U32:
  match i:
    case WSM.InMsg{msg}:
      b2u(U32.is_eq(msg_kind(msg), want))
    case WSM.InOp{fin, op, pay}:
      b2u(U32.is_zero(want))

def msg_row(+fin: Bool, +op: U32, +pay: List<&2, U32>, +want: U32) -> U32:
  b2u(U32.is_eq(msg_score(WSM.wsm_msg_of_frame(fin, op, pay), want),
    in_score(WSM.wsm_recv_in_of(fin, op, pay), want)))

def msg_all() -> U32:
  (msg_row(True{}, 1, [72, 105], 1)
    + msg_row(True{}, 2, [72], 2)
    + msg_row(True{}, 9, [1], 0)
    + msg_row(False{}, 1, [72], 0) : U32)

# wsm_out_op_of: the projection the single-match consumer answers.
def out_op_pair(p: WSM.WSOut) -> U32 & List<&2, U32>:
  match p:
    case WSM.OutMsg{msg}:
      (255, Nil{})
    case WSM.OutOp{op, pay}:
      (op, pay)
    case WSM.OutRaw{bs}:
      (255, bs)

def out_op_score(p: U32 & List<&2, U32>, +out: WSM.WSOut) -> U32:
  match p:
    case (op, pay):
      b2u(U32.is_eq(op, WSM.wsm_out_op_of(out)))

def out_op_all() -> U32:
  (out_op_score(out_op_pair(WSM.OutOp{8, [1, 2]}), WSM.OutOp{8, [1, 2]})
    + out_op_score(out_op_pair(WSM.OutMsg{WSM.WSText{"hi"}}),
        WSM.OutMsg{WSM.WSText{"hi"}}) : U32)

law main:
  IO(U32)

def main():
  +score : U32 = (split_all() + want_all() + peel_all() + msg_all()
    + out_op_all() : U32)
  contra_end(U32.is_eq(score, 25), score)

# split_all .... 11 (new vs the pre-TASK-040 reference, 11 buffers)
# want_all ...... 4 (explicit Got / NeedMore x2 / Bad)
# peel_all ...... 4 (peel vs x_take32 + x_drop32)
# msg_all ....... 4 (msg_of_frame vs recv_in_of)
# out_op_all .... 2 (out_op_of vs the pair consumer)
# total ........ 25
#|25
