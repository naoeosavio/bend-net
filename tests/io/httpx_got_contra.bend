# lib (httpx_got_contra): TASK-040 contra-proof for the got convention.
# The rule under test: a computed pair/triple cannot be scrutinized, so a
# projection pair only exists when it arrives as a PARAMETER; a got answer
# must equal the plain get projections on every arm, the unhappy ones
# included. Corpus: boundary exactly at the end of the buffer (TASK-026
# Phase 7b), no boundary, empty buffer, cut at the first byte, boundary in
# the middle, a three-byte window that is not a boundary yet.
#
# Self-failing on purpose: check.sh reads only the exit status and bend
# ignores the #| marker, so a wrong score halts with code 1 from contra_end.
import Base
import ../../lib/http1.bend as HTTP1
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

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

# Halts with code 1 when the score is not what the vectors expect.
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

# One split vector: input plus the answer every form must agree on.
type SplitVec is Data:
  SplitVec{bs: List<&2, U32>, head: List<&2, U32>,
    rest: List<&2, U32>, found: Bool}

# Boundary exactly at the end of the buffer (the 7b case), no boundary,
# empty, first byte, boundary in the middle, partial window.
def vectors() -> List<&2, SplitVec>:
  [SplitVec{[71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13,
      10, 13, 10], [71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46,
      49, 13, 10, 13, 10], Nil{}, True{}},
    SplitVec{[71, 69, 84], [71, 69, 84], Nil{}, False{}},
    SplitVec{Nil{}, Nil{}, Nil{}, False{}},
    SplitVec{[13], [13], Nil{}, False{}},
    SplitVec{[71, 13, 10, 13, 10, 88], [71, 13, 10, 13, 10], [88], True{}},
    SplitVec{[13, 10, 13], [13, 10, 13], Nil{}, False{}}]

# The get side: three projections, one x_h1.split per projection (a triple
# cannot be bound once and read twice — + on a pair/triple is refused, E3).
def vec_get(v: SplitVec) -> U32:
  match v:
    case SplitVec{+bs, head, rest, found}:
      (HTTP.x_eq(HTTP1.x_h1.split_head(HTTP1.x_h1.split(bs)), head)
        + HTTP.x_eq(HTTP1.x_h1.split_rest(HTTP1.x_h1.split(bs)), rest)
        + same_bool(HTTP1.x_h1.split_found(HTTP1.x_h1.split(bs)), found) : U32)

# The got side: the triple rides into a consumer as a PARAMETER (E1 refuses
# the computed form, E2 admits this one) and one match answers both parts.
def split_param(p: List<&2, U32> & List<&2, U32> & Bool,
  +head: List<&2, U32>, +rest: List<&2, U32>, found: Bool) -> U32:
  match p:
    case (got_head, got_rest, got_found):
      (HTTP.x_eq(got_head, head) + HTTP.x_eq(got_rest, rest)
        + same_bool(got_found, found) : U32)

def vec_got(v: SplitVec) -> U32:
  match v:
    case SplitVec{bs, head, rest, found}:
      split_param(HTTP1.x_h1.split(bs), head, rest, found)

# The rebuild-free probe must answer what split_found(split(bs)) answers.
def vec_test(v: SplitVec) -> U32:
  match v:
    case SplitVec{bs, head, rest, found}:
      same_bool(HTTP1.x_h1.split.test(bs), found)

def vec_sum(xs: List<&2, SplitVec>, acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case +h <> t:
      vec_sum(t, (acc + vec_get(h) + vec_got(h) + vec_test(h) : U32))

# Six vectors, seven points each: 3 get + 3 got + 1 probe.
def split_all() -> U32:
  vec_sum(vectors(), 0)

# H1 framing: the single-match consumer must answer the same triple the
# three get projections answer (cl / chunked / no_body).
def frame_got(p: HTTP.BodyFrame) -> U32 & Bool & Bool:
  match p:
    case HTTP.BodyFrame{cl, chunked, no_body}:
      (cl, chunked, no_body)

def frame_score(p: U32 & Bool & Bool, +want_cl: U32, want_chunked: Bool,
  want_nobody: Bool) -> U32:
  match p:
    case (cl, chunked, no_body):
      (b2u(U32.is_eq(cl, want_cl)) + same_bool(chunked, want_chunked)
        + same_bool(no_body, want_nobody) : U32)

def frame_vec(hs: List<&2, HTTP.Hdr>, method: String, status: U32,
  want_cl: U32, want_chunked: Bool, want_nobody: Bool) -> U32:
  frame_score(frame_got(HTTP1.x_h1.frame_of(hs, method, status)), want_cl,
    want_chunked, want_nobody)

def frame_all() -> U32:
  (b2u(U32.is_eq(frame_vec([HTTP.Hdr{"Content-Length", "5"}], "GET", 200, 5,
      False{}, False{}), 3))
    + b2u(U32.is_eq(frame_vec([HTTP.Hdr{"Transfer-Encoding", "chunked"}],
      "POST", 200, 0, True{}, False{}), 3))
    + b2u(U32.is_eq(frame_vec(Nil{}, "HEAD", 200, 0, False{}, True{}), 3))
    + b2u(U32.is_eq(frame_vec(Nil{}, "GET", 204, 0, False{}, True{}), 3)) : U32)

# HPACK response head: Fail and Done must agree with the projections.
# decode is pure and +Head through the alias is not stable, so each side
# decodes its own single-use copy (the miniunit workaround).
def resp_rh_score(head: HTTP.Head, is_ok: Bool) -> U32:
  match head:
    case HTTP.Head{status, headers}:
      match is_ok:
        case True{}:
          b2u(U32.is_eq(status, 200))
        case False{}:
          b2u(U32.is_zero(status))

def resp_get_score(+bs: List<&2, U32>) -> U32:
  resp_rh_score(HTTP2.x_resp.rh(HTTP2.x_resp.decode(bs, HTTP2.x_tab.empty())),
    HTTP2.x_resp.ok(HTTP2.x_resp.decode(bs, HTTP2.x_tab.empty())))

def resp_got_score(r: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) ->
  U32:
  match r:
    case Fail{e}:
      1
    case Done{(head, tab)}:
      match head:
        case HTTP.Head{status, headers}:
          match tab:
            case HTTP.Tab{ents, size, max}:
              b2u(U32.is_eq(status, 200))

def resp_all() -> U32:
  +blk : List<&2, U32> = HTTP2.x_block([HTTP.Hdr{":status", "200"}])
  (b2u(U32.is_eq(resp_get_score(blk), 1))
    + resp_got_score(HTTP2.x_resp.decode(blk, HTTP2.x_tab.empty()))
    + b2u(U32.is_eq(resp_get_score([128]), 1))
    + resp_got_score(HTTP2.x_resp.decode([128], HTTP2.x_tab.empty())) : U32)

# Slot wrapper: the got-B pair (slots, st) out of one match must answer
# what the two get projections answer.
def taken_got(p: HTTP.Taken) -> List<&2, HTTP.St> & HTTP.St:
  match p:
    case HTTP.Taken{+slots, +st}:
      (slots, st)

def slots_head_sid(slots: List<&2, HTTP.St>, +want_sid: U32) -> U32:
  match slots:
    case Nil{}:
      0
    case h <> t:
      match h:
        case HTTP.St{head, body, sid}:
          b2u(U32.is_eq(sid, want_sid))

def st_sid(st: HTTP.St, +want_sid: U32) -> U32:
  match st:
    case HTTP.St{head, body, sid}:
      b2u(U32.is_eq(sid, want_sid))

# The taken slot must be the one asked for, and the leftover list must hold
# the other one: two points.
def taken_score(p: List<&2, HTTP.St> & HTTP.St, +want_sid: U32,
  +rest_sid: U32) -> U32:
  match p:
    case (slots, st):
      (slots_head_sid(slots, rest_sid) + st_sid(st, want_sid) : U32)

def taken_all() -> U32:
  +slots : List<&2, HTTP.St> = [HTTP.St{None{}, Nil{}, 7},
    HTTP.St{None{}, Nil{}, 9}]
  taken_score(taken_got(HTTP2.httpxn.take_del(slots, 7)), 7, 9)

law main:
  IO(U32)

def main():
  +score : U32 = (split_all() + frame_all() + resp_all() + taken_all() : U32)
  contra_end(U32.is_eq(score, 52), score)

# 6 vectors x 7 (3 get + 3 got + 1 probe) = 42
# frame_all ................... 4
# resp_all .................... 4
# taken_all ................... 2
# total ....................... 52
#|52
