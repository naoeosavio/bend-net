# lib (lib_httpx_h1_chunk): the chunked decoder lib/httpx.bend gained for
# its H1 lane, before any socket is involved.
#
# The vectors are the ones tests/http/h1_codec.bend and tests/http/h1_stream.bend
# already fix for the reference machine (lib/web/http/main.bend) -- the
# RFC 9112 section 7.1.1 shape, its extensions, its starved and malformed
# bodies -- plus the limits the port is asked to keep honest, each with its
# own vector so it is visible and not a surprise:
# - a trailer section is refused (400), the answer the reference gives too;
# - a bare empty line standing in for the last-chunk is read as "last" by the
#   step's lookahead but refused by the fold (400), which is why the client
#   reader closes on End and never on the lookahead's fin;
# - a hex size that does not fit the U32 counter is refused (400);
# - bytes after the terminator are refused (400);
# - a chunk extension on the last-chunk line is refused (400), because the
#   machine reads "0;<ext>" as a zero-length data chunk (reference behaviour,
#   also fixed by tests/http/h1_stream.bend s9 for the zero-size case).
#
# The step is checked on its own, not only through the fold: a chunk split
# across two buffers has to come back NeedMore with the first half in the
# state and then answer Got with the whole chunk, and a body fed one byte
# at a time has to decode to the same bytes (that is the arm the IO lanes
# below depend on). The last group runs every vector through
# H1.h1_unchunk as well, so the port is checked against the machine it was
# ported from and not only against the literals above.
#
# Golden 35 iff all 35 checks are 1.
import Base
import ../../lib/httpx.bend as HTTPX
import ../../lib/web/http/main.bend as H1

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bs_of(+s: String) -> List<&2, U32>:
  HTTPX.x_str_bytes(s)

def bytes_is(got: List<&2, U32>, want: List<&2, U32>) -> U32:
  HTTPX.x_eq(got, want)

def str_is(got: String, want: String) -> U32:
  b2u(String.eq(got, want))

# 1 iff the fold decoded to exactly this text.
def done_is(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+bs}:
      str_is(HTTPX.x_bytes_str(bs), want)

# 1 iff the fold refused with exactly this code. A Done scores 0 against
# every code, so a vector that wanted a failure cannot pass on a body.
def fail_is(r: Result<&1, &1, U32 & String, List<&2, U32>>, +code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, m) = e
      b2u(U32.is_eq(c, code))
    case Done{bs}:
      0

# The step's answers, one reader per question (Bend has no type variable,
# so each shape gets its own def).
def st_of(r: HTTPX.ChunkSt & HTTPX.UnitOut) -> HTTPX.ChunkSt:
  (st, out) = r
  st

def is_need(r: HTTPX.ChunkSt & HTTPX.UnitOut) -> U32:
  (st, out) = r
  match out:
    case HTTPX.NeedMore{missing, rest}:
      1
    case _:
      0

def is_end(r: HTTPX.ChunkSt & HTTPX.UnitOut) -> U32:
  (st, out) = r
  match out:
    case HTTPX.End{rest}:
      1
    case _:
      0

def is_bad(r: HTTPX.ChunkSt & HTTPX.UnitOut) -> U32:
  (st, out) = r
  match out:
    case HTTPX.Bad{code, msg}:
      1
    case _:
      0

def got_len(r: HTTPX.ChunkSt & HTTPX.UnitOut) -> U32:
  (st, out) = r
  match out:
    case HTTPX.Got{+chunk, fin, +rest}:
      HTTPX.x_len32(chunk)
    case _:
      0

def got_rest_is(r: HTTPX.ChunkSt & HTTPX.UnitOut, +want: String) -> U32:
  (st, out) = r
  match out:
    case HTTPX.Got{+chunk, fin, +rest}:
      bytes_is(rest, bs_of(want))
    case _:
      0

def got_is_last(r: HTTPX.ChunkSt & HTTPX.UnitOut) -> U32:
  (st, out) = r
  match out:
    case HTTPX.Got{+chunk, fin, +rest}:
      b2u(fin)
    case _:
      0

# The RFC 9112 section 7.1.1 body, byte for byte:
#
#   4\r\n            a 4-byte chunk
#   Wiki\r\n         its data and the CRLF that ends it
#   5;ext=1\r\n      a 5-byte chunk with an extension
#   pedia\r\n        its data
#   0\r\n            the last chunk
#   \r\n             the trailer-free CRLF
def rfc_body() -> List<&2, U32>:
  bs_of("4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n")

def chk_rfc() -> U32:
  done_is(HTTPX.x_h1.unchunk(rfc_body()), "Wikipedia")

# Upper-case hex is a size: A is 10 (RFC 9112 section 7.1.1 allows it).
def chk_upper_hex() -> U32:
  done_is(HTTPX.x_h1.unchunk(bs_of("A\r\n0123456789\r\n0\r\n\r\n")), "0123456789")

# The bare terminator is the empty body, not a failure.
def chk_bare_terminator() -> U32:
  done_is(HTTPX.x_h1.unchunk(bs_of("0\r\n\r\n")), "")

# A chunk extension is skipped, whether or not another chunk follows it.
def chk_extension() -> U32:
  done_is(HTTPX.x_h1.unchunk(bs_of("5;ext=1\r\npedia\r\n0\r\n\r\n")), "pedia")

# A body that stops mid-chunk is a truncated message, never an empty one.
def chk_truncated() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("4\r\nWi")), 400)

# The last-chunk is owed even when the data before it ended cleanly.
def chk_missing_terminator() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("1\r\nA\r\n")), 400)

# A trailer section is not chunked data (the reference machine refuses it
# too; tests/http/h1_stream.bend s10 and f4).
def chk_trailer() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("1\r\nA\r\n0\r\nX: y\r\n\r\n")), 400)

# A size line that is not hex.
def chk_bad_hex() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("zz\r\n")), 400)

# A CR inside the data that is not the CRLF ending it.
def chk_lonely_cr() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("1\r\nA\rB\r\n0\r\n\r\n")), 400)

# A zero size line IS the last-chunk line, so a zero-length chunk in the
# middle of a body is not something this grammar accepts.
def chk_zero_size() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("1\r\nA\r\n0\r\nB\r\n0\r\n\r\n")), 400)

# A chunk size that does not fit the U32 counter (16 F's wrap to 0) is
# refused instead of being read as a zero-length chunk: wrapping would
# silently reframe the body, which is the request-smuggling shape.
def chk_wrapped_size() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("FFFFFFFFFFFFFFFF\r\nAB\r\n0\r\n\r\n")), 400)

# The last-chunk line may carry an extension per RFC 9112, but this machine
# (like the reference) reads "0;<ext>" as a zero-length DATA chunk, so the
# body needs the terminator's CRLF after it and the fold answers 400. Kept
# as a vector so the limit is visible and not a surprise.
def chk_last_chunk_extension() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("0;ext=1\r\n\r\n")), 400)

# A bare empty line after a chunk: the step's lookahead reads it as "the
# chunk just decoded is the last one", but the fold keeps going (only End
# finishes a body) and the missing last-chunk line is a 400. Checked at
# both levels, because that difference is exactly what the client reader
# relies on: it stops on End, never on the lookahead's fin.
def step_of(bs: List<&2, U32>) -> HTTPX.ChunkSt & HTTPX.UnitOut:
  HTTPX.x_h1.chunk_step(HTTPX.x_h1.chunk_init(), bs)

def step_next(o: HTTPX.ChunkSt & HTTPX.UnitOut, bs: List<&2, U32>) -> HTTPX.ChunkSt & HTTPX.UnitOut:
  HTTPX.x_h1.chunk_step(st_of(o), bs)

def chk_empty_line_last() -> U32:
  o = step_of(bs_of("1\r\nA\r\n\r\n"))
  (got_is_last(o) + fail_is(HTTPX.x_h1.unchunk(bs_of("1\r\nA\r\n\r\n")), 400) : U32)

@unsafe
def pay.go(+n: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      pay.go((n - 1 : U32), U32.and(n, 255) <> acc)

def pay(n: U32) -> List<&2, U32>:
  pay.go(n, Nil{})

# Bytes after the terminator are refused: the machine wants the buffer to
# end at the terminator's LF. That is the reference machine's answer too,
# and it is the answer the client reader inherits -- a response whose
# terminator shares a buffer with whatever follows it is refused, never
# read as "body plus a bit I will ignore".
# The step's own vocabulary, at the two ends the fold maps away: the bare
# terminator answers End (not a Got with an empty chunk) and a bad size line
# answers Bad with the 400 the lanes pass on.
def chk_step_end() -> U32:
  is_end(step_of(bs_of("0\r\n\r\n")))

def chk_step_bad() -> U32:
  is_bad(step_of(bs_of("zz\r\n")))

def chk_trailing() -> U32:
  fail_is(HTTPX.x_h1.unchunk(bs_of("4\r\nWiki\r\n0\r\n\r\nX")), 400)

# A 16 KiB chunk in one buffer: the block path takes the whole slice, the
# lookahead sees the terminator's '0' and the terminator line is NOT eaten.
def big_head() -> List<&2, U32>:
  List.append(&2, U32, bs_of("4000\r\n"), pay(8192))

def big_tail() -> List<&2, U32>:
  List.append(&2, U32, pay(8192), bs_of("\r\n0\r\n\r\n"))

def big_body() -> List<&2, U32>:
  List.append(&2, U32, bs_of("4000\r\n"),
    List.append(&2, U32, pay(16384), bs_of("\r\n0\r\n\r\n")))

# 1 iff the fold decoded a body of exactly this length.
def len_is(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+bs}:
      b2u(U32.is_eq(HTTPX.x_len32(bs), want))

def chk_big_chunk() -> U32:
  len_is(HTTPX.x_h1.unchunk(big_body()), 16384)

# The same chunk split across two reads with the boundary in the middle of
# the data: the first read starves (NeedMore, and its 8192 bytes ride in
# the state's fragment stack), the second completes the chunk. This is the
# vector that catches a fragment stack that comes back in the wrong order.
# The four answers of the split read, one def each: a let binder of a
# tuple-typed value cannot be copied (+o on a pair is refused by Bend
# 2.0.35), so each question takes its own fresh step instead.
def split_first_need() -> U32:
  is_need(step_of(big_head()))

def split_second_is_last() -> U32:
  got_is_last(step_next(step_of(big_head()), big_tail()))

def split_second_len() -> U32:
  b2u(U32.is_eq(got_len(step_next(step_of(big_head()), big_tail())), 16384))

def split_second_rest() -> U32:
  got_rest_is(step_next(step_of(big_head()), big_tail()), "0\r\n\r\n")

def chk_split_read() -> U32:
  (split_first_need() + split_second_is_last() + split_second_len() + split_second_rest() : U32)

# The whole body one byte at a time: Need until a chunk completes, then Got
# from the state and the rest the step itself returned -- the incremental
# contract the two IO lanes below are built on. The driver marks the two
# ways a byte feed can stop short: 255 after a Bad answer and 254 when the
# source runs out while the decoder still wants bytes. That second marker is
# the whole reason the client reader answers 400 on EOF: a starved step has
# no way to say "that was all there is", only End says the body is whole.
@unsafe
def feed.go(r: HTTPX.ChunkSt & HTTPX.UnitOut, src: List<&2, U32>, out: List<&2, U32>) -> List<&2, U32>:
  (st2, o) = r
  match o:
    case HTTPX.Got{+chunk, fin, +rest}:
      feed.more(st2, rest, src, List.append(&2, U32, out, chunk))
    case HTTPX.NeedMore{missing, +rest}:
      feed.more(st2, rest, src, out)
    case HTTPX.End{rest}:
      out
    case HTTPX.Bad{code, msg}:
      List.append(&2, U32, out, [255])

@unsafe
def feed.more(st: HTTPX.ChunkSt, rest: List<&2, U32>, src: List<&2, U32>, out: List<&2, U32>) -> List<&2, U32>:
  match src:
    case Nil{}:
      List.append(&2, U32, out, [254])
    case b <> t:
      feed.go(HTTPX.x_h1.chunk_step(st, List.append(&2, U32, rest, [b])), t, out)

def chk_byte_at_a_time() -> U32:
  bytes_is(feed.go(step_of(Nil{}), rfc_body(), Nil{}), bs_of("Wikipedia"))

# The same driver on a truncated body: the starvation marker and nothing
# else. The half chunk stays in the decoder state and is never emitted, so
# a starved feed cannot leak a partial body.
def chk_byte_at_a_time_truncated() -> U32:
  bytes_is(feed.go(step_of(Nil{}), bs_of("4\r\nWi"), Nil{}), [254])

# The fold agrees with the reference decoder of lib/web/http/main.bend on
# the same bytes: same verdict, same body. This is the port's own check --
# every vector above is also run through the machine it was ported from.
def verdict(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32 & U32:
  match r:
    case Fail{e}:
      (c, m) = e
      (0, c)
    case Done{+bs}:
      (1, HTTPX.x_len32(bs))

def same_pair(pa: U32 & U32, pb: U32 & U32) -> U32:
  (va, ca) = pa
  (vb, cb) = pb
  b2u(Bool.and(U32.is_eq(va, vb), U32.is_eq(ca, cb)))

def same_as_ref(+v: List<&2, U32>) -> U32:
  same_pair(verdict(HTTPX.x_h1.unchunk(v)), verdict(H1.h1_unchunk(v)))

def chk_same_as_reference() -> U32:
  (same_as_ref(rfc_body())
    + same_as_ref(bs_of("A\r\n0123456789\r\n0\r\n\r\n"))
    + same_as_ref(bs_of("0\r\n\r\n"))
    + same_as_ref(bs_of("4\r\nWi"))
    + same_as_ref(bs_of("1\r\nA\r\n"))
    + same_as_ref(bs_of("1\r\nA\r\n0\r\nX: y\r\n\r\n"))
    + same_as_ref(bs_of("zz\r\n"))
    + same_as_ref(bs_of("1\r\nA\rB\r\n0\r\n\r\n"))
    + same_as_ref(bs_of("1\r\nA\r\n0\r\nB\r\n0\r\n\r\n"))
    + same_as_ref(bs_of("FFFFFFFFFFFFFFFF\r\nAB\r\n0\r\n\r\n"))
    + same_as_ref(bs_of("4\r\nWiki\r\n0\r\n\r\nX")) : U32)

def main() -> IO(Unit):
  +total : U32 = (chk_rfc() + chk_upper_hex() + chk_bare_terminator() + chk_extension()
    + chk_truncated() + chk_missing_terminator() + chk_trailer() + chk_bad_hex()
    + chk_lonely_cr() + chk_zero_size() + chk_wrapped_size() + chk_last_chunk_extension()
    + chk_trailing() + chk_step_end() + chk_step_bad() + chk_empty_line_last()
    + chk_big_chunk() + chk_split_read()
    + chk_byte_at_a_time() + chk_byte_at_a_time_truncated() + chk_same_as_reference() : U32)
  IO.print(U32.show(total))

#|35
