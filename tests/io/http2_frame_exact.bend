# io (http2 frame exact read): the frame walk hands the frame over without
# a copy when the read buffer holds that frame alone (task-068 phase 10).
#
# The read loop asks for the bytes the walk still owes, so a frame arrives
# as its own buffer, and x_frame.fin3 answers that buffer as the unit and
# the empty list as the rest. The pure vectors pin the rule:
#   * a whole frame alone answers the frame and no rest;
#   * a frame with another frame behind it answers the same frame and that
#     other frame as the rest;
#   * the payload bytes are the same on both paths;
#   * a frame split by a short read answers the count the loop now asks
#     for, and the empty buffer asks for a nine-byte header;
#   * the padded frame, the bad pad, the SETTINGS read and the 16384-byte
#     payload keep their answer on the exact path.
#
# Golden 13.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bytes_eq.go(acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      bytes_eq.go(bytes_eq(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

# --- the vectors ---

# DATA, no flags, sid 1, three payload bytes.
def one() -> List<&2, U32>:
  [0, 0, 3, 0, 0, 0, 0, 0, 1, 104, 105, 106]

# A second DATA frame, sid 3, one payload byte.
def two() -> List<&2, U32>:
  [0, 0, 1, 0, 0, 0, 0, 0, 3, 200]

# The two frames in wire order: one, then two.
def one_two() -> List<&2, U32>:
  HTTP.x_cat.go(List.reverse(&2, U32, one()), two())

# DATA, PADDED, sid 1, declared length 4: pad length 1, one pad octet,
# then the two body bytes.
def padded() -> List<&2, U32>:
  [0, 0, 4, 0, 8, 0, 0, 0, 1, 1, 0, 104, 105]

# The same frame with pad length 200: the pad passes the payload.
def bad_pad() -> List<&2, U32>:
  [0, 0, 3, 0, 8, 0, 0, 0, 1, 200, 104, 105]

# SETTINGS with one entry: id 4, value 1024.
def settings() -> List<&2, U32>:
  [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 4, 0]

# A payload of n 'a' octets.
@unsafe
def fill(n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      fill((n - 1 : U32), 97 <> acc)

# --- the walk answers ---

# The unit length and the rest length of a Got answer.
def rest_of(out: HTTP.UnitOut) -> List<&2, U32>:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      rest
    case _:
      Nil{}

def unit_len(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      HTTP.x_len32(unit)
    case _:
      0

def rest_len(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      HTTP.x_len32(rest)
    case _:
      0

def payload_of(+f: HTTP.Frame) -> List<&2, U32>:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +len, +payload}:
      payload

def flags_of_frame(+f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +len, +payload}:
      flags

def settings_iw_frame(+f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +len, +payload}:
      HTTP2.x_settings.iw_of(payload, 0)

# The payload of a Got answer, or the empty list when the walk failed.
def pay(out: HTTP.UnitOut) -> List<&2, U32>:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      payload_of(HTTP2.x_frame_of(unit))
    case _:
      Nil{}

def flags_of(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      flags_of_frame(HTTP2.x_frame_of(unit))
    case _:
      0

def settings_iw(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      settings_iw_frame(HTTP2.x_frame_of(unit))
    case _:
      0

def need_missing(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.NeedMore{missing, rest}:
      missing
    case _:
      0

def need_rest_len(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.NeedMore{missing, +rest}:
      HTTP.x_len32(rest)
    case _:
      0

def is_bad_pad(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Bad{code, msg}:
      U32.mul(b2u(U32.is_eq(code, 1)), b2u(String.eq(msg, "bad padding")))
    case _:
      0

# The body of a DATA frame after the pad strip.
def body_len(+out: HTTP.UnitOut) -> U32:
  HTTP.x_len32(HTTP2.x_data_body(pay(out), flags_of(out)))

# --- the checks ---

# c1: the whole frame alone answers the frame and no rest.
def c1() -> U32:
  U32.mul(b2u(U32.is_eq(unit_len(HTTP2.x_parse(one())), 12)), b2u(U32.is_eq(rest_len(HTTP2.x_parse(one())), 0)))

# c2: a frame with another frame behind answers the same frame and the
# other frame as the rest.
def c2() -> U32:
  +out : HTTP.UnitOut = HTTP2.x_parse(one_two())
  U32.mul(b2u(U32.is_eq(unit_len(out), 12)), b2u(U32.is_eq(rest_len(out), 10)))

# c3: the payload bytes of the frame alone.
def c3() -> U32:
  bytes_eq(pay(HTTP2.x_parse(one())), [104, 105, 106])

# c4: the payload bytes are the same when another frame follows.
def c4() -> U32:
  bytes_eq(pay(HTTP2.x_parse(one_two())), [104, 105, 106])

# c6: the second frame parses out of the rest and leaves no rest.
def c6() -> U32:
  +out : HTTP.UnitOut = HTTP2.x_parse(one_two())
  +rest : List<&2, U32> = rest_of(out)
  U32.mul(b2u(U32.is_eq(unit_len(HTTP2.x_parse(rest)), 10)), b2u(U32.is_eq(rest_len(HTTP2.x_parse(rest)), 0)))

# c7: the header alone asks for the three payload bytes that are owed.
def c7() -> U32:
  +hd : List<&2, U32> = HTTP.x_take32(9, one())
  +out : HTTP.UnitOut = HTTP2.x_parse(hd)
  U32.mul(b2u(U32.is_eq(need_missing(out), 3)), b2u(U32.is_eq(need_rest_len(out), 0)))

# c8: the empty buffer asks for a nine-byte header.
def c8() -> U32:
  +out : HTTP.UnitOut = HTTP2.x_parse(Nil{})
  U32.mul(b2u(U32.is_eq(need_missing(out), 9)), b2u(U32.is_eq(need_rest_len(out), 0)))

# c9: a short payload read asks for the one byte owed and keeps the two
# payload bytes it holds.
def c9() -> U32:
  +short : List<&2, U32> = HTTP.x_take32(11, one())
  +out : HTTP.UnitOut = HTTP2.x_parse(short)
  U32.mul(b2u(U32.is_eq(need_missing(out), 1)), b2u(U32.is_eq(need_rest_len(out), 2)))

# c10: the padded frame alone keeps its declared frame and strips its pad.
def c10() -> U32:
  U32.mul(b2u(U32.is_eq(unit_len(HTTP2.x_parse(padded())), 13)), b2u(U32.is_eq(body_len(HTTP2.x_parse(padded())), 2)))

# c11: the bad pad is still a protocol error on the exact path.
def c11() -> U32:
  is_bad_pad(HTTP2.x_parse(bad_pad()))

# c12: the SETTINGS frame alone answers its announced window.
def c12() -> U32:
  b2u(U32.is_eq(settings_iw(HTTP2.x_parse(settings())), 1024))

# c13: a 16384-byte payload alone answers a 16393-byte frame and the
# whole payload, which is the cap the read loop asks for.
def c13() -> U32:
  +big : List<&2, U32> = HTTP2.x_frame_write(0, 0, 1, fill(16384, Nil{}))
  +out : HTTP.UnitOut = HTTP2.x_parse(big)
  U32.mul(b2u(U32.is_eq(unit_len(out), 16393)), b2u(U32.is_eq(HTTP.x_len32(pay(out)), 16384)))

# c14: the rest of a two-frame buffer is exactly the second frame bytes.
def c14() -> U32:
  bytes_eq(rest_of(HTTP2.x_parse(one_two())), two())

def main() -> IO(U32):
  do IO<U32>:
    +total : U32 = (c1() + c2() + c3() + c4() + c6() + c7() + c8() + c9() + c10() + c11() + c12() + c13() + c14() : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|13
