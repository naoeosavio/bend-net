# io (httpx_utf8_invalid): the utf-8 decode on INVALID input.
#
# x_utf8_decode and x_utf8_ok must agree on which byte runs are valid:
# both use x_utf8_is_cont and x_utf8_code_ok. The decoder used to accept
# a byte that is not a continuation as if it were one, so `C3 41`
# decoded to "Á" -- a character the bytes do not hold -- while
# x_utf8_ok answered False for the same pair. The decoder now checks
# every continuation byte with those rules, and aborts the sequence
# with one U+FFFD when the byte is wrong.
#
# The file pins the rule the invalid input already had, and the rule the
# fix added:
#   * a bad continuation aborts the sequence and answers one U+FFFD;
#   * an overlong or out-of-range code point answers one U+FFFD;
#   * a lone continuation answers one U+FFFD per pair, and the trailing
#     byte is dropped by the end (the rule httpx_utf8_str pins);
#   * a truncated tail is dropped, no U+FFFD;
#   * valid text still answers the same characters.
#
# Answers: one per vector that matches. Golden 11.
import Base
import ../../lib/http.bend as HTTP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

# One U+FFFD, the answer for an aborted sequence.
law fffd1:
  String

def fffd1():
  SCon{Chr{65533}, SNil{}}

# The bytes do not decode as a String. x_utf8_ok must say so too, so
# the decoder and the validator cannot drift apart again.
law same_verdict:
  for +bs: List<&2, U32>
  for +want: String
  U32

def same_verdict(bs, want):
  (b2u(String.eq(HTTP.x_utf8_decode(bs), want))
    * b2u(Bool.not(HTTP.x_utf8_ok(bs))) : U32)

# A non-continuation byte aborts a 2-byte sequence. It used to decode
# to "Á": the byte 41 was read as a continuation.
law chk_bad_cont2:
  U32

def chk_bad_cont2():
  same_verdict([195, 65], fffd1())

# A non-continuation byte aborts a 3-byte sequence.
law chk_bad_cont3:
  U32

def chk_bad_cont3():
  same_verdict([226, 130, 65], fffd1())

# A non-continuation byte aborts a 4-byte sequence.
law chk_bad_cont4:
  U32

def chk_bad_cont4():
  same_verdict([240, 159, 65], fffd1())

# A surrogate (ED A0 80 = U+D800) is not a legal code point.
law chk_surrogate:
  U32

def chk_surrogate():
  same_verdict([237, 160, 128], fffd1())

# A code point past U+10FFFF (F4 BF BF BF) is not legal.
law chk_too_big:
  U32

def chk_too_big():
  same_verdict([244, 191, 191, 191], fffd1())

# A lone continuation answers one U+FFFD per pair: 80 80 answers one.
law chk_lone_cont:
  U32

def chk_lone_cont():
  same_verdict([128, 128], fffd1())

# C0 80 is an overlong form of NUL: one U+FFFD, never a zero byte.
law chk_overlong:
  U32

def chk_overlong():
  same_verdict([192, 128], fffd1())

# A truncated 2-byte lead at the end is dropped, no U+FFFD.
law chk_trunc2:
  U32

def chk_trunc2():
  (b2u(String.is_empty(HTTP.x_utf8_decode([195])))
    * b2u(Bool.not(HTTP.x_utf8_ok([195]))) : U32)

# A truncated 3-byte sequence at the end is dropped, no U+FFFD.
law chk_trunc3:
  U32

def chk_trunc3():
  (b2u(String.is_empty(HTTP.x_utf8_decode([226, 130])))
    * b2u(Bool.not(HTTP.x_utf8_ok([226, 130]))) : U32)

# A valid 2-byte sequence still answers é.
law chk_valid2:
  U32

def chk_valid2():
  (b2u(String.eq(HTTP.x_utf8_decode([195, 169]), "é"))
    * b2u(HTTP.x_utf8_ok([195, 169])) : U32)

# A valid 4-byte sequence still answers one character.
law chk_valid4:
  U32

def chk_valid4():
  (b2u(String.eq(HTTP.x_utf8_decode([240, 159, 152, 128]), "😀"))
    * b2u(HTTP.x_utf8_ok([240, 159, 152, 128])) : U32)

law main:
  U32

def main():
  (chk_bad_cont2() + chk_bad_cont3() + chk_bad_cont4() + chk_surrogate()
    + chk_too_big() + chk_lone_cont() + chk_overlong() + chk_trunc2()
    + chk_trunc3() + chk_valid2() + chk_valid4() : U32)

#|11
