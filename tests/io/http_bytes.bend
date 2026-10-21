# io (http_bytes): the shared core of the HTTP library (lib/http.bend).
#
# This is the regression net for the module every lane imports. After
# task-057 phase 1 the core owns the bytes leaves (x_len32, x_str_bytes,
# x_bytes_str, x_utf8_decode), the small string checks (has_crlf,
# has_crlf3, has_nul, nul1, all_digits) and the 25 Data types.
#
# Why the 32 KB body: x_utf8_decode is a tail loop, so the size must not
# matter. The legacy one-frame-per-byte decoder handled 16384 bytes and
# died at 32768, and that death is what the core's text lane cannot have.
# 32767 'a' plus é also proves that a multi-byte sequence at the end of a
# long body still answers one character.
#
# Answers: one per check. Golden 10.
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

# One U+FFFD: what the decoder answers for an aborted sequence.
law fffd1:
  String

def fffd1():
  SCon{Chr{65533}, SNil{}}

# Builds n copies of byte b in front of acc, tail-recursive.
# @unsafe: the U32 counts down with `n - 1`, which the structural
# check cannot see.
@unsafe
def fill.go(n: U32, acc: List<&2, U32>, +b: U32) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      fill.go((n - 1 : U32), b <> acc, b)

# 32767 'a' then é: 32769 bytes that decode to 32768 characters.
law big_body:
  List<&2, U32>

def big_body():
  fill.go(32767, [195, 169], 97)

# ASCII is one byte per character.
law chk_ascii:
  U32

def chk_ascii():
  b2u(String.eq(HTTP.x_utf8_decode([72, 105]), "Hi"))

# Every valid sequence length answers one character.
law chk_valid:
  U32

def chk_valid():
  (b2u(String.eq(HTTP.x_utf8_decode([195, 169]), "é"))
    * b2u(String.eq(HTTP.x_utf8_decode([226, 130, 172]), "€"))
    * b2u(String.eq(HTTP.x_utf8_decode([240, 159, 152, 128]), "😀")) : U32)

# A bad sequence answers one U+FFFD, never a partial character.
law chk_bad:
  U32

def chk_bad():
  b2u(String.eq(HTTP.x_utf8_decode([195, 65]), fffd1()))

# A 32 KB body decodes, and the multi-byte tail is one character.
law chk_big:
  U32

def chk_big():
  b2u(U32.is_eq(
    U32.from_nat(String.length(HTTP.x_utf8_decode(big_body()))), 32768))

# Text to bytes and back is the identity for ASCII.
law chk_roundtrip:
  U32

def chk_roundtrip():
  b2u(String.eq(HTTP.x_bytes_str(HTTP.x_str_bytes("Hi")), "Hi"))

# x_len32 counts without the Nat boxing.
law chk_len:
  U32

def chk_len():
  (b2u(U32.is_eq(HTTP.x_len32([1, 2, 3]), 3))
    * b2u(U32.is_eq(HTTP.x_len32([]), 0)) : U32)

# CR and LF are rejected, and a clean path is not.
law chk_crlf:
  U32

def chk_crlf():
  (b2u(HTTP.has_crlf("\r")) * b2u(HTTP.has_crlf("a\nb"))
    * b2u(Bool.not(HTTP.has_crlf("abc"))) : U32)

# has_crlf3 owns three fields at once; one bad field is enough.
law chk_crlf3:
  U32

def chk_crlf3():
  (b2u(HTTP.has_crlf3("a", "b", "\r"))
    * b2u(Bool.not(HTTP.has_crlf3("a", "b", "c"))) : U32)

# NUL is rejected, and a clean path is not.
law chk_nul:
  U32

def chk_nul():
  (b2u(HTTP.has_nul(String.concat(["a", HTTP.nul1(), "b"])))
    * b2u(Bool.not(HTTP.has_nul("abc"))) : U32)

# all_digits is the shared decimal check: the dns.bend quad octet and the
# http1.bend Content-Length both call it. The empty string answers True,
# because the SNil arm is the base case. A sign or a space is not a digit.
law chk_digits:
  U32

def chk_digits():
  (b2u(HTTP.all_digits("0123456789")) * b2u(HTTP.all_digits(""))
    * b2u(Bool.not(HTTP.all_digits("12a")))
    * b2u(Bool.not(HTTP.all_digits("-1")))
    * b2u(Bool.not(HTTP.all_digits("1 "))) : U32)

law main:
  U32

def main():
  (chk_ascii() + chk_valid() + chk_bad() + chk_big() + chk_roundtrip()
    + chk_len() + chk_crlf() + chk_crlf3() + chk_nul() + chk_digits() : U32)

#|10
