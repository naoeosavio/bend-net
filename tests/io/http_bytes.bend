# io (http_bytes): the shared byte leaves of the HTTP core.
#
# The core module (lib/http.bend after task-057 phase 1) owns the four
# leaves that every lane uses: decode (bytes to text), to_string (the
# chunked decode), has_crlf and has_nul. This file is their regression
# net and it moves with them: only the import line changes when the
# leaves leave lib/http1.bend.
#
# Why the size matters: decode is one frame per byte, so a body past
# ~16 KB dies on the machine stack, and to_string exists to fix that --
# it cuts the bytes into 8 KB pieces and decodes each piece. A cut may
# never land in front of a continuation byte, so a multi-byte sequence
# that straddles a piece edge must still answer one character. That is
# the seam check below, and the only reason the body is 32 KB.
#
# Answers: one per check. Golden 7.
import Base
import ../../lib/http1.bend as HTTP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

# One U+FFFD: what decode answers for one aborted sequence. A bad
# continuation byte is consumed with its lead, the rule both HTTP
# decoders use.
law fffd1:
  String

def fffd1():
  SCon{Chr{65533}, SNil{}}

# One NUL character, to build the string has_nul must reject.
law nul1:
  String

def nul1():
  String.from_list([Chr{0}])

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

# 32767 'a' then é, so the 2-byte sequence straddles the piece edge at
# 16384. 32769 bytes decode to 32768 characters with no split.
law seam_body:
  List<&2, U32>

def seam_body():
  fill.go(32767, [195, 169], 97)

# ASCII is one byte per character.
law chk_ascii:
  U32

def chk_ascii():
  b2u(String.eq(HTTP.decode([72, 105]), "Hi"))

# Every valid sequence length answers one character.
law chk_valid:
  U32

def chk_valid():
  (b2u(String.eq(HTTP.decode([195, 169]), "é"))
    * b2u(String.eq(HTTP.decode([226, 130, 172]), "€"))
    * b2u(String.eq(HTTP.decode([240, 159, 152, 128]), "😀")) : U32)

# A bad sequence answers one U+FFFD, never a partial character: the bad
# continuation byte rides with its lead, and a lead at the end answers
# one U+FFFD by itself.
law chk_bad:
  U32

def chk_bad():
  (b2u(String.eq(HTTP.decode([195, 65]), fffd1()))
    * b2u(String.eq(HTTP.decode([195]), fffd1())) : U32)

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
  (b2u(HTTP.has_nul(String.concat(["a", nul1(), "b"])))
    * b2u(Bool.not(HTTP.has_nul("abc"))) : U32)

# to_string is the chunked decode: a 32 KB body decodes, and a 2-byte
# sequence that straddles a piece edge still answers one character.
law chk_seam:
  U32

def chk_seam():
  (b2u(U32.is_eq(
      U32.from_nat(String.length(HTTP.to_string(seam_body()))), 32768))
    * b2u(String.eq(HTTP.to_string([72, 105]), "Hi")) : U32)

law main:
  U32

def main():
  (chk_ascii() + chk_valid() + chk_bad() + chk_crlf() + chk_crlf3()
    + chk_nul() + chk_seam() : U32)

#|7
