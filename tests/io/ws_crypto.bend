# lib (ws_crypto): SHA-1 FIPS vectors plus base64 roundtrips.
# Pure crypto only, no net. Each check below must be 1.
import Base
import ../../lib/sha1.bend as SHA1
import ../../lib/b64.bend as B64

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law eq_list:
  for xs: List<&2, U32>
  for ys: List<&2, U32>
  U32

def eq_list(xs, ys):
  match xs:
    case Nil{}:
      match ys:
        case Nil{}:
          1
        case _ <> _:
          0
    case h1 <> t1:
      match ys:
        case Nil{}:
          0
        case h2 <> t2:
          (b2u(U32.is_eq(h1, h2)) * eq_list(t1, t2) : U32)

law is_fail400:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  U32

def is_fail400(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))
    case Done{bs}:
      0

law chk_sha_abc:
  U32

def chk_sha_abc():
  eq_list(SHA1.sha1([97, 98, 99]), [169, 153, 62, 54, 71, 6, 129, 106, 186, 62, 37, 113, 120, 80, 194, 108, 156, 208, 216, 157])

law chk_sha_empty:
  U32

def chk_sha_empty():
  eq_list(SHA1.sha1([]), [218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9])

law chk_b64_hi:
  U32

def chk_b64_hi():
  b2u(String.eq(B64.encode([72, 105]), "SGk="))

law chk_b64_pad2:
  U32

def chk_b64_pad2():
  b2u(String.eq(B64.encode([65]), "QQ=="))

law chk_b64_pad1:
  U32

def chk_b64_pad1():
  b2u(String.eq(B64.encode([65, 66]), "QUI="))

law unwrap_decode:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap_decode(r):
  match r:
    case Fail{e}:
      [255]
    case Done{bs}:
      bs

law chk_b64_round:
  U32

def chk_b64_round():
  eq_list(unwrap_decode(B64.decode("SGk=")), [72, 105])

law chk_b64_bad:
  U32

def chk_b64_bad():
  (is_fail400(B64.decode("!!!=")) + is_fail400(B64.decode("ABC")) : U32)

law main:
  U32

def main():
  (chk_sha_abc() + chk_sha_empty() + chk_b64_hi() + chk_b64_pad2() + chk_b64_pad1() + chk_b64_round() + chk_b64_bad() : U32)

#|8
