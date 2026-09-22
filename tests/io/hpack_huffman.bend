# HPACK huffman vectors (RFC 7541 Appendix B/C): C.4.1 :authority
# "www.example.com" (f1 e3 ... f4 ff), C.6.1 :status "302" (64 02),
# raw-string no-regression, and fail-closed errors (bad code,
# truncated, EOS). Pure layer, no IO. Golden 11111111.
import Base
import ../../lib/http2.bend as H2

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law str_ok:
  for r: Result<&1, &1, U32 & String, String & List<&2, U32>>
  for want: String
  U32

def str_ok(r, want):
  match r:
    case Fail{e}:
      0
    case Done{(s, rest)}:
      b2u(String.eq(s, want))

law is_fail_str:
  for r: Result<&1, &1, U32 & String, String & List<&2, U32>>
  U32

def is_fail_str(r):
  match r:
    case Fail{e}:
      1
    case Done{pair}:
      0

law req_ok:
  for r: Result<&1, &1, U32 & String, H2.H2ReqHead>
  U32

def req_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{rh}:
      match rh:
        case H2.H2ReqHead{+method, +path, +headers}:
          b2u(Bool.and(String.eq(method, "GET"), String.eq(path, "/")))

law head_ok:
  for r: Result<&1, &1, U32 & String, H2.H2Head>
  U32

def head_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{hd}:
      match hd:
        case H2.H2Head{+status, +headers}:
          b2u(U32.is_eq(status, 302))

law main:
  U32

def main():
  +a = str_ok(H2.hpack_str.dec.go([140, 241, 227, 194, 229, 242, 58, 107, 160, 171, 144, 244, 255]), "www.example.com")
  +b = str_ok(H2.hpack_str.dec.go([130, 100, 2]), "302")
  +c = str_ok(H2.hpack_str.dec.go([3, 97, 98, 99]), "abc")
  +d = req_ok(H2.h2_reqhead.of(H2.h2_reqhead.decode([130, 134, 132, 65, 140, 241, 227, 194, 229, 242, 58, 107, 160, 171, 144, 244, 255], H2.hp_empty())))
  +e = head_ok(H2.h2_head.of(H2.h2_head.decode([72, 130, 100, 2], H2.hp_empty())))
  +f1 = is_fail_str(H2.hpack_str.dec.go([129, 255]))
  +f2 = is_fail_str(H2.hpack_str.dec.go([129, 0]))
  +g = is_fail_str(H2.hpack_str.dec.go([132, 255, 255, 255, 255]))
  (a * 10000000 + b * 1000000 + c * 100000 + d * 10000 + e * 1000 + f1 * 100 + f2 * 10 + g : U32)

#|11111111
