# lib (lib_httpx_hpack_huffman): HPACK string vectors (RFC 7541 Appendix B/C)
# over the H2 codec in lib/http2.bend: C.4.1 ":authority" "www.example.com"
# (f1 e3 ... f4 ff behind the 0x8c length byte), C.6.1 ":status" "302"
# (64 02), a raw string with no Huffman bit set, and the three fail-closed
# shapes (bad code, EOS in the middle, truncated). Pure layer, no IO.
# Ported from hpack_huffman.bend (same RFC bytes, same expectations) when the
# old H2 codec was retired; golden 1 iff all 8 vectors score.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The string layer is the one the codec uses: the length byte carries the
# Huffman bit, so the vectors go in whole, exactly as a peer sends them.

def str_is.go(r: Result<&1, &1, U32 & String, String & List<&2, U32>>, want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{p}:
      (s, rest) = p
      b2u(Bool.and(String.eq(s, want), U32.is_eq(HTTP.x_len32(rest), 0)))

def str_is(bs: List<&2, U32>, want: String) -> U32:
  str_is.go(HTTP2.x_str.dec.go(bs), want)

def str_fails.go(r: Result<&1, &1, U32 & String, String & List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      1
    case Done{p}:
      0

def str_fails(bs: List<&2, U32>) -> U32:
  str_fails.go(HTTP2.x_str.dec.go(bs))

def v1_www() -> U32:
  str_is([140, 241, 227, 194, 229, 242, 58, 107, 160, 171, 144, 244, 255], "www.example.com")

def v2_status() -> U32:
  str_is([130, 100, 2], "302")

def v3_raw() -> U32:
  str_is([3, 97, 98, 99], "abc")

def v4_bad_code() -> U32:
  str_fails([129, 255])

def v5_eos_mid() -> U32:
  str_fails([129, 0])

def v6_truncated() -> U32:
  str_fails([132, 255, 255, 255, 255])

# A Huffman :authority inside a request block still lands as a header, so the
# string layer is wired to the block layer (not just reachable on its own).

def req_blk() -> List<&2, U32>:
  [130, 134, 132, 65, 140, 241, 227, 194, 229, 242, 58, 107, 160, 171, 144, 244, 255]

def req_head(head: HTTP.ReqHead, ok: Bool) -> U32:
  match head:
    case HTTP.ReqHead{method, path, headers}:
      b2u(Bool.and(ok, Bool.and(String.eq(method, "GET"), String.eq(path, "/"))))

def v7_req_block_go(got: HTTP.ReqHead & Bool & HTTP.Tab) -> U32:
  match got:
    case (+h, +ok, t):
      req_head(h, ok)

def v7_req_block() -> U32:
  v7_req_block_go(HTTP2.x_req.got(HTTP2.x_req.decode(req_blk(), HTTP2.x_tab.empty())))

# Indexed ":status 302" (0x48) plus the Huffman literal from v2: the response
# side of the same two layers.

def resp_head(head: HTTP.Head, ok: Bool) -> U32:
  match head:
    case HTTP.Head{status, headers}:
      b2u(Bool.and(ok, U32.is_eq(status, 302)))

def v8_resp_block() -> U32:
  resp_head(HTTP2.x_resp.rh(HTTP2.x_resp.decode([72, 130, 100, 2], HTTP2.x_tab.empty())),
    HTTP2.x_resp.ok(HTTP2.x_resp.decode([72, 130, 100, 2], HTTP2.x_tab.empty())))

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (v1_www() + v2_status() + v3_raw() + v4_bad_code()
      + v5_eos_mid() + v6_truncated() + v7_req_block() + v8_resp_block() : U32)
    +pass : U32 = b2u(U32.is_eq(total, 8))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
