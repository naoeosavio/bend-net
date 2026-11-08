# io (httpx_h2_static_table): the HPACK static table has one source
# (task-062 phase 7). x_static.go answers the 61 pairs of RFC 7541
# appendix A, and x_hdr.full only shapes the HdrGot from it. This test
# pins every pair against a literal copy, so an edit to the table shows
# up here and not on the wire.
#
# Golden 61: one point per pair.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The 61 pairs, in index order (RFC 7541 appendix A).
def want() -> List<&2, HTTP.Hdr>:
  [  HTTP.Hdr{":authority", ""},
  HTTP.Hdr{":method", "GET"},
  HTTP.Hdr{":method", "POST"},
  HTTP.Hdr{":path", "/"},
  HTTP.Hdr{":path", "/index.html"},
  HTTP.Hdr{":scheme", "http"},
  HTTP.Hdr{":scheme", "https"},
  HTTP.Hdr{":status", "200"},
  HTTP.Hdr{":status", "204"},
  HTTP.Hdr{":status", "206"},
  HTTP.Hdr{":status", "304"},
  HTTP.Hdr{":status", "400"},
  HTTP.Hdr{":status", "404"},
  HTTP.Hdr{":status", "500"},
  HTTP.Hdr{"accept-charset", ""},
  HTTP.Hdr{"accept-encoding", "gzip, deflate"},
  HTTP.Hdr{"accept-language", ""},
  HTTP.Hdr{"accept-ranges", ""},
  HTTP.Hdr{"accept", ""},
  HTTP.Hdr{"access-control-allow-origin", ""},
  HTTP.Hdr{"age", ""},
  HTTP.Hdr{"allow", ""},
  HTTP.Hdr{"authorization", ""},
  HTTP.Hdr{"cache-control", ""},
  HTTP.Hdr{"content-disposition", ""},
  HTTP.Hdr{"content-encoding", ""},
  HTTP.Hdr{"content-language", ""},
  HTTP.Hdr{"content-length", ""},
  HTTP.Hdr{"content-location", ""},
  HTTP.Hdr{"content-range", ""},
  HTTP.Hdr{"content-type", ""},
  HTTP.Hdr{"cookie", ""},
  HTTP.Hdr{"date", ""},
  HTTP.Hdr{"etag", ""},
  HTTP.Hdr{"expect", ""},
  HTTP.Hdr{"expires", ""},
  HTTP.Hdr{"from", ""},
  HTTP.Hdr{"host", ""},
  HTTP.Hdr{"if-match", ""},
  HTTP.Hdr{"if-modified-since", ""},
  HTTP.Hdr{"if-none-match", ""},
  HTTP.Hdr{"if-range", ""},
  HTTP.Hdr{"if-unmodified-since", ""},
  HTTP.Hdr{"last-modified", ""},
  HTTP.Hdr{"link", ""},
  HTTP.Hdr{"location", ""},
  HTTP.Hdr{"max-forwards", ""},
  HTTP.Hdr{"proxy-authenticate", ""},
  HTTP.Hdr{"proxy-authorization", ""},
  HTTP.Hdr{"range", ""},
  HTTP.Hdr{"referer", ""},
  HTTP.Hdr{"refresh", ""},
  HTTP.Hdr{"retry-after", ""},
  HTTP.Hdr{"server", ""},
  HTTP.Hdr{"set-cookie", ""},
  HTTP.Hdr{"strict-transport-security", ""},
  HTTP.Hdr{"transfer-encoding", ""},
  HTTP.Hdr{"user-agent", ""},
  HTTP.Hdr{"vary", ""},
  HTTP.Hdr{"via", ""},
  HTTP.Hdr{"www-authenticate", ""},
  ]

# The i-th pair, 1-based; a "?" pair past the end.
@unsafe
def nth(i: U32, xs: List<&2, HTTP.Hdr>) -> HTTP.Hdr:
  match i xs:
    case 1 h <> t:
      h
    case 1 Nil{}:
      HTTP.Hdr{"?", "?"}
    case _ h <> t:
      nth((i - 1 : U32), t)
    case _ Nil{}:
      HTTP.Hdr{"?", "?"}

def pair_eq(got: String & String, want1: HTTP.Hdr) -> Bool:
  (n, v) = got
  match want1:
    case HTTP.Hdr{n2, v2}:
      Bool.and(String.eq(n, n2), String.eq(v, v2))

@unsafe
def chk(+i: U32, +xs: List<&2, HTTP.Hdr>) -> U32:
  match i:
    case 0:
      0
    case _:
      (b2u(pair_eq(HTTP2.x_static.go(i), nth(i, xs))) + chk((i - 1 : U32), xs) : U32)

# A pair the frame lane reads comes from the same table.
def via_full_go(r: Result<&1, &1, U32 & String, HTTP.HdrGot>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{HTTP.HdrGot{+n, +v, +r, +t}}:
      b2u(Bool.and(String.eq(n, ":authority"), String.eq(v, "")))

def via_full() -> U32:
  via_full_go(HTTP2.x_hdr.full(1, Nil{}, HTTP2.x_tab.empty()))

def main() -> IO(U32):
  do IO<U32>:
    +total : U32 = (chk(61, want()) : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|61
