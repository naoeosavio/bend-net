# io (httpx_h2_url_pad): the URL reader and the padding check (task-062
# phase 7, findings 14 and 16).
#
# Pure vectors:
#   * https://host?x=1 is path "/?x=1", not a host with a query in it;
#   * https://[::1]:8443/x keeps the IPv6 literal whole and reads port
#     8443 (RFC 3986 section 3.2.2);
#   * https://[::1] reads the default port 443 and the path "/";
#   * a padded frame whose pad length passes its own payload is
#     Bad{1, "bad padding"}, and a pad inside the payload is a normal
#     frame.
#
# Golden 4.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# --- the URL reader ---

def url_eq(value: Bool & String & U32 & String, +host: String, +port: U32, +path: String) -> U32:
  match value:
    case (ok, h, p, pa):
      b2u(Bool.and(ok, Bool.and(String.eq(h, host), Bool.and(U32.is_eq(p, port), String.eq(pa, path)))))

def url_ok(r: Result<&1, &1, U32 & String, Bool & String & U32 & String>, +host: String, +port: U32, +path: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{value}:
      url_eq(value, host, port, path)

def query_t() -> U32:
  url_ok(HTTP2.h2_url.read("https://host?x=1"), "host", 443, "/?x=1")

def v6_port_t() -> U32:
  url_ok(HTTP2.h2_url.read("https://[::1]:8443/x"), "[::1]", 8443, "/x")

def v6_t() -> U32:
  url_ok(HTTP2.h2_url.read("https://[::1]"), "[::1]", 443, "/")

# --- the pad check ---

# DATA, PADDED, sid 1, declared length 3, pad length byte 200: the pad
# passes the payload.
def bad_pad_frame() -> List<&2, U32>:
  [0, 0, 3, 0, 8, 0, 0, 0, 1, 200, 104, 105]

# The same frame with pad length 1: one padding octet inside the payload.
def good_pad_frame() -> List<&2, U32>:
  [0, 0, 4, 0, 8, 0, 0, 0, 1, 1, 0, 104, 105]

def bad_pad(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Bad{code, msg}:
      U32.mul(b2u(U32.is_eq(code, 1)), b2u(String.eq(msg, "bad padding")))
    case _:
      0

def good_pad(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{unit, fin, rest}:
      b2u(U32.is_eq(HTTP.x_len32(unit), 13))
    case _:
      0

def bad_pad_t() -> U32:
  bad_pad(HTTP2.x_parse(bad_pad_frame()))

def good_pad_t() -> U32:
  good_pad(HTTP2.x_parse(good_pad_frame()))

def main() -> IO(U32):
  do IO<U32>:
    +total : U32 = (query_t() + v6_port_t() + v6_t() + bad_pad_t() + good_pad_t() : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|5
