# lib (rfc_httpx): RFC conformance over the deployed HTTP module —
# lib/httpx.bend, imported as HTTPX (the names the importers call).
#
# Pure only: no socket, no TLS. Every expected value is written
# longhand from the RFC section named next to it, never captured from
# the implementation; call shapes mirror the already-green
# tests/io/httpx_miniunit.bend, only the asserted values are new. The
# live leg of the same contract is tests/rfc/h1_oracle.js and
# tests/rfc/h2_oracle.js (node and bun).
#
# Groups: the ASCII byte lane pin (the H1 lane is code points, real
# UTF-8 lives in wsm), the H2 preface (RFC 9113 section 3.4), frame
# write/parse + short NeedMore + oversize Bad 413 (RFC 9113 section
# 4.1), HPACK req/resp round trips (RFC 7541 section 5.1), the H1 cut,
# request parse + version gate, render CRLF refusal (RFC 9112 section
# 3.2), framing pieces, the RFC 9112 section 7.1 chunked body, the 200
# first line and the URL gates. Golden 1 iff every check is 1.
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def u32_is(got: U32, want: U32) -> U32:
  b2u(U32.is_eq(got, want))

def bool_is(a: Bool, b: Bool) -> U32:
  match a b:
    case True{} True{}:
      1
    case False{} False{}:
      1
    case _ _:
      0

def same(got: List<&2, U32>, want: List<&2, U32>) -> U32:
  b2u(U32.is_eq(HTTPX.x_eq(got, want), 1))

def str_is(got: String, want: String) -> U32:
  b2u(String.eq(got, want))

# The byte lane is ASCII-only by design: "é" (U+00E9) rides as the raw
# code point 233, not as UTF-8 [195, 169] (that encoding is
# wsm_utf8_encode's job, pinned in tests/rfc/rfc_wsm.bend).
def ascii_t() -> U32:
  (same(HTTPX.x_str_bytes("é"), [233])
    + str_is(HTTPX.x_bytes_str([72, 105]), "Hi") : U32)

# RFC 9113 section 3.4: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".
def preface_t() -> U32:
  same(HTTPX.x_preface(), [80, 82, 73, 32, 42, 32, 72, 84, 84, 80,
    47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10])

# Frames, RFC 9113 section 4.1: write/parse identity, short header
# stays NeedMore, length past 65535 is Bad 413.
def got_is.go(out: HTTPX.UnitOut, unit: List<&2, U32>,
  rest: List<&2, U32>) -> U32:
  match out:
    case HTTPX.Got{g, fin, r}:
      (same(g, unit) + same(r, rest) : U32)
    case HTTPX.NeedMore{missing, rest}:
      0
    case HTTPX.End{rest}:
      0
    case HTTPX.Bad{code, msg}:
      0

def got_is(bs: List<&2, U32>, unit: List<&2, U32>,
  rest: List<&2, U32>) -> U32:
  got_is.go(HTTPX.x_parse(bs), unit, rest)

def is_need.go(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.Got{unit, fin, rest}:
      0
    case HTTPX.NeedMore{missing, rest}:
      1
    case HTTPX.End{rest}:
      0
    case HTTPX.Bad{code, msg}:
      0

def is_need(bs: List<&2, U32>) -> U32:
  is_need.go(HTTPX.x_parse(bs))

def is_bad.go(out: HTTPX.UnitOut, code: U32) -> U32:
  match out:
    case HTTPX.Got{unit, fin, rest}:
      0
    case HTTPX.NeedMore{missing, rest}:
      0
    case HTTPX.End{rest}:
      0
    case HTTPX.Bad{c, msg}:
      u32_is(c, code)

def is_bad(bs: List<&2, U32>, code: U32) -> U32:
  is_bad.go(HTTPX.x_parse(bs), code)

def frame_t() -> U32:
  +f1 = HTTPX.x_frame_write(1, 4, 1, [10, 20])
  (got_is(f1, f1, Nil{}) + is_need([0, 0, 3, 0])
    + is_bad([1, 0, 0, 0, 0, 0, 0, 0, 1], 413) : U32)

# HPACK: literal block decodes with method/path (:status) lifted.
# Call-it-twice shape is tests/io/httpx_miniunit.bend's (a +Result
# through the alias is rejected, decode is pure).
def req_blk() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.Hdr{":method", "POST"},
    HTTPX.Hdr{":path", "/echo"}])

def req_go(head: HTTPX.ReqHead, ok: Bool) -> U32:
  match head:
    case HTTPX.ReqHead{method, path, headers}:
      b2u(Bool.and(ok, Bool.and(String.eq(method, "POST"),
        String.eq(path, "/echo"))))

def req_t() -> U32:
  req_go(HTTPX.x_req.rh(HTTPX.x_req.decode(req_blk(),
    HTTPX.x_tab.empty())), HTTPX.x_req.ok(HTTPX.x_req.decode(req_blk(),
    HTTPX.x_tab.empty())))

def resp_blk() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.Hdr{":status", "200"},
    HTTPX.Hdr{"content-type", "text/plain"}])

def resp_go(head: HTTPX.Head, ok: Bool) -> U32:
  match head:
    case HTTPX.Head{status, headers}:
      b2u(Bool.and(ok, U32.is_eq(status, 200)))

def resp_t() -> U32:
  resp_go(HTTPX.x_resp.rh(HTTPX.x_resp.decode(resp_blk(),
    HTTPX.x_tab.empty())), HTTPX.x_resp.ok(HTTPX.x_resp.decode(resp_blk(),
    HTTPX.x_tab.empty())))

def hpack_t() -> U32:
  (req_t() + resp_t() : U32)

# H1 cut (RFC 9112 section 2.2).
def cut_head() -> List<&2, U32>:
  [71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49,
    13, 10, 13, 10]

def cut_t() -> U32:
  (bool_is(HTTPX.x_h1.split_found(HTTPX.x_h1.split(cut_head())),
      True{})
    + bool_is(HTTPX.x_h1.split_found(HTTPX.x_h1.split([71, 69,
      84])), False{})
    + same(HTTPX.x_h1.split_head(HTTPX.x_h1.split(cut_head())),
      cut_head()) : U32)

# Request parse + version gate + render refusal (RFC 9112 3.2).
def render_fails.go(r: Result<&1, &1, U32 & String, List<&2, U32>>,
  code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, msg) = e
      u32_is(c, code)
    case Done{bs}:
      0

def render_fails(code: U32) -> U32:
  render_fails.go(HTTPX.x_h1.render_req("BAD\r\nX", "/", "h", 80,
    Nil{}, Nil{}), code)

def tok_done.go(r: Result<&1, &1, U32 & String,
  String & String & String & Bool>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{q}:
      1

def head_fails.go(r: Result<&1, &1, U32 & String, HTTPX.ReqHead>,
  code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, msg) = e
      u32_is(c, code)
    case Done{head}:
      0

def head_method.go(r: Result<&1, &1, U32 & String, HTTPX.ReqHead>,
  want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{head}:
      match head:
        case HTTPX.ReqHead{method, path, headers}:
          str_is(method, want)

def parse_t() -> U32:
  (render_fails(400)
    + tok_done.go(HTTPX.x_h1.req_tok(["GET", "/", "HTTP/1.1"]))
    + head_fails.go(HTTPX.x_h1.req_head(HTTPX.x_h1.req_tok(
      ["GET", "/a", "HTTP/2.0"])), 400)
    + head_method.go(HTTPX.x_h1.req_head(HTTPX.x_h1.req_tok(
      ["POST", "/", "HTTP/1.1"])), "POST") : U32)

# Framing pieces: exact CL, chunked flag, no-body rule.
def cl_headers() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Content-Length", "5"}]

def both_headers() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Content-Length", "5"},
    HTTPX.Hdr{"Transfer-Encoding", "chunked"}]

def framing_t() -> U32:
  (u32_is(HTTPX.x_h1.cl_of(cl_headers()), 5)
    + bool_is(HTTPX.x_h1.is_chunked(both_headers()), True{})
    + bool_is(HTTPX.x_h1.is_chunked(cl_headers()), False{})
    + bool_is(HTTPX.x_h1.no_body("HEAD", 200), True{})
    + bool_is(HTTPX.x_h1.no_body("GET", 204), True{})
    + bool_is(HTTPX.x_h1.no_body("GET", 200), False{}) : U32)

# RFC 9112 section 7.1: 4/Wiki + 5;ext=1/pedia + terminator.
def chunked_body() -> List<&2, U32>:
  [52, 13, 10, 87, 105, 107, 105, 13, 10, 53, 59, 101, 120, 116,
    61, 49, 13, 10, 112, 101, 100, 105, 97, 13, 10, 48, 13, 10, 13, 10]

def unchunk_is.go(r: Result<&1, &1, U32 & String, List<&2, U32>>,
  want: List<&2, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{out}:
      same(out, want)

def unchunk_fails.go(r: Result<&1, &1, U32 & String,
  List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      1
    case Done{out}:
      0

def chunked_t() -> U32:
  (unchunk_is.go(HTTPX.x_h1.unchunk(chunked_body()), [87, 105, 107,
      105, 112, 101, 100, 105, 97])
    + unchunk_fails.go(HTTPX.x_h1.unchunk([52, 13, 10, 87, 105])) : U32)

# The 200 first line, read back off the rendered head (lines keep the
# trailing CR, so trim is part of the read-back — same as req_valid).
def status_t() -> U32:
  str_is(String.trim(HTTPX.x_h1.first_line(
    HTTPX.x_h1.head_lines(HTTPX.x_h1.show_resp_head(200, Nil{})))),
    "HTTP/1.1 200 OK")

# URL gates: explicit port, scheme flag, space-host refusal.
def url_fails.go(r: Result<&1, &1, U32 & String,
  Bool & String & U32 & String>) -> U32:
  match r:
    case Fail{e}:
      1
    case Done{u}:
      0

def url_port.go(r: Result<&1, &1, U32 & String,
  Bool & String & U32 & String>, want: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{u}:
      (secure, host, port, path) = u
      u32_is(port, want)

def url_secure.go(r: Result<&1, &1, U32 & String,
  Bool & String & U32 & String>, want: Bool) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{u}:
      (secure, host, port, path) = u
      bool_is(secure, want)

def url_t() -> U32:
  (url_port.go(HTTPX.httpx_url.read_url("https://example.com:8080/a"),
      8080)
    + url_secure.go(HTTPX.httpx_url.read_url("https://example.com/a"),
      True{})
    + url_secure.go(HTTPX.httpx_url.read_url("http://example.com/a"),
      False{})
    + url_fails.go(HTTPX.httpx_url.read_url("https://exa mple.com/a")) : U32)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (ascii_t() + preface_t() + frame_t() + hpack_t()
      + cut_t() + parse_t() + framing_t() + chunked_t() + status_t()
      + url_t() : U32)
    +want : U32 = (2 + 1 + 4 + 2 + 3 + 4 + 6 + 2 + 1 + 4 : U32)
    +pass : U32 = u32_is(total, want)
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
