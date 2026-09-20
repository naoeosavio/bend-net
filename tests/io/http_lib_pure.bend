# lib (lib_http_pure): the pure layer of lib/http.bend -- url parsing,
# case-insensitive header lookup, request/response roundtrips, the
# keep-alive decision, chunked decoding and the Bytes UTF-8 roundtrip.
# Request bodies are Strings here (not U32 lengths); lengths ride the
# Content-Length header instead.
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

law url_score:
  for url: Bool & String & U32 & String
  for sec: Bool
  for h: String
  for pt: U32
  for pa: String
  U32

def url_score(url, sec, h, pt, pa):
  (secure, host, port, path) = url
  (b2u(Cmp.is_eq(Bool.cmp(secure, sec))) + b2u(String.eq(host, h)) + b2u(U32.is_eq(port, pt)) + b2u(String.eq(path, pa)) : U32)

law chk_https:
  for u: Result<&1, &1, (U32 & String), Bool & String & U32 & String>
  U32

def chk_https(u):
  match u:
    case Done{url}:
      url_score(url, True{}, "example.com", 443, "/")
    case Fail{(c, e)}:
      0

law chk_http:
  for u: Result<&1, &1, (U32 & String), Bool & String & U32 & String>
  U32

def chk_http(u):
  match u:
    case Done{url}:
      url_score(url, False{}, "localhost", 8080, "/echo?q=1")
    case Fail{(c, e)}:
      0

law chk_bad:
  for u: Result<&1, &1, (U32 & String), Bool & String & U32 & String>
  U32

def chk_bad(u):
  match u:
    case Done{url}:
      0
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))

law chk_url:
  U32

def chk_url():
  (chk_https(HTTP.read_url("https://example.com/")) * 100 + chk_http(HTTP.read_url("http://localhost:8080/echo?q=1")) * 10 + chk_bad(HTTP.read_url("ftp://x/")) : U32)

law hdr_score.go:
  for hs: List<&1, (String & String)>
  for acc: U32
  U32

def hdr_score.go(hs, acc):
  match hs:
    case Nil{}:
      acc
    case (n, v) <> t:
      +nn = n
      +vv = String.trim(v)
      hdr_score.go(t, (acc + b2u(Bool.and(HTTP.eq_ci(nn, "Host"), String.eq(vv, "x"))) + b2u(Bool.and(HTTP.eq_ci(nn, "Accept"), String.eq(vv, "*/*"))) : U32))

law req_score:
  for req: String & String & List<&1, (String & String)> & String
  U32

def req_score(req):
  (m, p, hs, b) = req
  (b2u(String.eq(m, "GET")) + b2u(String.eq(p, "/a")) + hdr_score.go(hs, 0) : U32)

law chk_parse.rd:
  for r: Result<&1, &1, (U32 & String), String & String & List<&1, (String & String)> & String>
  U32

def chk_parse.rd(r):
  match r:
    case Done{req}:
      req_score(req)
    case Fail{(c, e)}:
      0

law chk_parse:
  U32

def chk_parse():
  chk_parse.rd(HTTP.read_request("GET /a HTTP/1.1\r\nhOsT: x\r\nAccept:  */*  \r\n\r\n"))

law rt_score:
  for req: String & String & List<&1, (String & String)> & String
  U32

def rt_score(req):
  (m, p, hs, b) = req
  (b2u(String.eq(m, "POST")) + b2u(String.eq(p, "/echo")) + b2u(String.eq(b, "hello")) + b2u(String.eq(HTTP.get_header("", "content-length", hs), "5")) : U32)

law chk_roundtrip.rd:
  for r: Result<&1, &1, (U32 & String), String & String & List<&1, (String & String)> & String>
  U32

def chk_roundtrip.rd(r):
  match r:
    case Done{req}:
      rt_score(req)
    case Fail{(c, e)}:
      0

law chk_roundtrip.show:
  for r: Result<&1, &1, (U32 & String), String>
  U32

def chk_roundtrip.show(r):
  match r:
    case Done{text}:
      chk_roundtrip.rd(HTTP.read_request(text))
    case Fail{(c, e)}:
      0

law chk_roundtrip:
  U32

def chk_roundtrip():
  chk_roundtrip.show(HTTP.show_request("POST", "/echo", [("Host", "h")], "hello"))

law resp_status_is:
  for resp: U32 & List<&1, (String & String)> & String
  for want: U32
  U32

def resp_status_is(resp, want):
  (s, hs, b) = resp
  b2u(U32.is_eq(s, want))

law chk_response.rd:
  for r: Result<&1, &1, (U32 & String), U32 & List<&1, (String & String)> & String>
  U32

def chk_response.rd(r):
  match r:
    case Done{resp}:
      resp_status_is(resp, 404)
    case Fail{(c, e)}:
      0

law chk_response.show:
  for r: Result<&1, &1, (U32 & String), String>
  U32

def chk_response.show(r):
  match r:
    case Done{text}:
      chk_response.rd(HTTP.read_response(text))
    case Fail{(c, e)}:
      0

law chk_response:
  U32

def chk_response():
  chk_response.show(HTTP.show_response(404, [], "oops"))

law chk_bad_req.rd:
  for r: Result<&1, &1, (U32 & String), String & String & List<&1, (String & String)> & String>
  U32

def chk_bad_req.rd(r):
  match r:
    case Done{req}:
      0
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))

law chk_bad_req:
  U32

def chk_bad_req():
  chk_bad_req.rd(HTTP.read_request("GARBAGE\r\n\r\n"))

law chk_keep:
  U32

def chk_keep():
  a = b2u(HTTP.keep_alive(True{}, []))
  b = b2u(HTTP.keep_alive(True{}, [("Connection", "close")]))
  c = b2u(HTTP.keep_alive(False{}, []))
  d = b2u(HTTP.keep_alive(False{}, [("cOnNeCtIoN", " Keep-Alive ")]))
  (a + b2u(U32.is_eq(b, 0)) + b2u(U32.is_eq(c, 0)) + d : U32)

law chk_chunked.eq:
  for r: Result<&1, &1, (U32 & String), List<&2, U32>>
  U32

def chk_chunked.eq(r):
  match r:
    case Done{bs}:
      b2u(String.eq(HTTP.decode(bs), "Wikipedia"))
    case Fail{(c, e)}:
      0

law chk_chunked.bad:
  for r: Result<&1, &1, (U32 & String), List<&2, U32>>
  U32

def chk_chunked.bad(r):
  match r:
    case Done{bs}:
      0
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))

law chk_chunked:
  U32

def chk_chunked():
  (chk_chunked.eq(HTTP.unchunk(HTTP.encode("4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"))) * 10 + chk_chunked.bad(HTTP.unchunk(HTTP.encode("4\r\nWi"))) : U32)

law chk_pack.rd:
  for r: U32 & List<&2, U32>
  U32

def chk_pack.rd(r):
  (n, data) = r
  (b2u(U32.is_eq(n, 10)) + b2u(String.eq(HTTP.decode(data), "héllo ✓")) : U32)

law chk_pack:
  U32

def chk_pack():
  chk_pack.rd(HTTP.from_string("héllo ✓"))

law chk_vr.bad.rd:
  for r: Result<&1, &1, (U32 & String), String & String & List<&1, (String & String)> & String>
  U32

def chk_vr.bad.rd(r):
  match r:
    case Done{req}:
      0
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))

law chk_vr.reason:
  for st: U32
  for want: String
  U32

def chk_vr.reason(st, want):
  b2u(String.eq(HTTP.reason(st), want))

law chk_vr:
  U32

def chk_vr():
  (chk_vr.bad.rd(HTTP.read_request("GET / HTTP/1.0\r\n\r\n")) + chk_vr.reason(418, "I'm a teapot") + chk_vr.reason(503, "Service Unavailable") + chk_vr.reason(999, "Status") : U32)

law main:
  U32

def main():
  (chk_vr() * 10000000 + chk_url() * 1000000 + chk_parse() * 100000 + chk_roundtrip() * 10000 + chk_response() * 1000 + chk_bad_req() * 100 + chk_keep() * 10 + chk_chunked() + chk_pack() : U32)

#|481441153
