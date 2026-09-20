# lib (lib_http_sec): the fail-closed surface of lib/http.bend. Every
# injection, oversize and malformed input below must Fail with the
# coded status; a missing header answers its default.
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

law fail_text:
  for r: Result<&1, &1, (U32 & String), String>
  for want: U32
  U32

def fail_text(r, want):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{text}:
      0

law fail_req:
  for r: Result<&1, &1, (U32 & String), String & String & List<&1, (String & String)> & String>
  for want: U32
  U32

def fail_req(r, want):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{req}:
      0

law fail_url:
  for r: Result<&1, &1, (U32 & String), Bool & String & U32 & String>
  for want: U32
  U32

def fail_url(r, want):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{u}:
      0

law fail_bytes:
  for r: Result<&1, &1, (U32 & String), List<&2, U32>>
  for want: U32
  U32

def fail_bytes(r, want):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{bs}:
      0

law chk_inject_method:
  U32

def chk_inject_method():
  fail_text(HTTP.show_request("GET\r\nEvil: 1", "/a", [], ""), 400)

law chk_inject_path:
  U32

def chk_inject_path():
  fail_text(HTTP.show_request("GET", "/a\r\nEvil: 1", [], ""), 400)

law chk_inject_header:
  U32

def chk_inject_header():
  fail_text(HTTP.show_request("GET", "/a", [("X", "v\r\nEvil: 1")], ""), 400)

law chk_inject_name:
  U32

def chk_inject_name():
  fail_text(HTTP.show_request("GET", "/a", [("X\r\nEvil", "v")], ""), 400)

law chk_inject_body:
  U32

def chk_inject_body():
  fail_text(HTTP.show_response(200, [], "a\r\nb"), 400)

law chk_oversize:
  U32

def chk_oversize():
  fail_req(HTTP.read_request(String.repeat("a", 20000n) ++ "\r\n\r\n"), 413)

law chk_garbage:
  U32

def chk_garbage():
  fail_req(HTTP.read_request("GARBAGE\r\n\r\n"), 400)

law chk_port_zero:
  U32

def chk_port_zero():
  fail_url(HTTP.read_url("http://h:0/"), 400)

law chk_port_alpha:
  U32

def chk_port_alpha():
  fail_url(HTTP.read_url("http://h:abc/"), 400)

law chk_no_host:
  U32

def chk_no_host():
  fail_url(HTTP.read_url("http:///path"), 400)

law chk_bad_status:
  U32

def chk_bad_status():
  (fail_text(HTTP.show_response(99, [], ""), 400) + fail_text(HTTP.show_response(600, [], ""), 400) : U32)

law chk_truncated:
  U32

def chk_truncated():
  fail_bytes(HTTP.unchunk(HTTP.encode("5\r\nhe")), 400)

law chk_default:
  U32

def chk_default():
  b2u(String.eq(HTTP.get_header("dflt", "X-Missing", [("A", "b")]), "dflt"))

law chk_nul_host:
  U32

def chk_nul_host():
  fail_url(HTTP.read_url("http://" ++ String.from_list([Chr{0}]) ++ "h/"), 400)

law main:
  U32

def main():
  (chk_inject_method() + chk_inject_path() + chk_inject_header() + chk_inject_name() + chk_inject_body() + chk_oversize() + chk_garbage() + chk_port_zero() + chk_port_alpha() + chk_no_host() + chk_bad_status() + chk_truncated() + chk_default() + chk_nul_host() : U32)

#|15
