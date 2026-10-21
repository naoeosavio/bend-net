# lib (lib_httpx_read_url): pure vectors for httpx_url.read_url (Phase 9)
# plus the top-level read_url wrapper (task-036 phase 4).
# No IO, no TLS: the URL layer ported from the retired HTTP/1.1 module
# must parse exactly like the original (same splits, same defaults, same
# Fail 400 codes). Golden 1 iff all 12 vectors score (9th exercises trim).
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bool_eq(a: Bool, b: Bool) -> Bool:
  match a b:
    case True{} True{}:
      True{}
    case False{} False{}:
      True{}
    case _ _:
      False{}

def url_ok4(port_ok: Bool, path_ok: Bool, host_ok: Bool, sec_ok: Bool) -> U32:
  b2u(Bool.and(Bool.and(port_ok, path_ok), Bool.and(host_ok, sec_ok)))

def url_ok_tuple(u: Bool & String & U32 & String, secure: Bool, host: String, port: U32, path: String) -> U32:
  match u:
    case (s, h, p, pa):
      url_ok4(U32.is_eq(p, port), String.eq(pa, path), String.eq(h, host), bool_eq(s, secure))

def url_ok(dec: Result<&1, &1, U32 & String, Bool & String & U32 & String>, secure: Bool, host: String, port: U32, path: String) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{u}:
      url_ok_tuple(u, secure, host, port, path)

def url_fail_code(e: U32 & String, code: U32) -> U32:
  (c, m) = e
  b2u(U32.is_eq(c, code))

def url_fail(dec: Result<&1, &1, U32 & String, Bool & String & U32 & String>, code: U32) -> U32:
  match dec:
    case Fail{e}:
      url_fail_code(e, code)
    case Done{u}:
      0

def v1() -> U32:
  url_ok(HTTPX.httpx_url.read_url("https://example.com/"), True{}, "example.com", 443, "/")

def v2() -> U32:
  url_ok(HTTPX.httpx_url.read_url("https://example.com:8443/a/b"), True{}, "example.com", 8443, "/a/b")

def v3() -> U32:
  url_ok(HTTPX.httpx_url.read_url("http://example.com/"), False{}, "example.com", 80, "/")

def v4() -> U32:
  url_ok(HTTPX.httpx_url.read_url("https://example.com"), True{}, "example.com", 443, "/")

def v5() -> U32:
  url_ok(HTTPX.httpx_url.read_url("https://example.com:/"), True{}, "example.com", 443, "/")

def v6() -> U32:
  url_fail(HTTPX.httpx_url.read_url("https://example.com:abc/"), 400)

def v7() -> U32:
  url_fail(HTTPX.httpx_url.read_url("https://bad host/"), 400)

def v8() -> U32:
  url_fail(HTTPX.httpx_url.read_url("ftp://example.com/"), 400)

def v9() -> U32:
  url_ok(HTTPX.httpx_url.read_url("https://  example.com  /x"), True{}, "example.com", 443, "/x")

def v10() -> U32:
  url_fail(HTTPX.httpx_url.read_url("https://example.com:0/"), 400)

def v11() -> U32:
  url_ok(HTTPX.read_url("https://example.com/a"), True{}, "example.com", 443, "/a")

def v12() -> U32:
  url_fail(HTTPX.read_url("ftp://example.com/"), 400)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (v1() + v2() + v3() + v4() + v5() + v6() + v7() + v8() + v9() + v10() + v11() + v12() : U32)
    +pass : U32 = b2u(U32.is_eq(total, 12))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
