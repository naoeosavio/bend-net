# lib (dns_resolve): DNS.resolve fast paths and the fail-closed host
# checks. Every case is hermetic: the quad and localhost lanes answer
# inside the pure layer, and each bad host fails 601 BEFORE the
# effect — no name ever leaves the machine here. The last four cases are
# address forms libc would read as an IP (01.2.3.4, 127.1, 0x7f.1,
# 256.1.1.1): they must fail 601 in BOTH lanes, never reach getaddrinfo
# (task-051 A2). The twins' real resolution is proven by the manual
# example (examples/real/httpx_h1_real.bend).
import Base
import ../../lib/dns.bend as DNS

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law is_ok:
  for r: Result<&1, &1, (U32 & String), String>
  for want: String
  U32

def is_ok(r, want):
  match r:
    case Done{ip}:
      b2u(String.eq(ip, want))
    case Fail{e}:
      0

law is_code:
  for r: Result<&1, &1, (U32 & String), String>
  for want: U32
  U32

def is_code(r, want):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{ip}:
      0

law main:
  IO(U32)

def main():
  do IO<U32>:
    a : Result<&1, &1, U32 & String, String> <- DNS.resolve("localhost")
    b : Result<&1, &1, U32 & String, String> <- DNS.resolve("127.0.0.1")
    c : Result<&1, &1, U32 & String, String> <- DNS.resolve("93.184.215.14")
    d : Result<&1, &1, U32 & String, String> <- DNS.resolve("")
    e : Result<&1, &1, U32 & String, String> <- DNS.resolve("a..b")
    f : Result<&1, &1, U32 & String, String> <- DNS.resolve("bad\r\nhost")
    g : Result<&1, &1, U32 & String, String> <- DNS.resolve(String.from_list([Chr{9}]) ++ "x")
    h : Result<&1, &1, U32 & String, String> <- DNS.resolve(String.from_list([Chr{0}]) ++ "h")
    i : Result<&1, &1, U32 & String, String> <- DNS.resolve(String.repeat("a", 70n))
    j : Result<&1, &1, U32 & String, String> <- DNS.resolve(String.repeat("a", 300n))
    k : Result<&1, &1, U32 & String, String> <- DNS.resolve("01.2.3.4")
    l : Result<&1, &1, U32 & String, String> <- DNS.resolve("127.1")
    m : Result<&1, &1, U32 & String, String> <- DNS.resolve("0x7f.1")
    n : Result<&1, &1, U32 & String, String> <- DNS.resolve("256.1.1.1")
    s1 : U32 = is_ok(a, "127.0.0.1")
    s2 : U32 = (is_ok(b, "127.0.0.1") * 10 : U32)
    s3 : U32 = (is_ok(c, "93.184.215.14") * 100 : U32)
    s4 : U32 = (is_code(d, 601) * 1000 : U32)
    s5 : U32 = (is_code(e, 601) * 10000 : U32)
    s6 : U32 = (is_code(f, 601) * 100000 : U32)
    s7 : U32 = (is_code(g, 601) * 1000000 : U32)
    s8 : U32 = (is_code(h, 601) * 10000000 : U32)
    s9 : U32 = (is_code(i, 601) * 100000000 : U32)
    s10 : U32 = (is_code(j, 601) * 1000000000 : U32)
    s11 : U32 = (is_code(k, 601) * 1000 : U32)
    s12 : U32 = (is_code(l, 601) * 100 : U32)
    s13 : U32 = (is_code(m, 601) * 10 : U32)
    s14 : U32 = is_code(n, 601)
    +total : U32 = (s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 + s9 + s10 : U32)
    +extra : U32 = (s11 + s12 + s13 + s14 : U32)
    w : Unit <- IO.print(U32.show(total) ++ U32.show(extra))
    return total

#|11111111111111
