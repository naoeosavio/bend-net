# Real-site smoke test for lib/httpx.bend: live pages BY NAME over
# TLS+HTTP/2. Manual smoke only (like http_real.bend) — never runs in
# the check.sh gate: it needs a working resolver and the public peer
# must speak the same HPACK subset.
#
# LIMITATIONS (fail-closed, observed on live hosts):
# - Bodies accumulate reversed per DATA (`x_rev_push`, bounded by chunk
#   size) and un-reverse once at finish (`x_cat`, tail-recursive); the
#   String conversion splits into 8KB chunks (`x_str_chunks`) for the
#   same reason — even ~1.3 MB (cloudflare.com) converts without
#   overflowing the interp machine stack. Only a small head is printed.
# - info.cern.ch negotiates no h2 (Fail 615 on H2-strict entries);
#   `fetch` covers it via the H1 fallback lane.
#
# Observed (2026-09-28, no transport hang):
#   example.com GET      OK (~1 KB body head)
#   example.com POST     OK (echo page head)
#   www.cloudflare.com   OK (~1.3 MB body head, plain fetch)
#   info.cern.ch         OK len=646 (H1 lane)
#
#   bend examples/https_real.bend
import Base
# import ../lib/http2.bend as H2
import ../lib/httpx.bend as HTTPX

def emit(label: String, r: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      IO.print(label ++ " FAIL " ++ U32.show(c) ++ " " ++ e)
    case Done{body}:
      IO.print(label ++ " OK\n" ++ String.take(body, 240n))

def main() -> IO(Unit):
  do IO<Unit>:
    a : Result<&1, &1, U32 & String, String> <- HTTPX.fetch("https://example.com/")
    x : Unit <- emit("GET example.com (fetch)", a)
    b : Result<&1, &1, U32 & String, String> <- HTTPX.send_request("example.com", 443, "/post", "POST", HTTPX.HttpxHdr{"content-type", "text/plain"} <> Nil{}, "bend")
    y : Unit <- emit("POST example.com/post (send_request)", b)
    c : Result<&1, &1, U32 & String, String> <- HTTPX.fetch("https://www.cloudflare.com/")
    z : Unit <- emit("GET cloudflare.com (fetch)", c)
    d : Result<&1, &1, U32 & String, String> <- HTTPX.fetch("https://info.cern.ch/")
    q : Unit <- emit("GET info.cern.ch (fetch)", d)
    return q
