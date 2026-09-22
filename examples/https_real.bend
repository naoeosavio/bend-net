# Real-site smoke test for lib/https.bend: download live pages BY
# NAME over TLS+HTTP/2. Manual smoke only (like http_real.bend) —
# never runs in the check.sh gate: it needs a working resolver and
# the public peer must speak the same HPACK subset.
#
# LIMITATION (fail-closed, observed on live hosts): lib/http2.bend
# refuses huffman strings and dynamic-table refs with Fail 502, but
# public peers usually hit earlier limits first — HPACK block split
# across CONTINUATION (backlog) answers 400 hpack eof*, and a frame
# over 16384 answers 413 frame too large. All are expected until
# huffman decode + CONTINUATION land; Bend↔Bend loopback (literal
# headers, no CONTINUATION) is the supported path. A Done body means
# the peer answered with the supported subset.
#
# Observed (2026-09-21, fail-closed, no transport hang):
#   example.com      FAIL 400 hpack eof str
#   example.com POST FAIL 400 hpack eof str
#   cloudflare.com   FAIL 400 hpack eof str
#   info.cern.ch     FAIL 413 frame too large
#   huffman path     FAIL 502 huffman refused (codec unit path)
#
#   bend examples/https_real.bend
import Base
import ../lib/http2.bend as H2
import ../lib/https.bend as HTTPS

def emit(label: String, r: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      IO.print(label ++ " FAIL " ++ U32.show(c) ++ " " ++ e)
    case Done{body}:
      IO.print(label ++ " OK\n" ++ String.take(body, 240n))

def main() -> IO(Unit):
  do IO<Unit>:
    a : Result<&1, &1, U32 & String, String> <- HTTPS.fetch("https://example.com/")
    x : Unit <- emit("GET example.com (fetch)", a)
    b : Result<&1, &1, U32 & String, String> <- HTTPS.send_request("example.com", 443, "/post", "POST", H2.H2Hdr{"content-type", "text/plain"} <> Nil{}, "bend")
    y : Unit <- emit("POST example.com/post (send_request)", b)
    c : Result<&1, &1, U32 & String, String> <- HTTPS.fetch("https://www.cloudflare.com/")
    z : Unit <- emit("GET cloudflare.com (fetch)", c)
    d : Result<&1, &1, U32 & String, String> <- HTTPS.fetch("https://info.cern.ch/")
    q : Unit <- emit("GET info.cern.ch (fetch)", d)
    return q
