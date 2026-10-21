# Real-site smoke test for the httpx H1 lane (plaintext): download the text
# of live pages with the lib's methods, BY NAME. Two ways into the lane:
# fetch_insecure("http://...") for GETs and request_plain for every other
# method (plain HTTP, no TLS at all -- the _insecure suffix means "TLS without
# verification", which is a different thing and would handshake-fail on port
# 80). The dial resolves the name to an IPv4, while the ORIGINAL host still
# rides the Host header, so vhosts work by name. Headers are the httpx Hdr
# record, not pairs.
#
#   bend examples/real/httpx_h1_real.bend
import Base
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def emit(label: String, r: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      IO.print(label ++ " FAIL " ++ U32.show(c) ++ " " ++ e)
    case Done{body}:
      IO.print(label ++ " OK\n" ++ String.take(body, 240n))

def main() -> IO(Unit):
  do IO<Unit>:
    a : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://httpbin.org/get")
    x : Unit <- emit("GET httpbin.org/get (fetch, CL)", a)
    b : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/post", "POST", [HTTP.Hdr{"Content-Type", "application/x-www-form-urlencoded"}], "nome=bend&lang=affine")
    y : Unit <- emit("POST httpbin.org/post (request)", b)
    c : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/put", "PUT", [HTTP.Hdr{"Content-Type", "text/plain"}], "affine")
    z : Unit <- emit("PUT httpbin.org/put (request)", c)
    g : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/delete", "DELETE", [], "")
    q : Unit <- emit("DELETE httpbin.org/delete (request)", g)
    con : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/anything", "CONNECT", [], "")
    conx : Unit <- emit("CONNECT httpbin.org/anything (request)", con)
    hd : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/get", "HEAD", [], "")
    hdx : Unit <- emit("HEAD httpbin.org/get (request)", hd)
    opt : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/anything", "OPTIONS", [], "")
    optx : Unit <- emit("OPTIONS httpbin.org/anything (request)", opt)
    trc : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/anything", "TRACE", [], "")
    trcx : Unit <- emit("TRACE httpbin.org/anything (request)", trc)
    ptc : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("httpbin.org", 80, "/patch", "PATCH", [HTTP.Hdr{"Content-Type", "text/plain"}], "affine")
    ptcx : Unit <- emit("PATCH httpbin.org/patch (request)", ptc)
    d : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://info.cern.ch/")
    w : Unit <- emit("GET info.cern.ch (CL, first website)", d)
    e : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://example.com/")
    v : Unit <- emit("GET example.com (chunked)", e)
    f : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure("http://httpforever.com/")
    u : Unit <- emit("GET httpforever.com (chunked)", f)
    return u
