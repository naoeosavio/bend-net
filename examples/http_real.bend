# Real-site smoke test for lib/http.bend: download the text of live
# pages with the lib's methods, BY NAME. lib/dns.bend resolves the
# IPv4 the connect rides, while fetch/send_request keep sending the
# original host in the Host header — so Cloudflare and CERN vhosts
# work by name (the old pinned-IP workaround is gone).
#
#   bend examples/http_real.bend
import Base
import ../lib/http.bend as HTTP

def emit(label: String, r: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      IO.print(label ++ " FAIL " ++ U32.show(c) ++ " " ++ e)
    case Done{body}:
      IO.print(label ++ " OK\n" ++ String.take(body, 240n))

def main() -> IO(Unit):
  do IO<Unit>:
    a : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://httpbin.org/get")
    x : Unit <- emit("GET httpbin.org/get (fetch, CL)", a)
    b : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/post", "POST", [("Content-Type", "application/x-www-form-urlencoded")], "nome=bend&lang=affine")
    y : Unit <- emit("POST httpbin.org/post (send_request)", b)
    c : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/put", "PUT", [("Content-Type", "text/plain")], "affine")
    z : Unit <- emit("PUT httpbin.org/put (send_request)", c)
    g : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/delete", "DELETE", [], "")
    q : Unit <- emit("DELETE httpbin.org/delete (send_request)", g)
    con : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/anything", "CONNECT", [], "")
    conx : Unit <- emit("CONNECT httpbin.org/anything (send_request)", con)
    hd : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/get", "HEAD", [], "")
    hdx : Unit <- emit("HEAD httpbin.org/get (send_request)", hd)
    opt : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/anything", "OPTIONS", [], "")
    optx : Unit <- emit("OPTIONS httpbin.org/anything (send_request)", opt)
    trc : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/anything", "TRACE", [], "")
    trcx : Unit <- emit("TRACE httpbin.org/anything (send_request)", trc)
    ptc : Result<&1, &1, U32 & String, String> <- HTTP.send_request("httpbin.org", 80, "/patch", "PATCH", [("Content-Type", "text/plain")], "affine")
    ptcx : Unit <- emit("PATCH httpbin.org/patch (send_request)", ptc)
    d : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://info.cern.ch/")
    w : Unit <- emit("GET info.cern.ch (CL, first website)", d)
    e : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://example.com/")
    v : Unit <- emit("GET example.com (chunked)", e)
    f : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://httpforever.com/")
    u : Unit <- emit("GET httpforever.com (chunked)", f)
    return u
