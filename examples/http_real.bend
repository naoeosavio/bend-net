# Real-site smoke test for lib/http.bend: download the text of live
# pages with the lib's methods.
#
# The TCP kit has no DNS, so the A records are resolved outside and
# pinned here. HTTP.fetch and HTTP.send_request both inject the Host
# header from the host they connect to, so httpbin accepts the IP.
# Cloudflare and CERN need the real vhost, so those connect by IP and
# hand the bytes to HTTP.fetch.exchange (the lib's framer: chunked,
# Content-Length, UTF-8).
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

def host_conn(conn: Result<&1, &1, U32 & String, Socket>, text: String) -> IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      HTTP.fetch.exchange(sock, text)

def host_get(ip: String, host: String, path: String) -> IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(ip, 80)
    host_conn(conn, "GET " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ "\r\nConnection: close\r\n\r\n")

def main() -> IO(Unit):
  do IO<Unit>:
    a : Result<&1, &1, U32 & String, String> <- HTTP.fetch("http://3.208.246.33/get")
    x : Unit <- emit("GET httpbin.org/get (fetch, CL)", a)
    b : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/post", "POST", [("Content-Type", "application/x-www-form-urlencoded")], "nome=bend&lang=affine")
    y : Unit <- emit("POST httpbin.org/post (send_request)", b)
    c : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/put", "PUT", [("Content-Type", "text/plain")], "affine")
    z : Unit <- emit("PUT httpbin.org/put (send_request)", c)
    g : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/delete", "DELETE", [], "")
    q : Unit <- emit("DELETE httpbin.org/delete (send_request)", g)
    con : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/anything", "CONNECT", [], "")
    conx : Unit <- emit("CONNECT httpbin.org/anything (send_request)", con)
    hd : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/get", "HEAD", [], "")
    hdx : Unit <- emit("HEAD httpbin.org/get (send_request)", hd)
    opt : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/anything", "OPTIONS", [], "")
    optx : Unit <- emit("OPTIONS httpbin.org/anything (send_request)", opt)
    trc : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/anything", "TRACE", [], "")
    trcx : Unit <- emit("TRACE httpbin.org/anything (send_request)", trc)
    ptc : Result<&1, &1, U32 & String, String> <- HTTP.send_request("3.208.246.33", 80, "/patch", "PATCH", [("Content-Type", "text/plain")], "affine")
    ptcx : Unit <- emit("PATCH httpbin.org/patch (send_request)", ptc)
    d : Result<&1, &1, U32 & String, String> <- host_get("188.184.67.127", "info.cern.ch", "/")
    w : Unit <- emit("GET info.cern.ch (CL, first website)", d)
    e : Result<&1, &1, U32 & String, String> <- host_get("172.66.147.243", "example.com", "/")
    v : Unit <- emit("GET example.com (chunked)", e)
    f : Result<&1, &1, U32 & String, String> <- host_get("104.21.4.210", "httpforever.com", "/")
    u : Unit <- emit("GET httpforever.com (chunked)", f)
    return u
