# HTTPS facade over TLS + DNS + HTTP/2 codec (RFC 7540/7541).
#
# Stack: TCP -> TLS (SNI, cert verify, ALPN h2) -> HTTP/2 frames/HPACK.
# This file is the public API; the codec lives in ./http2.bend (H2),
# the handshake in ./tls.bend (TLS), URL validation in ./http.bend (HTTP).
#
# RFC pattern (the core): headers are List<H2Hdr> byte pairs (lowercase,
# pseudo-headers :method/:path/:scheme/:authority handled by the codec);
# bodies are byte-faithful List<&2, U32>. Textual wrappers (fetch,
# send_request) encode/decode via H2.str_bytes / H2.bytes_str, mirroring
# lib/http.bend for HTTP/1.1.
#
# Fail codes surface unchanged: 400 bad input/scheme, 502 protocol,
# 503 bad preface, 413 too large, DNS 601-605, TLS 611-616.
#
# Discipline (same as lib/http.bend): callee above caller; match
# scrutinees are params or pattern-bound vars; self-recursion only
# (@unsafe for the accept/stream loops); + binders only for Data.
#
# Import as: import ./https.bend as HTTPS (from lib) or
# import ../../lib/https.bend as HTTPS (from tests/io).
import Base
import ./http.bend as HTTP
import ./http2.bend as H2
import ./tls.bend as TLS

# Bodies
# ------
# Textual conversions ride the codec helpers (UTF-8 shaped, same as
# H2.str_bytes / H2.bytes_str).

def encode_body(+body: String) -> List<&2, U32>:
  H2.str_bytes(body)

def decode_body(+body: List<&2, U32>) -> String:
  H2.bytes_str(body)

# Headers
# -------
# RFC core uses List<H2Hdr>; http-style pairs convert explicitly.

def pairs_to_h2(hs: List<&1, String & String>) -> List<&2, H2.H2Hdr>:
  match hs:
    case Nil{}:
      Nil{}
    case (n, v) <> t:
      H2.H2Hdr{n, v} <> pairs_to_h2(t)

def h2_to_pairs(hs: List<&2, H2.H2Hdr>) -> List<&1, String & String>:
  match hs:
    case Nil{}:
      Nil{}
    case H2.H2Hdr{n, v} <> t:
      (n, v) <> h2_to_pairs(t)

# Response
# --------
# Status projection and handler dispatch (mirror HTTP.route_status).

def route_status(resp: H2.H2Response) -> U32:
  match resp:
    case H2.H2Response{+status, +headers, +body}:
      status

def dispatch(route: H2.H2Request -> IO(H2.H2Response), req: H2.H2Request) ->
  IO(H2.H2Response):
  route(req)

# Single-shot request (RFC core)
# ------------------------------
# Connect, one exchange on stream 1, close. Returns the full H2Response
# (status + headers + byte body). Multi-stream keep-alive callers use
# H2.h2_connect + H2.h2_request directly and thread the socket + sid.

def request.closed(r: Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, r)

def request.body(got: Socket & Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        x : Unit <- TLS.tls_close(s2)
        request.closed(Fail{e})
    case Done{+resp}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        x : Unit <- TLS.tls_close(s2)
        request.closed(Done{resp})

def request.exch(sock: Socket, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
    got : Socket & Result<&1, &1, U32 & String, H2.H2Response> <- H2.h2_request(sock, 1, method, path, hs, body)
    request.body(got)

def request.conn(conn: Result<&1, &1, U32 & String, Socket>, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, Fail{e})
    case Done{sock}:
      request.exch(sock, method, path, hs, body)

def request.go(+host: String, port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match verify:
    case True{}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        conn : Result<&1, &1, U32 & String, Socket> <- H2.h2_connect(host, port)
        request.conn(conn, method, path, hs, body)
    case False{}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        conn : Result<&1, &1, U32 & String, Socket> <- H2.h2_connect_insecure(host, port)
        request.conn(conn, method, path, hs, body)

def request.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>, verify: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match fit:
    case True{}:
      request.go(host, port, method, path, hs, body, verify)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, Fail{(400, "bad request")})

def request(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  request.fit(host, port, path, method, hs, body, True{}, Bool.and(HTTP.valid_host(host), Bool.and(HTTP.valid_port(port), HTTP.valid_path(path))))

def request_insecure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  request.fit(host, port, path, method, hs, body, False{}, Bool.and(HTTP.valid_host(host), Bool.and(HTTP.valid_port(port), HTTP.valid_path(path))))

# Textual send_request (mirror HTTP.send_request)
# -----------------------------------------------
# Same exchange with a String body; answers the response body as String.

def send_request.text(r: Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, String>, Done{decode_body(body)})

def send_request.go(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    r : Result<&1, &1, U32 & String, H2.H2Response> <- request.go(host, port, method, path, hs, encode_body(body), verify)
    send_request.text(r)

def send_request.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String, verify: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match fit:
    case True{}:
      send_request.go(host, port, path, method, hs, body, verify)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad request")})

def send_request(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  send_request.fit(host, port, path, method, hs, body, True{}, Bool.and(HTTP.valid_host(host), Bool.and(HTTP.valid_port(port), HTTP.valid_path(path))))

def send_request_insecure(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  send_request.fit(host, port, path, method, hs, body, False{}, Bool.and(HTTP.valid_host(host), Bool.and(HTTP.valid_port(port), HTTP.valid_path(path))))

# fetch: GET by URL (mirror HTTP.fetch, https only)
# -------------------------------------------------
# Parses https://host[:port]/path via HTTP.read_url; http:// is refused
# with 400 (use HTTP.fetch for cleartext). Answers the body as String;
# fetch_bytes answers raw bytes.

def fetch.text(r: Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, String>, Done{decode_body(body)})

def fetch.raw(r: Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Done{body})

def fetch.get(+host: String, port: U32, path: String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    r : Result<&1, &1, U32 & String, H2.H2Response> <- request.go(host, port, "GET", path, Nil{}, Nil{}, verify)
    fetch.text(r)

def fetch_bytes.get(+host: String, port: U32, path: String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    r : Result<&1, &1, U32 & String, H2.H2Response> <- request.go(host, port, "GET", path, Nil{}, Nil{}, verify)
    fetch.raw(r)

def fetch.host(host: String, +port: U32, path: String, verify: Bool, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      fetch.get(host, port, path, verify)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad host")})

def fetch_bytes.host(host: String, +port: U32, path: String, verify: Bool, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match ok:
    case True{}:
      fetch_bytes.get(host, port, path, verify)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad host")})

def fetch.url.go(secure: Bool, +host: String, port: U32, path: String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match secure:
    case True{}:
      fetch.host(host, port, path, verify, HTTP.valid_host(host))
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad scheme")})

def fetch_bytes.url.go(secure: Bool, +host: String, port: U32, path: String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match secure:
    case True{}:
      fetch_bytes.host(host, port, path, verify, HTTP.valid_host(host))
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad scheme")})

def fetch.url(u: Bool & String & U32 & String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  (secure, host, port, path) = u
  fetch.url.go(secure, host, port, path, verify)

def fetch_bytes.url(u: Bool & String & U32 & String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  (secure, host, port, path) = u
  fetch_bytes.url.go(secure, host, port, path, verify)

def fetch.r(url: String, parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{u}:
      fetch.url(u, verify)

def fetch_bytes.r(url: String, parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{u}:
      fetch_bytes.url(u, verify)

law fetch:
  for url: String
  IO(Result<&1, &1, U32 & String, String>)

def fetch(url):
  +u = url
  fetch.r(u, HTTP.read_url(u), True{})

law fetch_insecure:
  for url: String
  IO(Result<&1, &1, U32 & String, String>)

def fetch_insecure(url):
  +u = url
  fetch.r(u, HTTP.read_url(u), False{})

law fetch_bytes:
  for url: String
  IO(Result<&1, &1, U32 & String, List<&2, U32>>)

def fetch_bytes(url):
  +u = url
  fetch_bytes.r(u, HTTP.read_url(u), True{})

law fetch_bytes_insecure:
  for url: String
  IO(Result<&1, &1, U32 & String, List<&2, U32>>)

def fetch_bytes_insecure(url):
  +u = url
  fetch_bytes.r(u, HTTP.read_url(u), False{})

# Server (generic, like HTTP.server_on)
# -------------------------------------
# The handler rides a template (~H) — a def name baked at the call site —
# because a function value can neither be copied nor thread a loop in
# affine user-land. Probe probe_tmpl.bend proved a template-specialized
# wrapper passes as a value: h2_serve_once(sock, apply_wrap(~H)) checks.
# Per-connection streams run sequentially (one H2SrvSt); concurrency
# across connections comes from IO.spawn per accept, like HTTP.server.conn.

def apply_wrap(~H: H2.H2Request -> IO(H2.H2Response), req: H2.H2Request) -> IO(H2.H2Response):
  H(req)

# Multi-stream sequential loop over one TLS connection. The first
# stream runs h2_serve_once (magic preface + SETTINGS); the rest run
# H2.h2_serve_next (established connection, no preface). Fuel n bounds
# the extra streams (self-recursion on Nat, socket threaded whole).

def serve_loop(~H: H2.H2Request -> IO(H2.H2Response), fuel: Nat, got: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Unit):
  match fuel:
    case 0n:
      (s0, r0) = got
      TLS.tls_close(s0)
    case 1n+t:
      (s2, r) = got
      match r:
        case Fail{e}:
          TLS.tls_close(s2)
        case Done{u}:
          do IO<Unit>:
            got2 : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_serve_next(s2, apply_wrap(~H))
            serve_loop(~H, t, got2)

def serve_start(~H: H2.H2Request -> IO(H2.H2Response), sock: Socket, n: Nat) -> IO(Unit):
  do IO<Unit>:
    got : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_serve_once(sock, apply_wrap(~H))
    serve_loop(~H, n, got)

def server.spawn(~H: H2.H2Request -> IO(H2.H2Response), sock: Socket, l: Listener, n: Nat) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, serve_start(~H, sock, n))
    return l

def server.conn(~H: H2.H2Request -> IO(H2.H2Response), m: Listener & Result<&1, &1, U32 & String, Socket>, n: Nat) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      server.spawn(~H, sock, l, n)

@unsafe
def server_on(~H: H2.H2Request -> IO(H2.H2Response), l: Listener, +cert: String, +key: String, +n: Nat) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.conn(~H, m, n)
    z : Unit <- server_on(~H, l2, cert, key, n)
    return z

# Concurrent streams (interleaved, 2 slots per connection)
# -------------------------------------------------------
# Sequential serve_next tracks ONE H2SrvSt, so pipelined frames of two
# open streams (HEADERS 1, HEADERS 3, DATA 1, DATA 3) would mix into one
# state. The mux below tracks TWO slots (sid 0 = empty): HEADERS claims
# a free slot, DATA appends to the matching slot, END_STREAM answers
# that slot immediately and frees it — both orders complete. A third
# SIMULTANEOUS stream (both slots busy) fails the connection closed
# (fail-closed, documented limit); sequential reuse of freed slots is
# unbounded. Single Socket & H2Got carrier threaded whole (like
# HTTP.srv threads mr); slot decisions ride Bool params computed in
# caller arg position (never computed scrutinees).

def mux.sid_of(st: H2.H2SrvSt) -> U32:
  match st:
    case H2.H2SrvSt{head, body, +sid}:
      sid

# SETTINGS classification fix: ack only a fresh (non-ACK) SETTINGS.
# An ACK already answers one; acking it back would ping-pong forever
# between two unbounded read loops (bounded single-shot readers never
# notice). base rides H2.h2_srv.classify.

def mux.cls_fix(base: U32, +flags: U32) -> U32:
  match base flags:
    case 1 1:
      0
    case _ _:
      base

def mux.sent_got(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2.H2Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, H2.H2GotErr{616, "tls io"})
    case Done{u}:
      (s2, H2.H2GotErr{0, "next"})

def mux.read_got(got: Socket & H2.H2Got) -> Socket & H2.H2Got:
  (s, g) = got
  (s, H2.H2GotErr{0, "next"})

def mux.close_got(got: Socket & H2.H2Got) -> IO(Unit):
  (s, g) = got
  TLS.tls_close(s)

def mux.ack(got: Socket & H2.H2Got) -> IO(Socket & H2.H2Got):
  (s, g) = got
  do IO<Socket & H2.H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s, H2.h2_t_settings(), H2.h2_f_ack(), 0, Nil{})
    IO.pure(Socket & H2.H2Got, mux.sent_got(sent))

# Slot decision leafs (plain defs, top-level matches only). HEADERS codes:
# 0 claim A, 1 answer A, 2 claim B, 3 answer B, 4 busy fail-closed,
# 5 head decode fail. DATA codes: 0 continue A, 1 answer A, 2 continue
# B, 3 answer B, 4 stray skip, 5 DATA-before-HEADERS A, 6 same B.

def mux.ok_of(r: Result<&1, &1, U32 & String, H2.H2ReqHead>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{rh}:
      True{}

def mux.rh_or(r: Result<&1, &1, U32 & String, H2.H2ReqHead>) -> H2.H2ReqHead:
  match r:
    case Fail{e}:
      H2.H2ReqHead{"", "", Nil{}}
    case Done{+rh}:
      rh

def mux.decide4(ok: Bool, a: Bool, b: Bool, +end: U32) -> U32:
  match ok a b end:
    case False{} _ _ _:
      5
    case True{} True{} _ 1:
      1
    case True{} True{} _ _:
      0
    case True{} False{} True{} 1:
      3
    case True{} False{} True{} _:
      2
    case True{} False{} False{} _:
      4
    case _ _ _ _:
      5

def mux.some_of(st: H2.H2SrvSt) -> Bool:
  match st:
    case H2.H2SrvSt{head, body, sid}:
      match head:
        case None{}:
          False{}
        case Some{rh}:
          True{}

def mux.rh_of(st: H2.H2SrvSt) -> H2.H2ReqHead:
  match st:
    case H2.H2SrvSt{head, body, sid}:
      match head:
        case None{}:
          H2.H2ReqHead{"", "", Nil{}}
        case Some{+rh}:
          rh

def mux.body_of(st: H2.H2SrvSt) -> List<&2, U32>:
  match st:
    case H2.H2SrvSt{head, +body, sid}:
      body

def mux.req_of(+rh: H2.H2ReqHead, +body: List<&2, U32>) -> H2.H2Request:
  match rh:
    case H2.H2ReqHead{+method, +path, +headers}:
      H2.H2Request{method, path, headers, body}

def mux.decide5(ha: Bool, sa: Bool, hb: Bool, sb: Bool, +end: U32) -> U32:
  match ha sa hb sb end:
    case True{} True{} _ _ 1:
      1
    case True{} True{} _ _ _:
      0
    case True{} False{} _ _ _:
      5
    case False{} _ True{} True{} 1:
      3
    case False{} _ True{} True{} _:
      2
    case False{} _ True{} False{} _:
      6
    case False{} _ False{} _ _:
      4
    case _ _ _ _ _:
      4

# Main interleave loop (single @unsafe self-recursive def, like HTTP.srv:
# phase-0 reset spelled out at each site (a reset helper would
# forward-call into mux). Single Socket carrier threaded whole, slot
# decisions as Bool params). Answers inline.

@unsafe
def mux(~H: H2.H2Request -> IO(H2.H2Response), phase: U32, got: Socket & H2.H2Got, +stA: H2.H2SrvSt, +stB: H2.H2SrvSt, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +a_free: Bool, +a_hit: Bool, +b_free: Bool, +b_hit: Bool, +rh: H2.H2ReqHead, act: U32, +rhA: H2.H2ReqHead, +bodyA: List<&2, U32>, +sidA: U32, +rhB: H2.H2ReqHead, +bodyB: List<&2, U32>, +sidB: U32) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      match g0:
        case H2.H2GotErr{code, msg}:
          match code:
            case 0:
              do IO<Unit>:
                got2 : Socket & H2.H2Got <- H2.h2_read_frame(s0, buf)
                mux(~H, 1, got2, stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
            case _:
              TLS.tls_close(s0)
        case H2.H2GotOk{frame0, buf0}:
          mux(~H, 1, got, stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
    case 1:
      (s1, g1) = got
      match g1:
        case H2.H2GotErr{code1, msg1}:
          TLS.tls_close(s1)
        case H2.H2GotOk{+frame, +buf2}:
          match frame:
            case H2.H2Frame{+typ2, +flags2, +sid22, +payload2}:
              mux(~H, 2, (s1, H2.H2GotOk{frame, buf2}), stA, stB, buf2, typ2, flags2, sid22, payload2, mux.cls_fix(H2.h2_srv.classify(frame), flags2), U32.and(flags2, H2.h2_f_end_stream()), U32.is_eq(mux.sid_of(stA), 0), U32.is_eq(mux.sid_of(stA), sid22), U32.is_eq(mux.sid_of(stB), 0), U32.is_eq(mux.sid_of(stB), sid22), H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
    case 2:
      match cls:
        case 1:
          do IO<Unit>:
            got2 : Socket & H2.H2Got <- mux.ack(got)
            mux(~H, 0, got2, stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 5:
          mux.close_got(got)
        case 6:
          mux(~H, 3, got, stA, stB, buf, typ, flags, sid2, payload, cls, end, a_free, a_hit, b_free, b_hit, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 0:
          mux(~H, 0, mux.read_got(got), stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case _:
          mux(~H, 0, mux.read_got(got), stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
    case 3:
      match typ:
        case 1:
          +dec : Result<&1, &1, U32 & String, H2.H2ReqHead> = H2.h2_reqhead.decode(payload)
          mux(~H, 4, got, stA, stB, buf, typ, flags, sid2, payload, cls, end, a_free, a_hit, b_free, b_hit, mux.rh_or(dec), mux.decide4(mux.ok_of(dec), a_free, b_free, end), H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 0:
          mux(~H, 5, got, stA, stB, buf, typ, flags, sid2, payload, cls, end, a_free, a_hit, b_free, b_hit, H2.H2ReqHead{"", "", Nil{}}, mux.decide5(a_hit, mux.some_of(stA), b_hit, mux.some_of(stB), end), mux.rh_of(stA), mux.body_of(stA), mux.sid_of(stA), mux.rh_of(stB), mux.body_of(stB), mux.sid_of(stB))
        case _:
          mux(~H, 0, mux.read_got(got), stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
    case 4:
      (s4, g4) = got
      match act:
        case 0:
          mux(~H, 0, mux.read_got(got), H2.H2SrvSt{Some{rh}, Nil{}, sid2}, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 1:
          do IO<Unit>:
            req : H2.H2Request = mux.req_of(rh, Nil{})
            resp : H2.H2Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_srv.send_resp(s4, sid2, resp)
            mux(~H, 0, mux.sent_got(sent), H2.H2SrvSt{None{}, Nil{}, 0}, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 2:
          mux(~H, 0, mux.read_got(got), stA, H2.H2SrvSt{Some{rh}, Nil{}, sid2}, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 3:
          do IO<Unit>:
            req : H2.H2Request = mux.req_of(rh, Nil{})
            resp : H2.H2Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_srv.send_resp(s4, sid2, resp)
            mux(~H, 0, mux.sent_got(sent), stA, H2.H2SrvSt{None{}, Nil{}, 0}, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 4:
          TLS.tls_close(s4)
        case 5:
          TLS.tls_close(s4)
        case _:
          TLS.tls_close(s4)
    case 5:
      (sm, gm) = got
      match act:
        case 0:
          +bA0 : List<&2, U32> = List.append(&2, U32, bodyA, payload)
          mux(~H, 0, mux.read_got(got), H2.H2SrvSt{Some{rhA}, bA0, sidA}, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 1:
          do IO<Unit>:
            +bA1 : List<&2, U32> = List.append(&2, U32, bodyA, payload)
            req : H2.H2Request = mux.req_of(rhA, bA1)
            resp : H2.H2Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_srv.send_resp(sm, sidA, resp)
            mux(~H, 0, mux.sent_got(sent), H2.H2SrvSt{None{}, Nil{}, 0}, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 2:
          +bB0 : List<&2, U32> = List.append(&2, U32, bodyB, payload)
          mux(~H, 0, mux.read_got(got), stA, H2.H2SrvSt{Some{rhB}, bB0, sidB}, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 3:
          do IO<Unit>:
            +bB1 : List<&2, U32> = List.append(&2, U32, bodyB, payload)
            req : H2.H2Request = mux.req_of(rhB, bB1)
            resp : H2.H2Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_srv.send_resp(sm, sidB, resp)
            mux(~H, 0, mux.sent_got(sent), stA, H2.H2SrvSt{None{}, Nil{}, 0}, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 4:
          mux(~H, 0, mux.read_got(got), stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case 5:
          TLS.tls_close(sm)
        case 6:
          TLS.tls_close(sm)
        case _:
          mux(~H, 0, mux.read_got(got), stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
    case _:
      mux(~H, 0, mux.read_got(got), stA, stB, buf, 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)

# Preface entry for the mux (owns the byte buffer end-to-end, so pipelined
# frames are never dropped between streams). Below mux: calls upward.

@unsafe
def mux_pre(~H: H2.H2Request -> IO(H2.H2Response), phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          mux_pre(~H, 1, (s0, Done{chunk}), acc2, H2.h2_srv.preface_ok(acc2), Nat.is_lt(H2.b_len(acc2), 24n))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            mux_pre(~H, 0, r2, acc, 0, False{})
        case False{}:
          mux_pre(~H, 2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s2, H2.h2_t_settings(), 0, 0, Nil{})
            mux(~H, 0, mux.sent_got(sent), H2.H2SrvSt{None{}, Nil{}, 0}, H2.H2SrvSt{None{}, Nil{}, 0}, H2.b_drop(24n, acc), 0, 0, 0, Nil{}, 0, 0, False{}, False{}, False{}, False{}, H2.H2ReqHead{"", "", Nil{}}, 4, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0, H2.H2ReqHead{"", "", Nil{}}, Nil{}, 0)
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def mux_start(~H: H2.H2Request -> IO(H2.H2Response), sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    mux_pre(~H, 0, r1, Nil{}, 0, False{})

def mux.spawn(~H: H2.H2Request -> IO(H2.H2Response), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, mux_start(~H, sock))
    return l

def mux.conn(~H: H2.H2Request -> IO(H2.H2Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      mux.spawn(~H, sock, l)

@unsafe
def server_on_concurrent(~H: H2.H2Request -> IO(H2.H2Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- mux.conn(~H, m)
    z : Unit <- server_on_concurrent(~H, l2, cert, key)
    return z

def echo.body(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def ok(+body: List<&2, U32>) -> H2.H2Response:
  H2.H2Response{200, Nil{}, body}
