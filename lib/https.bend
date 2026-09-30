# HTTPS facade over TLS + DNS + HTTP/2 codec (RFC 7540/7541).
#
# Stack: TCP -> TLS (SNI, cert verify, ALPN h2/http1.1) -> HTTP/2 frames
# or the HTTP/1.1 module. This file is the public API; the codec lives in
# ./http2.bend (H2), the handshake in ./tls.bend (TLS), and URL validation
# in ./http.bend (HTTP).
#
# RFC pattern (the core): headers are List<H2Hdr> String pairs (lowercase,
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
import ./https_http1.bend as HTTP1

type HTTPSCall is Data:
  HTTPSCall{host: String, port: U32, method: String, path: String, headers: List<&2, H2.H2Hdr>, body: List<&2, U32>}

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

# RFC 9113 requires :authority on every request; node:http2 closes the
# session without a stream when it is missing. Build it from the dial
# target (host:port) and drop any caller-supplied copy first.

def drop_authority.go(+n: String, +v: String, rec: List<&2, H2.H2Hdr>, is_auth: Bool) ->
  List<&2, H2.H2Hdr>:
  match is_auth:
    case True{}:
      rec
    case False{}:
      H2.H2Hdr{n, v} <> rec

def drop_authority(hs: List<&2, H2.H2Hdr>) -> List<&2, H2.H2Hdr>:
  match hs:
    case Nil{}:
      Nil{}
    case H2.H2Hdr{n, v} <> t:
      +nn = n
      +vv = v
      drop_authority.go(nn, vv, drop_authority(t), String.eq(nn, ":authority"))

def with_authority(+host: String, +port: U32, hs: List<&2, H2.H2Hdr>) ->
  List<&2, H2.H2Hdr>:
  H2.H2Hdr{":authority", host ++ ":" ++ U32.show(port)} <> drop_authority(hs)


def h1_headers.put(n: String, v: String,
  rec: List<&2, HTTP.Hdr>, drop: Bool) -> List<&2, HTTP.Hdr>:
  match drop:
    case True{}:
      rec
    case False{}:
      HTTP.Hdr{n, v} <> rec

def h1_headers(hs: List<&2, H2.H2Hdr>) -> List<&2, HTTP.Hdr>:
  match hs:
    case Nil{}:
      Nil{}
    case H2.H2Hdr{n, v} <> tail:
      +nn = n
      +vv = v
      h1_headers.put(nn, vv, h1_headers(tail),
        HTTP1.http1_forbidden(nn))

def h1_to_h2(headers: List<&2, HTTP.Hdr>) ->
  List<&2, H2.H2Hdr>:
  match headers:
    case Nil{}:
      Nil{}
    case HTTP.Hdr{name, value} <> tail:
      H2.H2Hdr{name, value} <> h1_to_h2(tail)

def request.http1_convert(
  got: Socket & Result<&1, &1, U32 & String, HTTP1.HTTP1Response>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2.H2Response>):
  (sock, result) = got
  match result:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2.H2Response>,
        (sock, Fail{e}))
    case Done{response}:
      match response:
        case HTTP1.HTTP1Response{status, headers, body}:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2.H2Response>,
            (sock, Done{H2.H2Response{status, h1_to_h2(headers), body}}))

# ------------------------------
# Connect, one exchange on stream 1, close. Returns the full H2Response
# (status + headers + byte body). Multi-stream keep-alive callers use
# H2.h2_connect + H2.h2_request directly and thread the socket + sid.

def request.body(got: Socket & Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        x : Unit <- TLS.tls_close(s2)
        IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, Fail{e})
    case Done{+resp}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        x : Unit <- TLS.tls_close(s2)
        IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, Done{resp})

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

def request.alpn.go(is_h2: Bool, sock: Socket,
  h2_call: HTTPSCall, h1_call: HTTP1.HTTPSCall) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match is_h2:
    case True{}:
      match h2_call:
        case HTTPSCall{host, port, +method, path, headers, body}:
          do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
            conn : Result<&1, &1, U32 & String, Socket> <-
              H2.h2_connect.go(Done{sock})
            request.conn(conn, method, path, headers, body)
    case False{}:
      do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, HTTP1.HTTP1Response> <-
          HTTP1.http1_exch(sock, h1_call)
        converted : Socket & Result<&1, &1, U32 & String, H2.H2Response> <-
          request.http1_convert(got)
        request.body(converted)

def request.alpn.conn(
  conn: Result<&1, &1, U32 & String, Socket & String>,
  h2_call: HTTPSCall, h1_call: HTTP1.HTTPSCall) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, Fail{e})
    case Done{value}:
      (sock, protocol) = value
      request.alpn.go(TLS.tls_alpn_is_h2(protocol), sock,
        h2_call, h1_call)

def request.secure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  +hs2 = with_authority(host, port, hs)
  +hs1 = h1_headers(hs2)
  do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
    conn : Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_connect_any(host, port)
    request.alpn.conn(conn, HTTPSCall{host, port, method, path, hs2, body},
      HTTP1.HTTPSCall{host, port, method, path, hs1, body})

def request.insecure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  +hs2 = with_authority(host, port, hs)
  +hs1 = h1_headers(hs2)
  do IO<Result<&1, &1, U32 & String, H2.H2Response>>:
    conn : Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_connect_any_insecure(host, port)
    request.alpn.conn(conn, HTTPSCall{host, port, method, path, hs2, body},
      HTTP1.HTTPSCall{host, port, method, path, hs1, body})

def request.go(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match verify:
    case True{}:
      request.secure(host, port, method, path, hs, body)
    case False{}:
      request.insecure(host, port, method, path, hs, body)

# One validation predicate for every public entry point (the mirror of
# HTTP.valid_host/valid_port/valid_path triple).
def valid.go(+host: String, +port: U32, +path: String) -> Bool:
  Bool.and(HTTP.valid_host(host), Bool.and(HTTP.valid_port(port), HTTP.valid_path(path)))

def request.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>, verify: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  match fit:
    case True{}:
      request.go(host, port, method, path, hs, body, verify)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, H2.H2Response>, Fail{(400, "bad request")})

def request(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  request.fit(host, port, path, method, hs, body, True{}, valid.go(host, port, path))

def request_insecure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, H2.H2Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, H2.H2Response>):
  request.fit(host, port, path, method, hs, body, False{}, valid.go(host, port, path))

# Response body projections
# -------------------------
# The textual entry points share one projection: the body of a Done
# response decodes as String, a Fail passes through untouched.

def body_text(r: Result<&1, &1, U32 & String, H2.H2Response>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, String>, Done{decode_body(body)})

# Textual send_request (mirror HTTP.send_request)
# -----------------------------------------------
# Same exchange with a String body; answers the response body as String.

def send_request.go(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String, verify: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    r : Result<&1, &1, U32 & String, H2.H2Response> <- request.go(host, port, method, path, hs, encode_body(body), verify)
    body_text(r)

def send_request.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String, verify: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match fit:
    case True{}:
      send_request.go(host, port, path, method, hs, body, verify)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad request")})

def send_request(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  send_request.fit(host, port, path, method, hs, body, True{}, valid.go(host, port, path))

def send_request_insecure(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, H2.H2Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  send_request.fit(host, port, path, method, hs, body, False{}, valid.go(host, port, path))

# fetch: GET by URL (mirror HTTP.fetch, https only)
# -------------------------------------------------
# Parses https://host[:port]/path via HTTP.read_url; http:// is refused
# with 400 (use HTTP.fetch for cleartext). Answers the body as String;
# fetch_bytes answers raw bytes.

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
    body_text(r)

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
# H2.h2_serve_next (established connection, no preface). The loop is
# unbounded: streams are served until GOAWAY/EOF/Fail, then the socket
# closes (@unsafe: no fuel decreases; the socket carrier threads whole).

@unsafe
def serve_loop(~H: H2.H2Request -> IO(H2.H2Response), got: Socket & Result<&1, &1, U32 & String, Unit> & H2.HpDyn) ->
  IO(Unit):
  (s2, r, tab) = got
  match r:
    case Fail{e}:
      TLS.tls_close(s2)
    case Done{u}:
      do IO<Unit>:
        got2 : Socket & Result<&1, &1, U32 & String, Unit> & H2.HpDyn <- H2.h2_serve_next(s2, apply_wrap(~H), tab)
        serve_loop(~H, got2)

def serve_start(~H: H2.H2Request -> IO(H2.H2Response), sock: Socket) -> IO(Unit):
  do IO<Unit>:
    got : Socket & Result<&1, &1, U32 & String, Unit> & H2.HpDyn <- H2.h2_serve_once(sock, apply_wrap(~H))
    serve_loop(~H, got)

@unsafe
def server_on_http1(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  listener: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP1.server_on_http1(~H, listener, cert, key)

# -------------------------------------------------------
# Sequential serve_next tracks ONE H2SrvSt, so pipelined frames of two
# open streams (HEADERS 1, HEADERS 3, DATA 1, DATA 3) would mix into one
# state. The mux below tracks open streams in a plain List<H2SrvSt>
# (sid 0 = empty): HEADERS claims a slot, DATA appends to the matching
# slot, END_STREAM answers that slot immediately and frees it — any
# count and any completion order work. Header fragments (HEADERS
# without END_HEADERS) park as headless slots until CONTINUATION
# completes the block; a parallel fends list remembers which fragments
# carried END_STREAM. Single Socket carrier threaded whole (like
# HTTP.srv threads mr); slot decisions ride Bool/U32 params computed in
# caller arg position (never computed scrutinees).

def mux.sid_of(st: H2.H2SrvSt) -> U32:
  match st:
    case H2.H2SrvSt{head, body, +sid, hp}:
      sid

# SETTINGS classification fix: ack only a fresh (non-ACK) SETTINGS.
# An ACK already answers one, and acking it back would make the two
# unbounded read loops (this mux and the client chain) answer each other
# forever; a bounded single-shot reader would never notice. base rides
# H2.h2_srv.classify.

def mux.cls_fix(base: U32, +flags: U32) -> U32:
  match base flags:
    case 1 1:
      0
    case _ _:
      base

# The loop below reads on every turn, so the carrier only has to carry the
# socket: the H2Got slot is parked on a frame-less value while no frame is
# in hand. The socket is affine and Bend recovers it only by matching the
# carrier, so this parking value is the honest minimum here (a new H2Got
# variant would break every match on the type, and a magic error code is
# worse).
def mux.again(s: Socket) -> Socket & H2.H2Got:
  (s, H2.H2GotOk{H2.H2Frame{0, 0, 0, Nil{}}, Nil{}})

def mux.close_got(got: Socket & H2.H2Got) -> IO(Unit):
  (s, g) = got
  TLS.tls_close(s)

# Housekeeping sends keep the connection alive even if the write fails:
# the next read answers the dead socket and closes the connection.
def mux.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2.H2Got:
  (s2, r) = sent
  mux.again(s2)

def mux.ack(got: Socket & H2.H2Got) -> IO(Socket & H2.H2Got):
  (s, g) = got
  do IO<Socket & H2.H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s, H2.h2_t_settings(), H2.h2_f_ack(), 0, Nil{})
    IO.pure(Socket & H2.H2Got, mux.sent(sent))

def mux.ack_ping(got: Socket & H2.H2Got, +payload: List<&2, U32>) -> IO(Socket & H2.H2Got):
  (s, g) = got
  do IO<Socket & H2.H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s, H2.h2_t_ping(), H2.h2_f_ack(), 0, payload)
    IO.pure(Socket & H2.H2Got, mux.sent(sent))

# Slot decision leafs (plain defs, top-level matches only). HEADERS codes:
# 0 claim A, 1 answer A, 2 claim B, 3 answer B, 4 busy fail-closed,
# 5 head decode fail. DATA codes: 0 continue A, 1 answer A, 2 continue
# B, 3 answer B, 4 stray skip, 5 DATA-before-HEADERS A, 6 same B.

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
    case H2.H2SrvSt{head, body, sid, hp}:
      match head:
        case None{}:
          False{}
        case Some{rh}:
          True{}

def mux.body_of(st: H2.H2SrvSt) -> List<&2, U32>:
  match st:
    case H2.H2SrvSt{head, +body, sid, hp}:
      body

def mux.req_of(+rh: H2.H2ReqHead, +body: List<&2, U32>) -> H2.H2Request:
  match rh:
    case H2.H2ReqHead{+method, +path, +headers}:
      H2.H2Request{method, path, headers, body}

# Phase 2 (task-021): request straight from the slot, no +rh/+body.
# One match on the slot (param, allowed); the head None case answers the
# empty head, exactly what slot_rh + req_of did. Thin projection style
# like h2_reqhead.rh/ok/tab: the caller holds one reusable Taken bind.
def mux.req_of_st(st: H2.H2SrvSt, +payload: List<&2, U32>) -> H2.H2Request:
  match st:
    case H2.H2SrvSt{head, +body, +sid, hp}:
      match head:
        case None{}:
          H2.H2Request{"", "", Nil{}, List.append(&2, U32, body, payload)}
        case Some{+rh}:
          match rh:
            case H2.H2ReqHead{+method, +path, +headers}:
              H2.H2Request{method, path, headers, List.append(&2, U32, body, payload)}

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

# Unbounded-slot leaves (Phase 5): pure helpers over List<H2SrvSt>
# reusing mux.sid_of/some_of/body_of and H2.hp_empty. The single
# @unsafe mux below is the only loop (helpers never call back into it).

# Phase 2 (task-021): single-traversal take. A top-level A & B pair is not
# Data and cannot be reused with +, so the take travels in a Data wrapper
# (proven in /tmp/opencode/t2/taken.bend). One traversal O(S) always (args
# are strict, so the tail recursion runs even on early match) replaces
# three (slot_body + slot_rh + del). Callee above caller; match scrutinees
# are params or pattern-bound vars; self-recursion only.
type MuxTaken is Data:
  MuxTaken{slots: List<&2, H2.H2SrvSt>, st: H2.H2SrvSt}

def muxn.no_slots() -> List<&2, H2.H2SrvSt>:
  Nil{}

def muxn.no_fends() -> List<&2, U32>:
  Nil{}

def muxn.pick_st(eq: Bool, +a: H2.H2SrvSt, +b: H2.H2SrvSt) -> H2.H2SrvSt:
  match eq:
    case True{}:
      a
    case False{}:
      b

def muxn.get(slots: List<&2, H2.H2SrvSt>, +sid: U32) -> H2.H2SrvSt:
  match slots:
    case Nil{}:
      H2.H2SrvSt{None{}, Nil{}, 0, H2.hp_empty()}
    case +st <> t:
      muxn.pick_st(U32.is_eq(mux.sid_of(st), sid), st, muxn.get(t, sid))

def muxn.has(slots: List<&2, H2.H2SrvSt>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      Bool.or(U32.is_eq(mux.sid_of(st), sid), muxn.has(t, sid))

def muxn.del_go(eq: Bool, +st: H2.H2SrvSt, rest: List<&2, H2.H2SrvSt>) -> List<&2, H2.H2SrvSt>:
  match eq:
    case True{}:
      rest
    case False{}:
      st <> rest

def muxn.del(slots: List<&2, H2.H2SrvSt>, +sid: U32) -> List<&2, H2.H2SrvSt>:
  match slots:
    case Nil{}:
      Nil{}
    case +st <> t:
      muxn.del_go(U32.is_eq(mux.sid_of(st), sid), st, muxn.del(t, sid))

# Phase 2 take: find and remove in one traversal. take_go is the combiner
# (no recursion); take_del is self-recursive only. On True the tail take
# already ran (strict arg) and found nothing (sids are unique via put), so
# its rest is the original tail: (rest, st) is correct. 1x O(S) always.
def muxn.take_go(eq: Bool, +st: H2.H2SrvSt, p: MuxTaken) -> MuxTaken:
  match eq:
    case True{}:
      match p:
        case MuxTaken{+slots, st2}:
          MuxTaken{slots, st}
    case False{}:
      match p:
        case MuxTaken{+slots2, +found2}:
          MuxTaken{(st <> slots2), found2}

def muxn.take_del(slots: List<&2, H2.H2SrvSt>, +sid: U32) -> MuxTaken:
  match slots:
    case Nil{}:
      MuxTaken{Nil{}, H2.H2SrvSt{None{}, Nil{}, 0, H2.hp_empty()}}
    case +st <> t:
      muxn.take_go(U32.is_eq(mux.sid_of(st), sid), st, muxn.take_del(t, sid))

# Thin projections over one reusable Taken bind, like h2_reqhead.rh/ok/tab.
def muxn.taken_slots(p: MuxTaken) -> List<&2, H2.H2SrvSt>:
  match p:
    case MuxTaken{+slots, st}:
      slots

def muxn.taken_st(p: MuxTaken) -> H2.H2SrvSt:
  match p:
    case MuxTaken{slots, +st}:
      st

# DATA continue: keep the slot with the appended body. Mirrors the old
# put(St{Some{slot_rh}, append(slot_body), sid2}): rh from the head (empty
# when None), hp reset to empty, sid preserved (equals sid2 when found).
def muxn.data_cont_slots(p: MuxTaken, +payload: List<&2, U32>) -> List<&2, H2.H2SrvSt>:
  match p:
    case MuxTaken{+rest, st}:
      match st:
        case H2.H2SrvSt{head, +body, +sid, hp}:
          match head:
            case None{}:
              ((H2.H2SrvSt{Some{H2.H2ReqHead{"", "", Nil{}}}, List.append(&2, U32, body, payload), sid, H2.hp_empty()} <> rest))
            case Some{+rh}:
              ((H2.H2SrvSt{Some{rh}, List.append(&2, U32, body, payload), sid, H2.hp_empty()} <> rest))

# CONTINUATION fragment: head stays None, body grows. Mirrors the old
# put(St{None{}, append(slot_body), sid2}).
def muxn.frag_cont_slots(p: MuxTaken, +payload: List<&2, U32>) -> List<&2, H2.H2SrvSt>:
  match p:
    case MuxTaken{+rest, st}:
      match st:
        case H2.H2SrvSt{head, +body, +sid, hp}:
          ((H2.H2SrvSt{None{}, List.append(&2, U32, body, payload), sid, H2.hp_empty()} <> rest))

def muxn.put(slots: List<&2, H2.H2SrvSt>, +st: H2.H2SrvSt) -> List<&2, H2.H2SrvSt>:
  st <> muxn.del(slots, mux.sid_of(st))

def muxn.fhas(fends: List<&2, U32>, +sid: U32) -> Bool:
  match fends:
    case Nil{}:
      False{}
    case +x <> t:
      Bool.or(U32.is_eq(x, sid), muxn.fhas(t, sid))

def muxn.fdel_go(eq: Bool, +x: U32, rest: List<&2, U32>) -> List<&2, U32>:
  match eq:
    case True{}:
      rest
    case False{}:
      x <> rest

def muxn.fdel(fends: List<&2, U32>, +sid: U32) -> List<&2, U32>:
  match fends:
    case Nil{}:
      Nil{}
    case +x <> t:
      muxn.fdel_go(U32.is_eq(x, sid), x, muxn.fdel(t, sid))

def muxn.fput(fends: List<&2, U32>, +sid: U32) -> List<&2, U32>:
  sid <> muxn.fdel(fends, sid)

def muxn.fend_up(fends: List<&2, U32>, +sid: U32, is_end: Bool) -> List<&2, U32>:
  match is_end:
    case True{}:
      muxn.fput(fends, sid)
    case False{}:
      muxn.fdel(fends, sid)

def muxn.fend_flag_go(has: Bool) -> U32:
  match has:
    case True{}:
      1
    case False{}:
      0

def muxn.fend_flag(fends: List<&2, U32>, +sid: U32) -> U32:
  muxn.fend_flag_go(muxn.fhas(fends, sid))

def muxn.frag_has_go(has: Bool, some: Bool) -> Bool:
  match has some:
    case True{} False{}:
      True{}
    case _ _:
      False{}

def muxn.frag_has(+slots: List<&2, H2.H2SrvSt>, +sid: U32) -> Bool:
  muxn.frag_has_go(muxn.has(slots, sid), mux.some_of(muxn.get(slots, sid)))

# HEADERS action codes: 0 claim slot, 1 answer now, 5 decode fail,
# 6 park header fragment (HEADERS without END_HEADERS).
def muxn.head_act(need: U32, ok: Bool, +end: U32) -> U32:
  match need ok end:
    case 1 _ _:
      6
    case 0 False{} _:
      5
    case 0 True{} 1:
      1
    case _ _ _:
      0

# DATA action codes: 0 append, 1 answer, 4 stray skip-or-close.
def muxn.decide_data(has: Bool, +end: U32) -> U32:
  match has end:
    case False{} _:
      4
    case True{} 1:
      1
    case _ _:
      0

# CONTINUATION action codes: 0 append fragment, 1 finish block,
# 4 connection error (no open fragment for this sid).
def muxn.decide_cont(has_frag: Bool, +endh: U32) -> U32:
  match has_frag endh:
    case False{} _:
      4
    case True{} 0:
      0
    case True{} 4:
      1
    case _ _:
      4

def muxn.need_go(needs: Bool) -> U32:
  match needs:
    case True{}:
      1
    case False{}:
      0

def muxn.need_u(+typ: U32, +flags: U32) -> U32:
  muxn.need_go(H2.h2_needs_cont(typ, flags))

def muxn.cont_failed(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = sent
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      TLS.tls_close(s)

# Main interleave loop (single @unsafe self-recursive def, like HTTP.srv:
# phase-0 reset spelled out at each site (a reset helper would
# forward-call into mux). Single Socket carrier threaded whole, slot
# decisions as Bool/U32 params computed in caller arg position, open
# streams as List<H2SrvSt> + fragment END_STREAM ledger fends).
# Phases: 0 read the next frame (the carrier only carries the socket),
# 1 decompose, 2 connection dispatch (cls),
# 3 stream dispatch (typ), 4 HEADERS-complete, 5 DATA, 6 CONTINUATION.
# Answers inline via H2.h2_srv.send_resp; inbound DATA flow credit
# rides H2.h2_read_frame (best-effort WINDOW_UPDATE, Phase 3).

@unsafe
def mux(~H: H2.H2Request -> IO(H2.H2Response), phase: U32, got: Socket & H2.H2Got, +slots: List<&2, H2.H2SrvSt>, +fends: List<&2, U32>, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +rh: H2.H2ReqHead, act: U32, +tab: H2.HpDyn) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & H2.H2Got <- H2.h2_read_frame(s0, buf)
        mux(~H, 1, got2, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
    case 1:
      (s1, g1) = got
      match g1:
        case H2.H2GotErr{code1, msg1}:
          TLS.tls_close(s1)
        case H2.H2GotOk{+frame, +buf2}:
          match frame:
            case H2.H2Frame{+typ2, +flags2, +sid22, +payload2}:
              mux(~H, 2, (s1, H2.H2GotOk{frame, buf2}), slots, fends, buf2, typ2, flags2, sid22, payload2, mux.cls_fix(H2.h2_srv.classify(frame), flags2), U32.and(flags2, H2.h2_f_end_stream()), H2.H2ReqHead{"", "", Nil{}}, 4, tab)
    case 2:
      match cls:
        case 1:
          do IO<Unit>:
            got2 : Socket & H2.H2Got <- mux.ack(got)
            mux(~H, 0, got2, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 4:
          do IO<Unit>:
            gotp : Socket & H2.H2Got <- mux.ack_ping(got, payload)
            mux(~H, 0, gotp, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 5:
          mux.close_got(got)
        case 2:
          mux(~H, 0, got, muxn.del(slots, sid2), muxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 7:
          mux(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 9:
          mux.close_got(got)
        case 8:
          mux(~H, 6, got, slots, fends, buf, typ, flags, sid2, payload, cls, U32.and(flags, H2.h2_f_end_headers()), H2.H2ReqHead{"", "", Nil{}}, muxn.decide_cont(muxn.frag_has(slots, sid2), U32.and(flags, H2.h2_f_end_headers())), tab)
        case 6:
          mux(~H, 3, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 0:
          mux(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case _:
          mux(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
    case 3:
      match typ:
        case 1:
          +pr : Result<&1, &1, U32 & String, H2.H2ReqHead & H2.HpDyn> = H2.h2_reqhead.decode(payload, tab)
          mux(~H, 4, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, H2.h2_reqhead.rh(pr), muxn.head_act(muxn.need_u(typ, flags), H2.h2_reqhead.ok(pr), end), H2.h2_reqhead.tab(pr))
        case 0:
          mux(~H, 5, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, H2.H2ReqHead{"", "", Nil{}}, muxn.decide_data(muxn.has(slots, sid2), end), tab)
        case _:
          mux(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
    case 4:
      (s4, g4) = got
      match act:
        case 0:
          mux(~H, 0, got, muxn.put(slots, H2.H2SrvSt{Some{rh}, Nil{}, sid2, H2.hp_empty()}), muxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 1:
          do IO<Unit>:
            req : H2.H2Request = mux.req_of(rh, Nil{})
            resp : H2.H2Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_srv.send_resp(s4, sid2, resp)
            mux(~H, 0, mux.sent(sent), muxn.del(slots, sid2), muxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 6:
          mux(~H, 0, got, muxn.put(slots, H2.H2SrvSt{None{}, payload, sid2, H2.hp_empty()}), muxn.fend_up(fends, sid2, U32.is_eq(end, 1)), buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 5:
          TLS.tls_close(s4)
        case _:
          TLS.tls_close(s4)
    case 5:
      (sm, gm) = got
      match act:
        case 0:
          mux(~H, 0, got, muxn.data_cont_slots(muxn.take_del(slots, sid2), payload), fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 1:
          do IO<Unit>:
            +tp : MuxTaken = muxn.take_del(slots, sid2)
            req : H2.H2Request = mux.req_of_st(muxn.taken_st(tp), payload)
            resp : H2.H2Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_srv.send_resp(sm, sid2, resp)
            mux(~H, 0, mux.sent(sent), muxn.taken_slots(tp), muxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 4:
          mux.close_got(got)
        case _:
          mux.close_got(got)
    case 6:
      (s6, g6) = got
      match act:
        case 0:
          mux(~H, 0, got, muxn.frag_cont_slots(muxn.take_del(slots, sid2), payload), fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)
        case 1:
          +tp2 : MuxTaken = muxn.take_del(slots, sid2)
          +full : List<&2, U32> = List.append(&2, U32, mux.body_of(muxn.taken_st(tp2)), payload)
          +pr6 : Result<&1, &1, U32 & String, H2.H2ReqHead & H2.HpDyn> = H2.h2_reqhead.decode(full, tab)
          +ff : U32 = muxn.fend_flag(fends, sid2)
          mux(~H, 4, got, muxn.taken_slots(tp2), muxn.fdel(fends, sid2), buf, typ, flags, sid2, Nil{}, cls, ff, H2.h2_reqhead.rh(pr6), muxn.head_act(0, H2.h2_reqhead.ok(pr6), ff), H2.h2_reqhead.tab(pr6))
        case _:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_goaway(s6, 0, 1)
            muxn.cont_failed(sent)
    case _:
      mux(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, tab)

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
          mux_pre(~H, 1, (s0, Done{chunk}), acc2, H2.h2_srv.preface_ok(acc2), U32.is_lt(H2.b_len32(acc2), 24))
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
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s2, H2.h2_t_settings(), 0, 0, H2.h2_settings_initial_pay())
            mux(~H, 0, mux.sent(sent), muxn.no_slots(), muxn.no_fends(), H2.b_drop32(24, acc), 0, 0, 0, Nil{}, 0, 0, H2.H2ReqHead{"", "", Nil{}}, 4, H2.hp_empty())
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def mux_start(~H: H2.H2Request -> IO(H2.H2Response), sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    mux_pre(~H, 0, r1, Nil{}, 0, False{})

# Accept plumbing shared by both servers: one stream at a time
# (is_mux = False) or the unbounded-slot mux (is_mux = True). The two
# differ only in the per-connection start (serve_start vs mux_start), so
# one pair serves both and lives here, below the two starts. HTTP/1.1
# connections never reach it: the ALPN split hands them to
# HTTP1.http1_spawn.

def serve.spawn.go(~H: H2.H2Request -> IO(H2.H2Response), is_mux: Bool, sock: Socket) ->
  IO(Unit):
  match is_mux:
    case True{}:
      mux_start(~H, sock)
    case False{}:
      serve_start(~H, sock)

def serve.spawn(~H: H2.H2Request -> IO(H2.H2Response), is_mux: Bool, sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, serve.spawn.go(~H, is_mux, sock))
    return l

def serve.conn(~H: H2.H2Request -> IO(H2.H2Response), is_mux: Bool, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      serve.spawn(~H, is_mux, sock, l)

# ALPN split: h2 connections go to the H2 codec, http/1.1 (or no ALPN)
# to the HTTP/1.1 module, on the same port.

def serve.alpn_conn.go(
  ~H2: H2.H2Request -> IO(H2.H2Response),
  ~H1: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  is_mux: Bool, is_h2: Bool, listener: Listener, sock: Socket) -> IO(Listener):
  match is_h2:
    case True{}:
      serve.spawn(~H2, is_mux, sock, listener)
    case False{}:
      HTTP1.http1_spawn(~H1, sock, listener)

def serve.alpn_conn(
  ~H2: H2.H2Request -> IO(H2.H2Response),
  ~H1: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  is_mux: Bool,
  accepted: Listener & Result<&1, &1, U32 & String, Socket & String>) -> IO(Listener):
  (listener, result) = accepted
  match result:
    case Fail{e}:
      IO.pure(Listener, listener)
    case Done{value}:
      (sock, protocol) = value
      serve.alpn_conn.go(~H2, ~H1, is_mux, TLS.tls_alpn_is_h2(protocol),
        listener, sock)

# Public servers. The plain pair keeps the legacy H2-only contract
# (strict h2 ALPN); the _alpn pair accepts HTTP/1.1 on the same port.

@unsafe
def server_on(~H: H2.H2Request -> IO(H2.H2Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- serve.conn(~H, False{}, m)
    z : Unit <- server_on(~H, l2, cert, key)
    return z

@unsafe
def server_on_concurrent(~H: H2.H2Request -> IO(H2.H2Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- serve.conn(~H, True{}, m)
    z : Unit <- server_on_concurrent(~H, l2, cert, key)
    return z

@unsafe
def server_on_alpn(
  ~H2: H2.H2Request -> IO(H2.H2Response),
  ~H1: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  listener: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_accept_alpn(listener, cert, key)
    next : Listener <- serve.alpn_conn(~H2, ~H1, False{}, accepted)
    z : Unit <- server_on_alpn(~H2, ~H1, next, cert, key)
    return z

@unsafe
def server_on_concurrent_alpn(
  ~H2: H2.H2Request -> IO(H2.H2Response),
  ~H1: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  listener: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_accept_alpn(listener, cert, key)
    next : Listener <- serve.alpn_conn(~H2, ~H1, True{}, accepted)
    z : Unit <- server_on_concurrent_alpn(~H2, ~H1, next, cert, key)
    return z
