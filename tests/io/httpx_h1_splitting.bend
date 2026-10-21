# httpx (lib_httpx_h1_splitting): header splitting on the H1 render
# (TASK-030).
#
# x_h1.render_hs.go writes "name: value\r\n" verbatim, so a CR/LF/NUL in
# either half ended the field early and the rest was read as headers the
# caller never asked for. The same def renders both directions, so the one
# hole was request splitting on the client (x_h1.render_req, the one-shot
# and keep-alive lanes) and response splitting on the server
# (x_h1.show_resp/show_resp_head) — and the request expression was copied
# inline in a third site, the 101 upgrade lane (x_h1.cli.exch.open.fit).
#
# Phase 1 — pure vectors over the request render. A CR/LF in a value, a
# CR/LF in a name and a NUL in a value are all Fail 400 before any byte is
# rendered; a clean header whose value carries a space (the "gzip, deflate"
# shape) still renders as exactly one well-formed field, which is what
# keeps the fix from being a blunt reject of every legitimate header.
#
# Phase 2 — the same reject on the wire, against a real server
# (server.on_h1_plain) over real TCP, and the session stays usable after
# it: the rejected request is followed by a clean one on the SAME socket,
# and the handler reports what it actually parsed — "CLEAN" or "INJECTED"
# (the field the split would have produced). So the second body is the
# wire-level witness that the payload never reached a handler, and "the
# clean request still gets an answer" shows the fail left no half-written
# request behind. Measured against the unfixed tree (lib stashed): the test
# prints 2, not 9 — the first exchange ANSWERS instead of failing, which is
# the discriminating vector; the second still scores because an injected
# field is a valid header and the peer answers the request normally, so
# only the Fail itself separates the two worlds.
#
# Phase 3 — the server direction. x_h1.srv.safe_resp replaces a whole
# response whose handler headers cannot be rendered with a bare 500 (two
# pure vectors: the bad one collapses, the clean one is untouched), and the
# wire vector asks a handler for exactly that bad response: the client must
# read 500 with no injected field and no body. With the injection in place
# the parser would have produced the "Injected" field, so its absence is
# the witness.
# Golden 9.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http1.bend as HTTP1
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def hdr(n: String, v: String) -> HTTP.Hdr:
  HTTP.Hdr{n, v}

# fail_code(r, want): 1 iff r is Fail with the wanted code.
def fail_code(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: U32) ->
  U32:
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{bs}:
      0

# fail_code_req(r, want): the same check over a Response result.
def fail_code_req(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: U32) ->
  U32:
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, want))
    case Done{resp}:
      0

# has_field(r, want): 1 iff r rendered and the bytes contain that field.
def has_field(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: String) ->
  U32:
  match r:
    case Fail{e}:
      0
    case Done{+bs}:
      b2u(String.contains(HTTP.x_bytes_str(bs), want))

# A CR/LF in the value would end the field after "x: a" and the peer would
# read "Injected: 1" as a header of its own.
def v_value_crlf() -> U32:
  fail_code(HTTP1.x_h1.render_req("POST", "/echo", "127.0.0.1", 80,
    [hdr("x", "a\r\nInjected: 1")], Nil{}), 400)

# The name side splits the same way, one field earlier.
def v_name_crlf() -> U32:
  fail_code(HTTP1.x_h1.render_req("POST", "/echo", "127.0.0.1", 80,
    [hdr("x\r\nInjected: 1", "a")], Nil{}), 400)

# NUL is not a line terminator, but it is the other character that makes
# the field text unrenderable (the same predicate valid_host uses).
def v_value_nul() -> U32:
  fail_code(HTTP1.x_h1.render_req("POST", "/echo", "127.0.0.1", 80,
    [hdr("x", String.from_list([Chr{0}]))], Nil{}), 400)

# The control: a space in a value is legal, and the field must come out
# whole ("x-ok: gzip, deflate\r\n").
def v_value_space_ok() -> U32:
  has_field(HTTP1.x_h1.render_req("POST", "/echo", "127.0.0.1", 80,
    [hdr("x-ok", "gzip, deflate")], Nil{}), "x-ok: gzip, deflate\r\n")

def hdrs_none(hs: List<&2, HTTP.Hdr>) -> Bool:
  match hs:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

# resp_is_500(resp): 1 iff the guard collapsed the response: 500, no
# headers at all, no body. Nothing of what the handler asked to send is
# left — not even the field that was fine.
def resp_is_500(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 500),
        Bool.and(hdrs_none(headers), List.is_empty(&2, U32, body))))

# resp_kept(resp): 1 iff a renderable response came through untouched.
def resp_kept(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 200),
        U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("keep")), 1)))

def v_resp_bad() -> U32:
  resp_is_500(HTTP1.x_h1.srv.safe_resp(
    HTTP.Response{200, [hdr("x-echo", "a\r\nInjected: 1")],
      HTTP.x_str_bytes("leak")}))

def v_resp_ok() -> U32:
  resp_kept(HTTP1.x_h1.srv.safe_resp(
    HTTP.Response{200, [hdr("x-ok", "1")], HTTP.x_str_bytes("keep")}))

def vectors() -> U32:
  (v_value_crlf() + v_name_crlf() + v_value_nul() + v_value_space_ok()
    + v_resp_bad() + v_resp_ok() : U32)

law listen_retry:
  for port: U32
  for r: Result<&1, &1, (U32 & String), Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

law listen_any:
  for tries: Nat
  for +port: U32
  IO(Listener & U32)

def listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

# Phase 2/3 — wire ----------------------------------------------------
# ---------------------------------------------------------------------

# seen_go(hs, acc): True when the field the split would have produced
# ("Injected: 1") is really there in the header list being looked at — the
# request the handler was given, or the response the client parsed.
def seen_go(+hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      +hit = Bool.and(HTTP1.x_h1.eq_ci(n, "injected"), String.eq(v, "1"))
      seen_go(t, Bool.or(acc, hit))

def seen_text(is_injected: Bool) -> String:
  match is_injected:
    case True{}:
      "INJECTED"
    case False{}:
      "CLEAN"

# route_go(headers, is_bad): the echo route answers the verdict on its own
# parsed headers (never a body echo), so the response body is the witness
# of what crossed the wire; /bad asks for the header that cannot be
# rendered, which is Phase 3's trigger.
def route_go(+headers: List<&2, HTTP.Hdr>, is_bad: Bool) -> HTTP.Response:
  match is_bad:
    case True{}:
      HTTP.Response{200, [hdr("x-echo", "a\r\nInjected: 1")],
        HTTP.x_str_bytes("leak")}
    case False{}:
      HTTP.Response{200, Nil{},
        HTTP.x_str_bytes(seen_text(seen_go(headers, False{})))}

def echo_service(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, route_go(headers, String.eq(path, "/bad")))

def body_ok(resp: HTTP.Response, +want: String) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 200),
        U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes(want)), 1)))

# ok_reply(r, want): 1 iff r is a 200 whose body is `want`.
def ok_reply(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: String) ->
  U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      body_ok(resp, want)

# reply_500.go(resp): 1 iff the guarded answer came back — 500, the
# injected field absent (the parser would have made one out of the split),
# no body. Content-Length rides in the parsed headers, so only the injected
# name is checked here, not emptiness.
def reply_500.go(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 500),
        Bool.and(Bool.not(seen_go(headers, False{})),
          List.is_empty(&2, U32, body))))

def reply_500(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      reply_500.go(resp)

# The last step: score the guarded /bad answer and close. `ab` is the score
# of the two exchanges that came before it on this same socket.
def wire_done(out: Socket & Result<&1, &1, U32 & String, HTTP.Response>, +ab: U32) ->
  IO(U32):
  (s3, r3) = out
  do IO<U32>:
    +c : U32 = reply_500(r3)
    cl : Unit <- Socket.close(s3)
    IO.pure(U32, (ab + c : U32))

def wire_bad(out: Socket & Result<&1, &1, U32 & String, HTTP.Response>, +a: U32, +port: U32) ->
  IO(U32):
  (s2, r2) = out
  do IO<U32>:
    +b : U32 = ok_reply(r2, "CLEAN")
    out3 : Socket & Result<&1, &1, U32 & String, HTTP.Response> <-
      HTTP1.x_h1.cli.exch(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, s2, "127.0.0.1", port, "GET", "/bad", Nil{}, Nil{})
    wire_done(out3, (a + b : U32))

# The exchanges on one socket, in order. wire_go sends the bad-header
# request; the pair comes back with the socket untouched (the render failed
# before any byte), and wire_clean reuses that same socket for a clean
# request, which is what only works if nothing was written.
def wire_clean(out: Socket & Result<&1, &1, U32 & String, HTTP.Response>, +port: U32) ->
  IO(U32):
  (s1, r1) = out
  do IO<U32>:
    +a : U32 = fail_code_req(r1, 400)
    out2 : Socket & Result<&1, &1, U32 & String, HTTP.Response> <-
      HTTP1.x_h1.cli.exch(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, s1, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("ho"))
    wire_bad(out2, a, port)

def wire_go(sock: Socket, +port: U32) -> IO(U32):
  do IO<U32>:
    out1 : Socket & Result<&1, &1, U32 & String, HTTP.Response> <-
      HTTP1.x_h1.cli.exch(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "POST", "/echo", [hdr("x", "a\r\nInjected: 1")], HTTP.x_str_bytes("hi"))
    wire_clean(out1, port)

def srv_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.on_h1_plain(~echo_service, l)
    IO.pure(U32, 0)

def wire_dial(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      wire_go(sock, port)

def wire_run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, srv_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    wire_dial(conn, port)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +pure : U32 = vectors()
    b : Listener & U32 <- listen_any(32n, 18530)
    +wire : U32 <- wire_run(b)
    +total : U32 = (pure + wire : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|9
