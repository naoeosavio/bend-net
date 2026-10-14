# io (httpx_h2_goaway): a GOAWAY or an RST_STREAM must arrive as a typed
# stream error, not as a bare 502 (task-042 phase 5).
#
# The peer is a canned H2 server: TLS accept, preface consumed, SETTINGS
# out, then hand-built frames. Six connections, one shape each:
#   scen 0: HEADERS(:status 200, END_HEADERS, no END_STREAM) then
#           GOAWAY(NO_ERROR, last=1) -- the peer did process stream 1, so
#           the response is incomplete: a real failure (502), but typed
#           with the error name, the last-stream-id and the sid;
#   scen 1: GOAWAY(REFUSED_STREAM, last=0) with no response -- stream 1 is
#           above last, so it was NOT processed and repeating the request
#           is allowed: 503 (RFC 9113 section 8.7);
#   scen 2: RST_STREAM(REFUSED_STREAM) -- the same "not processed" signal
#           on the stream itself: 503;
#   scen 3: the node:http2 shape -- answer stream 1, then, once stream 3's
#           request is in, reset stream 1 (NO_ERROR) and answer stream 3.
#           A sibling's RST must stay invisible: before the fix the second
#           request died with `Fail{502, "rst_stream"}`;
#   scen 4: the streaming lane (client.stream) with
#           GOAWAY(REFUSED_STREAM, last=0): 503;
#   scen 5: the concurrent batch with GOAWAY(NO_ERROR, last=1): the batch
#           opens sid 1 first, so the peer may have acted on it -- 502.
#
# Before the fix every one of these was `Fail{502, "goaway"}` /
# `Fail{502, "rst_stream"}` regardless of the wired code or the
# last-stream-id; the measured "before" is in .p42/goaway.before.txt.
#
# Score: one point per scenario (the batch scores only with both 200s),
# golden 6.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def PORT() -> U32:
  18574

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Wired H2 error codes (RFC 9113 section 7.1) and the fail codes the
# client answers: 503 = the stream was not processed, 502 = it may have
# been.
def NO_ERROR() -> U32:
  0

def REFUSED_STREAM() -> U32:
  7

def CANCELLED() -> U32:
  8

def NOT_PROCESSED() -> U32:
  503

def MAYBE_PROCESSED() -> U32:
  502

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def req(path: String) -> HTTPX.Request:
  HTTPX.Request{"GET", path, Nil{}, Nil{}}

def head_block() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.Hdr{":status", "200"}])

def end_flags() -> U32:
  (HTTPX.x_f_end_headers() + HTTPX.x_f_end_stream() : U32)

# Client side scoring: one point per scenario, exact Fail code and text.

def fail_eq(e: U32 & String, +code: U32, +msg: String) -> U32:
  (c, m) = e
  U32.mul(b2u(U32.is_eq(c, code)), b2u(String.eq(m, msg)))

def want_resp(r: Result<&1, &1, U32 & String, HTTPX.Response>, +code: U32, +msg: String) -> U32:
  match r:
    case Fail{e}:
      fail_eq(e, code, msg)
    case Done{resp}:
      0

def want_stream(r: Result<&1, &1, U32 & String, U32 & U32>, +code: U32, +msg: String) -> U32:
  match r:
    case Fail{e}:
      fail_eq(e, code, msg)
    case Done{counts}:
      0

def want_total(r: Result<&1, &1, U32 & String, U32>, +code: U32, +msg: String) -> U32:
  match r:
    case Fail{e}:
      fail_eq(e, code, msg)
    case Done{+total}:
      0

def resp_ok(r: HTTPX.Response) -> U32:
  match r:
    case HTTPX.Response{+status, +headers, +body}:
      b2u(U32.is_eq(status, 200))

# scen 3: both answers must land, in order, with status 200.
def batch_score(r: Result<&1, &1, U32 & String, List<&2, HTTPX.Response>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+rs}:
      match rs:
        case Nil{}:
          0
        case r1 <> t1:
          match t1:
            case Nil{}:
              0
            case r2 <> _:
              U32.mul(resp_ok(r1), resp_ok(r2))

def sh(ev: HTTPX.StreamEv) -> HTTPX.StreamOut:
  match ev:
    case HTTPX.StreamHead{head}:
      HTTPX.StreamContinue{}
    case HTTPX.StreamData{chunk, fin}:
      HTTPX.StreamContinue{}

def sc(resp: HTTPX.Response) -> U32:
  resp_ok(resp)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r0 : Result<&1, &1, U32 & String, HTTPX.Response> <- HTTPX.client.once_insecure(HOST(), port, req("/g1"))
    r1 : Result<&1, &1, U32 & String, HTTPX.Response> <- HTTPX.client.once_insecure(HOST(), port, req("/g0"))
    r2 : Result<&1, &1, U32 & String, HTTPX.Response> <- HTTPX.client.once_insecure(HOST(), port, req("/r7"))
    r3 : Result<&1, &1, U32 & String, List<&2, HTTPX.Response>> <- HTTPX.client.on_insecure(HOST(), port, [req("/a"), req("/b")])
    r4 : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_insecure(~sh, HOST(), port, "GET", "/sg", Nil{}, Nil{})
    r5 : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~sc, HOST(), port, [req("/c")])
    +s0 : U32 = want_resp(r0, MAYBE_PROCESSED(), "goaway NO_ERROR(0) last=1 sid=1")
    +s1 : U32 = want_resp(r1, NOT_PROCESSED(), "goaway REFUSED_STREAM(7) last=0 sid=1")
    +s2 : U32 = want_resp(r2, NOT_PROCESSED(), "rst_stream REFUSED_STREAM(7)")
    +s3 : U32 = batch_score(r3)
    +s4 : U32 = want_stream(r4, NOT_PROCESSED(), "goaway REFUSED_STREAM(7) last=0 sid=1")
    +s5 : U32 = want_total(r5, MAYBE_PROCESSED(), "goaway NO_ERROR(0) last=1 sid=1")
    IO.pure(U32, (s0 + s1 + s2 + s3 + s4 + s5 : U32))

# Server side: the canned peer (mold tests/io/httpx_h2_stream_trailers.bend).

def srv_sock(got: Socket & HTTPX.Got) -> Socket:
  (s, g) = got
  s

def srv_acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTPX.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTPX.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTPX.GotErr{0, "next"})

# Answers are out: read until the client closes (a real H2 peer does not
# close without GOAWAY, and closing here would race the client's own
# frames).
@unsafe
def srv_idle(phase: U32, got: Socket & HTTPX.Got, +buf: List<&2, U32>) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTPX.Got <- HTTPX.x_read_frame(s0, buf)
        srv_idle(1, got2, buf)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTPX.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTPX.GotOk{+frame, +buf2}:
          srv_idle(0, (s1, HTTPX.GotOk{frame, buf2}), buf2)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle(0, (s, HTTPX.GotErr{0, "next"}), Nil{})

# scen 0 tail: the head is out, then the peer goes away without ever
# closing the response body.
def srv_go_after_head(m: Socket & Result<&1, &1, U32 & String, Unit>, +last: U32, +code: U32) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_goaway(s, last, code)
        srv_idle_from(sent)

def srv_answer(sock: Socket, +scen: U32) -> IO(Unit):
  match scen:
    case 0:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(sock, HTTPX.x_t_headers(), HTTPX.x_f_end_headers(), 1, head_block())
        srv_go_after_head(sent, 1, NO_ERROR())
    case 2:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_rst(sock, 1, REFUSED_STREAM())
        srv_idle_from(sent)
    case 5:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_goaway(sock, 1, NO_ERROR())
        srv_idle_from(sent)
    case _:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_goaway(sock, 0, REFUSED_STREAM())
        srv_idle_from(sent)

def srv_is_head(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTPX.x_t_headers())

# What the loop does with a classified frame: 2 answers the request (scens
# 0/1/2/4/5), 3 answers stream 1 and keeps reading (scen 3, stage 0), 4
# resets stream 1 and answers stream 3 (scen 3, stage 1), 0 skips. The
# first scrutinee of a multi-scrutinee match has to be the def's first
# parameter: bend 2.0.36 rejects any other order with "a match on a
# parameter or field".
def srv_act(is_head: Bool, +scen: U32, +stage: U32) -> U32:
  match is_head scen stage:
    case True{} 3 0:
      3
    case True{} 3 _:
      4
    case True{} _ _:
      2
    case False{} _ _:
      0

# Frame loop with the two-request stage of scen 3: stage 0 answers stream 1
# and keeps reading, stage 1 resets stream 1 and answers stream 3.
@unsafe
def srv(phase: U32, got: Socket & HTTPX.Got, +buf: List<&2, U32>, +typ: U32, +scen: U32, +stage: U32, act: U32) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTPX.Got <- HTTPX.x_read_frame(s0, buf)
        srv(1, got2, buf, 0, scen, stage, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTPX.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTPX.GotOk{+frame, +buf2}:
          match frame:
            case HTTPX.Frame{+typ2, +flags2, +sid2, +payload2}:
              srv(2, (s1, HTTPX.GotOk{frame, buf2}), buf2, typ2, scen, stage, srv_act(srv_is_head(typ2), scen, stage))
    case 2:
      match act:
        case 2:
          srv_answer(srv_sock(got), scen)
        case 3:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(srv_sock(got), HTTPX.x_t_headers(), end_flags(), 1, head_block())
            srv(0, srv_acked(sent), buf, 0, scen, 1, 4)
        case 4:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_rst(srv_sock(got), 1, NO_ERROR())
            srv(3, srv_acked(sent), buf, 0, scen, 2, 4)
        case _:
          srv(0, got, buf, typ, scen, stage, 4)
    case 3:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(srv_sock(got), HTTPX.x_t_headers(), end_flags(), 3, head_block())
        srv_idle_from(sent)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

# The SETTINGS the peer sends after the preface, and then the frame loop.
# `rest` is what came AFTER the 24 preface bytes in the first read, and it
# must be handed on: TLS.recv answers with every application byte the pump
# is holding, up to max -- the plaintext lane answers with whatever the
# socket buffer holds, and the portable lane does the same -- so one read
# routinely carries the preface, the client's SETTINGS and its first
# request together. Starting the loop on Nil{} dropped all of it, and the
# peer then waited for a request it had already received: the retired
# OpenSSL twin returned one record per read, which is what hid this. A
# deadlock only the portable lane could show.
def srv_set(got: Socket & HTTPX.Got, +rest: List<&2, U32>, +scen: U32) -> IO(Unit):
  (s, g) = got
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_settings(), 0, 0, HTTPX.x_settings_initial_pay())
    srv(0, srv_acked(sent), rest, 0, scen, 0, 4)

# The client preface is not a frame: consume its 24 bytes first (mold
# tests/io/httpx_client_cont.bend; @unsafe for the same reason: the phase
# ping-pong does not shrink a structural argument).
@unsafe
def srv_pre(phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool, +scen: U32) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          srv_pre(1, (s0, Done{chunk}), acc2, HTTPX.x_preface_ok(acc2), U32.is_lt(HTTPX.x_len32(acc2), 24), scen)
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            srv_pre(0, r2, acc, 0, False{}, scen)
        case False{}:
          srv_pre(2, rs, acc, ok, short, scen)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          srv_set((s2, HTTPX.GotErr{0, "next"}), HTTPX.x_drop32(24, acc), scen)
        case _:
          do IO<Unit>:
            TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def srv_start(sock: Socket, +scen: U32) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    srv_pre(0, r1, Nil{}, 0, False{}, scen)

# Six accepts, one per scenario, in client call order: the client dials the
# next connection only after the previous exchange is answered and closed,
# so the backlog holds it until this loop comes back.
def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +scen: U32) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- srv_start(sock, scen)
        return l

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    m0 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    l1 : Listener <- srv_conn(m0, 0)
    m1 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l1, CERT(), KEY())
    l2 : Listener <- srv_conn(m1, 1)
    m2 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l2, CERT(), KEY())
    l3 : Listener <- srv_conn(m2, 2)
    m3 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l3, CERT(), KEY())
    l4 : Listener <- srv_conn(m3, 3)
    m4 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l4, CERT(), KEY())
    l5 : Listener <- srv_conn(m4, 4)
    m5 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l5, CERT(), KEY())
    l6 : Listener <- srv_conn(m5, 5)
    return "up"

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

def run(l: Listener, +port: U32) -> IO(U32):
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|6
