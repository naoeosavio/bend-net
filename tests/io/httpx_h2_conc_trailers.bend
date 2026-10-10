# io (httpx_h2_conc_trailers): a trailer block must not become the answer
# on the concurrent lane either (task-042 phase 3b, the fourth and last of
# the trailer-blind drains found in phase 3).
#
# The peer is a canned H2 server: TLS accept, preface consumed, SETTINGS
# out, read frames until both requests are in, then two answers on one
# connection, one per sid:
#   sid 1: HEADERS(:status 200, END_HEADERS), DATA("hi", no END_STREAM)
#          and HEADERS(x-sum: 3, END_HEADERS|END_STREAM) — the shape
#          node's stream.sendTrailers() puts on the wire;
#   sid 3: the same head and trailer fragmented (HEADERS without
#          END_HEADERS plus CONTINUATION), the path client_conc.drain
#          reassembles inline (phase 6/8).
#
# The client scores each response 1 iff status 200 and body "hi"; before
# the fix the trailer decoded to Head{0}, took act 1 and answered
# Response{0, ...} from the decoded block instead of the stored one, so
# the body accumulated in the slot ledger was lost: 0 + 0. Now the entry
# is taken and the stored head and body ride out: 1 + 1, golden 2.
#
# The single connection answers only after BOTH requests are read: the
# concurrent sender discards any frame that arrives while it is sending
# (client_conc.send_kept, task-042 phase 2b), so an early answer would be
# dropped before the drain ever runs.
#
# Score: sum of the two response scores, golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def PORT() -> U32:
  18565

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HI() -> List<&2, U32>:
  [104, 105]

def head_block() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.Hdr{":status", "200"}])

def trailer_block() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.Hdr{"x-sum", "3"}])

# Blocks are split at 6 bytes to force the CONTINUATION path.
def head_first() -> List<&2, U32>:
  HTTPX.x_take32(6, head_block())

def head_rest() -> List<&2, U32>:
  HTTPX.x_drop32(6, head_block())

def trailer_first() -> List<&2, U32>:
  HTTPX.x_take32(6, trailer_block())

def trailer_rest() -> List<&2, U32>:
  HTTPX.x_drop32(6, trailer_block())

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def h(resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTPX.x_eq(body, HI()), 1)))

def reqs() -> List<&2, HTTPX.Request>:
  [HTTPX.Request{"POST", "/trailer", Nil{}, HI()}, HTTPX.Request{"POST", "/trailer-cont", Nil{}, HI()}]

def client_score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      total

def client(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~h, HOST(), port, reqs())
    IO.pure(U32, client_score(r))

def srv_close(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  TLS.tls_close(s)

# Answers are out: a real H2 peer keeps the connection (it does not close
# without GOAWAY), so read until the client closes. Closing right here
# would race the credit the client sends for the DATA it just read: the
# write hits a dead socket, the peer answers RST and the frames still in
# flight are lost.
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

# sid 3 tail: fragmented trailer, its END_STREAM on the CONTINUATION.
def srv_tr3_cont(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_cont(), (HTTPX.x_f_end_headers() + HTTPX.x_f_end_stream() : U32), 3, trailer_rest())
        srv_idle_from(sent)

def srv_tr3(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_headers(), 0, 3, trailer_first())
        srv_tr3_cont(sent)

def srv_data3(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_data(), 0, 3, HI())
        srv_tr3(sent)

def srv_head3_cont(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_cont(), HTTPX.x_f_end_headers(), 3, head_rest())
        srv_data3(sent)

# sid 3 head goes out fragmented; it is the handover from the sid 1 chain.
def srv_head3(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_headers(), 0, 3, head_first())
        srv_head3_cont(sent)

# sid 1 tail: complete trailer, then hand over to the sid 3 chain.
def srv_tr1(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_headers(), (HTTPX.x_f_end_headers() + HTTPX.x_f_end_stream() : U32), 1, trailer_block())
        srv_head3(sent)

def srv_data1(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_data(), 0, 1, HI())
        srv_tr1(sent)

def srv_answer(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(sock, HTTPX.x_t_headers(), HTTPX.x_f_end_headers(), 1, head_block())
    srv_data1(sent)

# Frame loop (mold tests/io/httpx_client_cont_conc.bend): ack SETTINGS,
# count the two DATA END_STREAM frames, then answer both sids. stage 0 is
# "no request complete yet", stage 1 is "one in, keep reading".
def srv_acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTPX.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTPX.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTPX.GotErr{0, "next"})

def srv_ack(got: Socket & HTTPX.Got) -> IO(Socket & HTTPX.Got):
  (s, g) = got
  do IO<Socket & HTTPX.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_settings(), HTTPX.x_f_ack(), 0, Nil{})
    IO.pure(Socket & HTTPX.Got, srv_acked(sent))

def srv_pinged(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTPX.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTPX.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTPX.GotErr{0, "next"})

def srv_ping(got: Socket & HTTPX.Got, +payload: List<&2, U32>) -> IO(Socket & HTTPX.Got):
  (s, g) = got
  do IO<Socket & HTTPX.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_ping(), HTTPX.x_f_ack(), 0, payload)
    IO.pure(Socket & HTTPX.Got, srv_pinged(sent))

def srv_is_settings_ack(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, HTTPX.x_t_settings()), U32.is_eq(flags, 1))

def srv_is_settings(+typ: U32) -> Bool:
  U32.is_eq(typ, HTTPX.x_t_settings())

def srv_is_data_end(+typ: U32, +end: U32) -> Bool:
  Bool.and(U32.is_eq(typ, HTTPX.x_t_data()), U32.is_eq(end, 1))

def srv_act_data(is_end: Bool) -> U32:
  match is_end:
    case True{}:
      2
    case False{}:
      0

def srv_act_mid(is_set: Bool, +typ: U32, +end: U32) -> U32:
  match is_set:
    case True{}:
      1
    case False{}:
      srv_act_data(srv_is_data_end(typ, end))

def srv_act_go(is_ack: Bool, +typ: U32, +flags: U32, +end: U32) -> U32:
  match is_ack:
    case True{}:
      0
    case False{}:
      srv_act_mid(srv_is_settings(typ), typ, end)

def srv_act(+typ: U32, +flags: U32, +end: U32) -> U32:
  srv_act_go(srv_is_settings_ack(typ, flags), typ, flags, end)

def srv_sock(got: Socket & HTTPX.Got) -> Socket:
  (s, g) = got
  s

@unsafe
def srv(phase: U32, got: Socket & HTTPX.Got, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +end: U32, act: U32, +stage: U32) -> IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTPX.Got <- HTTPX.x_read_frame(s0, buf)
        srv(1, got2, buf, 0, 0, 0, Nil{}, 0, 4, stage)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTPX.GotErr{code, msg}:
          TLS.tls_close(s1)
        case HTTPX.GotOk{+frame, +buf2}:
          match frame:
            case HTTPX.Frame{+typ2, +flags2, +sid2, +payload2}:
              srv(2, (s1, HTTPX.GotOk{frame, buf2}), buf2, typ2, flags2, sid2, payload2, U32.and(flags2, HTTPX.x_f_end_stream()), srv_act(typ2, flags2, U32.and(flags2, HTTPX.x_f_end_stream())), stage)
    case 2:
      match act:
        case 1:
          do IO<Unit>:
            got2 : Socket & HTTPX.Got <- srv_ack(got)
            srv(0, got2, buf, 0, 0, 0, Nil{}, 0, 4, stage)
        case 2:
          match stage:
            case 0:
              srv(0, got, buf, typ, flags, sid, payload, 0, 4, 1)
            case _:
              srv_answer(srv_sock(got))
        case _:
          srv(3, got, buf, typ, flags, sid, payload, end, 4, stage)
    case 3:
      match typ:
        case 6:
          do IO<Unit>:
            gotp : Socket & HTTPX.Got <- srv_ping(got, payload)
            srv(0, gotp, buf, 0, 0, 0, Nil{}, 0, 4, stage)
        case _:
          srv(0, got, buf, 0, 0, 0, Nil{}, 0, 4, stage)
    case _:
      (s9, g9) = got
      TLS.tls_close(s9)

def srv_set(got: Socket & HTTPX.Got) -> IO(Socket & HTTPX.Got):
  (s, g) = got
  do IO<Socket & HTTPX.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTPX.x_send_frame(s, HTTPX.x_t_settings(), 0, 0, HTTPX.x_settings_initial_pay())
    IO.pure(Socket & HTTPX.Got, srv_acked(sent))

@unsafe
def srv_pre(phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          srv_pre(1, (s0, Done{chunk}), acc2, HTTPX.x_preface_ok(acc2), U32.is_lt(HTTPX.x_len32(acc2), 24))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            srv_pre(0, r2, acc, 0, False{})
        case False{}:
          srv_pre(2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            got : Socket & HTTPX.Got <- srv_set((s2, HTTPX.GotErr{0, "next"}))
            srv(0, got, HTTPX.x_drop32(24, acc), 0, 0, 0, Nil{}, 0, 4, 0)
        case _:
          do IO<Unit>:
            TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def srv_start(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    srv_pre(0, r1, Nil{}, 0, False{})

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{sock}:
      srv_start(sock)

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    x : Unit <- srv_conn(m)
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

#|2
