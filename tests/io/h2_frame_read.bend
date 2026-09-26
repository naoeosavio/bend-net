# lib (lib_h2_frame_read): Phase 7 frame reader.
# The reader used to unroll exactly four reads and then answer `400 eof`
# whatever the peer had sent, so any response bigger than ~64KB (or split
# over more than four TLS records) failed as a truncated stream. That is
# the real shape of a public peer: Cloudflare delivers ~1.4KB per record,
# so its 3.6KB HEADERS block alone needs three reads and the 8KB DATA
# behind it six more. The reader is now a single unbounded loop that ends
# only on a real EOF.
#
# Pure checks pin the parser contract (empty buffer, half header, exact
# frame, length over the 65535 cap). The IO part is a loopback where a
# canned peer paces the response — the head block in 128-byte pieces and
# the body as four 512B DATA frames, one TLS record (and so one read)
# each, more reads than the old budget allowed, all small enough for the
# interpreter — and the client must assemble the whole body.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as H2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def need_more(out: H2.H2FrameOut) -> U32:
  match out:
    case H2.H2NeedMore{missing}:
      1
    case _:
      0

def frame_len(out: H2.H2FrameOut) -> U32:
  match out:
    case H2.H2FrameOk{frame, rest}:
      match frame:
        case H2.H2Frame{+typ, +flags, +sid, +payload}:
          U32.from_nat(H2.b_len(payload))
    case _:
      0

def frame_sid(out: H2.H2FrameOut) -> U32:
  match out:
    case H2.H2FrameOk{frame, rest}:
      match frame:
        case H2.H2Frame{+typ, +flags, +sid, +payload}:
          sid
    case _:
      0

def bad_len(out: H2.H2FrameOut) -> U32:
  match out:
    case H2.H2FrameBad{code, msg}:
      code
    case _:
      0

def chk_parser() -> U32:
  (need_more(H2.h2_frame_read(Nil{}))
   + need_more(H2.h2_frame_read([0, 0, 4, 0, 0, 0, 0, 1]))
   + frame_len(H2.h2_frame_read(H2.h2_frame_write(0, 1, 1, [104, 105])))
   + frame_sid(H2.h2_frame_read(H2.h2_frame_write(0, 1, 1, [104, 105])))
   + bad_len(H2.h2_frame_read([0, 2, 2, 0, 0, 0, 0, 0, 1, 0])) : U32)

# Canned peer response: a head block written in 128-byte pieces (one
# read each) plus four 512-byte DATA frames, also one read each.

def fill_go(+n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+m:
      fill_go(m, 97 <> acc)

def fill(n: Nat) -> List<&2, U32>:
  fill_go(n, Nil{})

def pads_go(+n: Nat, acc: List<&2, H2.H2Hdr>) -> List<&2, H2.H2Hdr>:
  match n:
    case 0n:
      acc
    case 1n+m:
      pads_go(m, H2.H2Hdr{"x-pad", "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv"} <> acc)

def head_frame() -> List<&2, U32>:
  H2.h2_frame_write(1, 4, 1, H2.hpack_block(
    List.append(&2, H2.H2Hdr, [H2.H2Hdr{":status", "200"}], pads_go(8n, Nil{}))))

def chk_pieces() -> U32:
  b2u(Nat.is_gt(H2.b_len(head_frame()), 640n))

def send_paced(prev: Socket & Result<&1, &1, (U32 & String), Unit>, +chunk: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  (s, r) = prev
  do IO<Socket & Result<&1, &1, (U32 & String), Unit>>:
    sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TLS.tls_send_bytes(s, chunk)
    w : Unit <- IO.sleep(25)
    return sent

# The last DATA frame closes the response (END_STREAM).
def data_flags(last: Nat) -> U32:
  match last:
    case 0n:
      1
    case _:
      0

def send_frames(+left: Nat, state: Socket & Result<&1, &1, (U32 & String), Unit>, +chunk: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  match left:
    case 0n:
      (s0, r0) = state
      IO.pure(Socket & Result<&1, &1, (U32 & String), Unit>, (s0, r0))
    case 1n+m:
      (s1, r1) = state
      do IO<Socket & Result<&1, &1, (U32 & String), Unit>>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <-
          send_paced((s1, r1), H2.h2_frame_write(0, data_flags(m), 1, chunk))
        send_frames(m, sent, chunk)

# Writes the head block in 128-byte pieces: every send is one TLS record,
# so the reader needs one read per piece.
@unsafe
def send_sliced(+left: Nat, prev: Socket & Result<&1, &1, (U32 & String), Unit>, +rest: List<&2, U32>, +piece: List<&2, U32>, done: Bool) ->
  IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  match left:
    case 0n:
      (s0, r0) = prev
      IO.pure(Socket & Result<&1, &1, (U32 & String), Unit>, (s0, r0))
    case 1n+m:
      (s, r) = prev
      match done:
        case True{}:
          IO.pure(Socket & Result<&1, &1, (U32 & String), Unit>, (s, r))
        case False{}:
          do IO<Socket & Result<&1, &1, (U32 & String), Unit>>:
            sent : Socket & Result<&1, &1, (U32 & String), Unit> <-
              send_paced((s, r), H2.b_take(H2.b_len(piece), rest))
            send_sliced(m, sent, H2.b_drop(H2.b_len(piece), rest), piece,
              Nat.is_le(H2.b_len(rest), H2.b_len(piece)))

def srv_send(sock: Socket) -> IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  do IO<Socket & Result<&1, &1, (U32 & String), Unit>>:
    a0 : Socket & Result<&1, &1, (U32 & String), Unit> <-
      H2.h2_send_frame(sock, 4, 0, 0, H2.h2_settings_initial_pay())
    a1 : Socket & Result<&1, &1, (U32 & String), Unit> <-
      send_sliced(8n, a0, head_frame(), fill(128n), False{})
    send_frames(4n, a1, fill(512n))

def srv_fail(sock: Socket) -> IO(String):
  do IO<String>:
    x : Unit <- TLS.tls_close(sock)
    return "down"

def srv_next(prev: Socket & H2.H2Got) -> IO(Socket & H2.H2Got):
  (s, g) = prev
  match g:
    case H2.H2GotOk{+frame, +buf}:
      H2.h2_read_frame(s, buf)
    case H2.H2GotErr{code, msg}:
      IO.pure(Socket & H2.H2Got, (s, H2.H2GotErr{code, msg}))

def srv_done(sent: Socket & Result<&1, &1, (U32 & String), Unit>) -> IO(String):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(String, "down")
    case Done{u}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s)
        return "up"

def srv_send_after(got: Socket & H2.H2Got) -> IO(String):
  (s, g) = got
  match g:
    case H2.H2GotOk{+frame, +buf}:
      do IO<String>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <- srv_send(s)
        srv_done(sent)
    case H2.H2GotErr{code, msg}:
      IO.pure(String, "down")

def srv_frames(g0: Socket & H2.H2Got) -> IO(String):
  do IO<String>:
    g1 : Socket & H2.H2Got <- srv_next(g0)
    g2 : Socket & H2.H2Got <- srv_next(g1)
    g3 : Socket & H2.H2Got <- srv_next(g2)
    srv_send_after(g3)

def canned_magic(sock: Socket, +chunk: List<&2, U32>, +magic: U32) -> IO(String):
  match magic:
    case 1:
      do IO<String>:
        g0 : Socket & H2.H2Got <- H2.h2_read_frame(sock, H2.b_drop(24n, chunk))
        srv_frames(g0)
    case _:
      srv_fail(sock)

def canned_retry(r2: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>, +chunk: List<&2, U32>) -> IO(String):
  (s2, r) = r2
  match r:
    case Fail{e}:
      srv_fail(s2)
    case Done{+c2}:
      canned_magic(s2, H2.b_append(chunk, c2), H2.h2_srv.preface_ok(H2.b_append(chunk, c2)))

def canned_chunk(sock: Socket, +chunk: List<&2, U32>, +n: Nat, enough: Bool) -> IO(String):
  match enough:
    case True{}:
      canned_magic(sock, chunk, H2.h2_srv.preface_ok(chunk))
    case False{}:
      do IO<String>:
        r2 : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        canned_retry(r2, chunk)

def canned_pref(r1: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>) -> IO(String):
  (s1, r) = r1
  match r:
    case Fail{e}:
      srv_fail(s1)
    case Done{+chunk}:
      canned_chunk(s1, chunk, H2.b_len(chunk), Nat.is_ge(H2.b_len(chunk), 24n))

def canned_talk(sock: Socket) -> IO(String):
  do IO<String>:
    r1 : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    canned_pref(r1)

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(String)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- Listener.close(l)
        return "down"
    case Done{sock}:
      do IO<String>:
        out : String <- canned_talk(sock)
        x : Unit <- Listener.close(l)
        return out

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    server_conn(m)

def client_done(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return acc
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          do IO<U32>:
            x : Unit <- TLS.tls_close(s2)
            +ok : U32 = (b2u(U32.is_eq(status, 200)) + b2u(Nat.is_eq(H2.b_len(body), 2048n)) : U32)
            return (acc + ok : U32)

def client_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(sock, 1, "GET", "/", Nil{}, Nil{})
        client_done(0, got)

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- H2.h2_connect_insecure("127.0.0.1", port)
    client_conn(conn)

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

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    s : String <- IO.join(String, chan)
    +up : U32 = b2u(String.eq(s, "up"))
    +total : U32 = (a + up + chk_parser() + chk_pieces() : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18580)
    main_go(b)

#|8
