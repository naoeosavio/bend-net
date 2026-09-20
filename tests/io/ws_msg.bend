# lib (ws_msg): WSMessage send/recv generics over loopback.
# Pure: text/binary roundtrips, fragmented/control rejects, ping as
# InOp. Net (one listener, three accepts): raw send_bytes/recv_bytes
# plus text and binary echo. Scores 1000*pure + 100*raw + 10*text + bin.
import Base
import ../../lib/ws.bend as WS
import ../../lib/tcp.bend as TCP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law eq_list:
  for xs: List<&2, U32>
  for ys: List<&2, U32>
  U32

def eq_list(xs, ys):
  match xs:
    case Nil{}:
      match ys:
        case Nil{}:
          1
        case _ <> _:
          0
    case h1 <> t1:
      match ys:
        case Nil{}:
          0
        case h2 <> t2:
          (b2u(U32.is_eq(h1, h2)) * eq_list(t1, t2) : U32)

law unwrap_frame:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap_frame(r):
  match r:
    case Fail{e}:
      [255]
    case Done{bs}:
      bs

law read_of:
  for mres: Result<&1, &1, U32 & String, List<&2, U32>>
  Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>

def read_of(mres):
  match mres:
    case Fail{e}:
      Fail{e}
    case Done{bs}:
      WS.read_frame(bs)

law msg_of_res:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  Result<&1, &1, U32 & String, WS.WSMessage>

def msg_of_res(r):
  match r:
    case Fail{e}:
      Fail{e}
    case Done{t}:
      (fin, op, pay) = t
      WS.msg_of_frame(fin, op, pay)

law msg_text_ok:
  for r: Result<&1, &1, U32 & String, WS.WSMessage>
  U32

def msg_text_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{m}:
      match m:
        case WS.WSText{text}:
          b2u(String.eq(text, "Hi"))
        case WS.WSBin{data}:
          0

law msg_bin_ok:
  for r: Result<&1, &1, U32 & String, WS.WSMessage>
  U32

def msg_bin_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{m}:
      match m:
        case WS.WSText{text}:
          0
        case WS.WSBin{data}:
          eq_list(data, [1, 2, 3, 250])

law is_fail400m:
  for r: Result<&1, &1, U32 & String, WS.WSMessage>
  U32

def is_fail400m(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))
    case Done{m}:
      0

law inop9_ok:
  for w: WS.WSIn
  U32

def inop9_ok(w):
  match w:
    case WS.InMsg{msg}:
      0
    case WS.InOp{fin, op, pay}:
      b2u(Bool.and(fin, Bool.and(U32.is_eq(op, 9), U32.is_eq(eq_list(pay, [72, 105]), 1))))

law chk_to_op_text:
  U32

def chk_to_op_text():
  b2u(U32.is_eq(WS.msg_to_op(WS.WSText{"Hi"}), 1))

law chk_to_op_bin:
  U32

def chk_to_op_bin():
  b2u(U32.is_eq(WS.msg_to_op(WS.WSBin{[1, 2, 3, 250]}), 2))

law chk_to_bytes_text:
  U32

def chk_to_bytes_text():
  eq_list(WS.msg_to_bytes(WS.WSText{"Hi"}), [72, 105])

law chk_to_bytes_bin:
  U32

def chk_to_bytes_bin():
  eq_list(WS.msg_to_bytes(WS.WSBin{[1, 2, 3, 250]}), [1, 2, 3, 250])

law chk_text:
  U32

def chk_text():
  msg_text_ok(msg_of_res(read_of(WS.show_masked(True{}, 1, [72, 105], 1, 2, 3, 4))))

law chk_bin:
  U32

def chk_bin():
  msg_bin_ok(msg_of_res(read_of(WS.show_masked(True{}, 2, [1, 2, 3, 250], 5, 6, 7, 8))))

law chk_frag:
  U32

def chk_frag():
  is_fail400m(msg_of_res(WS.read_frame([1, 130, 1, 2, 3, 4, 73, 107])))

law chk_ping:
  U32

def chk_ping():
  inop9_ok(WS.recv_in_of(True{}, 9, [72, 105]))

law chk_ctrl:
  U32

def chk_ctrl():
  is_fail400m(msg_of_res(WS.read_frame([137, 130, 1, 2, 3, 4, 73, 107])))

law pure_sum:
  U32

def pure_sum():
  (chk_to_op_text() + chk_to_op_bin() + chk_to_bytes_text() + chk_to_bytes_bin() + chk_text() + chk_bin() + chk_frag() + chk_ping() + chk_ctrl() : U32)

law pure:
  U32

def pure():
  b2u(U32.is_eq(pure_sum(), 9))

law raw_eq:
  for bs: List<&2, U32>
  U32

def raw_eq(bs):
  eq_list(bs, [129, 130, 1, 2, 3, 4, 73, 107])

law srv3:
  for m3: Listener & Result<&1, &1, U32 & String, Socket>
  for +raw_ok: U32
  IO(U32)

def srv3(m3, raw_ok):
  (l, r) = m3
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        return raw_ok
    case Done{s3}:
      do IO<U32>:
        u : Unit <- WS.serve_once(s3)
        x : Unit <- Listener.close(l)
        return raw_ok

law srv2:
  for m2: Listener & Result<&1, &1, U32 & String, Socket>
  for +raw_ok: U32
  IO(U32)

def srv2(m2, raw_ok):
  (l, r) = m2
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        return raw_ok
    case Done{s2}:
      do IO<U32>:
        u : Unit <- WS.serve_once(s2)
        m3 : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
        srv3(m3, raw_ok)

law raw_done:
  for m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>
  for l: Listener
  IO(U32)

def raw_done(m, l):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        y : Unit <- Listener.close(l)
        return 0
    case Done{bs}:
      ok = raw_eq(bs)
      do IO<U32>:
        x : Unit <- Socket.close(s)
        m2 : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
        srv2(m2, ok)

law srv1:
  for m1: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def srv1(m1):
  (l, r) = m1
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        return 0
    case Done{s1}:
      do IO<U32>:
        m : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- WS.recv_bytes(s1)
        raw_done(m, l)

law server_side:
  for l: Listener
  IO(U32)

def server_side(l):
  do IO<U32>:
    m1 : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    srv1(m1)

law raw_conn:
  for conn: Result<&1, &1, U32 & String, Socket>
  IO(Unit)

def raw_conn(conn):
  match conn:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{sock}:
      WS.send_bytes((sock, Done{[129, 130, 1, 2, 3, 4, 73, 107]}))

law raw_client:
  for +host: String
  for port: U32
  IO(Unit)

def raw_client(host, port):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    raw_conn(conn)

law text_ok:
  for r: Result<&1, &1, U32 & String, String>
  U32

def text_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, "Hi"))

law bin_echo_got:
  for m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>
  for +want: List<&2, U32>
  IO(U32)

def bin_echo_got(m, want):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{got}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return b2u(U32.is_eq(eq_list(got, want), 1))

law bin_echo_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +frame_txt: List<&2, U32>
  for +want: List<&2, U32>
  IO(U32)

def bin_echo_sent(m, frame_txt, want):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <-
          TCP.recv_bytes(s, 8192)
        bin_echo_got(got, want)

law bin_hs_got:
  for m: Socket & Result<&1, &1, U32 & String, String>
  for +frame_txt: List<&2, U32>
  for +want: List<&2, U32>
  IO(U32)

def bin_hs_got(m, frame_txt, want):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{hsresp}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <-
          TCP.send_bytes(s, frame_txt)
        bin_echo_sent(sent, frame_txt, want)

law bin_req_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +frame_txt: List<&2, U32>
  for +want: List<&2, U32>
  IO(U32)

def bin_req_sent(m, frame_txt, want):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        bin_hs_got(got, frame_txt, want)

law bin_conn:
  for conn: Result<&1, &1, U32 & String, Socket>
  for +req_txt: String
  for +frame_txt: List<&2, U32>
  for +want: List<&2, U32>
  IO(U32)

def bin_conn(conn, req_txt, frame_txt, want):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        bin_req_sent(sent, frame_txt, want)

law bin_frames_put:
  for mres: Result<&1, &1, U32 & String, List<&2, U32>>
  for eres: Result<&1, &1, U32 & String, List<&2, U32>>
  Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>

def bin_frames_put(mres, eres):
  match mres:
    case Fail{e}:
      Fail{e}
    case Done{mbytes}:
      match eres:
        case Fail{e}:
          Fail{e}
        case Done{eby}:
          Done{(mbytes, eby)}

law bin_frames:
  Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>

def bin_frames():
  bin_frames_put(WS.show_masked(True{}, 2, [1, 2, 3, 250], 5, 6, 7, 8), WS.show_frame(True{}, 2, [1, 2, 3, 250]))

law bin_go:
  for +host: String
  for port: U32
  for +req_txt: String
  for frames: List<&2, U32> & List<&2, U32>
  IO(U32)

def bin_go(host, port, req_txt, frames):
  (frame_txt, want) = frames
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    bin_conn(conn, req_txt, frame_txt, want)

law bin_req_ok:
  for +host: String
  for port: U32
  for req: Result<&1, &1, U32 & String, String>
  for frames: Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>
  IO(U32)

def bin_req_ok(host, port, req, frames):
  match req:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{req_txt}:
      match frames:
        case Fail{e}:
          IO.pure(U32, 0)
        case Done{fr}:
          bin_go(host, port, req_txt, fr)

law bin_client:
  for +host: String
  for port: U32
  IO(U32)

def bin_client(host, port):
  bin_req_ok(host, port, WS.client_request(host, "/chat", "dGhlIHNhbXBsZSBub25jZQ=="), bin_frames())

law listen_retry:
  for port: U32
  for r: Result<&1, &1, U32 & String, Listener>
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
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, server_side(l))
    u : Unit <- raw_client("127.0.0.1", port)
    r : Result<&1, &1, U32 & String, String> <- WS.client_echo("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    c : U32 <- bin_client("127.0.0.1", port)
    s : U32 <- IO.join(U32, chan)
    +total : U32 = (pure() * 1000 + s * 100 + text_ok(r) * 10 + c : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19887)
    main_go(b)

#|1111
