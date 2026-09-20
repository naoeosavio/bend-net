# lib (ws_server_once): WS.serve_once — the single-shot server.
# Mirror of ws_server_on.bend for the `once` API: each connection
# answers exactly one frame and closes. Two sequential connections on
# one listener prove it: (1) masked text "hi" -> unmasked echo + EOF,
# (2) masked ping [1,2] -> pong + EOF. The server returns 1 on a clean
# double-serve; the client scores echo*1000 + eof1*100 + pong*10 + eof2
# and multiplies by the joined server result.
import Base
import ../../lib/ws.bend as WS

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

law srv.second:
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def srv.second(m):
  (l, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        return 0
    case Done{sock}:
      do IO<U32>:
        u : Unit <- WS.serve_once(sock)
        x : Unit <- Listener.close(l)
        return 1

law srv.first:
  for m: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def srv.first(m):
  (l, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        return 0
    case Done{sock}:
      do IO<U32>:
        u : Unit <- WS.serve_once(sock)
        m2 : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
        srv.second(m2)

law server_side:
  for l: Listener
  IO(U32)

def server_side(l):
  do IO<U32>:
    m1 : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    srv.first(m1)

law cli.shut:
  for s: Socket
  for +acc: U32
  IO(U32)

def cli.shut(s, acc):
  do IO<U32>:
    x : Unit <- Socket.close(s)
    return acc

law cli.eof2:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.eof2(m, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.shut(s, (acc + 1 : U32))
    case Done{t}:
      cli.shut(s, acc)

law cli.pggot:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.pggot(m, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{t}:
      (fin, op, pay) = t
      ok = b2u(Bool.and(U32.is_eq(op, 10), U32.is_eq(eq_list(pay, [1, 2]), 1)))
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WS.recv_op_client_framed(s, rest)
        cli.eof2(m2, (acc + ok * 10 : U32))

law cli.pgsent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for buf: List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.pgsent(m, buf, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WS.recv_op_client_framed(s, buf)
        cli.pggot(m2, acc)

law cli.session2:
  for ok: U32
  for s: Socket
  for +acc: U32
  IO(U32)

def cli.session2(ok, s, acc):
  match ok:
    case 1:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 9, [1, 2])
        cli.pgsent(sent, [], acc)
    case _:
      cli.shut(s, acc)

law cli.hs2:
  for m: Socket & Result<&1, &1, U32 & String, String>
  for +acc: U32
  IO(U32)

def cli.hs2(m, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{resp}:
      cli.session2(b2u(String.contains(resp, "101")), s, acc)

law cli.sent2:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +acc: U32
  IO(U32)

def cli.sent2(m, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        cli.hs2(got, acc)

law cli.open2:
  for conn: Result<&1, &1, U32 & String, Socket>
  for +req_txt: String
  for +acc: U32
  IO(U32)

def cli.open2(conn, req_txt, acc):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        cli.sent2(m, acc)

law cli.second:
  for +host: String
  for +port: U32
  for req: Result<&1, &1, U32 & String, String>
  for +acc: U32
  IO(U32)

def cli.second(host, port, req, acc):
  match req:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{req_txt}:
      do IO<U32>:
        conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
        cli.open2(conn, req_txt, acc)

law cli.eof1:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.eof1(m, host, port, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        cli.second(host, port, WS.client_request(host, "/chat", "dGhlIHNhbXBsZSBub25jZQ=="), (acc + 100 : U32))
    case Done{msg}:
      cli.shut(s, acc)

law cli.e1got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.e1got(m, host, port, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          ok = b2u(String.eq(text, "hi"))
          do IO<U32>:
            m2 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(s, rest)
            cli.eof1(m2, host, port, (acc + ok * 1000 : U32))
        case WS.WSBin{data}:
          cli.shut(s, acc)

law cli.e1sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.e1sent(m, host, port, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(s, [])
        cli.e1got(m2, host, port, acc)

law cli.session:
  for ok: U32
  for s: Socket
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.session(ok, s, host, port, acc):
  match ok:
    case 1:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_msg(s, WS.WSText{"hi"})
        cli.e1sent(sent, host, port, acc)
    case _:
      cli.shut(s, acc)

law cli.hs1:
  for m: Socket & Result<&1, &1, U32 & String, String>
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.hs1(m, host, port, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{resp}:
      cli.session(b2u(String.contains(resp, "101")), s, host, port, acc)

law cli.sent1:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.sent1(m, host, port, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.shut(s, acc)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        cli.hs1(got, host, port, acc)

law cli.open1:
  for conn: Result<&1, &1, U32 & String, Socket>
  for +req_txt: String
  for +host: String
  for port: U32
  for +acc: U32
  IO(U32)

def cli.open1(conn, req_txt, host, port, acc):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        cli.sent1(m, host, port, acc)

law cli.start:
  for +host: String
  for +port: U32
  for req: Result<&1, &1, U32 & String, String>
  for +acc: U32
  IO(U32)

def cli.start(host, port, req, acc):
  match req:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{req_txt}:
      do IO<U32>:
        conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
        cli.open1(conn, req_txt, host, port, acc)

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
    chan : Chan(U32) <- IO.fork(U32, server_side(l))
    acc : U32 <- cli.start("127.0.0.1", port, WS.client_request("127.0.0.1", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="), 0)
    j : U32 <- IO.join(U32, chan)
    +total : U32 = (acc * j : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19691)
    main_go(b)

#|1111
