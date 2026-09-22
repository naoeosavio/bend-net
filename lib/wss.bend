# WebSocket Secure (RFC 6455 over TLS) for Bend.
#
# Import as: import ./wss.bend as WSS (from lib) or
# import ../../lib/wss.bend as WSS (from tests/io).
# Reuses the pure codec and event types from ./ws.bend (WS) and the
# TLS lane from ./tls.bend (TLS): frames ride TLS.tls_send_bytes /
# TLS.tls_recv_bytes, never Base TCP or Socket.close. Handlers share
# WS.WSEv / WS.WSOut / WS.WSMessage — import WS for the types.
#
# Scope mirrors lib/ws.bend: server and client, text and binary,
# ping/pong/close. The client dials with tls_connect_noalpn[_insecure]
# (ALPN none — WSS is HTTP/1.1 Upgrade, not h2); the server accepts
# with tls_accept (already NOACK when the client offers no ALPN).
#
# Fail codes surface unchanged: WS 400/413, DNS 601-605, TLS 611-616.
# Every path closes the TLS socket via TLS.tls_close.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
# - helpers above drivers are leaves: they never call back down.
import Base
import ./http.bend as HTTP
import ./tls.bend as TLS
import ./ws.bend as WS

# Transport
# ---------
# Byte-faithful send/recv over a TLS socket. Fail short-circuits with
# the socket still open so the caller can tls_close it.

def wss_send_bytes(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{bs}:
      TLS.tls_send_bytes(s, bs)

def wss_send_str(s: Socket, +txt: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(s, HTTP.encode(txt))

def wss_close(s: Socket) -> IO(Unit):
  TLS.tls_close(s)

# Frame isolation over TLS
# ------------------------
# TLS has no recv_frame effect: accumulate tls_recv_bytes into buf and
# split with the pure WS codec until one frame is complete. The rest
# past the frame threads back as the next buf (every byte consumed
# exactly once). Empty read is EOF (Fail 400). unmasked_ok selects
# frame_split_unmasked (client side reads server frames).
# One self-recursive def: state 0 absorbs a recv, state 1 splits.

def wss_split_fail(s: Socket, +code: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, (s, Fail{(code, msg)}))

def wss_split_got(s: Socket, +frame: List<&2, U32>, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, (s, Done{(frame, rest)}))

def wss_do_split(+buf: List<&2, U32>, unmasked_ok: Bool) -> WS.WSFrameSplit:
  match unmasked_ok:
    case True{}:
      WS.frame_split_unmasked(buf)
    case False{}:
      WS.frame_split(buf)

@unsafe
def wss_fill(st: U32, m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>, +unmasked_ok: Bool, +sp: WS.WSFrameSplit) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  match st:
    case 0:
      (s2, r) = m
      match r:
        case Fail{e}:
          wss_split_fail(s2, 400, "tls recv")
        case Done{bs}:
          match bs:
            case Nil{}:
              wss_split_fail(s2, 400, "eof")
            case _ <> _:
              +buf2 = List.append(&2, U32, buf, bs)
              wss_fill(1, (s2, Done{Nil{}}), buf2, unmasked_ok, wss_do_split(buf2, unmasked_ok))
    case 1:
      (s2, r2) = m
      match sp:
        case WS.NeedMore{missing}:
          do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>>:
            m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s2, 8192)
            wss_fill(0, m2, buf, unmasked_ok, sp)
        case WS.FrameGot{frame, rest}:
          wss_split_got(s2, frame, rest)
        case WS.FrameBad{code, msg}:
          wss_split_fail(s2, code, msg)
    case _:
      (s2, r2) = m
      wss_split_fail(s2, 400, "bad state")

def wss_split_more(s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  wss_fill(1, (s, Done{Nil{}}), buf, unmasked_ok, wss_do_split(buf, unmasked_ok))

# One framed frame into the wire triple (fin & op & payload).

def wss_recv_frame_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, Fail{e}, []))
    case Done{fr}:
      (frame, rest) = fr
      match unmasked_ok:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, WS.read_frame_unmasked(frame), rest))
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, WS.read_frame(frame), rest))

def wss_recv_frame(s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wss_split_more(s, buf, unmasked_ok)
    wss_recv_frame_got(m, unmasked_ok)

def wss_recv_in_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      IO.pure(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>, (s, Done{WS.recv_in_of(fin, op, pay)}, rest))

def wss_recv_in(s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- wss_recv_frame(s, buf, unmasked_ok)
    wss_recv_in_got(m)

# Open sends (stay open; the session driver closes).

def client_out_bytes(out: WS.WSOut) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match out:
    case WS.OutMsg{msg}:
      +mm = msg
      WS.show_masked(True{}, WS.msg_to_op(mm), WS.msg_to_bytes(mm), 1, 2, 3, 4)
    case WS.OutOp{op, pay}:
      WS.show_masked(True{}, op, pay, 1, 2, 3, 4)
    case WS.OutRaw{bs}:
      Done{bs}

def wss_send_open(s: Socket, out: WS.WSOut) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wss_send_bytes((s, WS.out_bytes(out)))

def wss_send_open_masked(s: Socket, out: WS.WSOut) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wss_send_bytes((s, client_out_bytes(out)))

# Handshake over TLS (byte lane)
# ------------------------------
# Accumulate until the blank line under the 16KB cap (same as WS),
# decode ASCII, run WS.handshake / WS.read_response. Empty read is EOF.
# One self-recursive def: state 0 absorbs a recv, state 1 checks fit.

def wss_hs_cut(s: Socket, +taken: List<&2, U32>, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, (s, Done{(taken, rest)}))

@unsafe
def wss_hs_scan(st: U32, m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  match st:
    case 0:
      (s2, r) = m
      match r:
        case Fail{e}:
          wss_split_fail(s2, 400, "tls recv")
        case Done{bs}:
          match bs:
            case Nil{}:
              wss_split_fail(s2, 400, "eof")
            case _ <> _:
              +acc2 = List.append(&2, U32, acc, bs)
              wss_hs_scan(1, (s2, Done{Nil{}}), acc2, WS.client_scan_fit(acc2), Nat.is_le(List.length(&2, U32, acc2), 16384n))
    case 1:
      (s2, r2) = m
      match fit:
        case True{}:
          +len = WS.client_scan_len(acc)
          +taken = List.take(&2, U32, acc, U32.to_nat(len))
          +rest = List.drop(&2, U32, acc, U32.to_nat(len))
          wss_hs_cut(s2, taken, rest)
        case False{}:
          match ok:
            case True{}:
              do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>>:
                m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s2, 8192)
                wss_hs_scan(0, m2, acc, fit, ok)
            case False{}:
              wss_split_fail(s2, 413, "head too large")
    case _:
      (s2, r2) = m
      wss_split_fail(s2, 400, "bad state")

def wss_hs_start(s: Socket, +acc: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  wss_hs_scan(1, (s, Done{Nil{}}), acc, fit, ok)

# serve_once: single-shot server echo over one TLS socket.
# Handshake (byte lane) -> 101 -> one masked frame -> unmasked echo ->
# tls_close. Mirrors WS.serve_once with the TLS transport.

def wss_after_send(m: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Unit):
  (s, r) = m
  wss_close(s)

def wss_echo_reply(s: Socket, framed: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Unit):
  do IO<Unit>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_bytes((s, framed))
    wss_after_send(m)

def wss_echo_frame(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) ->
  IO(Unit):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      wss_close(s)
    case Done{t}:
      (fin, op, pay) = t
      wss_echo_reply(s, WS.show_frame(True{}, op, pay))

def wss_after_101(m: Socket & Result<&1, &1, U32 & String, Unit>, +rest: List<&2, U32>) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      wss_close(s)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- wss_recv_frame(s, rest, False{})
        wss_echo_frame(m2)

def wss_serve_go(s: Socket, hs: Result<&1, &1, U32 & String, String>, +rest: List<&2, U32>) ->
  IO(Unit):
  match hs:
    case Fail{e}:
      wss_close(s)
    case Done{resp}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_str(s, resp)
        wss_after_101(m, rest)

def wss_after_hs(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      wss_close(s)
    case Done{pair}:
      (head, rest) = pair
      wss_serve_go(s, WS.handshake(HTTP.decode(head)), rest)

def serve_once(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wss_hs_start(sock, Nil{}, False{}, True{})
    wss_after_hs(m)

# server_on: event-driven persistent server over TLS.
# Same ~H contract as WS.server_on: one EvOpen after the 101, one
# step per complete frame, handler's WSOut sent unmasked verbatim
# (ping/close policies via WS.ping_reply / WS.close_answer).
# wss_loop is one self-recursive def (no mutual recursion), mirroring
# WS.ws_loop; only the transport differs (TLS + user-land split).

def wss_recv_after(m: Socket & Result<&1, &1, U32 & String, Unit>, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{u}:
      wss_recv_in(s, buf, False{})

def wss_close_snd(m: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Unit):
  (s, r) = m
  wss_close(s)

@unsafe
def wss_loop(~H: WS.WSEv -> IO(WS.WSOut), st: U32, mf: Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>, ev: WS.WSEv, +buf: List<&2, U32>) ->
  IO(Unit):
  match st:
    case 1:
      (s, r, rest) = mf
      match r:
        case Fail{e}:
          wss_close(s)
        case Done{inn}:
          match inn:
            case WS.InMsg{msg}:
              wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvMsg{msg}, rest)
            case WS.InOp{fin, op, pay}:
              match op:
                case 8:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvClose{pay}, rest)
                case 9:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvPing{pay}, rest)
                case 10:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvPong{pay}, rest)
                case 0:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "not data"}, rest)
                case 1:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "fragmented"}, rest)
                case 2:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "fragmented"}, rest)
                case _:
                  wss_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "bad frame"}, rest)
    case 2:
      (s, r, b) = mf
      match ev:
        case WS.EvOpen{}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvOpen{})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open(s, out)
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_recv_after(m2, buf)
            wss_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvMsg{msg}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvMsg{msg})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open(s, out)
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_recv_after(m2, buf)
            wss_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvPing{pay}:
          +pp = pay
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvPing{pp})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open(s, WS.ping_reply(pp, out))
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_recv_after(m2, buf)
            wss_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvPong{pay}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvPong{pay})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open(s, out)
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_recv_after(m2, buf)
            wss_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvClose{pay}:
          +pp = pay
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvClose{pp})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open(s, WS.close_answer(pp, out))
            wss_close_snd(m2)
        case WS.EvError{code, msg}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvError{code, msg})
            wss_close(s)
    case _:
      IO.pure(Unit, Unit{})

def wss_hs_open(~H: WS.WSEv -> IO(WS.WSOut), m: Socket & Result<&1, &1, U32 & String, Unit>, +rest: List<&2, U32>) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      wss_close(s)
    case Done{u}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvOpen{})
        m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open(s, out)
        m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_recv_after(m2, rest)
        wss_loop(~H, 1, m3, WS.EvError{0, ""}, [])

def wss_hs_send(~H: WS.WSEv -> IO(WS.WSOut), s: Socket, +resp: String, +rest: List<&2, U32>) ->
  IO(Unit):
  do IO<Unit>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_str(s, resp)
    wss_hs_open(~H, m, rest)

def wss_hs_reply(~H: WS.WSEv -> IO(WS.WSOut), s: Socket, hs: Result<&1, &1, U32 & String, String>, +rest: List<&2, U32>) ->
  IO(Unit):
  match hs:
    case Fail{e}:
      wss_close(s)
    case Done{resp}:
      wss_hs_send(~H, s, resp, rest)

def wss_hs_scan_done(~H: WS.WSEv -> IO(WS.WSOut), m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      wss_close(s)
    case Done{pair}:
      (head, rest) = pair
      wss_hs_reply(~H, s, WS.handshake(HTTP.decode(head)), rest)

def wss_serve(~H: WS.WSEv -> IO(WS.WSOut), sock: Socket, cert: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wss_hs_start(sock, Nil{}, False{}, True{})
    wss_hs_scan_done(~H, m)

def wss_conn(~H: WS.WSEv -> IO(WS.WSOut), m: Listener & Result<&1, &1, U32 & String, Socket>, +cert: String, +key: String) ->
  IO(Listener):
  (l, r) = m
  do IO<Listener>:
    s : Socket <- IO.pass(Socket, r)
    IO.spawn(Unit, wss_serve(~H, s, cert))
    return l

@unsafe
def server_on(~H: WS.WSEv -> IO(WS.WSOut), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- wss_conn(~H, m, cert, key)
    z : Unit <- server_on(~H, l2, cert, key)
    return z

# client_on: event-driven persistent client over TLS, the mirror of
# server_on. Same ~H contract as WS.client_on: dial noalpn, send the
# upgrade, validate 101 + Accept, EvOpen, masked sends, unmasked recvs.
# wss_client_loop is one self-recursive def (no mutual recursion).

def wss_client_recv_after(m: Socket & Result<&1, &1, U32 & String, Unit>, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{u}:
      wss_recv_in(s, buf, True{})

@unsafe
def wss_client_loop(~H: WS.WSEv -> IO(WS.WSOut), st: U32, mf: Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32>, ev: WS.WSEv, +buf: List<&2, U32>) ->
  IO(Unit):
  match st:
    case 1:
      (s, r, rest) = mf
      match r:
        case Fail{(c, m)}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvError{c, m})
            wss_close(s)
        case Done{inn}:
          match inn:
            case WS.InMsg{msg}:
              wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvMsg{msg}, rest)
            case WS.InOp{fin, op, pay}:
              match op:
                case 8:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvClose{pay}, rest)
                case 9:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvPing{pay}, rest)
                case 10:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvPong{pay}, rest)
                case 0:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "not data"}, rest)
                case 1:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "fragmented"}, rest)
                case 2:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "fragmented"}, rest)
                case _:
                  wss_client_loop(~H, 2, (s, Done{WS.InOp{False{}, 0, []}}, []), WS.EvError{400, "bad frame"}, rest)
    case 2:
      (s, r, b) = mf
      match ev:
        case WS.EvOpen{}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvOpen{})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open_masked(s, out)
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_client_recv_after(m2, buf)
            wss_client_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvMsg{msg}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvMsg{msg})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open_masked(s, out)
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_client_recv_after(m2, buf)
            wss_client_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvPing{pay}:
          +pp = pay
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvPing{pp})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open_masked(s, WS.ping_reply(pp, out))
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_client_recv_after(m2, buf)
            wss_client_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvPong{pay}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvPong{pay})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open_masked(s, out)
            m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_client_recv_after(m2, buf)
            wss_client_loop(~H, 1, m3, WS.EvError{0, ""}, [])
        case WS.EvClose{pay}:
          +pp = pay
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvClose{pp})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open_masked(s, WS.close_answer(pp, out))
            wss_close_snd(m2)
        case WS.EvError{code, msg}:
          do IO<Unit>:
            out : WS.WSOut <- H(WS.EvError{code, msg})
            wss_close(s)
    case _:
      IO.pure(Unit, Unit{})

def wss_client_hs_go(~H: WS.WSEv -> IO(WS.WSOut), s: Socket, ok: Bool, +rest: List<&2, U32>) ->
  IO(Unit):
  match ok:
    case True{}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvOpen{})
        m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_open_masked(s, out)
        m3 : Socket & Result<&1, &1, U32 & String, WS.WSIn> & List<&2, U32> <- wss_client_recv_after(m2, rest)
        wss_client_loop(~H, 1, m3, WS.EvError{0, ""}, [])
    case False{}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvError{400, "bad handshake"})
        wss_close(s)

def wss_client_hs_parsed(~H: WS.WSEv -> IO(WS.WSOut), s: Socket, parsed: Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>, +rest: List<&2, U32>, +accept: String) ->
  IO(Unit):
  match parsed:
    case Fail{(c, m)}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvError{c, m})
        wss_close(s)
    case Done{pr}:
      (st, hs, body) = pr
      wss_client_hs_go(~H, s, WS.client_ok_of(st, hs, accept), rest)

def wss_client_hs(~H: WS.WSEv -> IO(WS.WSOut), m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, +accept: String) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{(c, msg)}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvError{c, msg})
        wss_close(s)
    case Done{pair}:
      (head, rest) = pair
      wss_client_hs_parsed(~H, s, HTTP.read_response(HTTP.decode(head) ++ "\r\n\r\n"), rest, accept)

def wss_client_req_sent(~H: WS.WSEv -> IO(WS.WSOut), m: Socket & Result<&1, &1, U32 & String, Unit>, +accept: String) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{(c, msg)}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvError{c, msg})
        wss_close(s)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wss_hs_start(s, Nil{}, False{}, True{})
        wss_client_hs(~H, m2, accept)

def wss_client_dial(~H: WS.WSEv -> IO(WS.WSOut), conn: Result<&1, &1, U32 & String, Socket>, +req_txt: String, +accept: String) ->
  IO(Unit):
  match conn:
    case Fail{(c, m)}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvError{c, m})
        return Unit{}
    case Done{sock}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_str(sock, req_txt)
        wss_client_req_sent(~H, m, accept)

def wss_on_go(~H: WS.WSEv -> IO(WS.WSOut), verify: U32, +host: String, port: U32, +req_txt: String, +accept: String) ->
  IO(Unit):
  match verify:
    case 0:
      do IO<Unit>:
        conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure(host, port)
        wss_client_dial(~H, conn, req_txt, accept)
    case _:
      do IO<Unit>:
        conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn(host, port)
        wss_client_dial(~H, conn, req_txt, accept)

def wss_client_req(~H: WS.WSEv -> IO(WS.WSOut), verify: U32, +host: String, port: U32, +accept: String, req: Result<&1, &1, U32 & String, String>) ->
  IO(Unit):
  match req:
    case Fail{(c, m)}:
      do IO<Unit>:
        out : WS.WSOut <- H(WS.EvError{c, m})
        return Unit{}
    case Done{req_txt}:
      wss_on_go(~H, verify, host, port, req_txt, accept)

def client_on(~H: WS.WSEv -> IO(WS.WSOut), +host: String, port: U32, +path: String, +key: String) ->
  IO(Unit):
  wss_client_req(~H, 1, host, port, WS.accept_of(key), WS.client_request(host, path, key))

def client_on_insecure(~H: WS.WSEv -> IO(WS.WSOut), +host: String, port: U32, +path: String, +key: String) ->
  IO(Unit):
  wss_client_req(~H, 0, host, port, WS.accept_of(key), WS.client_request(host, path, key))

# Client echo (single-shot, fixed mask) for loopback tests.
# Mirrors WS.client_echo: dial noalpn, handshake, send masked frame,
# read unmasked echo, tls_close. Done{"Hi"} on exact echo.

def wss_eq_bytes(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs:
    case Nil{}:
      match ys:
        case Nil{}:
          True{}
        case _ <> _:
          False{}
    case h1 <> t1:
      match ys:
        case Nil{}:
          False{}
        case h2 <> t2:
          Bool.and(U32.is_eq(h1, h2), wss_eq_bytes(t1, t2))

def wss_echo_score(ok: Bool) -> IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Done{"Hi"})
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad echo")})

def wss_echo_ok(s: Socket, bs: List<&2, U32>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    x : Unit <- wss_close(s)
    wss_echo_score(wss_eq_bytes(bs, want))

def wss_echo_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- wss_close(s)
        return Fail{e}
    case Done{fr}:
      (frame, rest) = fr
      wss_echo_ok(s, frame, want)

def wss_echo_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- wss_close(s)
        return Fail{e}
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, String>>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wss_split_more(s, Nil{}, True{})
        wss_echo_got(m2, want)

def wss_echo_hs_chk(s: Socket, ok: Bool, +rest: List<&2, U32>, +framed: List<&2, U32>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case False{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- wss_close(s)
        return Fail{(400, "bad handshake")}
    case True{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_bytes((s, Done{List.append(&2, U32, rest, framed)}))
        wss_echo_sent(m, want)

def wss_echo_hs_ok(s: Socket, parsed: Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>, +rest: List<&2, U32>, +framed: List<&2, U32>, +want: List<&2, U32>, +key: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match parsed:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- wss_close(s)
        return Fail{e}
    case Done{pr}:
      (st, hs, body) = pr
      wss_echo_hs_chk(s, WS.client_ok_of(st, hs, WS.accept_of(key)), rest, framed, want)

def wss_echo_hs(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, +framed: List<&2, U32>, +want: List<&2, U32>, +key: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- wss_close(s)
        return Fail{e}
    case Done{pair}:
      (head, rest) = pair
      wss_echo_hs_ok(s, HTTP.read_response(HTTP.decode(head) ++ "\r\n\r\n"), rest, framed, want, key)

def wss_client_hs_start(m: Socket & Result<&1, &1, U32 & String, Unit>, +framed: List<&2, U32>, +want: List<&2, U32>, +key: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- wss_close(s)
        return Fail{e}
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, String>>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wss_hs_start(s, Nil{}, False{}, True{})
        wss_echo_hs(m2, framed, want, key)

def wss_client_conn(conn: Result<&1, &1, U32 & String, Socket>, +req_txt: String, +framed: List<&2, U32>, +want: List<&2, U32>, +key: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, String>>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- wss_send_str(sock, req_txt)
        wss_client_hs_start(m, framed, want, key)

def wss_client_go(+host: String, port: U32, verify: U32, +req_txt: String, +framed: List<&2, U32>, +want: List<&2, U32>, +key: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match verify:
    case 0:
      do IO<Result<&1, &1, U32 & String, String>>:
        conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure(host, port)
        wss_client_conn(conn, req_txt, framed, want, key)
    case _:
      do IO<Result<&1, &1, U32 & String, String>>:
        conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn(host, port)
        wss_client_conn(conn, req_txt, framed, want, key)

def wss_client_want(+host: String, port: U32, verify: U32, +req_txt: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>, +key: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match want:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{wb}:
      wss_client_go(host, port, verify, req_txt, framed, wb, key)

def wss_client_start(+host: String, port: U32, verify: U32, +path: String, +key: String, +msg: String, req: Result<&1, &1, U32 & String, String>, framed: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match req:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{req_txt}:
      match framed:
        case Fail{e}:
          IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
        case Done{fb}:
          wss_client_want(host, port, verify, req_txt, fb, WS.show_frame(True{}, 1, HTTP.encode(msg)), key)

def client_echo(+host: String, port: U32, +path: String, +key: String, +msg: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  wss_client_start(host, port, 1, path, key, msg, WS.client_request(host, path, key), WS.show_masked(True{}, 1, HTTP.encode(msg), 1, 2, 3, 4))

def client_echo_insecure(+host: String, port: U32, +path: String, +key: String, +msg: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  wss_client_start(host, port, 0, path, key, msg, WS.client_request(host, path, key), WS.show_masked(True{}, 1, HTTP.encode(msg), 1, 2, 3, 4))
