# WebSocket RFC 6455 full-duplex pure in Bend (no native effects).
#
# Import as: import ./ws.bend as WS (from lib) or
# import ../../lib/ws.bend as WS (from tests/io).
# Reuses Base, HTTP, SHA1, B64 plus existing TCP/File effects.
#
# Scope: server and client, text and binary frames, fragmentation,
# ping/pong/close. No TLS (same limit as HTTP.fetch). Binary IO over
# TCP.String is ASCII-only on the wire (UTF-8 edge); pure codec is
# full binary on List<U32>. See DESIGN below.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
# - helpers above drivers are leaves: they never call back down.
import Base
import ./http.bend as HTTP
import ./sha1.bend as SHA1
import ./b64.bend as B64

# Handshake
# ---------
# Server validates GET + Upgrade: websocket + Version: 13 + Key,
# then answers 101 with Accept = b64(sha1(key ++ GUID)).
# Anything else is Fail{400} and never becomes 101.

def guid() -> String:
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def scan_go(hs: List<&1, String & String>, +key_acc: String, up_ok: Bool, ver_ok: Bool, conn_ok: Bool) -> String & Bool:
  match hs:
    case Nil{}:
      (key_acc, Bool.and(up_ok, Bool.and(ver_ok, Bool.and(conn_ok, Bool.not(String.is_empty(String.trim(key_acc)))))))
    case (n, v) <> t:
      +nn = n
      +vv = v
      +tv = String.trim(vv)
      +low = String.to_lower(String.trim(vv))
      scan_go(t, Bool.pick(String, HTTP.eq_ci(nn, "Sec-WebSocket-Key"), tv, key_acc), Bool.or(up_ok, Bool.and(HTTP.eq_ci(nn, "Upgrade"), String.eq(low, "websocket"))), Bool.or(ver_ok, Bool.and(HTTP.eq_ci(nn, "Sec-WebSocket-Version"), String.eq(tv, "13"))), Bool.or(conn_ok, Bool.and(HTTP.eq_ci(nn, "Connection"), String.contains(low, "upgrade"))))

def scan(hs: List<&1, String & String>) -> String & Bool:
  scan_go(hs, "", False{}, False{}, False{})

def accept_of(+key: String) -> String:
  +trimmed = String.trim(key)
  +joined = trimmed ++ guid()
  B64.encode(SHA1.sha1(HTTP.encode(joined)))

def show_101.go(+accept: String, bad: Bool) -> Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad accept")}
    case False{}:
      Done{"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ++ accept ++ "\r\n\r\n"}

def show_101(+accept: String) -> Result<&1, &1, U32 & String, String>:
  show_101.go(accept, HTTP.has_crlf(accept))

def chk_headers(+key: String, ok: Bool) -> Result<&1, &1, U32 & String, String>:
  match ok:
    case True{}:
      show_101(accept_of(key))
    case False{}:
      Fail{(400, "bad headers")}

def chk_method(+key: String, headers_ok: Bool, is_get: Bool) -> Result<&1, &1, U32 & String, String>:
  match is_get:
    case True{}:
      chk_headers(key, headers_ok)
    case False{}:
      Fail{(400, "bad method")}

def handshake_keys(m: String, pair: String & Bool) -> Result<&1, &1, U32 & String, String>:
  (key, ok) = pair
  chk_method(key, ok, String.eq(m, "GET"))

def handshake_req(req: String & String & List<&1, String & String> & String) -> Result<&1, &1, U32 & String, String>:
  (m, p, hs, body) = req
  handshake_keys(m, scan(hs))

def handshake_parsed(parsed: Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>) -> Result<&1, &1, U32 & String, String>:
  match parsed:
    case Fail{e}:
      Fail{e}
    case Done{req}:
      handshake_req(req)

def handshake(+s: String) -> Result<&1, &1, U32 & String, String>:
  handshake_parsed(HTTP.read_request(s))

# Frames
# ------
# Pure codec on byte lists. Server reads masked client frames with
# read_frame; server writes unmasked frames with show_frame.
# Fail-closed: unmasked client frames, control >125 or fragmented,
# reserved opcodes or RSV, and payloads over 1MB all Fail.
#
# Messages (generic API): WSText is UTF-8 String on the wire via
# HTTP.encode/decode; WSBin is raw bytes. Controls (0/8/9/10) and
# fragmented frames (FIN=False) stay outside WSMessage and Fail{400}
# on the msg path; the generic recv reports them as InOp.

type WSMessage is Data:
  WSText{text: String}
  WSBin{data: List<&2, U32>}

type WSOut is Data:
  OutMsg{msg: WSMessage}
  OutOp{op: U32, pay: List<&2, U32>}
  OutRaw{bs: List<&2, U32>}

type WSIn is Data:
  InMsg{msg: WSMessage}
  InOp{fin: Bool, op: U32, pay: List<&2, U32>}

def msg_to_op(msg: WSMessage) -> U32:
  match msg:
    case WSText{text}:
      1
    case WSBin{data}:
      2

def msg_to_bytes(msg: WSMessage) -> List<&2, U32>:
  match msg:
    case WSText{text}:
      HTTP.encode(text)
    case WSBin{data}:
      data

def msg_of_frame.go2(is_text: Bool, is_bin: Bool, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  match is_text is_bin:
    case True{} True{}:
      Done{WSText{HTTP.decode(pay)}}
    case True{} False{}:
      Done{WSText{HTTP.decode(pay)}}
    case False{} True{}:
      Done{WSBin{pay}}
    case False{} False{}:
      Fail{(400, "not data")}

def msg_of_frame.go(fin: Bool, is_text: Bool, is_bin: Bool, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  match fin:
    case True{}:
      msg_of_frame.go2(is_text, is_bin, pay)
    case False{}:
      Fail{(400, "fragmented")}

def msg_of_frame(fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  msg_of_frame.go(fin, U32.is_eq(op, 1), U32.is_eq(op, 2), pay)

def unmask_byte(+b: U32, +k0: U32, +k1: U32, +k2: U32, +k3: U32, pos: U32) -> U32:
  match pos:
    case 0:
      U32.xor(b, k0)
    case 1:
      U32.xor(b, k1)
    case 2:
      U32.xor(b, k2)
    case 3:
      U32.xor(b, k3)
    case _:
      U32.xor(b, k0)

def unmask(bs: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, pos: U32) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case b <> rest:
      match pos:
        case 0:
          unmask_byte(b, k0, k1, k2, k3, 0) <> unmask(rest, k0, k1, k2, k3, 1)
        case 1:
          unmask_byte(b, k0, k1, k2, k3, 1) <> unmask(rest, k0, k1, k2, k3, 2)
        case 2:
          unmask_byte(b, k0, k1, k2, k3, 2) <> unmask(rest, k0, k1, k2, k3, 3)
        case 3:
          unmask_byte(b, k0, k1, k2, k3, 3) <> unmask(rest, k0, k1, k2, k3, 0)
        case _:
          unmask_byte(b, k0, k1, k2, k3, 0) <> unmask(rest, k0, k1, k2, k3, 1)

def is_ctrl(op: U32) -> Bool:
  match op:
    case 8:
      True{}
    case 9:
      True{}
    case 10:
      True{}
    case _:
      False{}

def is_op_ok(op: U32) -> Bool:
  match op:
    case 0:
      True{}
    case 1:
      True{}
    case 2:
      True{}
    case 8:
      True{}
    case 9:
      True{}
    case 10:
      True{}
    case _:
      False{}

def ws_is_nil(bs: List<&2, U32>) -> Bool:
  match bs:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

def finish_frame(ok: Bool, code: U32, fin: Bool, op: U32, +payload: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match ok:
    case True{}:
      Done{(fin, op, payload)}
    case False{}:
      Fail{(code, "bad frame")}

def ctrl_ok.go(is_c: Bool, fin: Bool, +len: U32) -> Bool:
  match is_c:
    case True{}:
      Bool.and(fin, U32.is_le(len, 125))
    case False{}:
      True{}

def ctrl_ok(+op: U32, fin: Bool, +len: U32) -> Bool:
  ctrl_ok.go(is_ctrl(op), fin, len)

def payload_ok(rsv_ok: Bool, +op: U32, fin: Bool, +len: U32, len_ok: Bool, cap_ok: Bool) -> Bool:
  Bool.and(rsv_ok, Bool.and(is_op_ok(op), Bool.and(ctrl_ok(op, fin, len), Bool.and(len_ok, cap_ok))))

def frame_payload(+fin: Bool, rsv_ok: Bool, +op: U32, +len: U32, +k0: U32, +k1: U32, +k2: U32, +k3: U32, +rest: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  +taken = List.take(&2, U32, rest, U32.to_nat(len))
  +dropped = List.drop(&2, U32, rest, U32.to_nat(len))
  +len_ok = Bool.and(ws_is_nil(dropped), Nat.is_eq(List.length(&2, U32, taken), U32.to_nat(len)))
  +cap_ok = U32.is_le(len, 1048576)
  +unmasked = unmask(taken, k0, k1, k2, k3, 0)
  +ok = payload_ok(rsv_ok, op, fin, len, len_ok, cap_ok)
  +code = Bool.pick(U32, Bool.not(cap_ok), 413, 400)
  finish_frame(ok, code, fin, op, unmasked)

def mask_keys(fin: Bool, rsv_ok: Bool, +op: U32, +len: U32, masked: Bool, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match masked:
    case True{}:
      match rest:
        case Nil{}:
          Fail{(400, "missing mask")}
        case k0 <> r1:
          match r1:
            case Nil{}:
              Fail{(400, "missing mask")}
            case k1 <> r2:
              match r2:
                case Nil{}:
                  Fail{(400, "missing mask")}
                case k2 <> r3:
                  match r3:
                    case Nil{}:
                      Fail{(400, "missing mask")}
                    case k3 <> payload:
                      frame_payload(fin, rsv_ok, op, len, k0, k1, k2, k3, payload)
    case False{}:
      match unmasked_ok:
        case True{}:
          frame_payload(fin, rsv_ok, op, len, 0, 0, 0, 0, rest)
        case False{}:
          Fail{(400, "unmasked client frame")}

def len64.go(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, +lo: U32, rest: List<&2, U32>, is0: Bool, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match is0:
    case True{}:
      mask_keys(fin, rsv_ok, op, lo, masked, rest, unmasked_ok)
    case False{}:
      Fail{(413, "frame too large")}

def len64(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, +b0: U32, +b1: U32, +b2: U32, +b3: U32, +b4: U32, +b5: U32, +b6: U32, +b7: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  +hi = SHA1.word_of4(b0, b1, b2, b3)
  +lo = SHA1.word_of4(b4, b5, b6, b7)
  len64.go(fin, rsv_ok, op, masked, lo, rest, U32.is_zero(hi), unmasked_ok)

def len16(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, +b0: U32, +b1: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  mask_keys(fin, rsv_ok, op, (b0 * 256 + b1 : U32), masked, rest, unmasked_ok)

def len7.go(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, len7: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match len7:
    case 126:
      match rest:
        case Nil{}:
          Fail{(400, "short len")}
        case b0 <> r1:
          match r1:
            case Nil{}:
              Fail{(400, "short len")}
            case b1 <> rest2:
              len16(fin, rsv_ok, op, masked, b0, b1, rest2, unmasked_ok)
    case 127:
      match rest:
        case Nil{}:
          Fail{(400, "short len")}
        case b0 <> r1:
          match r1:
            case Nil{}:
              Fail{(400, "short len")}
            case b1 <> r2:
              match r2:
                case Nil{}:
                  Fail{(400, "short len")}
                case b2 <> r3:
                  match r3:
                    case Nil{}:
                      Fail{(400, "short len")}
                    case b3 <> r4:
                      match r4:
                        case Nil{}:
                          Fail{(400, "short len")}
                        case b4 <> r5:
                          match r5:
                            case Nil{}:
                              Fail{(400, "short len")}
                            case b5 <> r6:
                              match r6:
                                case Nil{}:
                                  Fail{(400, "short len")}
                                case b6 <> r7:
                                  match r7:
                                    case Nil{}:
                                      Fail{(400, "short len")}
                                    case b7 <> rest2:
                                      len64(fin, rsv_ok, op, masked, b0, b1, b2, b3, b4, b5, b6, b7, rest2, unmasked_ok)
    case _:
      mask_keys(fin, rsv_ok, op, len7, masked, rest, unmasked_ok)

def read_frame(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match bs:
    case Nil{}:
      Fail{(400, "short frame")}
    case +b0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "short frame")}
        case +b1 <> rest:
          len7.go(U32.is_ge(b0, 128), U32.is_zero(U32.and(U32.shrn(b0, 4n), 7)), U32.and(b0, 15), U32.is_ge(b1, 128), U32.and(b1, 127), rest, False{})

# Client parse: server frames arrive unmasked (RFC 6455 server-to-client).
# Same caps as read_frame (1MB, control rules); masked frames still parse.

def read_frame_unmasked(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match bs:
    case Nil{}:
      Fail{(400, "short frame")}
    case +b0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "short frame")}
        case +b1 <> rest:
          len7.go(U32.is_ge(b0, 128), U32.is_zero(U32.and(U32.shrn(b0, 4n), 7)), U32.and(b0, 15), U32.is_ge(b1, 128), U32.and(b1, 127), rest, True{})

def show_b0(fin: Bool, +op: U32) -> U32:
  (Bool.pick(U32, fin, 128, 0) + op : U32)

def show_small(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, [show_b0(fin, op), len], payload)

def show_med(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, [show_b0(fin, op), 126, U32.div(len, 256), U32.mod(len, 256)], payload)

def show_big(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, [show_b0(fin, op), 127, 0, 0, 0, 0], SHA1.bytes_of_word(len)), payload)

def show_head.go(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>, is_small: Bool, is_med: Bool) -> List<&2, U32>:
  match is_small is_med:
    case True{} True{}:
      show_small(fin, op, len, payload)
    case True{} False{}:
      show_small(fin, op, len, payload)
    case False{} True{}:
      show_med(fin, op, len, payload)
    case False{} False{}:
      show_big(fin, op, len, payload)

def show_go(ok: Bool, code: U32, fin: Bool, +op: U32, +payload: List<&2, U32>, +len: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      Done{show_head.go(fin, op, len, payload, U32.is_le(len, 125), U32.is_le(len, 65535))}
    case False{}:
      Fail{(code, "bad show")}

def show_frame(+fin: Bool, +op: U32, +payload: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +len = U32.from_nat(List.length(&2, U32, payload))
  +ok = Bool.and(is_op_ok(op), Bool.and(ctrl_ok(op, fin, len), U32.is_le(len, 1048576)))
  +code = Bool.pick(U32, Bool.not(U32.is_le(len, 1048576)), 413, 400)
  show_go(ok, code, fin, op, payload, len)

# Client
# ------
# Builds the opening request and masked frames (fixed key in tests).

def client_req.go(+host: String, +path: String, +key: String, bad: Bool) -> Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      Done{"GET " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " ++ key ++ "\r\nSec-WebSocket-Version: 13\r\n\r\n"}

def client_request(+host: String, +path: String, +key: String) -> Result<&1, &1, U32 & String, String>:
  client_req.go(host, path, key, HTTP.has_crlf3(host, path, key))

def show_masked_small(+fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> List<&2, U32>:
  List.append(&2, U32, [show_b0(fin, op), (len + 128 : U32), k0, k1, k2, k3], masked)

def show_masked_med(+fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> List<&2, U32>:
  List.append(&2, U32, [show_b0(fin, op), 254, U32.div(len, 256), U32.mod(len, 256), k0, k1, k2, k3], masked)

def show_masked_big(+fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, List.append(&2, U32, [show_b0(fin, op), 255, 0, 0, 0, 0], SHA1.bytes_of_word(len)), [k0, k1, k2, k3]), masked)

def show_masked_head.go(fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, is_small: Bool, is_med: Bool) -> List<&2, U32>:
  match is_small is_med:
    case True{} True{}:
      show_masked_small(fin, op, len, masked, k0, k1, k2, k3)
    case True{} False{}:
      show_masked_small(fin, op, len, masked, k0, k1, k2, k3)
    case False{} True{}:
      show_masked_med(fin, op, len, masked, k0, k1, k2, k3)
    case False{} False{}:
      show_masked_big(fin, op, len, masked, k0, k1, k2, k3)

def show_masked.go(fin: Bool, +op: U32, +payload: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      +len = U32.from_nat(List.length(&2, U32, payload))
      Done{show_masked_head.go(fin, op, len, unmask(payload, k0, k1, k2, k3, 0), k0, k1, k2, k3, U32.is_le(len, 125), U32.is_le(len, 65535))}
    case False{}:
      Fail{(400, "bad masked")}

def show_masked(+fin: Bool, +op: U32, +payload: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +len = U32.from_nat(List.length(&2, U32, payload))
  show_masked.go(fin, op, payload, k0, k1, k2, k3, Bool.and(is_op_ok(op), Bool.and(ctrl_ok(op, fin, len), U32.is_le(len, 1048576))))

# IO: single-shot echo plus parallel accept loop (mold HTTP.echo).
# TCP.String is UTF-8 on the wire; frames use Latin-1 (byte <-> Chr)
# so Bend-to-Bend loopbacks preserve 0..255. External interop needs
# a byte lane in the runtime (documented limit, no new effects here).

def chars_of_bytes(bs: List<&2, U32>) -> List<&2, Char>:
  match bs:
    case Nil{}:
      Nil{}
    case b <> rest:
      Char.from_u32(b) <> chars_of_bytes(rest)

def string_of_bytes(+bs: List<&2, U32>) -> String:
  String.from_list(chars_of_bytes(bs))

def bytes_of_chars(cs: List<&2, Char>) -> List<&2, U32>:
  match cs:
    case Nil{}:
      Nil{}
    case c <> rest:
      Char.to_u32(c) <> bytes_of_chars(rest)

def bytes_of_string(s: String) -> List<&2, U32>:
  bytes_of_chars(String.to_list(s))

def send_shipped(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, r2) = sent
  Socket.close(s2)

def send_bytes(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{bs}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, string_of_bytes(bs))
        send_shipped(sent)

def send_msg.go(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Unit):
  send_bytes((s, show_frame(True{}, op, pay)))

def send_msg(s: Socket, +msg: WSMessage) -> IO(Unit):
  send_msg.go(s, msg_to_op(msg), msg_to_bytes(msg))

def send_op(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Unit):
  send_bytes((s, show_frame(True{}, op, pay)))

def send(s: Socket, out: WSOut) -> IO(Unit):
  match out:
    case OutMsg{msg}:
      send_msg(s, msg)
    case OutOp{op, pay}:
      send_op(s, op, pay)
    case OutRaw{bs}:
      send_bytes((s, Done{bs}))

# Open sends (server sessions): unmasked like send_op/send_msg but the
# socket stays open; the session driver closes it.

def send_open_bytes(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{bs}:
      TCP.send(s, string_of_bytes(bs))

def send_open_op(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  send_open_bytes((s, show_frame(True{}, op, pay)))

def send_open_msg(s: Socket, +msg: WSMessage) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  send_open_op(s, msg_to_op(msg), msg_to_bytes(msg))

def on_op(s: Socket, fin: Bool, op: U32, +pay: List<&2, U32>) -> IO(Unit):
  match op:
    case 0:
      send_op(s, 0, pay)
    case 1:
      send_op(s, 1, pay)
    case 2:
      send_op(s, 2, pay)
    case 8:
      send_op(s, 8, pay)
    case 9:
      send_op(s, 10, pay)
    case 10:
      Socket.close(s)
    case _:
      Socket.close(s)

# Recv (generic API): raw wire bytes as List, no parse, no close.
# The server side reads masked frames, the client side the unmasked
# echo; only the parse above differs. Handshake recvs stay on
# TCP.recv(String) directly (no Latin-1 roundtrip); only frame paths
# migrate here.

def recv_bytes_got(got: Socket & Result<&1, &1, U32 & String, String>) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s2, r2) = got
  match r2:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>, (s2, Fail{e}))
    case Done{txt}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>, (s2, Done{bytes_of_string(txt)}))

def recv_bytes(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
    got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(sock, 8192)
    recv_bytes_got(got)

def recv_bytes_client(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
    got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(sock, 8192)
    recv_bytes_got(got)

def recv_op_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>, (s, Fail{e}))
    case Done{bs}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>, (s, read_frame(bs)))

def recv_op(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>):
  do IO<Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv_bytes(sock)
    recv_op_got(m)

def recv_msg_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage>, (s, Fail{e}))
    case Done{t}:
      (fin, op, pay) = t
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage>, (s, msg_of_frame(fin, op, pay)))

def recv_msg(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage>):
  do IO<Socket & Result<&1, &1, U32 & String, WSMessage>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- recv_op(sock)
    recv_msg_got(m)

def recv_pick(msg_res: Result<&1, &1, U32 & String, WSMessage>, fin: Bool, +op: U32, +pay: List<&2, U32>) -> WSIn:
  match msg_res:
    case Done{msg}:
      InMsg{msg}
    case Fail{e}:
      InOp{fin, op, pay}

def recv_in_of(+fin: Bool, +op: U32, +pay: List<&2, U32>) -> WSIn:
  recv_pick(msg_of_frame(fin, op, pay), fin, op, pay)

def recv_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn>, (s, Fail{e}))
    case Done{t}:
      (fin, op, pay) = t
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn>, (s, Done{recv_in_of(fin, op, pay)}))

def recv(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, WSIn>):
  do IO<Socket & Result<&1, &1, U32 & String, WSIn>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- recv_op(sock)
    recv_got(m)

def frame_echo(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{t}:
      (fin, op, pay) = t
      on_op(s, fin, op, pay)

def frame_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s2, r2) = m
  match r2:
    case Fail{e}:
      Socket.close(s2)
    case Done{bs}:
      frame_echo((s2, read_frame(bs)))

def frame_recv(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv_bytes(s)
        frame_got(m2)

def hs_reply(m: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{resp}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, resp)
        frame_recv(sent)

def hs_recv(m: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{req}:
      hs_reply((s, handshake(req)))

def serve_once(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(sock, 8192)
    hs_recv(got)

def ws_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  do IO<Listener>:
    s : Socket <- IO.pass(Socket, r)
    IO.spawn(Unit, serve_once(s))
    return l

@unsafe
def ws_serve(l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    l2 : Listener <- ws_conn(m)
    ws_serve(l2)

# Client echo (single Hi, fixed mask) for loopback tests.
# Returns Done{"Hi"} on exact echo, Fail otherwise. Closes always.

def client_validated(m: Socket & Bool & String) -> IO(Result<&1, &1, U32 & String, String>):
  (s, ok, txt) = m
  match ok:
    case True{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Done{txt}
    case False{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{(400, "bad echo")}

def client_echo_got(m: Socket & Result<&1, &1, U32 & String, String>, +want: String) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{txt}:
      client_validated((s, String.eq(txt, want), "Hi"))

def client_echo_got_list(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +want: String) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{bs}:
      client_validated((s, String.eq(string_of_bytes(bs), want), "Hi"))

def client_echo_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +frame_txt: String, +want: String) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, String>>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv_bytes_client(s)
        client_echo_got_list(m2, want)

def client_hs_got(m: Socket & Result<&1, &1, U32 & String, String>, +frame_txt: String, +want: String) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{hsresp}:
      do IO<Result<&1, &1, U32 & String, String>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, frame_txt)
        client_echo_sent(sent, frame_txt, want)

def client_req_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +frame_txt: String, +want: String) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, String>>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        client_hs_got(got, frame_txt, want)

def client_conn(conn: Result<&1, &1, U32 & String, Socket>, +req_txt: String, +frame_txt: String, +want: String) -> IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, String>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        client_req_sent(sent, frame_txt, want)

def client_frames_put(mres: Result<&1, &1, U32 & String, List<&2, U32>>, eres: Result<&1, &1, U32 & String, List<&2, U32>>) -> Result<&1, &1, U32 & String, String & String>:
  match mres:
    case Fail{e}:
      Fail{e}
    case Done{mbytes}:
      match eres:
        case Fail{e}:
          Fail{e}
        case Done{eby}:
          Done{(string_of_bytes(mbytes), string_of_bytes(eby))}

def client_frames(+msg: String) -> Result<&1, &1, U32 & String, String & String>:
  client_frames_put(show_masked(True{}, 1, bytes_of_string(msg), 1, 2, 3, 4), show_frame(True{}, 1, bytes_of_string(msg)))

def client_go(+host: String, port: U32, +path: String, +key: String, +msg: String, req: String, frames: String & String) -> IO(Result<&1, &1, U32 & String, String>):
  (frame_txt, want) = frames
  do IO<Result<&1, &1, U32 & String, String>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    client_conn(conn, req, frame_txt, want)

def client_req_ok(+host: String, port: U32, +path: String, +key: String, +msg: String, req: Result<&1, &1, U32 & String, String>, frames: Result<&1, &1, U32 & String, String & String>) -> IO(Result<&1, &1, U32 & String, String>):
  match req:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{req_txt}:
      match frames:
        case Fail{e}:
          IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
        case Done{fr}:
          client_go(host, port, path, key, msg, req_txt, fr)

def client_echo(+host: String, port: U32, +path: String, +key: String, +msg: String) -> IO(Result<&1, &1, U32 & String, String>):
  client_req_ok(host, port, path, key, msg, client_request(host, path, key), client_frames(msg))

# Client session (interop): masked sends with a fixed key, unmasked recvs.
# The socket stays open across calls; the session driver closes it.

def client_send_bytes(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{bs}:
      TCP.send(s, string_of_bytes(bs))

def client_send_op(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  client_send_bytes((s, show_masked(True{}, op, pay, 1, 2, 3, 4)))

def client_send_msg(s: Socket, +msg: WSMessage) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  client_send_op(s, msg_to_op(msg), msg_to_bytes(msg))

def recv_op_client_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>, (s, Fail{e}))
    case Done{bs}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>, (s, read_frame_unmasked(bs)))

def recv_op_client(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>):
  do IO<Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv_bytes_client(sock)
    recv_op_client_got(m)

def recv_msg_client(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage>):
  do IO<Socket & Result<&1, &1, U32 & String, WSMessage>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- recv_op_client(sock)
    recv_msg_got(m)

def recv_client(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, WSIn>):
  do IO<Socket & Result<&1, &1, U32 & String, WSIn>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- recv_op_client(sock)
    recv_got(m)
