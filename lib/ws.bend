# WebSocket RFC 6455 full-duplex in Bend.
#
# SUPERSEDED (task-028 Phase 5): use lib/wsm.bend (import as WSM), the
# unified ws:// + wss:// implementation built on the httpx H1 upgrade
# lane. This file stays for the old callers during migration.
#
# Import as: import ./ws.bend as WS (from lib) or
# import ../../lib/ws.bend as WS (from tests/io).
# Reuses Base, HTTP, SHA1, B64 and the byte effects in lib/tcp.bend
# (TCP.send_bytes/TCP.recv_bytes).
#
# Scope: server and client, text and binary frames, fragmentation,
# ping/pong/close. No TLS (same limit as HTTP.fetch). Frames ride
# TCP.send_bytes/TCP.recv_bytes, byte-faithful on List<U32>; the pure
# codec stays full binary on List<U32>. See DESIGN below.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
# - helpers above drivers are leaves: they never call back down.
import Base
import ./http1.bend as HTTP
import ./sha1.bend as SHA1
import ./b64.bend as B64
import ./tcp.bend as TCP

# Handshake
# ---------
# Server validates GET + Upgrade: websocket + Version: 13 + Key,
# then answers 101 with Accept = b64(sha1(key ++ GUID)).
# Anything else is Fail{400} and never becomes 101.

def guid() -> String:
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Phase 2 helpers: strict handshake validation plus subprotocol picks.
# All comments in English; callees stay above callers.

def ws_is_b64(+code: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(code, 65), U32.is_le(code, 90)), Bool.or(Bool.and(U32.is_ge(code, 97), U32.is_le(code, 122)), Bool.or(Bool.and(U32.is_ge(code, 48), U32.is_le(code, 57)), Bool.or(U32.is_eq(code, 43), U32.is_eq(code, 47)))))

def ws_b64_char_ok(c: Char) -> Bool:
  match c:
    case Chr{code}:
      ws_is_b64(code)

def ws_b64_list_ok(cs: List<&2, Char>) -> Bool:
  match cs:
    case Nil{}:
      True{}
    case h <> t:
      Bool.and(ws_b64_char_ok(h), ws_b64_list_ok(t))

def ws_key_ok(+key: String) -> Bool:
  +trimmed = String.trim(key)
  +head22 = String.take(trimmed, 22n)
  Bool.and(Nat.is_eq(String.length(trimmed), 24n), Bool.and(String.ends_with(trimmed, "=="), ws_b64_list_ok(String.to_list(head22))))

def ws_conn_tok_ok(+tok: String) -> Bool:
  String.eq(String.to_lower(String.trim(tok)), "upgrade")

def ws_conn_list_ok(toks: List<&2, String>) -> Bool:
  match toks:
    case Nil{}:
      False{}
    case h <> t:
      +hh = h
      Bool.or(ws_conn_tok_ok(hh), ws_conn_list_ok(t))

def ws_conn_has_upgrade(+val: String) -> Bool:
  ws_conn_list_ok(String.split(val, ','))

def ws_trim_nonempty(+tok: String) -> Bool:
  Bool.not(String.is_empty(String.trim(tok)))

def ws_proto_cons(+trimmed: String, +rest: List<&2, String>, keep: Bool) -> List<&2, String>:
  match keep:
    case True{}:
      trimmed <> rest
    case False{}:
      rest

def ws_trim_protos(toks: List<&2, String>) -> List<&2, String>:
  match toks:
    case Nil{}:
      Nil{}
    case h <> t:
      +hh = h
      +trimmed = String.trim(hh)
      ws_proto_cons(trimmed, ws_trim_protos(t), ws_trim_nonempty(hh))

def ws_protos_of(+val: String) -> List<&2, String>:
  ws_trim_protos(String.split(val, ','))

def ws_list_contains(xs: List<&2, String>, +item: String) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case h <> t:
      +hh = h
      +it = item
      Bool.or(String.eq(hh, it), ws_list_contains(t, it))

def ws_pick_go(+served: List<&2, String>, +client: List<&2, String>) -> Maybe<&2, String>:
  match served:
    case Nil{}:
      None{}
    case h <> t:
      +hh = h
      +tt = t
      +cc = client
      +hh2 = hh
      +cc2 = cc
      Bool.pick(Maybe<&2, String>, ws_list_contains(cc, hh), Some{hh2}, ws_pick_go(tt, cc2))

def ws_pick_sub(+client: List<&2, String>, +served: List<&2, String>) -> Maybe<&2, String>:
  ws_pick_go(served, client)

def ws_host_port_go(+host: String, +port: U32, is_def: Bool) -> String:
  match is_def:
    case True{}:
      host
    case False{}:
      host ++ ":" ++ U32.show(port)

def ws_host_port(+host: String, +port: U32) -> String:
  ws_host_port_go(host, port, Bool.or(U32.is_eq(port, 80), U32.is_eq(port, 443)))

def scan_proto_add(+acc: List<&2, String>, +val: String, is_proto: Bool) -> List<&2, String>:
  match is_proto:
    case True{}:
      List.append(&2, String, acc, ws_protos_of(val))
    case False{}:
      acc

def scan_go(hs: List<&1, String & String>, +key_acc: String, up_ok: Bool, ver_ok: Bool, conn_ok: Bool) -> String & Bool:
  match hs:
    case Nil{}:
      (key_acc, Bool.and(up_ok, Bool.and(ver_ok, Bool.and(conn_ok, ws_key_ok(key_acc)))))
    case (n, v) <> t:
      +nn = n
      +vv = v
      +tv = String.trim(vv)
      +low = String.to_lower(String.trim(vv))
      scan_go(t, Bool.pick(String, HTTP.eq_ci(nn, "Sec-WebSocket-Key"), tv, key_acc), Bool.or(up_ok, Bool.and(HTTP.eq_ci(nn, "Upgrade"), String.eq(low, "websocket"))), Bool.or(ver_ok, Bool.and(HTTP.eq_ci(nn, "Sec-WebSocket-Version"), String.eq(tv, "13"))), Bool.or(conn_ok, Bool.and(HTTP.eq_ci(nn, "Connection"), ws_conn_has_upgrade(vv))))

def scan(hs: List<&1, String & String>) -> String & Bool:
  scan_go(hs, "", False{}, False{}, False{})

def scan_full_go(hs: List<&1, String & String>, +key_acc: String, up_ok: Bool, ver_ok: Bool, conn_ok: Bool, +proto_acc: List<&2, String>) -> String & Bool & List<&2, String>:
  match hs:
    case Nil{}:
      (key_acc, Bool.and(up_ok, Bool.and(ver_ok, Bool.and(conn_ok, ws_key_ok(key_acc)))), proto_acc)
    case (n, v) <> t:
      +nn = n
      +vv = v
      +tv = String.trim(vv)
      +low = String.to_lower(String.trim(vv))
      +nn2 = nn
      +nn3 = nn
      +nn4 = nn
      +vv2 = vv
      +vv3 = vv
      scan_full_go(t, Bool.pick(String, HTTP.eq_ci(nn, "Sec-WebSocket-Key"), tv, key_acc), Bool.or(up_ok, Bool.and(HTTP.eq_ci(nn2, "Upgrade"), String.eq(low, "websocket"))), Bool.or(ver_ok, Bool.and(HTTP.eq_ci(nn3, "Sec-WebSocket-Version"), String.eq(tv, "13"))), Bool.or(conn_ok, Bool.and(HTTP.eq_ci(nn4, "Connection"), ws_conn_has_upgrade(vv2))), scan_proto_add(proto_acc, vv3, HTTP.eq_ci(nn, "Sec-WebSocket-Protocol")))

def scan_full(hs: List<&1, String & String>) -> String & Bool & List<&2, String>:
  scan_full_go(hs, "", False{}, False{}, False{}, Nil{})

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

def show_101_sub_go(+accept: String, +proto: String, bad: Bool) -> Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad accept")}
    case False{}:
      Done{"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ++ accept ++ "\r\nSec-WebSocket-Protocol: " ++ proto ++ "\r\n\r\n"}

def show_101_with(+accept: String, +proto: String) -> Result<&1, &1, U32 & String, String>:
  show_101_sub_go(accept, proto, Bool.or(HTTP.has_crlf(accept), HTTP.has_crlf(proto)))

def show_101_sub(+accept: String, proto: Maybe<&2, String>) -> Result<&1, &1, U32 & String, String>:
  match proto:
    case None{}:
      show_101(accept)
    case Some{p}:
      show_101_with(accept, p)

def chk_headers_sub(+key: String, ok: Bool, proto: Maybe<&2, String>) -> Result<&1, &1, U32 & String, String>:
  match ok:
    case True{}:
      show_101_sub(accept_of(key), proto)
    case False{}:
      Fail{(400, "bad headers")}

def chk_method_sub(+key: String, headers_ok: Bool, is_get: Bool, proto: Maybe<&2, String>) -> Result<&1, &1, U32 & String, String>:
  match is_get:
    case True{}:
      chk_headers_sub(key, headers_ok, proto)
    case False{}:
      Fail{(400, "bad method")}

def handshake_keys_sub(m: String, trio: String & Bool & List<&2, String>, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  (key, ok, cprotos) = trio
  chk_method_sub(key, ok, String.eq(m, "GET"), ws_pick_sub(cprotos, wanted))

def handshake_req_sub(req: String & String & List<&1, String & String> & String, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  (m, p, hs, body) = req
  handshake_keys_sub(m, scan_full(hs), wanted)

def handshake_parsed_sub(parsed: Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  match parsed:
    case Fail{e}:
      Fail{e}
    case Done{req}:
      handshake_req_sub(req, wanted)

def handshake_sub(+s: String, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  handshake_parsed_sub(HTTP.read_request(s), wanted)

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
# reserved opcodes or RSV, and payloads over 16MB all Fail.
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

# Lifecycle events (server_on API): named open/message/ping/pong/close/
# error over the frozen wire types. WSMessage/WSIn/WSOut stay byte-exact;
# the persistent server maps each complete frame to one WSEv and answers
# the handler's single WSOut per step, always sent verbatim — except ping,
# where an OutOp or a non-empty OutRaw wins (OutRaw may glue the pong
# with the next frame, like the server's echo step) and OutRaw{[]}/OutMsg
# fall back to pong, and close, which replies and shuts. Return OutRaw{[]}
# to continue silently on pong (zero-byte send, no wire effect) or OutOp
# to override and close.
# client_on mirrors the API over a connect (same WSEv/WSOut, sends masked).

# Fragment reassembly state (RFC 6455 section 5.4). FragIdle means no
# open fragment; FragOpen holds the leading opcode (1 text, 2 binary)
# plus the bytes stitched so far.

type MsgAcc is Data:
  FragIdle{}
  FragOpen{op: U32, buf: List<&2, U32>}

type WSEv is Data:
  EvOpen{}
  EvMsg{msg: WSMessage}
  EvPing{pay: List<&2, U32>}
  EvPong{pay: List<&2, U32>}
  EvClose{pay: List<&2, U32>}
  EvError{code: U32, msg: String}

# Loop-internal step carrier: the session loops fold each frame into
# one of these before dispatching. StepEv carries a handler-bound
# event; StepFrag means a fragment was stitched and the loop must keep
# reading silently; StepOut carries a handler answer still to send
# (the send edge also learns whether the answer closes). Handlers
# never see this type, so WSEv above stays a stable public contract.

type WsStep is Data:
  StepEv{ev: WSEv}
  StepFrag{acc: MsgAcc}
  StepOut{out: WSOut}

def op_text() -> U32:
  1

def op_bin() -> U32:
  2

def op_close() -> U32:
  8

def op_ping() -> U32:
  9

def op_pong() -> U32:
  10

def out_ping(+pay: List<&2, U32>) -> WSOut:
  OutOp{op_ping(), pay}

def out_pong(+pay: List<&2, U32>) -> WSOut:
  OutOp{op_pong(), pay}

def out_close(+pay: List<&2, U32>) -> WSOut:
  OutOp{op_close(), pay}

def ping_reply.go(+pay: List<&2, U32>, +bs: List<&2, U32>) -> WSOut:
  match bs:
    case Nil{}:
      out_pong(pay)
    case _ <> _:
      OutRaw{bs}

def ping_reply(+pay: List<&2, U32>, out: WSOut) -> WSOut:
  match out:
    case OutOp{op, pp}:
      OutOp{op, pp}
    case OutMsg{msg}:
      out_pong(pay)
    case OutRaw{bs}:
      ping_reply.go(pay, bs)

# Wire denormalization for close echoes: our normalized empty (1005)
# must never reach the wire (RFC 6455 forbids 1005/1006/1015 on the
# wire), so answers to it go out empty; every other code echoes.

def close_is_1005(+pay: List<&2, U32>) -> Bool:
  match pay:
    case Nil{}:
      True{}
    case hi <> t:
      match t:
        case Nil{}:
          False{}
        case lo <> rest:
          match rest:
            case Nil{}:
              Bool.and(U32.is_eq(hi, 3), U32.is_eq(lo, 237))
            case _ <> _:
              False{}

def close_wire_of.go(+pay: List<&2, U32>, deny: Bool) -> List<&2, U32>:
  match deny:
    case True{}:
      []
    case False{}:
      pay

def close_wire_of(+pay: List<&2, U32>) -> List<&2, U32>:
  close_wire_of.go(pay, close_is_1005(pay))

# Send-side guard: a handler echoing a normalized empty close would
# otherwise put 1005 on the wire through the verbatim OutOp path, and
# the peer would fail the close with 1006. Only close frames carrying
# our internal 1005 marker are rewritten to empty; every other opcode
# and payload rides untouched.

def out_op_pay.go(+pay: List<&2, U32>, keep: Bool) -> List<&2, U32>:
  match keep:
    case True{}:
      pay
    case False{}:
      []

def out_op_pay(+op: U32, +pay: List<&2, U32>) -> List<&2, U32>:
  out_op_pay.go(pay, Bool.or(Bool.not(U32.is_eq(op, 8)), Bool.not(close_is_1005(pay))))

def close_answer(+pay: List<&2, U32>, out: WSOut) -> WSOut:
  match out:
    case OutOp{op, pp}:
      OutOp{op, pp}
    case OutMsg{msg}:
      out_close(close_wire_of(pay))
    case OutRaw{bs}:
      out_close(close_wire_of(pay))

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

# Largest single-frame payload accepted on the wire (16MB). Both the
# masked and unmasked splits and both show paths enforce it; the
# reassembly accumulator enforces the same bound on the stitched
# message (see frag_acc below).
def ws_max_payload() -> U32:
  16777216

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

# Strict UTF-8 validation over byte lists (RFC 6455 section 5.6: text
# frames and close reasons must be valid UTF-8, else 1007). One
# self-recursive walker carries the open sequence length (need: 0 for
# a fresh lead byte, 1-3 for open continuations, 9 for poisoned), its
# minimum code point (min, rejects overlongs) and the running value
# (code); the last continuation validates the code point (no
# surrogates, nothing past U+10FFFF) back into need 0 or 9, so every
# branch stays inside this single def.

def utf8_is_cont(+b: U32) -> Bool:
  Bool.and(U32.is_ge(b, 128), U32.is_le(b, 191))

def utf8_need(+b: U32) -> U32:
  Bool.pick(U32, U32.is_lt(b, 128), 0, Bool.pick(U32, U32.is_lt(b, 194), 9, Bool.pick(U32, U32.is_lt(b, 224), 1, Bool.pick(U32, U32.is_lt(b, 240), 2, Bool.pick(U32, U32.is_le(b, 244), 3, 9)))))

def utf8_min(+need: U32) -> U32:
  match need:
    case 1:
      128
    case 2:
      2048
    case 3:
      65536
    case _:
      0

def utf8_mask(+need: U32) -> U32:
  match need:
    case 1:
      31
    case 2:
      15
    case 3:
      7
    case _:
      0

def utf8_code_ok(+code: U32, +min: U32) -> Bool:
  Bool.and(U32.is_ge(code, min), Bool.and(Bool.not(Bool.and(U32.is_ge(code, 55296), U32.is_le(code, 57343))), U32.is_le(code, 1114111)))

def utf8_fin2(+code2: U32, +min: U32) -> U32:
  Bool.pick(U32, utf8_code_ok(code2, min), 0, 9)

def utf8_fin(+code: U32, +min: U32, +b: U32) -> U32:
  Bool.pick(U32, utf8_is_cont(b), utf8_fin2((code * 64 + U32.and(b, 63) : U32), min), 9)

def utf8_go(+bs: List<&2, U32>, +need: U32, +min: U32, +code: U32) -> Bool:
  match bs:
    case Nil{}:
      U32.is_zero(need)
    case b <> t:
      match need:
        case 0:
          utf8_go(t, utf8_need(b), utf8_min(utf8_need(b)), U32.and(b, utf8_mask(utf8_need(b))))
        case 1:
          utf8_go(t, utf8_fin(code, min, b), 0, 0)
        case 2:
          utf8_go(t, Bool.pick(U32, utf8_is_cont(b), 1, 9), min, (code * 64 + U32.and(b, 63) : U32))
        case 3:
          utf8_go(t, Bool.pick(U32, utf8_is_cont(b), 2, 9), min, (code * 64 + U32.and(b, 63) : U32))
        case _:
          False{}

def utf8_ok(bs: List<&2, U32>) -> Bool:
  utf8_go(bs, 0, 0, 0)

# Close payload validation (RFC 6455 section 5.5.1): empty or a 2-byte
# big-endian status code plus a UTF-8 reason. Empty normalizes to the
# 1005 wire form so the application always sees a code; reserved codes
# (under 1000, 1004-1006, 1015, 1016-2999, past 4999) fail 1002 and a
# non-UTF-8 reason fails 1007.

def close_in1000(+code: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(code, 1000), U32.is_le(code, 1011)), Bool.and(U32.is_ge(code, 3000), U32.is_le(code, 4999)))

def close_reserved(+code: U32) -> Bool:
  Bool.or(Bool.or(U32.is_eq(code, 1004), U32.is_eq(code, 1005)), Bool.or(U32.is_eq(code, 1006), U32.is_eq(code, 1015)))

def close_code_ok(+code: U32) -> Bool:
  Bool.and(close_in1000(code), Bool.not(close_reserved(code)))

def close_reason.go(+pay: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      Done{pay}
    case False{}:
      Fail{(1007, "bad close reason")}

def close_reason(+pay: List<&2, U32>, +reason: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  close_reason.go(pay, utf8_ok(reason))

def close_code.go(+pay: List<&2, U32>, +reason: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      close_reason(pay, reason)
    case False{}:
      Fail{(1002, "bad close code")}

def close_code(+pay: List<&2, U32>, +code: U32, +reason: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  close_code.go(pay, reason, close_code_ok(code))

def close_hi(+pay: List<&2, U32>, +hi: U32, +t: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match t:
    case Nil{}:
      Fail{(1002, "short close")}
    case lo <> reason:
      close_code(pay, (hi * 256 + lo : U32), reason)

def close_norm(+pay: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match pay:
    case Nil{}:
      Done{[3, 237]}
    case hi <> t:
      close_hi(pay, hi, t)

def close_ev.go(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> WSEv:
  match r:
    case Fail{(c, m)}:
      EvError{c, m}
    case Done{norm}:
      EvClose{norm}

def close_ev(+pay: List<&2, U32>) -> WSEv:
  close_ev.go(close_norm(pay))

# Fragment reassembly (RFC 6455 section 5.4): frag_step folds one data
# frame (op 1/2 to open, 0 to continue) into the accumulator. A leading
# frame with FIN set emits at once; otherwise bytes stitch until FIN
# and only the stitched message emits (text validated as UTF-8 at
# completion, since a code point may straddle fragments). An orphan
# continuation or a new data frame mid-reassembly fails 400; anything
# past ws_max_payload fails 413 so the loops can answer close 1009.
# Control frames never reach this fold; the loops emit them at once.

def frag_capped(+buf: List<&2, U32>) -> Bool:
  U32.is_le(U32.from_nat(List.length(&2, U32, buf)), ws_max_payload())

def frag_text.go(+buf: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, WSMessage>:
  match ok:
    case True{}:
      Done{WSText{HTTP.decode(buf)}}
    case False{}:
      Fail{(1007, "bad utf8")}

def frag_text(+buf: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  frag_text.go(buf, utf8_ok(buf))

def frag_msg.go(+op: U32, +buf: List<&2, U32>, is_text: Bool) -> Result<&1, &1, U32 & String, WSMessage>:
  match is_text:
    case True{}:
      frag_text(buf)
    case False{}:
      Done{WSBin{buf}}

def frag_msg(+op: U32, +buf: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  frag_msg.go(op, buf, U32.is_eq(op, 1))

def frag_msg_done(r: Result<&1, &1, U32 & String, WSMessage>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{msg}:
      Done{(FragIdle{}, Some{msg})}

def frag_single_msg(+op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_msg_done(frag_msg(op, pay))

def frag_single.go(+op: U32, +pay: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match ok:
    case True{}:
      frag_single_msg(op, pay)
    case False{}:
      Fail{(413, "message too large")}

def frag_single(+op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_single.go(op, pay, frag_capped(pay))

def frag_begin.go(+op: U32, +pay: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match ok:
    case True{}:
      Done{(FragOpen{op, pay}, None{})}
    case False{}:
      Fail{(413, "fragment too large")}

def frag_begin(+op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_begin.go(op, pay, frag_capped(pay))

def frag_first(fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match fin:
    case True{}:
      frag_single(op, pay)
    case False{}:
      frag_begin(op, pay)

def frag_open.go(fin: Bool, +op: U32, +pay: List<&2, U32>, is_data: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match is_data:
    case True{}:
      frag_first(fin, op, pay)
    case False{}:
      Fail{(400, "not data")}

def frag_open(fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_open.go(fin, op, pay, Bool.or(U32.is_eq(op, 1), U32.is_eq(op, 2)))

def frag_last(fin: Bool, +op0: U32, +grown: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match fin:
    case True{}:
      frag_single_msg(op0, grown)
    case False{}:
      Done{(FragOpen{op0, grown}, None{})}

def frag_cont2(fin: Bool, +op0: U32, +grown: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match ok:
    case True{}:
      frag_last(fin, op0, grown)
    case False{}:
      Fail{(413, "message too large")}

def frag_cont.go(fin: Bool, +op0: U32, +grown: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_cont2(fin, op0, grown, frag_capped(grown))

def frag_cont(fin: Bool, +op0: U32, +buf: List<&2, U32>, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_cont.go(fin, op0, List.append(&2, U32, buf, pay))

def frag_got.go(fin: Bool, +op0: U32, +buf: List<&2, U32>, +pay: List<&2, U32>, is_cont: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match is_cont:
    case True{}:
      frag_cont(fin, op0, buf, pay)
    case False{}:
      Fail{(400, "mixed fragment")}

def frag_got(fin: Bool, +op: U32, +op0: U32, +pay: List<&2, U32>, +buf: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  frag_got.go(fin, op0, buf, pay, U32.is_eq(op, 0))

def frag_step(+acc: MsgAcc, fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match acc:
    case FragIdle{}:
      frag_open(fin, op, pay)
    case FragOpen{op0, buf}:
      frag_got(fin, op, op0, pay, buf)

def frag_done(+acc2: MsgAcc, maybe: Maybe<&2, WSMessage>) -> WsStep:
  match maybe:
    case None{}:
      StepFrag{acc2}
    case Some{msg}:
      StepEv{EvMsg{msg}}

def frag_ev.go(r: Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>) -> WsStep:
  match r:
    case Fail{(c, m)}:
      StepEv{EvError{c, m}}
    case Done{pr}:
      (acc2, maybe) = pr
      frag_done(acc2, maybe)

def frag_ev(+acc: MsgAcc, fin: Bool, +op: U32, +pay: List<&2, U32>) -> WsStep:
  frag_ev.go(frag_step(acc, fin, op, pay))

# Loop helpers: the 1009 close answered on Fail 413, and the opcode
# carried by a handler answer (255 when the answer is no opcode frame,
# so the loops can tell a handler-initiated close apart).

def cap_close_out() -> WSOut:
  out_close([3, 249])

def out_op_of(out: WSOut) -> U32:
  match out:
    case OutOp{op, pay}:
      op
    case OutMsg{msg}:
      255
    case OutRaw{bs}:
      255

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
  +cap_ok = U32.is_le(len, ws_max_payload())
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
# Same caps as read_frame (16MB, control rules); masked frames still parse.

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

# Incremental framing: total-first split for the recv accumulator.
# frame_need(bs) is the header read (2 + ext 0/2/8 + mask 0/4 +
# payload) under the same rules as read_frame (RSV/opcode/control
# and the 16MB cap); short headers Fail "short ...", invalid ones
# Fail 400/413. frame_split(bs) never fails soft data: NeedMore
# with the missing count while the bytes fall short (1 while the
# header itself is short), FrameGot with the frame plus the exact
# rest once complete, FrameBad on invalid headers. The unmasked
# twins serve the client side, like read_frame_unmasked.

type WSFrameSplit is Data:
  NeedMore{missing: U32}
  FrameGot{frame: List<&2, U32>, rest: List<&2, U32>}
  FrameBad{code: U32, msg: String}

def frame_is_short(+e: String) -> Bool:
  Bool.or(String.eq(e, "short frame"), String.eq(e, "short len"))

def frame_need_done(ok: Bool, code: U32, +total: U32) -> Result<&1, &1, U32 & String, U32>:
  match ok:
    case True{}:
      Done{total}
    case False{}:
      Fail{(code, "bad frame")}

def frame_need_len(fin: Bool, rsv_ok: Bool, op: U32, +masked: Bool, +len: U32, ext: U32, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  +mask_len = Bool.pick(U32, masked, 4, 0)
  +total = (2 + ext + mask_len + len : U32)
  +cap_ok = U32.is_le(len, ws_max_payload())
  +mask_ok = Bool.or(masked, unmasked_ok)
  +ok = Bool.and(mask_ok, payload_ok(rsv_ok, op, fin, len, True{}, cap_ok))
  +code = Bool.pick(U32, Bool.not(cap_ok), 413, 400)
  frame_need_done(ok, code, total)

def frame_need_small(fin: Bool, rsv_ok: Bool, op: U32, masked: Bool, len: U32, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  frame_need_len(fin, rsv_ok, op, masked, len, 0, unmasked_ok)

def frame_need_med(fin: Bool, rsv_ok: Bool, op: U32, masked: Bool, b0: U32, b1: U32, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  frame_need_len(fin, rsv_ok, op, masked, (b0 * 256 + b1 : U32), 2, unmasked_ok)

def frame_need_big(fin: Bool, rsv_ok: Bool, op: U32, masked: Bool, lo: U32, is_hi0: Bool, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  match is_hi0:
    case True{}:
      frame_need_len(fin, rsv_ok, op, masked, lo, 8, unmasked_ok)
    case False{}:
      Fail{(413, "frame too large")}

def frame_need_ext(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, len7: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
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
              frame_need_med(fin, rsv_ok, op, masked, b0, b1, unmasked_ok)
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
                                      frame_need_big(fin, rsv_ok, op, masked, SHA1.word_of4(b4, b5, b6, b7), U32.is_zero(SHA1.word_of4(b0, b1, b2, b3)), unmasked_ok)
    case _:
      frame_need_small(fin, rsv_ok, op, masked, len7, unmasked_ok)

def frame_need_go(bs: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  match bs:
    case Nil{}:
      Fail{(400, "short frame")}
    case +b0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "short frame")}
        case +b1 <> rest:
          frame_need_ext(U32.is_ge(b0, 128), U32.is_zero(U32.and(U32.shrn(b0, 4n), 7)), U32.and(b0, 15), U32.is_ge(b1, 128), U32.and(b1, 127), rest, unmasked_ok)

def frame_need(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, U32>:
  frame_need_go(bs, False{})

def frame_need_unmasked(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, U32>:
  frame_need_go(bs, True{})

def frame_got_go(frame: List<&2, U32>, rest: List<&2, U32>, eq: Bool, missing: U32) -> WSFrameSplit:
  match eq:
    case True{}:
      FrameGot{frame, rest}
    case False{}:
      NeedMore{missing}

def frame_split_got(+bs: List<&2, U32>, +total: U32) -> WSFrameSplit:
  +taken = List.take(&2, U32, bs, U32.to_nat(total))
  +rest = List.drop(&2, U32, bs, U32.to_nat(total))
  +got = U32.from_nat(List.length(&2, U32, taken))
  +missing = U32.sub(total, got)
  frame_got_go(taken, rest, U32.is_eq(got, total), missing)

def frame_split_bad_go(code: U32, msg: String, is_short: Bool) -> WSFrameSplit:
  match is_short:
    case True{}:
      NeedMore{1}
    case False{}:
      FrameBad{code, msg}

def frame_split_bad(code: U32, +msg: String) -> WSFrameSplit:
  frame_split_bad_go(code, msg, frame_is_short(msg))

def frame_split_res(bs: List<&2, U32>, need: Result<&1, &1, U32 & String, U32>) -> WSFrameSplit:
  match need:
    case Fail{(c, e)}:
      frame_split_bad(c, e)
    case Done{total}:
      frame_split_got(bs, total)

def frame_split_go(+bs: List<&2, U32>, unmasked_ok: Bool) -> WSFrameSplit:
  frame_split_res(bs, frame_need_go(bs, unmasked_ok))

def frame_split(bs: List<&2, U32>) -> WSFrameSplit:
  frame_split_go(bs, False{})

def frame_split_unmasked(bs: List<&2, U32>) -> WSFrameSplit:
  frame_split_go(bs, True{})

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
  +ok = Bool.and(is_op_ok(op), Bool.and(ctrl_ok(op, fin, len), U32.is_le(len, ws_max_payload())))
  +code = Bool.pick(U32, Bool.not(U32.is_le(len, ws_max_payload())), 413, 400)
  show_go(ok, code, fin, op, payload, len)

# Client
# ------
# Builds the opening request and masked frames (fixed key in tests).

def ws_has_proto(protos: List<&2, String>) -> Bool:
  match protos:
    case Nil{}:
      False{}
    case _ <> _:
      True{}

def ws_proto_line_go(+joined: String, has_any: Bool) -> String:
  match has_any:
    case True{}:
      "\r\nSec-WebSocket-Protocol: " ++ joined
    case False{}:
      ""

def ws_proto_line(+protos: List<&2, String>) -> String:
  +pp = protos
  ws_proto_line_go(String.join(pp, ", "), ws_has_proto(pp))

def ws_protos_bad(protos: List<&2, String>) -> Bool:
  match protos:
    case Nil{}:
      False{}
    case h <> t:
      +hh = h
      Bool.or(HTTP.has_crlf(hh), ws_protos_bad(t))

def client_req.go(+host: String, +path: String, +key: String, bad: Bool) -> Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      Done{"GET " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " ++ key ++ "\r\nSec-WebSocket-Version: 13\r\n\r\n"}

def client_request(+host: String, +path: String, +key: String) -> Result<&1, &1, U32 & String, String>:
  client_req.go(host, path, key, HTTP.has_crlf3(host, path, key))

def client_req_sub_go(+hostport: String, +path: String, +key: String, +protoline: String, bad: Bool) -> Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      Done{"GET " ++ path ++ " HTTP/1.1\r\nHost: " ++ hostport ++ "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " ++ key ++ protoline ++ "\r\nSec-WebSocket-Version: 13\r\n\r\n"}

def client_request_sub(+host: String, +port: U32, +path: String, +key: String, +protos: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  +hp = ws_host_port(host, port)
  +pl = ws_proto_line(protos)
  client_req_sub_go(hp, path, key, pl, Bool.or(HTTP.has_crlf3(host, path, key), ws_protos_bad(protos)))

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
  show_masked.go(fin, op, payload, k0, k1, k2, k3, Bool.and(is_op_ok(op), Bool.and(ctrl_ok(op, fin, len), U32.is_le(len, ws_max_payload()))))

# Client masking key (RFC 6455 section 5.3): every client frame needs a
# fresh unpredictable key, never a constant. IO.random_u32 reads the
# host entropy pool (getrandom on Linux, arc4random on Apple), so two
# draws give 64 bits for the 32-bit field the RFC asks to be
# unpredictable. show_masked above stays public for tests that want a
# fixed key on purpose.
type WSMask is Data:
  WSMask{k0: U32, k1: U32, k2: U32, k3: U32}

def mask_key.go(a: Result<&1, &1, U32 & String, U32>, b: Result<&1, &1, U32 & String, U32>) ->
  WSMask:
  match a b:
    case Done{+hi} Done{+lo}:
      WSMask{U32.and(hi, 255), U32.and(U32.shrn(hi, 8n), 255), U32.and(U32.shrn(hi, 16n), 255), U32.and(lo, 255)}
    case _ _:
      WSMask{1, 2, 3, 4}

def mask_key() -> IO(WSMask):
  do IO<WSMask>:
    a : Result<&1, &1, U32 & String, U32> <- IO.random_u32()
    b : Result<&1, &1, U32 & String, U32> <- IO.random_u32()
    IO.pure(WSMask, mask_key.go(a, b))

def show_masked_key(+fin: Bool, +op: U32, +payload: List<&2, U32>, +key: WSMask) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  match key:
    case WSMask{k0, k1, k2, k3}:
      show_masked(fin, op, payload, k0, k1, k2, k3)

def show_masked_random(+fin: Bool, +op: U32, +payload: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    +key : WSMask <- mask_key()
    IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, show_masked_key(fin, op, payload, key))

# IO: single-shot echo plus parallel accept loop (mold HTTP.echo).
# Frames ride TCP.send_bytes/TCP.recv_bytes (byte-faithful 0..255);
# only the HTTP handshake stays on TCP.send/recv (ASCII text).

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
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, bs)
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
      TCP.send_bytes(s, bs)

def send_open_op(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  send_open_bytes((s, show_frame(True{}, op, pay)))

def send_open_msg(s: Socket, +msg: WSMessage) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  send_open_op(s, msg_to_op(msg), msg_to_bytes(msg))

# Open send from a WSOut (persistent sessions): one verbatim frame, the
# socket stays open; the session loop owns the close. The closing
# single-shot send/send_op above is never used on this path.

def out_bytes(out: WSOut) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match out:
    case OutMsg{msg}:
      +mm = msg
      show_frame(True{}, msg_to_op(mm), msg_to_bytes(mm))
    case OutOp{op, pay}:
      +oo = op
      +pp = pay
      show_frame(True{}, oo, out_op_pay(oo, pp))
    case OutRaw{bs}:
      Done{bs}

# One-shot echo policy (serve_once / client_echo only; a persistent
# session runs ws_loop, which reassembles fragments and answers ping via
# ping_reply). Codes: 1 echo the same op, 2 answer a ping with a pong,
# 0 close. A fragment (fin=false) means a message this path cannot
# answer whole, and control frames may not be fragmented at all, so
# both close instead of echoing a truncated frame. A continuation means
# the same thing one step later, and an unsolicited pong has nothing to
# answer: those close too (they used to put op 0 / op 10 on the wire).
def echo_op_fin(op: U32) -> U32:
  match op:
    case 1:
      1
    case 2:
      1
    case 8:
      1
    case 9:
      2
    case _:
      0

def echo_op(fin: Bool, op: U32) -> U32:
  match fin:
    case True{}:
      echo_op_fin(op)
    case False{}:
      0

def on_op.go(act: U32, s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Unit):
  match act:
    case 1:
      send_op(s, op, pay)
    case 2:
      send_op(s, 10, pay)
    case _:
      Socket.close(s)

def on_op(s: Socket, fin: Bool, +op: U32, +pay: List<&2, U32>) -> IO(Unit):
  on_op.go(echo_op(fin, op), s, op, pay)

# Recv (generic API): raw wire bytes as List, no parse, no close.
# The server side reads masked frames, the client side the unmasked
# echo; only the parse above differs. Handshake recvs stay on
# TCP.recv(String) directly; frame paths ride TCP.recv_bytes.

def recv_bytes(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  TCP.recv_bytes(sock, 8192)

def recv_bytes_client(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  TCP.recv_bytes(sock, 8192)

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

# Framed recv: one TCP.recv_frame call isolates exactly one frame from
# the byte stream, holding bytes already read (buf) plus the socket
# until the length prefix completes. The effect only counts the total
# (2 + ext + mask + payload, capped); the pure codec above still
# validates the isolated bytes, so every Fail path below stays exact.
# Each answer carries the rest past the frame: the driver threads it
# into the next call, and every byte read is consumed exactly once.
# No user-land loop could do this (a match takes only params and
# fields, do tails are terms, mutual recursion is out), so the loop
# lives in the effect: one hop per frame.

def recv_framed_max() -> U32:
  +cap = ws_max_payload()
  (cap + 14 : U32)

def recv_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  TCP.recv_frame(sock, buf, recv_framed_max())

def recv_op_framed_done(s: Socket, p: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>, rest: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  match p:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, Done{t}, rest))

def recv_op_framed_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, Fail{e}, []))
    case Done{fr}:
      (frame, rest) = fr
      recv_op_framed_done(s, read_frame(frame), rest)

def recv_op_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- recv_framed(sock, buf)
    recv_op_framed_got(m)

def recv_op_client_framed_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, Fail{e}, []))
    case Done{fr}:
      (frame, rest) = fr
      recv_op_framed_done(s, read_frame_unmasked(frame), rest)

def recv_op_client_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- recv_framed(sock, buf)
    recv_op_client_framed_got(m)

def recv_msg_framed_done(s: Socket, p: Result<&1, &1, U32 & String, WSMessage>, rest: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  match p:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Fail{e}, []))
    case Done{msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Done{msg}, rest))

def recv_msg_framed_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      recv_msg_framed_done(s, msg_of_frame(fin, op, pay), rest)

def recv_msg_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- recv_op_framed(sock, buf)
    recv_msg_framed_got(m)

def recv_msg_client_framed_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      recv_msg_framed_done(s, msg_of_frame(fin, op, pay), rest)

def recv_msg_client_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- recv_op_client_framed(sock, buf)
    recv_msg_client_framed_got(m)

def recv_in_framed_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Done{recv_in_of(fin, op, pay)}, rest))

def recv_in_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- recv_op_framed(sock, buf)
    recv_in_framed_got(m)

def recv_in_client_framed_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Done{recv_in_of(fin, op, pay)}, rest))

def recv_in_client_framed(sock: Socket, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- recv_op_client_framed(sock, buf)
    recv_in_client_framed_got(m)

# Loop edges for the persistent server (both leaves: no recursion, they
# only pack the next hop). recv_after answers a send before reading on:
# a failed send short-circuits with no syscall and the dispatcher closes
# on the Fail. hs_open answers the handshake send the same way.
# close_done shuts after the close answer, both loops (ws_loop/client_loop):
# the socket closes on the Fail and on the Done alike.

def recv_after(m: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{u}:
      recv_in_framed(s, buf)

def hs_open(m: Socket & Result<&1, &1, U32 & String, Unit>, out: WSOut) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{u}:
      send_open_bytes((s, out_bytes(out)))

def close_done(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{u}:
      Socket.close(s)

def frame_echo(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{t}:
      (fin, op, pay) = t
      on_op(s, fin, op, pay)

# Echo path, framed: the rest past the frame is dropped on purpose, the
# echo answers a single frame per connection and closes right after.
def frame_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>) -> IO(Unit):
  (s2, r2) = m
  match r2:
    case Fail{e}:
      Socket.close(s2)
    case Done{fr}:
      (frame, rest) = fr
      frame_echo((s2, read_frame(frame)))

def frame_recv(m: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- recv_framed(s, buf)
        frame_got(m2)

def hs_reply(m: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{resp}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, resp)
        frame_recv(sent, [])

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

# server_on: the generic persistent WS server. The handler rides a
# template (~H) — a def name baked at the call site (server_on~h) —
# because a function value can neither be copied nor thread a loop in
# affine user-land (no function type is Data). The handshake driver
# (ws_hs, states 0/1/3) accumulates the head until the blank line under
# the same 16KB cap as HTTP.read_request, answers 101 or closes, emits
# one EvOpen and enters the frame loop (ws_loop, states 1/2): each
# complete frame arrives via TCP.recv_frame with its rest threaded as
# the next buf, maps to one WSEv, and the handler's single WSOut goes
# out verbatim over send_open_bytes (OutRaw{[]} continues silently).
# Ping with an OutOp answer sends it verbatim and falls back to pong
# otherwise; close replies and shuts; transport Fail and EvError close. Two defs, not one: the
# handshake prefix (String lane) and the frame loop (byte lane) carry
# different carriers, and a single def would thread two sockets through
# dummy carriers (affine duplication); the split keeps one direction
# only (hs into loop, each self-recursive, no mutual recursion) with
# the template threaded through both.

@unsafe
def ws_loop(~H: WSEv -> IO(WSOut), st: U32, mf: Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, step: WsStep, +buf: List<&2, U32>, acc: MsgAcc, shut: Bool) -> IO(Unit):
  match st:
    case 1:
      (s, r, rest) = mf
      match r:
        case Fail{(c, m)}:
          match c:
            case 413:
              do IO<Unit>:
                m2 : Socket & Result<&1, &1, U32 & String, Unit> <- send_open_bytes((s, out_bytes(cap_close_out())))
                close_done(m2)
            case _:
              Socket.close(s)
        case Done{inn}:
          match inn:
            case InMsg{msg}:
              ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvMsg{msg}}, rest, FragIdle{}, shut)
            case InOp{fin, op, pay}:
              match op:
                case 8:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{close_ev(pay)}, rest, FragIdle{}, shut)
                case 9:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvPing{pay}}, rest, FragIdle{}, shut)
                case 10:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvPong{pay}}, rest, FragIdle{}, shut)
                case 0:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case 1:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case 2:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case _:
                  ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvError{400, "bad frame"}}, rest, FragIdle{}, shut)
    case 2:
      (s, r, b) = mf
      match step:
        case StepEv{ev}:
          match ev:
            case EvOpen{}:
              do IO<Unit>:
                out : WSOut <- H(EvOpen{})
                ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvMsg{msg}:
              do IO<Unit>:
                out : WSOut <- H(EvMsg{msg})
                ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvPing{pay}:
              +pp = pay
              do IO<Unit>:
                out : WSOut <- H(EvPing{pp})
                ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{ping_reply(pp, out)}, buf, acc, shut)
            case EvPong{pay}:
              do IO<Unit>:
                out : WSOut <- H(EvPong{pay})
                ws_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvClose{pay}:
              match shut:
                case True{}:
                  Socket.close(s)
                case False{}:
                  +pp = pay
                  do IO<Unit>:
                    out : WSOut <- H(EvClose{pp})
                    m2 : Socket & Result<&1, &1, U32 & String, Unit> <- send_open_bytes((s, out_bytes(close_answer(pp, out))))
                    close_done(m2)
            case EvError{code, msg}:
              do IO<Unit>:
                out : WSOut <- H(EvError{code, msg})
                x : Unit <- Socket.close(s)
                return x
        case StepFrag{acc2}:
          do IO<Unit>:
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- recv_in_framed(s, b)
            ws_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], acc2, shut)
        case StepOut{out2}:
          +o2 = out2
          do IO<Unit>:
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- send_open_bytes((s, out_bytes(o2)))
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- recv_after(m2, buf)
            ws_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], acc, Bool.or(shut, U32.is_eq(out_op_of(o2), 8)))
    case _:
      IO.pure(Unit, Unit{})

@unsafe
def ws_hs(~H: WSEv -> IO(WSOut), st: U32, mr: Socket & Result<&1, &1, U32 & String, String>, mp: Result<&1, &1, U32 & String, String>, +acc: String, +fit: Bool, +ok: Bool) -> IO(Unit):
  match st:
    case 0:
      (s, r) = mr
      match r:
        case Fail{e}:
          Socket.close(s)
        case Done{part}:
          +acc2 = acc ++ part
          ws_hs(~H, 1, (s, Done{""}), Fail{(0, "")}, acc2, HTTP.has_blank(acc2), Nat.is_le(String.length(acc2), 16384n))
    case 1:
      (s, r) = mr
      match fit:
        case True{}:
          ws_hs(~H, 3, (s, Done{""}), handshake(acc), acc, fit, ok)
        case False{}:
          match ok:
            case True{}:
              do IO<Unit>:
                mr2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
                ws_hs(~H, 0, mr2, Fail{(0, "")}, acc, fit, ok)
            case False{}:
              Socket.close(s)
    case 3:
      (s, r) = mr
      match mp:
        case Fail{e}:
          Socket.close(s)
        case Done{resp}:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, resp)
            out : WSOut <- H(EvOpen{})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- hs_open(sent, out)
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- recv_after(m2, [])
            ws_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], FragIdle{}, False{})
    case _:
      IO.pure(Unit, Unit{})

def server_conn(~H: WSEv -> IO(WSOut), m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  do IO<Listener>:
    s : Socket <- IO.pass(Socket, r)
    IO.spawn(Unit, ws_hs(~H, 0, (s, Done{""}), Fail{(0, "")}, "", False{}, True{}))
    return l

@unsafe
def server_on(~H: WSEv -> IO(WSOut), l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    l2 : Listener <- server_conn(~H, m)
    z : Unit <- server_on(~H, l2)
    return z

# server_on_sub: same persistent server but negotiates Sec-WebSocket-Protocol.
# wanted lists the protocols the application supports; the handshake echoes
# the first overlap with the client's offer (or none when disjoint, per RFC
# the server may ignore). Plain server_on stays a Nil-wanted wrapper so old
# goldens never regress.

@unsafe
def ws_hs_sub(~H: WSEv -> IO(WSOut), st: U32, mr: Socket & Result<&1, &1, U32 & String, String>, mp: Result<&1, &1, U32 & String, String>, +acc: String, +fit: Bool, +ok: Bool, +wanted: List<&2, String>) -> IO(Unit):
  match st:
    case 0:
      (s, r) = mr
      match r:
        case Fail{e}:
          Socket.close(s)
        case Done{part}:
          +acc2 = acc ++ part
          +w = wanted
          ws_hs_sub(~H, 1, (s, Done{""}), Fail{(0, "")}, acc2, HTTP.has_blank(acc2), Nat.is_le(String.length(acc2), 16384n), w)
    case 1:
      (s, r) = mr
      match fit:
        case True{}:
          +a = acc
          +w = wanted
          ws_hs_sub(~H, 3, (s, Done{""}), handshake_sub(a, w), acc, fit, ok, wanted)
        case False{}:
          match ok:
            case True{}:
              +w = wanted
              do IO<Unit>:
                mr2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
                ws_hs_sub(~H, 0, mr2, Fail{(0, "")}, acc, fit, ok, w)
            case False{}:
              Socket.close(s)
    case 3:
      (s, r) = mr
      match mp:
        case Fail{e}:
          Socket.close(s)
        case Done{resp}:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, resp)
            out : WSOut <- H(EvOpen{})
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- hs_open(sent, out)
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- recv_after(m2, [])
            ws_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], FragIdle{}, False{})
    case _:
      IO.pure(Unit, Unit{})

def server_conn_sub(~H: WSEv -> IO(WSOut), m: Listener & Result<&1, &1, U32 & String, Socket>, +wanted: List<&2, String>) -> IO(Listener):
  (l, r) = m
  do IO<Listener>:
    s : Socket <- IO.pass(Socket, r)
    IO.spawn(Unit, ws_hs_sub(~H, 0, (s, Done{""}), Fail{(0, "")}, "", False{}, True{}, wanted))
    return l

@unsafe
def server_on_sub(~H: WSEv -> IO(WSOut), l: Listener, +wanted: List<&2, String>) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    l2 : Listener <- server_conn_sub(~H, m, wanted)
    z : Unit <- server_on_sub(~H, l2, wanted)
    return z

# Client echo (single Hi, fixed mask) for loopback tests.
# Returns Done{"Hi"} on exact echo, Fail otherwise. Closes always.
# Frames ride the byte lane; only the handshake request stays String.

def eq_bytes(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
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
          Bool.and(U32.is_eq(h1, h2), eq_bytes(t1, t2))

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

def client_echo_got_list(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +want: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{bs}:
      client_validated((s, eq_bytes(bs, want), "Hi"))

def client_echo_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +frame_txt: List<&2, U32>, +want: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, String>):
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

def client_hs_got(m: Socket & Result<&1, &1, U32 & String, String>, +frame_txt: List<&2, U32>, +want: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, String>):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- Socket.close(s)
        return Fail{e}
    case Done{hsresp}:
      do IO<Result<&1, &1, U32 & String, String>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, frame_txt)
        client_echo_sent(sent, frame_txt, want)

def client_req_sent(m: Socket & Result<&1, &1, U32 & String, Unit>, +frame_txt: List<&2, U32>, +want: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, String>):
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

def client_conn(conn: Result<&1, &1, U32 & String, Socket>, +req_txt: String, +frame_txt: List<&2, U32>, +want: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, String>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        client_req_sent(sent, frame_txt, want)

def client_frames_put(mres: Result<&1, &1, U32 & String, List<&2, U32>>, eres: Result<&1, &1, U32 & String, List<&2, U32>>) -> Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>:
  match mres:
    case Fail{e}:
      Fail{e}
    case Done{mbytes}:
      match eres:
        case Fail{e}:
          Fail{e}
        case Done{eby}:
          Done{(mbytes, eby)}

# The masked frame of the one-shot echo client: a fresh key per frame.
def client_frames(+msg: String) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  show_masked_random(True{}, 1, HTTP.encode(msg))

def client_go(+host: String, port: U32, +path: String, +key: String, +msg: String, req: String, frames: List<&2, U32> & List<&2, U32>) -> IO(Result<&1, &1, U32 & String, String>):
  (frame_txt, want) = frames
  do IO<Result<&1, &1, U32 & String, String>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    client_conn(conn, req, frame_txt, want)

def client_echo_go(+host: String, port: U32, +path: String, +key: String, +msg: String, +req_txt: String, frames: Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match frames:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{fr}:
      client_go(host, port, path, key, msg, req_txt, fr)

def client_echo_frame(+host: String, port: U32, +path: String, +key: String, +msg: String, +req_txt: String, +fb: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  client_echo_go(host, port, path, key, msg, req_txt, client_frames_put(Done{fb}, show_frame(True{}, 1, HTTP.encode(msg))))

def client_req_ok(+host: String, port: U32, +path: String, +key: String, +msg: String, req: Result<&1, &1, U32 & String, String>, frames: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Result<&1, &1, U32 & String, String>):
  match req:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{req_txt}:
      match frames:
        case Fail{e}:
          IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
        case Done{fb}:
          client_echo_frame(host, port, path, key, msg, req_txt, fb)

def client_echo(+host: String, port: U32, +path: String, +key: String, +msg: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    fr : Result<&1, &1, U32 & String, List<&2, U32>> <- client_frames(msg)
    client_req_ok(host, port, path, key, msg, client_request(host, path, key), fr)

# Client session (interop): masked sends with a fresh random key
# (WS.mask_key), unmasked recvs. The socket stays open across calls;
# the session driver closes it.

def client_send_bytes(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{bs}:
      TCP.send_bytes(s, bs)

def client_send_op(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    fr : Result<&1, &1, U32 & String, List<&2, U32>> <- show_masked_random(True{}, op, pay)
    client_send_bytes((s, fr))

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

# client_on: the generic persistent WS client, the mirror of server_on.
# The handler rides the same template (~H: WSEv -> IO(WSOut), baked at
# the call site as client_on~h). The handshake driver (client_hs, states
# 0/1/3) connects, sends client_request, accumulates the response head
# until the blank line under the same 16KB cap, and validates status 101
# plus Sec-WebSocket-Accept = accept_of(key); anything else emits one
# EvError and closes (the client must learn WHY it died, unlike the
# server, whose caller already saw the accept). On success it emits one
# EvOpen, sends the handler's WSOut masked (a fresh random key, like
# client_send_op) and enters the frame loop (client_loop, states 1/2):
# each complete server frame arrives unmasked via recv_in_client_framed
# with its rest threaded as the next buf, maps to one WSEv, and the
# handler's single WSOut goes out masked verbatim — EvPing without an
# OutOp answer falls back to pong, EvClose replies close and shuts,
# EvPong sends verbatim (OutRaw{[]} continues silently), EvError and a
# transport Fail report through the handler and close. The loop mirrors
# ws_loop with the mask sides swapped: the client sends masked and reads
# unmasked, so the dispatch lives in its own def, not behind a flag.

def client_out_bytes(out: WSOut, +key: WSMask) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match out:
    case OutMsg{msg}:
      +mm = msg
      show_masked_key(True{}, msg_to_op(mm), msg_to_bytes(mm), key)
    case OutOp{op, pay}:
      +oo = op
      +pp = pay
      show_masked_key(True{}, oo, out_op_pay(oo, pp), key)
    case OutRaw{bs}:
      Done{bs}

def client_out_bytes_random(out: WSOut) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    key : WSMask <- mask_key()
    IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, client_out_bytes(out, key))

def client_recv_after(m: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{u}:
      recv_in_client_framed(s, buf)

def client_proto_go(hs: List<&1, String & String>, +found: String, got: Bool) -> String & Bool:
  match hs:
    case Nil{}:
      (found, got)
    case (n, v) <> t:
      +is_p = HTTP.eq_ci(n, "Sec-WebSocket-Protocol")
      +vv = v
      client_proto_go(t, Bool.pick(String, is_p, String.trim(vv), found), Bool.or(got, is_p))

def client_proto_found(pair: String & Bool) -> Maybe<&2, String>:
  (found, got) = pair
  match got:
    case True{}:
      Some{found}
    case False{}:
      None{}

def client_proto_of(hs: List<&1, String & String>) -> Maybe<&2, String>:
  client_proto_found(client_proto_go(hs, "", False{}))

def client_proto_ok(proto: Maybe<&2, String>, +offered: List<&2, String>) -> Bool:
  match proto:
    case None{}:
      True{}
    case Some{p}:
      ws_list_contains(offered, p)

def client_check_end(+offered: List<&2, String>, +found: String, acc_ok: Bool, got: Bool) -> Bool:
  match got:
    case True{}:
      Bool.and(acc_ok, ws_list_contains(offered, found))
    case False{}:
      acc_ok

def client_check_go(hs: List<&1, String & String>, +want: String, +offered: List<&2, String>, acc_ok: Bool, +found: String, got: Bool) -> Bool:
  match hs:
    case Nil{}:
      client_check_end(offered, found, acc_ok, got)
    case (n, v) <> t:
      +nn = n
      +vv = v
      +nn2 = nn
      +vv2 = vv
      +want2 = want
      +off2 = offered
      +found2 = found
      client_check_go(t, want2, off2, Bool.or(acc_ok, Bool.and(HTTP.eq_ci(nn, "Sec-WebSocket-Accept"), String.eq(String.trim(vv), want))), Bool.pick(String, HTTP.eq_ci(nn2, "Sec-WebSocket-Protocol"), String.trim(vv2), found2), Bool.or(got, HTTP.eq_ci(nn, "Sec-WebSocket-Protocol")))

def client_ok_of_sub(st: U32, hs: List<&1, String & String>, +want: String, +offered: List<&2, String>) -> Bool:
  Bool.and(U32.is_eq(st, 101), client_check_go(hs, want, offered, False{}, "", False{}))

def client_acc.go(hs: List<&1, String & String>, +want: String, got: Bool) -> Bool:
  match hs:
    case Nil{}:
      got
    case (n, v) <> t:
      +hit = HTTP.eq_ci(n, "Sec-WebSocket-Accept")
      +acc = String.eq(String.trim(v), want)
      client_acc.go(t, want, Bool.or(got, Bool.and(hit, acc)))

def client_ok_of(st: U32, hs: List<&1, String & String>, +want: String) -> Bool:
  Bool.and(U32.is_eq(st, 101), client_acc.go(hs, want, False{}))

@unsafe
def client_loop(~H: WSEv -> IO(WSOut), st: U32, mf: Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, step: WsStep, +buf: List<&2, U32>, acc: MsgAcc, shut: Bool) -> IO(Unit):
  match st:
    case 1:
      (s, r, rest) = mf
      match r:
        case Fail{(c, m)}:
          match c:
            case 413:
              do IO<Unit>:
                f1 : Result<&1, &1, U32 & String, List<&2, U32>> <- client_out_bytes_random(cap_close_out())
                m2 : Socket & Result<&1, &1, U32 & String, Unit> <- client_send_bytes((s, f1))
                close_done(m2)
            case _:
              do IO<Unit>:
                out : WSOut <- H(EvError{c, m})
                x : Unit <- Socket.close(s)
                return x
        case Done{inn}:
          match inn:
            case InMsg{msg}:
              client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvMsg{msg}}, rest, FragIdle{}, shut)
            case InOp{fin, op, pay}:
              match op:
                case 8:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{close_ev(pay)}, rest, FragIdle{}, shut)
                case 9:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvPing{pay}}, rest, FragIdle{}, shut)
                case 10:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvPong{pay}}, rest, FragIdle{}, shut)
                case 0:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case 1:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case 2:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case _:
                  client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvError{400, "bad frame"}}, rest, FragIdle{}, shut)
    case 2:
      (s, r, b) = mf
      match step:
        case StepEv{ev}:
          match ev:
            case EvOpen{}:
              do IO<Unit>:
                out : WSOut <- H(EvOpen{})
                client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvMsg{msg}:
              do IO<Unit>:
                out : WSOut <- H(EvMsg{msg})
                client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvPing{pay}:
              +pp = pay
              do IO<Unit>:
                out : WSOut <- H(EvPing{pp})
                client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{ping_reply(pp, out)}, buf, acc, shut)
            case EvPong{pay}:
              do IO<Unit>:
                out : WSOut <- H(EvPong{pay})
                client_loop(~H, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvClose{pay}:
              match shut:
                case True{}:
                  Socket.close(s)
                case False{}:
                  +pp = pay
                  do IO<Unit>:
                    out : WSOut <- H(EvClose{pp})
                    f2 : Result<&1, &1, U32 & String, List<&2, U32>> <- client_out_bytes_random(close_answer(pp, out))
                    m2 : Socket & Result<&1, &1, U32 & String, Unit> <- client_send_bytes((s, f2))
                    close_done(m2)
            case EvError{code, msg}:
              do IO<Unit>:
                out : WSOut <- H(EvError{code, msg})
                x : Unit <- Socket.close(s)
                return x
        case StepFrag{acc2}:
          do IO<Unit>:
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- recv_in_client_framed(s, b)
            client_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], acc2, shut)
        case StepOut{out2}:
          +o2 = out2
          do IO<Unit>:
            f3 : Result<&1, &1, U32 & String, List<&2, U32>> <- client_out_bytes_random(o2)
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- client_send_bytes((s, f3))
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- client_recv_after(m2, buf)
            client_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], acc, Bool.or(shut, U32.is_eq(out_op_of(o2), 8)))
    case _:
      IO.pure(Unit, Unit{})

def client_hs.go(~H: WSEv -> IO(WSOut), s: Socket, ok: Bool, +want: String, +buf: List<&2, U32>) -> IO(Unit):
  match ok:
    case True{}:
      do IO<Unit>:
        out : WSOut <- H(EvOpen{})
        f4 : Result<&1, &1, U32 & String, List<&2, U32>> <- client_out_bytes_random(out)
        m2 : Socket & Result<&1, &1, U32 & String, Unit> <- client_send_bytes((s, f4))
        m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- client_recv_after(m2, buf)
        client_loop(~H, 1, m3, StepEv{EvError{0, ""}}, [], FragIdle{}, False{})
    case False{}:
      do IO<Unit>:
        out : WSOut <- H(EvError{400, "bad handshake"})
        x : Unit <- Socket.close(s)
        return x

# The client's response head rides the BYTE lane: the 101 and the
# server's first frame may coalesce in one segment, and a String recv
# would swallow the frame bytes (UTF-8 decoding mangles them; the frame
# loop then starves). client_scan_fit walks the accumulation for the
# \r\n\r\n window (last three bytes carried, the new byte closes it);
# client_scan_len answers the head's length including the terminator,
# so state 1 splits head from rest by index (take/drop) and the rest
# seeds the frame loop's buf — every byte read is consumed exactly
# once. The head is ASCII by RFC, so decode rebuilds the String and
# read_response parses it with the terminator glued back.

def client_scan_fit.go(bs: List<&2, U32>, w0: U32, w1: U32, w2: U32) -> Bool:
  match bs:
    case Nil{}:
      False{}
    case b <> t:
      +bb = b
      +w00 = w0
      +w11 = w1
      +w22 = w2
      +is_end = Bool.and(U32.is_eq(w00, 13), Bool.and(U32.is_eq(w11, 10), Bool.and(U32.is_eq(w22, 13), U32.is_eq(bb, 10))))
      Bool.pick(Bool, is_end, True{}, client_scan_fit.go(t, w11, w22, bb))

def client_scan_fit(bs: List<&2, U32>) -> Bool:
  client_scan_fit.go(bs, 0, 0, 0)

def client_scan_len.go(bs: List<&2, U32>, +n: U32, w0: U32, w1: U32, w2: U32) -> U32:
  match bs:
    case Nil{}:
      0
    case b <> t:
      +bb = b
      +w00 = w0
      +w11 = w1
      +w22 = w2
      +is_end = Bool.and(U32.is_eq(w00, 13), Bool.and(U32.is_eq(w11, 10), Bool.and(U32.is_eq(w22, 13), U32.is_eq(bb, 10))))
      Bool.pick(U32, is_end, (n + 1 : U32), client_scan_len.go(t, (n + 1 : U32), w11, w22, bb))

def client_scan_len(bs: List<&2, U32>) -> U32:
  client_scan_len.go(bs, 0, 0, 0, 0)

@unsafe
def client_hs(~H: WSEv -> IO(WSOut), st: U32, mr: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, mp: Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>, +acc: List<&2, U32>, +fit: Bool, +ok: Bool, +buf: List<&2, U32>, +want: String) -> IO(Unit):
  match st:
    case 0:
      (s, r) = mr
      match r:
        case Fail{(c, m)}:
          do IO<Unit>:
            out : WSOut <- H(EvError{c, m})
            x : Unit <- Socket.close(s)
            return x
        case Done{bs}:
          +acc2 = List.append(&2, U32, acc, bs)
          client_hs(~H, 1, (s, Done{Nil{}}), Fail{(0, "")}, acc2, client_scan_fit(acc2), Nat.is_le(List.length(&2, U32, acc2), 16384n), Nil{}, want)
    case 1:
      (s, r) = mr
      match fit:
        case True{}:
          +len = client_scan_len(acc)
          +taken = List.take(&2, U32, acc, U32.to_nat(len))
          +rest = List.drop(&2, U32, acc, U32.to_nat(len))
          client_hs(~H, 3, (s, Done{Nil{}}), HTTP.read_response(HTTP.decode(taken) ++ "\r\n\r\n"), acc, fit, ok, rest, want)
        case False{}:
          match ok:
            case True{}:
              do IO<Unit>:
                mr2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s, 8192)
                client_hs(~H, 0, mr2, Fail{(0, "")}, acc, fit, ok, buf, want)
            case False{}:
              do IO<Unit>:
                out : WSOut <- H(EvError{413, "head too large"})
                x : Unit <- Socket.close(s)
                return x
    case 3:
      (s, r) = mr
      match mp:
        case Fail{(c, m)}:
          do IO<Unit>:
            out : WSOut <- H(EvError{c, m})
            x : Unit <- Socket.close(s)
            return x
        case Done{parsed}:
          (st2, hs, body) = parsed
          client_hs.go(~H, s, client_ok_of(st2, hs, want), want, buf)
    case _:
      IO.pure(Unit, Unit{})

def client_start.ship(~H: WSEv -> IO(WSOut), m: Socket & Result<&1, &1, U32 & String, Unit>, +want: String) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{(c, m2)}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c, m2})
        x : Unit <- Socket.close(s)
        return x
    case Done{u}:
      do IO<Unit>:
        client_hs(~H, 0, (s, Done{Nil{}}), Fail{(0, "")}, Nil{}, False{}, True{}, Nil{}, want)

def client_start.yes(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, +want: String, +req_txt: String) -> IO(Unit):
  match conn:
    case Fail{(c, m)}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c, m})
        return Unit{}
    case Done{sock}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        client_start.ship(~H, sent, want)

def client_start.no(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, c: U32, +m: String) -> IO(Unit):
  match conn:
    case Fail{(c2, m2)}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c2, m2})
        return Unit{}
    case Done{sock}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c, m})
        x : Unit <- Socket.close(sock)
        return x

def client_start(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, +want: String, req: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match req:
    case Fail{(c, m)}:
      client_start.no(~H, conn, c, m)
    case Done{req_txt}:
      client_start.yes(~H, conn, want, req_txt)

def client_on(~H: WSEv -> IO(WSOut), +host: String, port: U32, +path: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    client_start(~H, conn, accept_of(key), client_request(host, path, key))

# client_on_sub: same persistent client but offers Sec-WebSocket-Protocol.
# protos lists the protocols the client offers; the server's choice is
# validated to be one of them (absent choice always ok). Plain client_on
# stays a Nil-offer wrapper.

@unsafe
def client_hs_sub(~H: WSEv -> IO(WSOut), st: U32, mr: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, mp: Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>, +acc: List<&2, U32>, +fit: Bool, +ok: Bool, +buf: List<&2, U32>, +want: String, +offered: List<&2, String>) -> IO(Unit):
  match st:
    case 0:
      (s, r) = mr
      match r:
        case Fail{(c, m)}:
          do IO<Unit>:
            out : WSOut <- H(EvError{c, m})
            x : Unit <- Socket.close(s)
            return x
        case Done{bs}:
          +acc2 = List.append(&2, U32, acc, bs)
          client_hs_sub(~H, 1, (s, Done{Nil{}}), Fail{(0, "")}, acc2, client_scan_fit(acc2), Nat.is_le(List.length(&2, U32, acc2), 16384n), Nil{}, want, offered)
    case 1:
      (s, r) = mr
      match fit:
        case True{}:
          +len = client_scan_len(acc)
          +taken = List.take(&2, U32, acc, U32.to_nat(len))
          +rest = List.drop(&2, U32, acc, U32.to_nat(len))
          client_hs_sub(~H, 3, (s, Done{Nil{}}), HTTP.read_response(HTTP.decode(taken) ++ "\r\n\r\n"), acc, fit, ok, rest, want, offered)
        case False{}:
          match ok:
            case True{}:
              do IO<Unit>:
                mr2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s, 8192)
                client_hs_sub(~H, 0, mr2, Fail{(0, "")}, acc, fit, ok, buf, want, offered)
            case False{}:
              do IO<Unit>:
                out : WSOut <- H(EvError{413, "head too large"})
                x : Unit <- Socket.close(s)
                return x
    case 3:
      (s, r) = mr
      match mp:
        case Fail{(c, m)}:
          do IO<Unit>:
            out : WSOut <- H(EvError{c, m})
            x : Unit <- Socket.close(s)
            return x
        case Done{parsed}:
          (st2, hs, body) = parsed
          client_hs.go(~H, s, client_ok_of_sub(st2, hs, want, offered), want, buf)
    case _:
      IO.pure(Unit, Unit{})

def client_start_sub.ship(~H: WSEv -> IO(WSOut), m: Socket & Result<&1, &1, U32 & String, Unit>, +want: String, +offered: List<&2, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{(c, m2)}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c, m2})
        x : Unit <- Socket.close(s)
        return x
    case Done{u}:
      do IO<Unit>:
        client_hs_sub(~H, 0, (s, Done{Nil{}}), Fail{(0, "")}, Nil{}, False{}, True{}, Nil{}, want, offered)

def client_start_sub.yes(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, +want: String, +offered: List<&2, String>, +req_txt: String) -> IO(Unit):
  match conn:
    case Fail{(c, m)}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c, m})
        return Unit{}
    case Done{sock}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        client_start_sub.ship(~H, sent, want, offered)

def client_start_sub.no(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, c: U32, +m: String) -> IO(Unit):
  match conn:
    case Fail{(c2, m2)}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c2, m2})
        return Unit{}
    case Done{sock}:
      do IO<Unit>:
        out : WSOut <- H(EvError{c, m})
        x : Unit <- Socket.close(sock)
        return x

def client_start_sub(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, +want: String, +offered: List<&2, String>, req: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match req:
    case Fail{(c, m)}:
      client_start_sub.no(~H, conn, c, m)
    case Done{req_txt}:
      client_start_sub.yes(~H, conn, want, offered, req_txt)

def client_on_sub(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +path: String, +key: String, +protos: List<&2, String>) -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    client_start_sub(~H, conn, accept_of(key), protos, client_request_sub(host, port, path, key, protos))
