# WSM: the WebSocket library for Bend (RFC 6455, ws:// + wss://) —
# handshake, frame codec and session loop, client and server, in one
# file. This is the whole WebSocket surface, not a standalone server
# next to another one: it supersedes lib/ws.bend and lib/wss.bend (still
# in the tree, no longer imported or published).
#
# Import as: import ./wsm.bend as WSM (from lib) or
# import ../../lib/wsm.bend as WSM (from tests/io and examples/).
#
# One module, one surface, two lanes, built on the HTTP library. The
# handshake rides the H1 upgrade lane: h1_open for TLS, TCP.connect +
# x_h1.cli.exch.open for cleartext, on_h1_open(+_plain) for the server;
# frames ride tls.bend / tcp.bend directly once ~K owns the socket.
# The codec (frames, mask, close, ping/pong, fragments) and the handshake
# live in this file, ported def by def and adapted to HTTP.Hdr; the H1
# text leaves (x_h1.split, x_h1.parse_hs, x_h1.render_req.go) come from
# ./http1.bend, and UTF-8 lives in the core (HTTP.x_utf8_*) with
# wsm_utf8_* wrappers.
#
# Imports: Base (prelude); ./httpx.bend as HTTPX (the upgrade and server
# entries); ./http1.bend as HTTP1 (the H1 text helpers and the open
# exchange); ./http.bend as HTTP (the types and the byte leaves);
# ./tls.bend as TLS and ./tcp.bend as TCPB (the two transports);
# ./sha1.bend as SHA1 and ./b64.bend as B64 (the leaf codecs behind
# Sec-WebSocket-Accept). No lanes, no HTTP text layer of its own.
#
# Surface: `server_on` (+ `_sub`, `_plain`) and `client_on` (+ `_sub`,
# `_plain`, `_insecure`) take one pure ~H over WSEv/WSOut; `client_echo`
# is the disposable round trip; `serve_once` serves one accepted socket;
# `wsm_session_open`, `wsm_recv_frame`, `wsm_recv_msg`, `wsm_send_open`
# and `wsm_send_bytes` are the lane templates underneath them, each one
# transport-agnostic (~recv / ~send / ~close).
#
# Types mirror lib/websocket/type.bend and lib/ws.bend under the same
# names, so the [mig] is a requalification, not a redesign: WSMessage
# (WSText / WSBin), WSOut (answers), WSIn (one read), WSEv (lifecycle),
# WsStep (loop carrier), MsgAcc (fragment reassembly), WSMask (client
# key). The incremental framing answer is HTTP.UnitOut itself (Got /
# NeedMore / End / Bad) — http.bend's TASK-026 mirror of CT.UnitOut,
# shared instead of redeclared: one question, one shape, the same answer
# the H1 chunked decoder gives.
#
# Discipline (same as lib/httpx.bend): callee above caller; match
# scrutinees are params or pattern-bound vars; self-recursion only,
# with a structurally shrinking argument; + binders only for Data.
# Streaming note: this module answers WSEv/WSOut only; the HTTP
# streaming families (HTTP.StreamEv/SrvEv) and CT.StreamEv/StreamOut
# of lib/core/type.bend are different contracts kept by decision
# (TASK-036) — do not look for them here.
import Base
import ./httpx.bend as HTTPX
import ./http.bend as HTTP
import ./tls.bend as TLS
import ./tcp.bend as TCPB
import ./sha1.bend as SHA1
import ./b64.bend as B64
import ./http1.bend as HTTP1

# Messages: WSText is UTF-8 String on the wire via wsm_utf8_encode /
# wsm_utf8_decode (this module's text lane, TASK-028 Phase 5.9);
# WSBin is raw bytes. Controls (8/9/10) and fragmented
# frames (FIN=False) stay outside WSMessage and Fail{400} on the msg
# path; the generic recv reports them as InOp.

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

# Fragment reassembly state (RFC 6455 section 5.4). FragIdle means no
# open fragment; FragOpen holds the leading opcode (1 text, 2 binary)
# plus the bytes stitched so far, REVERSED (same rev-body discipline
# as the HTTP lanes: per-fragment work stays O(frag) and the
# un-reverse happens once with x_cat at completion).

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

# Client masking key (RFC 6455 section 5.3): every client frame needs a
# fresh unpredictable key, never a constant. IO.random_u32 reads the
# host entropy pool, so two draws give 64 bits for the 32-bit field
# the RFC asks to be unpredictable. show_masked stays public for tests
# that want a fixed key on purpose.

type WSMask is Data:
  WSMask{k0: U32, k1: U32, k2: U32, k3: U32}

# UTF-8 (RFC 3629): WSText on the wire. The machine lives in httpx
# (HTTP.x_utf8_*, TASK-036 Phase 3) — this module keeps the wsm_utf8_*
# names as thin callers' vocabulary, one implementation, no fork.
# The H1 byte helpers in httpx (x_str_bytes/x_bytes_str) are ASCII-only
# (raw code points, one byte each) and feed the H1 renderers; real text
# rides x_utf8 here and in fetch/request bodies alike.
# ---------------------------------------------------------------------

def wsm_utf8_encode.go2(+code: U32) -> List<&2, U32>:
  HTTP.x_utf8_encode.go2(code)

def wsm_utf8_encode.go3(+code: U32) -> List<&2, U32>:
  HTTP.x_utf8_encode.go3(code)

def wsm_utf8_encode.go4(+code: U32) -> List<&2, U32>:
  HTTP.x_utf8_encode.go4(code)

def wsm_utf8_encode.big(code: U32, is2: Bool, is3: Bool) -> List<&2, U32>:
  HTTP.x_utf8_encode.big(code, is2, is3)

def wsm_utf8_encode.small(code: U32, is1: Bool, is2: Bool, is3: Bool) -> List<&2, U32>:
  HTTP.x_utf8_encode.small(code, is1, is2, is3)

def wsm_utf8_encode_char(+code: U32) -> List<&2, U32>:
  HTTP.x_utf8_encode_char(code)

def wsm_utf8_encode.one(c: Char) -> List<&2, U32>:
  HTTP.x_utf8_encode.one(c)

def wsm_utf8_encode(s: String) -> List<&2, U32>:
  HTTP.x_utf8_encode(s)

def wsm_utf8_is_cont(+b: U32) -> Bool:
  HTTP.x_utf8_is_cont(b)

def wsm_utf8_need(+b: U32) -> U32:
  HTTP.x_utf8_need(b)

def wsm_utf8_min(+need: U32) -> U32:
  HTTP.x_utf8_min(need)

def wsm_utf8_mask(+need: U32) -> U32:
  HTTP.x_utf8_mask(need)

def wsm_utf8_code_ok(+code: U32, +min: U32) -> Bool:
  HTTP.x_utf8_code_ok(code, min)

def wsm_utf8_fin2(+code2: U32, +min: U32) -> U32:
  HTTP.x_utf8_fin2(code2, min)

def wsm_utf8_fin(+code: U32, +min: U32, +b: U32) -> U32:
  HTTP.x_utf8_fin(code, min, b)

def wsm_utf8_go(+bs: List<&2, U32>, +need: U32, +min: U32, +code: U32) -> Bool:
  HTTP.x_utf8_go(bs, need, min, code)

def wsm_utf8_ok(bs: List<&2, U32>) -> Bool:
  HTTP.x_utf8_ok(bs)

# need 8 is the ASCII fast path (emit the byte carried in code) and
# need 7 is a fresh lead byte (step the machine on the carried byte) —
# both keep one self-recursive def with a shrinking tail.
# need 8 is pending ASCII (emit on the next step): bytes under 128 must
# not enter the multi-byte machine, which would swallow them. Every arm
# shrinks the tail, so this stays one self-recursive def.
# The whole-message decode is the tail decoder (x_utf8_decode), like
# the HTTP body lane. Incremental validation rides wsm_utf8_ok, which
# never holds more than one frame.
def wsm_utf8_decode(bs: List<&2, U32>) -> String:
  HTTP.x_utf8_decode(bs)

# Small pure helpers (the ones the old tree spread over HTTP/UTILS/CORE;
# each is a few lines, so they live here instead of growing imports).
# ---------------------------------------------------------------------

def wsm_eq_ci(a: String, b: String) -> Bool:
  String.eq(String.to_lower(a), String.to_lower(b))

def wsm_has_crlf.go(cs: List<&2, Char>) -> Bool:
  match cs:
    case Nil{}:
      False{}
    case Chr{+code} <> t:
      Bool.or(Bool.or(U32.is_eq(code, 13), U32.is_eq(code, 10)), wsm_has_crlf.go(t))

def wsm_has_crlf(+s: String) -> Bool:
  wsm_has_crlf.go(String.to_list(s))

# Big-endian word from four bytes (the one helper the old codec took
# from SHA1.bytes_of_word's twin word_of4; httpx only kept the
# constructor x_be32, so the projection lives here).
def wsm_word_of4(+b0: U32, +b1: U32, +b2: U32, +b3: U32) -> U32:
  (b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 : U32)


# Handshake (pure): key validation, Upgrade/Connection/Version scan,
# Sec-WebSocket-Accept, and the client request — over httpx.Request /
# Hdr, never over raw head text (the H1 lane owns the bytes now).
# ---------------------------------------------------------------------

def wsm_guid() -> String:
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def wsm_is_b64(+code: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(code, 65), U32.is_le(code, 90)), Bool.or(Bool.and(U32.is_ge(code, 97), U32.is_le(code, 122)), Bool.or(Bool.and(U32.is_ge(code, 48), U32.is_le(code, 57)), Bool.or(U32.is_eq(code, 43), U32.is_eq(code, 47)))))

def wsm_b64_char_ok(c: Char) -> Bool:
  match c:
    case Chr{code}:
      wsm_is_b64(code)

def wsm_b64_list_ok(cs: List<&2, Char>) -> Bool:
  match cs:
    case Nil{}:
      True{}
    case h <> t:
      Bool.and(wsm_b64_char_ok(h), wsm_b64_list_ok(t))

def wsm_key_ok(+key: String) -> Bool:
  +trimmed = String.trim(key)
  +head22 = String.take(trimmed, 22n)
  Bool.and(Nat.is_eq(String.length(trimmed), 24n), Bool.and(String.ends_with(trimmed, "=="), wsm_b64_list_ok(String.to_list(head22))))

def wsm_conn_tok_ok(+tok: String) -> Bool:
  String.eq(String.to_lower(String.trim(tok)), "upgrade")

def wsm_conn_list_ok(toks: List<&2, String>) -> Bool:
  match toks:
    case Nil{}:
      False{}
    case h <> t:
      +hh = h
      Bool.or(wsm_conn_tok_ok(hh), wsm_conn_list_ok(t))

def wsm_conn_has_upgrade(+val: String) -> Bool:
  wsm_conn_list_ok(String.split(val, ','))

def wsm_trim_nonempty(+tok: String) -> Bool:
  Bool.not(String.is_empty(String.trim(tok)))

def wsm_proto_cons(+trimmed: String, +rest: List<&2, String>, keep: Bool) -> List<&2, String>:
  match keep:
    case True{}:
      trimmed <> rest
    case False{}:
      rest

def wsm_trim_protos(toks: List<&2, String>) -> List<&2, String>:
  match toks:
    case Nil{}:
      Nil{}
    case h <> t:
      +hh = h
      +trimmed = String.trim(hh)
      wsm_proto_cons(trimmed, wsm_trim_protos(t), wsm_trim_nonempty(hh))

def wsm_protos_of(+val: String) -> List<&2, String>:
  wsm_trim_protos(String.split(val, ','))

def wsm_list_contains(xs: List<&2, String>, +item: String) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case h <> t:
      +hh = h
      +it = item
      Bool.or(String.eq(hh, it), wsm_list_contains(t, it))

def wsm_pick_go(+served: List<&2, String>, +client: List<&2, String>) -> Maybe<&2, String>:
  match served:
    case Nil{}:
      None{}
    case h <> t:
      +hh = h
      +tt = t
      +cc = client
      +hh2 = hh
      +cc2 = cc
      Bool.pick(Maybe<&2, String>, wsm_list_contains(cc, hh), Some{hh2}, wsm_pick_go(tt, cc2))

def wsm_pick_sub(+client: List<&2, String>, +served: List<&2, String>) -> Maybe<&2, String>:
  wsm_pick_go(served, client)

def wsm_scan_proto_add(+acc: List<&2, String>, +val: String, is_proto: Bool) -> List<&2, String>:
  match is_proto:
    case True{}:
      List.append(&2, String, acc, wsm_protos_of(val))
    case False{}:
      acc

def wsm_scan_go(hs: List<&2, HTTP.Hdr>, +key_acc: String, up_ok: Bool, ver_ok: Bool, conn_ok: Bool) -> String & Bool:
  match hs:
    case Nil{}:
      (key_acc, Bool.and(up_ok, Bool.and(ver_ok, Bool.and(conn_ok, wsm_key_ok(key_acc)))))
    case HTTP.Hdr{name, value} <> t:
      +nn = name
      +vv = value
      +tv = String.trim(vv)
      +low = String.to_lower(String.trim(vv))
      wsm_scan_go(t, Bool.pick(String, wsm_eq_ci(nn, "Sec-WebSocket-Key"), tv, key_acc), Bool.or(up_ok, Bool.and(wsm_eq_ci(nn, "Upgrade"), String.eq(low, "websocket"))), Bool.or(ver_ok, Bool.and(wsm_eq_ci(nn, "Sec-WebSocket-Version"), String.eq(tv, "13"))), Bool.or(conn_ok, Bool.and(wsm_eq_ci(nn, "Connection"), wsm_conn_has_upgrade(vv))))

def wsm_scan(hs: List<&2, HTTP.Hdr>) -> String & Bool:
  wsm_scan_go(hs, "", False{}, False{}, False{})

def wsm_scan_full_go(hs: List<&2, HTTP.Hdr>, +key_acc: String, up_ok: Bool, ver_ok: Bool, conn_ok: Bool, +proto_acc: List<&2, String>) -> String & Bool & List<&2, String>:
  match hs:
    case Nil{}:
      (key_acc, Bool.and(up_ok, Bool.and(ver_ok, Bool.and(conn_ok, wsm_key_ok(key_acc)))), proto_acc)
    case HTTP.Hdr{name, value} <> t:
      +nn = name
      +vv = value
      +tv = String.trim(vv)
      +low = String.to_lower(String.trim(vv))
      +nn2 = nn
      +nn3 = nn
      +nn4 = nn
      +vv2 = vv
      +vv3 = vv
      +nn5 = nn
      +vv4 = vv
      wsm_scan_full_go(t, Bool.pick(String, wsm_eq_ci(nn, "Sec-WebSocket-Key"), tv, key_acc), Bool.or(up_ok, Bool.and(wsm_eq_ci(nn2, "Upgrade"), String.eq(low, "websocket"))), Bool.or(ver_ok, Bool.and(wsm_eq_ci(nn3, "Sec-WebSocket-Version"), String.eq(tv, "13"))), Bool.or(conn_ok, Bool.and(wsm_eq_ci(nn4, "Connection"), wsm_conn_has_upgrade(vv2))), wsm_scan_proto_add(proto_acc, vv3, wsm_eq_ci(nn5, "Sec-WebSocket-Protocol")))

def wsm_scan_full(hs: List<&2, HTTP.Hdr>) -> String & Bool & List<&2, String>:
  wsm_scan_full_go(hs, "", False{}, False{}, False{}, Nil{})

def wsm_accept_of(+key: String) -> String:
  +trimmed = String.trim(key)
  +joined = trimmed ++ wsm_guid()
  B64.encode(SHA1.sha1(wsm_utf8_encode(joined)))

def wsm_accept_hdrs(+accept: String) -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", accept}]

def wsm_accept_hdrs_sub(+accept: String, +proto: String) -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", accept}, HTTP.Hdr{"Sec-WebSocket-Protocol", proto}]

def wsm_valid_headers(+key: String, ok: Bool) -> Result<&1, &1, U32 & String, String>:
  match ok:
    case True{}:
      Done{key}
    case False{}:
      Fail{(400, "bad headers")}

def wsm_valid_method(+key: String, headers_ok: Bool, is_get: Bool) -> Result<&1, &1, U32 & String, String>:
  match is_get:
    case True{}:
      wsm_valid_headers(key, headers_ok)
    case False{}:
      Fail{(400, "bad method")}

def wsm_validate.go(+m: String, pair: String & Bool) -> Result<&1, &1, U32 & String, String>:
  (key, ok) = pair
  wsm_valid_method(key, ok, String.eq(m, "GET"))

def wsm_validate(+m: String, hs: List<&2, HTTP.Hdr>) -> Result<&1, &1, U32 & String, String>:
  wsm_validate.go(m, wsm_scan(hs))

def wsm_valid_sub.go(+key: String, ok: Bool, +cprotos: List<&2, String>, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String & Maybe<&2, String>>:
  match ok:
    case True{}:
      Done{(key, wsm_pick_sub(cprotos, wanted))}
    case False{}:
      Fail{(400, "bad headers")}

def wsm_validate_sub.method(+key: String, ok: Bool, +cprotos: List<&2, String>, +wanted: List<&2, String>, is_get: Bool) -> Result<&1, &1, U32 & String, String & Maybe<&2, String>>:
  match is_get:
    case True{}:
      wsm_valid_sub.go(key, ok, cprotos, wanted)
    case False{}:
      Fail{(400, "bad method")}

def wsm_validate_sub.go(+m: String, trio: String & Bool & List<&2, String>, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String & Maybe<&2, String>>:
  (key, ok, cprotos) = trio
  wsm_validate_sub.method(key, ok, cprotos, wanted, String.eq(m, "GET"))

def wsm_validate_sub(+m: String, hs: List<&2, HTTP.Hdr>, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String & Maybe<&2, String>>:
  wsm_validate_sub.go(m, wsm_scan_full(hs), wanted)

# The client request is an httpx.Request, not head text: the lane renders
# it (and keeps the handshake headers via upgrade=True). Host never rides
# the Request — the lane injects it from the dial params, and its
# bad_char covers method/path/host at send time — so key and protos are
# the only CRLF checks left here: Fail 400 before any byte leaves.
def wsm_bad_req(+path: String, +key: String) -> Bool:
  Bool.or(wsm_has_crlf(path), wsm_has_crlf(key))

def wsm_protos_bad(protos: List<&2, String>) -> Bool:
  match protos:
    case Nil{}:
      False{}
    case h <> t:
      +hh = h
      Bool.or(wsm_has_crlf(hh), wsm_protos_bad(t))

def wsm_client_req.go(+path: String, +key: String, bad: Bool) -> Result<&1, &1, U32 & String, HTTP.Request>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      Done{HTTP.Request{"GET", path, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Key", key}, HTTP.Hdr{"Sec-WebSocket-Version", "13"}], Nil{}}}

def wsm_client_request(+path: String, +key: String) -> Result<&1, &1, U32 & String, HTTP.Request>:
  wsm_client_req.go(path, key, wsm_bad_req(path, key))

def wsm_has_proto(protos: List<&2, String>) -> Bool:
  match protos:
    case Nil{}:
      False{}
    case _ <> _:
      True{}

def wsm_proto_join(+protos: List<&2, String>) -> String:
  String.join(protos, ", ")

def wsm_client_req_sub.hs(+path: String, +key: String, +protos: List<&2, String>, has_any: Bool) -> Result<&1, &1, U32 & String, HTTP.Request>:
  match has_any:
    case True{}:
      Done{HTTP.Request{"GET", path, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Key", key}, HTTP.Hdr{"Sec-WebSocket-Protocol", wsm_proto_join(protos)}, HTTP.Hdr{"Sec-WebSocket-Version", "13"}], Nil{}}}
    case False{}:
      Done{HTTP.Request{"GET", path, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Key", key}, HTTP.Hdr{"Sec-WebSocket-Version", "13"}], Nil{}}}

def wsm_client_req_sub.go(+path: String, +key: String, +protos: List<&2, String>, bad: Bool) -> Result<&1, &1, U32 & String, HTTP.Request>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      wsm_client_req_sub.hs(path, key, protos, wsm_has_proto(protos))

def wsm_client_request_sub(+path: String, +key: String, +protos: List<&2, String>) -> Result<&1, &1, U32 & String, HTTP.Request>:
  wsm_client_req_sub.go(path, key, protos, Bool.or(wsm_bad_req(path, key), wsm_protos_bad(protos)))

# Text entry points (pure, TASK-028 Phase 5.5): head text in, head text
# out. They exist for the tests, examples and the old ws.bend API that
# speak the handshake as String — NOT because the lane needs them: the
# lanes use the Hdr/Request defs above. Composition, not fork: the raw
# head is parsed by the H1 lane (x_h1.split -> head_lines ->
# req_tok/parse_hs) and the 101 is rendered by the H1 lane
# (x_h1.show_resp_head), so the tree still has one parser and one
# renderer. The client side is the same: wsm_client_head renders through
# x_h1.render_req.go with upgrade=True.
#
# NOT here, on purpose: host_port (the lane renders the Host, always
# host:port — a second formatter would be a second source of truth) and
# scan_len (the lane splits the head and hands the caller the rest; a
# WSM-side rescan would invite the take/drop reconstruction that the
# upgrade lane deleted).
# ---------------------------------------------------------------------

def wsm_text_parse_req(tok: Result<&1, &1, U32 & String, String & String & String & Bool>, hs: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>) ->
  Result<&1, &1, U32 & String, String & List<&2, HTTP.Hdr>>:
  match tok:
    case Fail{e}:
      Fail{e}
    case Done{quad}:
      (m, p, v, ok) = quad
      match hs:
        case Fail{e2}:
          Fail{e2}
        case Done{headers}:
          Bool.pick(Result<&1, &1, U32 & String, String & List<&2, HTTP.Hdr>>, ok, Done{(m, headers)}, Fail{(400, "bad request line")})

def wsm_text_hs_of(raw: String) -> Result<&1, &1, U32 & String, String & List<&2, HTTP.Hdr>>:
  split = HTTP1.x_h1.split(HTTP.x_str_bytes(raw))
  head = HTTP1.x_h1.split_head(split)
  +lines = HTTP1.x_h1.head_lines(head)
  wsm_text_parse_req(HTTP1.x_h1.req_tok(String.split(HTTP1.x_h1.first_line(lines), ' ')), HTTP1.x_h1.parse_hs(HTTP1.x_h1.rest_lines(lines)))

def wsm_text_validate.go(r: Result<&1, &1, U32 & String, String & List<&2, HTTP.Hdr>>) -> Result<&1, &1, U32 & String, String>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{pair}:
      (m, hs) = pair
      wsm_validate(m, hs)

def wsm_text_validate(raw: String) -> Result<&1, &1, U32 & String, String>:
  wsm_text_validate.go(wsm_text_hs_of(raw))

def wsm_text_validate_sub.go(r: Result<&1, &1, U32 & String, String & List<&2, HTTP.Hdr>>, +wanted: List<&2, String>) ->
  Result<&1, &1, U32 & String, String & Maybe<&2, String>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{pair}:
      (m, hs) = pair
      wsm_validate_sub(m, hs, wanted)

def wsm_text_validate_sub(raw: String, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String & Maybe<&2, String>>:
  wsm_text_validate_sub.go(wsm_text_hs_of(raw), wanted)

def wsm_text_accept(+accept: String) -> List<&2, U32>:
  HTTP1.x_h1.show_resp_head(101, wsm_accept_hdrs(accept))

def wsm_text_accept_sub(pick: Maybe<&2, String>, +accept: String) -> List<&2, U32>:
  match pick:
    case Some{p}:
      HTTP1.x_h1.show_resp_head(101, wsm_accept_hdrs_sub(accept, p))
    case None{}:
      wsm_text_accept(accept)

# The rendered head is never empty (status line alone is longer), so the
# guard is a fail-closed shape, not a size check.
def wsm_text_str(+bs: List<&2, U32>) -> Result<&1, &1, U32 & String, String>:
  match bs:
    case Nil{}:
      Fail{(400, "no response")}
    case b <> t:
      Done{HTTP.x_bytes_str(bs)}

def wsm_text_key.go(r: Result<&1, &1, U32 & String, String>) -> Result<&1, &1, U32 & String, String>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{key}:
      wsm_text_str(wsm_text_accept(wsm_accept_of(key)))

def wsm_text_key_sub.go(r: Result<&1, &1, U32 & String, String & Maybe<&2, String>>) -> Result<&1, &1, U32 & String, String>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{pair}:
      (key, pick) = pair
      wsm_text_str(wsm_text_accept_sub(pick, wsm_accept_of(key)))

# show_101* render an accept the CALLER computed (that is the point: a
# test pins a known key/accept pair and reads back the exact 101 head).
# The handshake* family below derives it from the request's own
# Sec-WebSocket-Key instead. Keeping the two apart is the whole fix for
# "show_101_sub silently ignores the accept it was given".
def wsm_show_101(+accept: String) -> Result<&1, &1, U32 & String, String>:
  wsm_text_str(wsm_text_accept(accept))

def wsm_show_101_sub(+accept: String, proto: Maybe<&2, String>) -> Result<&1, &1, U32 & String, String>:
  wsm_text_str(wsm_text_accept_sub(proto, accept))

def wsm_handshake(raw: String) -> Result<&1, &1, U32 & String, String>:
  wsm_text_key.go(wsm_text_validate(raw))

def wsm_handshake_sub(raw: String, +wanted: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  wsm_text_key_sub.go(wsm_text_validate_sub(raw, wanted))

def wsm_client_head.render_bytes(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> Result<&1, &1, U32 & String, String>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{bs}:
      Done{HTTP.x_bytes_str(bs)}

def wsm_client_head.render(+method: String, +path: String, +host: String, +port: U32, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String>:
  wsm_client_head.render_bytes(HTTP1.x_h1.render_req.go(True{}, False{}, method, path, host, port, hs, body))

def wsm_client_head.go(r: Result<&1, &1, U32 & String, HTTP.Request>, +host: String, +port: U32) -> Result<&1, &1, U32 & String, String>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{req}:
      match req:
        case HTTP.Request{method, path, headers, body}:
          wsm_client_head.render(method, path, host, port, headers, body)

def wsm_client_head(+host: String, +port: U32, +path: String, +key: String) -> Result<&1, &1, U32 & String, String>:
  wsm_client_head.go(wsm_client_request(path, key), host, port)

def wsm_client_head_sub(+host: String, +port: U32, +path: String, +key: String, +protos: List<&2, String>) -> Result<&1, &1, U32 & String, String>:
  wsm_client_head.go(wsm_client_request_sub(path, key, protos), host, port)

# Client-side 101 validation over the lane's parsed Response: status 101
# plus the Accept echoing accept_of(key) (plus the subprotocol pick for
# _sub). Fail-closed, like the old client_ok_of over head text.
def wsm_client_acc.go(hs: List<&2, HTTP.Hdr>, +want: String, got: Bool) -> Bool:
  match hs:
    case Nil{}:
      got
    case HTTP.Hdr{name, value} <> t:
      +nn = name
      +vv = value
      +hit = wsm_eq_ci(nn, "Sec-WebSocket-Accept")
      +acc = String.eq(String.trim(vv), want)
      wsm_client_acc.go(t, want, Bool.or(got, Bool.and(hit, acc)))

def wsm_client_ok(+status: U32, hs: List<&2, HTTP.Hdr>, +want: String) -> Bool:
  Bool.and(U32.is_eq(status, 101), wsm_client_acc.go(hs, want, False{}))

def wsm_client_check_end(+offered: List<&2, String>, +found: String, acc_ok: Bool, got: Bool) -> Bool:
  match got:
    case True{}:
      Bool.and(acc_ok, wsm_list_contains(offered, found))
    case False{}:
      acc_ok

def wsm_client_check_go(hs: List<&2, HTTP.Hdr>, +want: String, +offered: List<&2, String>, acc_ok: Bool, +found: String, got: Bool) -> Bool:
  match hs:
    case Nil{}:
      wsm_client_check_end(offered, found, acc_ok, got)
    case HTTP.Hdr{name, value} <> t:
      +nn = name
      +vv = value
      +nn2 = nn
      +vv2 = vv
      +want2 = want
      +off2 = offered
      +found2 = found
      wsm_client_check_go(t, want2, off2, Bool.or(acc_ok, Bool.and(wsm_eq_ci(nn, "Sec-WebSocket-Accept"), String.eq(String.trim(vv), want))), Bool.pick(String, wsm_eq_ci(nn2, "Sec-WebSocket-Protocol"), String.trim(vv2), found2), Bool.or(got, wsm_eq_ci(nn, "Sec-WebSocket-Protocol")))

def wsm_client_ok_sub(+status: U32, hs: List<&2, HTTP.Hdr>, +want: String, +offered: List<&2, String>) -> Bool:
  Bool.and(U32.is_eq(status, 101), wsm_client_check_go(hs, want, offered, False{}, "", False{}))

# Pure compatibility defs (TASK-028 Phase 5.7): names the retired
# lib/ws.bend exposed and the importers still call. They are callers'
# vocabulary, not lane internals — each one reuses the def that owns the
# rule instead of reimplementing it.

# Head length up to and including the CRLFCRLF terminator. Reuse: the H1
# split owns the scan (and the found-at-the-end fix of TASK-026 Phase
# 7b); a second scanner here is what the upgrade lane deleted. Not-found
# answers 0 like the retired lane (TASK-036: split_head alone would
# answer len(buf); the found guard keeps the old contract).
def client_scan_len.go(p: List<&2, U32> & List<&2, U32> & Bool) -> U32:
  match p:
    case (h, r, f):
      match f:
        case True{}:
          U32.from_nat(List.length(&2, U32, h))
        case False{}:
          0

def client_scan_len(bs: List<&2, U32>) -> U32:
  client_scan_len.go(HTTP1.x_h1.split(bs))

# Fit twin of the length above: True iff the head terminator is present.
# Reuse: the same H1 split (one scan, one window constant) instead of a
# second 4-byte scanner; compat-only, no live lane calls it.
def client_scan_fit(bs: List<&2, U32>) -> Bool:
  HTTP1.x_h1.split_found(HTTP1.x_h1.split(bs))

# Host header of the RETIRED lane: the default port (80/443) is omitted.
# The WSM wire always renders host:port (the H1 renderer owns the Host,
# pinned by httpx_h1_upgrade_client with Host: h:80), so this formatter
# is caller vocabulary only — do not use it to build a WSM request.
def ws_host_port_go(+host: String, +port: U32, is_def: Bool) -> String:
  Bool.pick(String, is_def, host, host ++ ":" ++ U32.show(port))

def ws_host_port(+host: String, +port: U32) -> String:
  ws_host_port_go(host, port, Bool.or(U32.is_eq(port, 80), U32.is_eq(port, 443)))

# Frame codec (pure): parse and render both ways, mask, message layer,
# strict UTF-8, close-code rules, fragment reassembly, incremental split.
# Ported from the old lane and adapted: WST.* gone (own types above),
# H1.h1_encode/decode is HTTP.x_utf8_encode/decode, SHA1.bytes_of_word is
# HTTP.x_be32, SHA1.word_of4 is wsm_word_of4, UTILS.len_upto is
# HTTP.x_len_upto, and the split answer is HTTP.UnitOut.
# ---------------------------------------------------------------------

def wsm_op_text() -> U32:
  1

def wsm_op_bin() -> U32:
  2

def wsm_op_close() -> U32:
  8

def wsm_op_ping() -> U32:
  9

def wsm_op_pong() -> U32:
  10

def wsm_out_ping(+pay: List<&2, U32>) -> WSOut:
  OutOp{wsm_op_ping(), pay}

def wsm_out_pong(+pay: List<&2, U32>) -> WSOut:
  OutOp{wsm_op_pong(), pay}

def wsm_out_close(+pay: List<&2, U32>) -> WSOut:
  OutOp{wsm_op_close(), pay}

def wsm_ping_reply.go(+pay: List<&2, U32>, +bs: List<&2, U32>) -> WSOut:
  match bs:
    case Nil{}:
      wsm_out_pong(pay)
    case _ <> _:
      OutRaw{bs}

def wsm_ping_reply(+pay: List<&2, U32>, out: WSOut) -> WSOut:
  match out:
    case OutOp{op, pp}:
      OutOp{op, pp}
    case OutMsg{msg}:
      wsm_out_pong(pay)
    case OutRaw{bs}:
      wsm_ping_reply.go(pay, bs)

# Wire denormalization for close echoes: our normalized empty (1005)
# must never reach the wire (RFC 6455 forbids 1005/1006/1015 on the
# wire), so answers to it go out empty; every other code echoes.

def wsm_close_is_1005(+pay: List<&2, U32>) -> Bool:
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

def wsm_close_wire_of.go(+pay: List<&2, U32>, deny: Bool) -> List<&2, U32>:
  match deny:
    case True{}:
      []
    case False{}:
      pay

def wsm_close_wire_of(+pay: List<&2, U32>) -> List<&2, U32>:
  wsm_close_wire_of.go(pay, wsm_close_is_1005(pay))

# Send-side guard: a handler echoing a normalized empty close would
# otherwise put 1005 on the wire through the verbatim OutOp path, and
# the peer would fail the close with 1006. Only close frames carrying
# our internal 1005 marker are rewritten to empty; every other opcode
# and payload rides untouched.

def wsm_out_op_pay.go(+pay: List<&2, U32>, keep: Bool) -> List<&2, U32>:
  match keep:
    case True{}:
      pay
    case False{}:
      []

def wsm_out_op_pay(+op: U32, +pay: List<&2, U32>) -> List<&2, U32>:
  wsm_out_op_pay.go(pay, Bool.or(Bool.not(U32.is_eq(op, 8)), Bool.not(wsm_close_is_1005(pay))))

def wsm_close_answer(+pay: List<&2, U32>, out: WSOut) -> WSOut:
  match out:
    case OutOp{op, pp}:
      OutOp{op, pp}
    case OutMsg{msg}:
      wsm_out_close(wsm_close_wire_of(pay))
    case OutRaw{bs}:
      wsm_out_close(wsm_close_wire_of(pay))

def wsm_msg_to_op(msg: WSMessage) -> U32:
  match msg:
    case WSText{text}:
      1
    case WSBin{data}:
      2

def wsm_msg_to_bytes(msg: WSMessage) -> List<&2, U32>:
  match msg:
    case WSText{text}:
      wsm_utf8_encode(text)
    case WSBin{data}:
      data

# Largest single-frame payload accepted on the wire (16MB). Both the
# masked and unmasked splits and both show paths enforce it; the
# reassembly accumulator enforces the same bound on the stitched
# message (see wsm_frag_acc below).
def wsm_max_payload() -> U32:
  16777216

def wsm_msg_of_frame.go2(is_text: Bool, is_bin: Bool, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  match is_text is_bin:
    case True{} True{}:
      Done{WSText{wsm_utf8_decode(pay)}}
    case True{} False{}:
      Done{WSText{wsm_utf8_decode(pay)}}
    case False{} True{}:
      Done{WSBin{pay}}
    case False{} False{}:
      Fail{(400, "not data")}

def wsm_msg_of_frame.go(fin: Bool, is_text: Bool, is_bin: Bool, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  match fin:
    case True{}:
      wsm_msg_of_frame.go2(is_text, is_bin, pay)
    case False{}:
      Fail{(400, "fragmented")}

def wsm_msg_of_frame(fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  wsm_msg_of_frame.go(fin, U32.is_eq(op, 1), U32.is_eq(op, 2), pay)

# Close payload validation (RFC 6455 section 5.5.1): empty or a 2-byte
# big-endian status code plus a UTF-8 reason. Empty normalizes to the
# 1005 wire form so the application always sees a code; reserved codes
# (under 1000, 1004-1006, 1015, 1016-2999, past 4999) fail 1002 and a
# non-UTF-8 reason fails 1007.

def wsm_close_in1000(+code: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(code, 1000), U32.is_le(code, 1011)), Bool.and(U32.is_ge(code, 3000), U32.is_le(code, 4999)))

def wsm_close_reserved(+code: U32) -> Bool:
  Bool.or(Bool.or(U32.is_eq(code, 1004), U32.is_eq(code, 1005)), Bool.or(U32.is_eq(code, 1006), U32.is_eq(code, 1015)))

def wsm_close_code_ok(+code: U32) -> Bool:
  Bool.and(wsm_close_in1000(code), Bool.not(wsm_close_reserved(code)))

def wsm_close_reason.go(+pay: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      Done{pay}
    case False{}:
      Fail{(1007, "bad close reason")}

def wsm_close_reason(+pay: List<&2, U32>, +reason: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  wsm_close_reason.go(pay, wsm_utf8_ok(reason))

def wsm_close_code.go(+pay: List<&2, U32>, +reason: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      wsm_close_reason(pay, reason)
    case False{}:
      Fail{(1002, "bad close code")}

def wsm_close_code(+pay: List<&2, U32>, +code: U32, +reason: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  wsm_close_code.go(pay, reason, wsm_close_code_ok(code))

def wsm_close_hi(+pay: List<&2, U32>, +hi: U32, +t: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match t:
    case Nil{}:
      Fail{(1002, "short close")}
    case lo <> reason:
      wsm_close_code(pay, (hi * 256 + lo : U32), reason)

def wsm_close_norm(+pay: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match pay:
    case Nil{}:
      Done{[3, 237]}
    case hi <> t:
      wsm_close_hi(pay, hi, t)

def wsm_close_ev.go(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> WSEv:
  match r:
    case Fail{(c, m)}:
      EvError{c, m}
    case Done{norm}:
      EvClose{norm}

def wsm_close_ev(+pay: List<&2, U32>) -> WSEv:
  wsm_close_ev.go(wsm_close_norm(pay))

# Fragment reassembly (RFC 6455 section 5.4): wsm_frag_step folds one data
# frame (op 1/2 to open, 0 to continue) into the accumulator. A leading
# frame with FIN set emits at once; otherwise bytes stitch until FIN
# and only the stitched message emits (text validated as UTF-8 at
# completion, since a code point may straddle fragments). An orphan
# continuation or a new data frame mid-reassembly fails 400; anything
# past wsm_max_payload fails 413 so the loops can answer close 1009.
# Control frames never reach this fold; the loops emit them at once.

def wsm_frag_capped(+buf: List<&2, U32>) -> Bool:
  U32.is_le(HTTP.x_len32(buf), wsm_max_payload())

def wsm_frag_text.go(+buf: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, WSMessage>:
  match ok:
    case True{}:
      Done{WSText{wsm_utf8_decode(buf)}}
    case False{}:
      Fail{(1007, "bad utf8")}

def wsm_frag_text(+buf: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  wsm_frag_text.go(buf, wsm_utf8_ok(buf))

def wsm_frag_msg.go(+op: U32, +buf: List<&2, U32>, is_text: Bool) -> Result<&1, &1, U32 & String, WSMessage>:
  match is_text:
    case True{}:
      wsm_frag_text(buf)
    case False{}:
      Done{WSBin{buf}}

def wsm_frag_msg(+op: U32, +buf: List<&2, U32>) -> Result<&1, &1, U32 & String, WSMessage>:
  wsm_frag_msg.go(op, buf, U32.is_eq(op, 1))

def wsm_frag_msg_done(r: Result<&1, &1, U32 & String, WSMessage>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{msg}:
      Done{(FragIdle{}, Some{msg})}

def wsm_frag_single_msg(+op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_msg_done(wsm_frag_msg(op, pay))

def wsm_frag_single.go(+op: U32, +pay: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match ok:
    case True{}:
      wsm_frag_single_msg(op, pay)
    case False{}:
      Fail{(413, "message too large")}

def wsm_frag_single(+op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_single.go(op, pay, wsm_frag_capped(pay))

def wsm_frag_begin.go(+op: U32, +pay: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match ok:
    case True{}:
      Done{(FragOpen{op, HTTP.x_cat(pay)}, None{})}
    case False{}:
      Fail{(413, "fragment too large")}

def wsm_frag_begin(+op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_begin.go(op, pay, wsm_frag_capped(pay))

def wsm_frag_first(fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match fin:
    case True{}:
      wsm_frag_single(op, pay)
    case False{}:
      wsm_frag_begin(op, pay)

def wsm_frag_open.go(fin: Bool, +op: U32, +pay: List<&2, U32>, is_data: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match is_data:
    case True{}:
      wsm_frag_first(fin, op, pay)
    case False{}:
      Fail{(400, "not data")}

def wsm_frag_open(fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_open.go(fin, op, pay, Bool.or(U32.is_eq(op, 1), U32.is_eq(op, 2)))

def wsm_frag_last(fin: Bool, +op0: U32, +grown: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match fin:
    case True{}:
      wsm_frag_single_msg(op0, HTTP.x_cat(grown))
    case False{}:
      Done{(FragOpen{op0, grown}, None{})}

def wsm_frag_cont2(fin: Bool, +op0: U32, +grown: List<&2, U32>, ok: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match ok:
    case True{}:
      wsm_frag_last(fin, op0, grown)
    case False{}:
      Fail{(413, "message too large")}

def wsm_frag_cont.go(fin: Bool, +op0: U32, +grown: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_cont2(fin, op0, grown, wsm_frag_capped(grown))

def wsm_frag_cont(fin: Bool, +op0: U32, +buf: List<&2, U32>, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_cont.go(fin, op0, HTTP.x_rev_push(pay, buf))

def wsm_frag_got.go(fin: Bool, +op0: U32, +buf: List<&2, U32>, +pay: List<&2, U32>, is_cont: Bool) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match is_cont:
    case True{}:
      wsm_frag_cont(fin, op0, buf, pay)
    case False{}:
      Fail{(400, "mixed fragment")}

def wsm_frag_got(fin: Bool, +op: U32, +op0: U32, +pay: List<&2, U32>, +buf: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  wsm_frag_got.go(fin, op0, buf, pay, U32.is_eq(op, 0))

def wsm_frag_step(+acc: MsgAcc, fin: Bool, +op: U32, +pay: List<&2, U32>) -> Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>:
  match acc:
    case FragIdle{}:
      wsm_frag_open(fin, op, pay)
    case FragOpen{op0, buf}:
      wsm_frag_got(fin, op, op0, pay, buf)

def wsm_frag_done(+acc2: MsgAcc, maybe: Maybe<&2, WSMessage>) -> WsStep:
  match maybe:
    case None{}:
      StepFrag{acc2}
    case Some{msg}:
      StepEv{EvMsg{msg}}

def wsm_frag_ev.go(r: Result<&1, &1, U32 & String, MsgAcc & Maybe<&2, WSMessage>>) -> WsStep:
  match r:
    case Fail{(c, m)}:
      StepEv{EvError{c, m}}
    case Done{pr}:
      (acc2, maybe) = pr
      wsm_frag_done(acc2, maybe)

def wsm_frag_ev(+acc: MsgAcc, fin: Bool, +op: U32, +pay: List<&2, U32>) -> WsStep:
  wsm_frag_ev.go(wsm_frag_step(acc, fin, op, pay))

# A whole data message that arrives while a fragment is still open is a
# mixed fragment (RFC 6455 section 5.4). The frame decoder reports a
# complete message as InMsg, so this path never reaches the reassembly
# fold: the loop has to reject it here exactly like the fold rejects a
# non-continuation frame on the InOp path (wsm_frag_got -> Fail 400
# "mixed fragment"). One match on the accumulator, no traversal and no
# allocation: the check is O(1) whatever the open fragment holds.
def wsm_msg_step(+acc: MsgAcc, msg: WSMessage) -> WsStep:
  match acc:
    case FragIdle{}:
      StepEv{EvMsg{msg}}
    case FragOpen{op0, buf}:
      StepEv{EvError{400, "mixed fragment"}}

# Loop helpers: the 1009 close answered on Fail 413, and the opcode
# carried by a handler answer (255 when the answer is no opcode frame,
# so the loops can tell a handler-initiated close apart).

def wsm_cap_close_out() -> WSOut:
  wsm_out_close([3, 241])

def wsm_out_op_of(out: WSOut) -> U32:
  match out:
    case OutOp{op, pay}:
      op
    case OutMsg{msg}:
      255
    case OutRaw{bs}:
      255

def wsm_unmask_byte(+b: U32, +k0: U32, +k1: U32, +k2: U32, +k3: U32, pos: U32) -> U32:
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

# XOR the payload with the 4-byte key, rotating the key by position. The
# accumulator rides REVERSED (x_cat once at the end): the direct
# cons-per-byte recursion was non-tail, so a payload past ~48 KB
# overflowed the interp machine stack (the hazard x_rev_push's header
# documents for the HTTP lanes).
def wsm_unmask.go(bs: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, pos: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      HTTP.x_cat(acc)
    case b <> rest:
      match pos:
        case 0:
          wsm_unmask.go(rest, k0, k1, k2, k3, 1, wsm_unmask_byte(b, k0, k1, k2, k3, 0) <> acc)
        case 1:
          wsm_unmask.go(rest, k0, k1, k2, k3, 2, wsm_unmask_byte(b, k0, k1, k2, k3, 1) <> acc)
        case 2:
          wsm_unmask.go(rest, k0, k1, k2, k3, 3, wsm_unmask_byte(b, k0, k1, k2, k3, 2) <> acc)
        case 3:
          wsm_unmask.go(rest, k0, k1, k2, k3, 0, wsm_unmask_byte(b, k0, k1, k2, k3, 3) <> acc)
        case _:
          wsm_unmask.go(rest, k0, k1, k2, k3, 1, wsm_unmask_byte(b, k0, k1, k2, k3, 0) <> acc)

def wsm_unmask(bs: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, pos: U32) -> List<&2, U32>:
  wsm_unmask.go(bs, k0, k1, k2, k3, pos, Nil{})

def wsm_is_ctrl(op: U32) -> Bool:
  match op:
    case 8:
      True{}
    case 9:
      True{}
    case 10:
      True{}
    case _:
      False{}

def wsm_is_op_ok(op: U32) -> Bool:
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

def wsm_is_nil(bs: List<&2, U32>) -> Bool:
  match bs:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

def wsm_finish_frame(ok: Bool, code: U32, fin: Bool, op: U32, +payload: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match ok:
    case True{}:
      Done{(fin, op, payload)}
    case False{}:
      Fail{(code, "bad frame")}

def wsm_ctrl_ok.go(is_c: Bool, fin: Bool, +len: U32) -> Bool:
  match is_c:
    case True{}:
      Bool.and(fin, U32.is_le(len, 125))
    case False{}:
      True{}

def wsm_ctrl_ok(+op: U32, fin: Bool, +len: U32) -> Bool:
  wsm_ctrl_ok.go(wsm_is_ctrl(op), fin, len)

def wsm_payload_ok(rsv_ok: Bool, +op: U32, fin: Bool, +len: U32, len_ok: Bool, cap_ok: Bool) -> Bool:
  Bool.and(rsv_ok, Bool.and(wsm_is_op_ok(op), Bool.and(wsm_ctrl_ok(op, fin, len), Bool.and(len_ok, cap_ok))))

def wsm_frame_payload(+fin: Bool, rsv_ok: Bool, +op: U32, +len: U32, +k0: U32, +k1: U32, +k2: U32, +k3: U32, +rest: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  +taken = HTTP.x_take32(len, rest)
  +len_ok = U32.is_eq(HTTP.x_len32(rest), len)
  +cap_ok = U32.is_le(len, wsm_max_payload())
  +unmasked = wsm_unmask(taken, k0, k1, k2, k3, 0)
  +ok = wsm_payload_ok(rsv_ok, op, fin, len, len_ok, cap_ok)
  +code = Bool.pick(U32, Bool.not(cap_ok), 413, 400)
  wsm_finish_frame(ok, code, fin, op, unmasked)

def wsm_mask_keys(fin: Bool, rsv_ok: Bool, +op: U32, +len: U32, masked: Bool, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
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
                      wsm_frame_payload(fin, rsv_ok, op, len, k0, k1, k2, k3, payload)
    case False{}:
      match unmasked_ok:
        case True{}:
          wsm_frame_payload(fin, rsv_ok, op, len, 0, 0, 0, 0, rest)
        case False{}:
          Fail{(400, "unmasked client frame")}

def wsm_len64.go(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, +lo: U32, rest: List<&2, U32>, is0: Bool, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match is0:
    case True{}:
      wsm_mask_keys(fin, rsv_ok, op, lo, masked, rest, unmasked_ok)
    case False{}:
      Fail{(413, "frame too large")}

def wsm_len64(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, +b0: U32, +b1: U32, +b2: U32, +b3: U32, +b4: U32, +b5: U32, +b6: U32, +b7: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  +hi = wsm_word_of4(b0, b1, b2, b3)
  +lo = wsm_word_of4(b4, b5, b6, b7)
  wsm_len64.go(fin, rsv_ok, op, masked, lo, rest, U32.is_zero(hi), unmasked_ok)

def wsm_len16(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, +b0: U32, +b1: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  wsm_mask_keys(fin, rsv_ok, op, (b0 * 256 + b1 : U32), masked, rest, unmasked_ok)

def wsm_len7.go(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, len7: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
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
              wsm_len16(fin, rsv_ok, op, masked, b0, b1, rest2, unmasked_ok)
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
                                      wsm_len64(fin, rsv_ok, op, masked, b0, b1, b2, b3, b4, b5, b6, b7, rest2, unmasked_ok)
    case _:
      wsm_mask_keys(fin, rsv_ok, op, len7, masked, rest, unmasked_ok)

def wsm_read_frame(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match bs:
    case Nil{}:
      Fail{(400, "short frame")}
    case +b0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "short frame")}
        case +b1 <> rest:
          wsm_len7.go(U32.is_ge(b0, 128), U32.is_zero(U32.and(U32.shrn(b0, 4n), 7)), U32.and(b0, 15), U32.is_ge(b1, 128), U32.and(b1, 127), rest, False{})

# Client parse: server frames arrive unmasked (RFC 6455 server-to-client).
# Same caps as wsm_read_frame (16MB, control rules); masked frames still
# parse.

def wsm_read_frame_unmasked(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>:
  match bs:
    case Nil{}:
      Fail{(400, "short frame")}
    case +b0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "short frame")}
        case +b1 <> rest:
          wsm_len7.go(U32.is_ge(b0, 128), U32.is_zero(U32.and(U32.shrn(b0, 4n), 7)), U32.and(b0, 15), U32.is_ge(b1, 128), U32.and(b1, 127), rest, True{})

# Incremental framing: total-first split for the recv accumulator.
# wsm_frame_need(bs) is the header read (2 + ext 0/2/8 + mask 0/4 +
# payload) under the same rules as wsm_read_frame (RSV/opcode/control
# and the 16MB cap); short headers Fail "short ...", invalid ones
# Fail 400/413. wsm_frame_split(bs) never fails soft data: it answers
# HTTP.UnitOut with NeedMore and the real missing count while the bytes
# fall short, Got with the frame plus the exact rest once complete, Bad
# on invalid headers. The unmasked twins serve the client side, like
# wsm_read_frame_unmasked. A partial frame is never materialized: the
# slice is built only in the arm that hands it over, and header
# completeness is measured with x_len_upto (never past 10 bytes — the
# largest a frame header can have). Got carries fin False on purpose: a
# WebSocket frame is not a message and does not end one — reassembly is
# the loop's job, above this — so the protocol-neutral fin of the shared
# outcome has no value to carry here (same convention as the new tree).
# End has no producer in this lane (a frame stream has no terminator);
# the fill answers it fail-closed, like a bad header).

def wsm_frame_need_done(ok: Bool, code: U32, +total: U32) -> Result<&1, &1, U32 & String, U32>:
  match ok:
    case True{}:
      Done{total}
    case False{}:
      Fail{(code, "bad frame")}

def wsm_frame_need_len(fin: Bool, rsv_ok: Bool, op: U32, +masked: Bool, +len: U32, ext: U32, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  +mask_len = Bool.pick(U32, masked, 4, 0)
  +total = (2 + ext + mask_len + len : U32)
  +cap_ok = U32.is_le(len, wsm_max_payload())
  +mask_ok = Bool.or(masked, unmasked_ok)
  +ok = Bool.and(mask_ok, wsm_payload_ok(rsv_ok, op, fin, len, True{}, cap_ok))
  +code = Bool.pick(U32, Bool.not(cap_ok), 413, 400)
  wsm_frame_need_done(ok, code, total)

def wsm_frame_need_small(fin: Bool, rsv_ok: Bool, op: U32, masked: Bool, len: U32, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  wsm_frame_need_len(fin, rsv_ok, op, masked, len, 0, unmasked_ok)

def wsm_frame_need_med(fin: Bool, rsv_ok: Bool, op: U32, masked: Bool, b0: U32, b1: U32, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  wsm_frame_need_len(fin, rsv_ok, op, masked, (b0 * 256 + b1 : U32), 2, unmasked_ok)

def wsm_frame_need_big(fin: Bool, rsv_ok: Bool, op: U32, masked: Bool, lo: U32, is_hi0: Bool, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  match is_hi0:
    case True{}:
      wsm_frame_need_len(fin, rsv_ok, op, masked, lo, 8, unmasked_ok)
    case False{}:
      Fail{(413, "frame too large")}

def wsm_frame_need_ext(fin: Bool, rsv_ok: Bool, +op: U32, masked: Bool, len7: U32, rest: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
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
              wsm_frame_need_med(fin, rsv_ok, op, masked, b0, b1, unmasked_ok)
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
                                      wsm_frame_need_big(fin, rsv_ok, op, masked, wsm_word_of4(b4, b5, b6, b7), U32.is_zero(wsm_word_of4(b0, b1, b2, b3)), unmasked_ok)
    case _:
      wsm_frame_need_small(fin, rsv_ok, op, masked, len7, unmasked_ok)

def wsm_frame_need_go(bs: List<&2, U32>, unmasked_ok: Bool) -> Result<&1, &1, U32 & String, U32>:
  match bs:
    case Nil{}:
      Fail{(400, "short frame")}
    case +b0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "short frame")}
        case +b1 <> rest:
          wsm_frame_need_ext(U32.is_ge(b0, 128), U32.is_zero(U32.and(U32.shrn(b0, 4n), 7)), U32.and(b0, 15), U32.is_ge(b1, 128), U32.and(b1, 127), rest, unmasked_ok)

def wsm_frame_need(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, U32>:
  wsm_frame_need_go(bs, False{})

def wsm_frame_need_unmasked(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, U32>:
  wsm_frame_need_go(bs, True{})

def wsm_frame_hdr.ext.go(len7: U32) -> U32:
  match len7:
    case 126:
      2
    case 127:
      8
    case _:
      0

def wsm_frame_hdr.ext(+b1: U32) -> U32:
  wsm_frame_hdr.ext.go(U32.and(b1, 127))

def wsm_frame_hdr.left(short: Bool, +want: U32, +have: U32) -> U32:
  match short:
    case True{}:
      (want - have : U32)
    case False{}:
      0

def wsm_frame_hdr.put(+have: U32, +want: U32) -> U32:
  wsm_frame_hdr.left(U32.is_lt(have, want), want, have)

def wsm_frame_hdr_go(hd: List<&2, U32>, have: U32) -> U32:
  match hd:
    case Nil{}:
      1
    case _ <> r1:
      match r1:
        case Nil{}:
          1
        case b1 <> _:
          wsm_frame_hdr.put(have, (2 + wsm_frame_hdr.ext(b1) : U32))

# One walk answers both halves (TASK-040 derivation, from test.bend's
# "the pair costs nothing, the rebuild costs everything"): the frame was
# peeled by x_take32 into a reversed accumulator and the tail was found by
# x_drop32, a second walk over the same cells — three walks plus x_cat's
# reverse for one complete frame. Here the peel builds the reversed frame
# and hands the untouched tail back with it, and the pair rides into its
# consumer as a PARAMETER (a computed pair cannot be scrutinized, E1; a
# parameter can, E2), so x_cat is the only remaining pass.
def wsm_frame_take.go(+bs: List<&2, U32>, +n: Nat, acc: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match bs:
    case Nil{}:
      (acc, Nil{})
    case h <> t:
      match n:
        case 0n:
          (acc, h <> t)
        case 1n+p:
          wsm_frame_take.go(t, p, h <> acc)

def wsm_frame_take(+bs: List<&2, U32>, +total: U32) -> List<&2, U32> & List<&2, U32>:
  wsm_frame_take.go(bs, U32.to_nat(total), Nil{})

def wsm_frame_take.got(p: List<&2, U32> & List<&2, U32>) -> HTTP.UnitOut:
  match p:
    case (acc, rest):
      HTTP.Got{HTTP.x_cat(acc), False{}, rest}

def wsm_frame_got_go(+bs: List<&2, U32>, +total: U32, eq: Bool, +missing: U32) -> HTTP.UnitOut:
  match eq:
    case True{}:
      wsm_frame_take.got(wsm_frame_take(bs, total))
    case False{}:
      HTTP.NeedMore{missing, bs}

def wsm_frame_split_got(+bs: List<&2, U32>, +total: U32) -> HTTP.UnitOut:
  +got = HTTP.x_len_upto(total, bs)
  wsm_frame_got_go(bs, total, U32.is_eq(got, total), U32.sub(total, got))

def wsm_frame_split_res(bs: List<&2, U32>, need: Result<&1, &1, U32 & String, U32>) -> HTTP.UnitOut:
  match need:
    case Fail{(c, e)}:
      HTTP.Bad{c, e}
    case Done{total}:
      wsm_frame_split_got(bs, total)

def wsm_frame_split_hd(+bs: List<&2, U32>, unmasked_ok: Bool, missing: U32) -> HTTP.UnitOut:
  match missing:
    case 0:
      wsm_frame_split_res(bs, wsm_frame_need_go(bs, unmasked_ok))
    case _:
      HTTP.NeedMore{missing, bs}

def wsm_frame_split_go(+bs: List<&2, U32>, unmasked_ok: Bool) -> HTTP.UnitOut:
  wsm_frame_split_hd(bs, unmasked_ok, wsm_frame_hdr_go(bs, HTTP.x_len_upto(10, bs)))

def wsm_frame_split(bs: List<&2, U32>) -> HTTP.UnitOut:
  wsm_frame_split_go(bs, False{})

def wsm_frame_split_unmasked(bs: List<&2, U32>) -> HTTP.UnitOut:
  wsm_frame_split_go(bs, True{})

def wsm_show_b0(fin: Bool, +op: U32) -> U32:
  (Bool.pick(U32, fin, 128, 0) + op : U32)

def wsm_show_small(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, [wsm_show_b0(fin, op), len], payload)

def wsm_show_med(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, [wsm_show_b0(fin, op), 126, U32.div(len, 256), U32.mod(len, 256)], payload)

def wsm_show_big(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, [wsm_show_b0(fin, op), 127, 0, 0, 0, 0], HTTP.x_be32(len)), payload)

def wsm_show_head.go(fin: Bool, +op: U32, +len: U32, +payload: List<&2, U32>, is_small: Bool, is_med: Bool) -> List<&2, U32>:
  match is_small is_med:
    case True{} True{}:
      wsm_show_small(fin, op, len, payload)
    case True{} False{}:
      wsm_show_small(fin, op, len, payload)
    case False{} True{}:
      wsm_show_med(fin, op, len, payload)
    case False{} False{}:
      wsm_show_big(fin, op, len, payload)

def wsm_show_go(ok: Bool, code: U32, fin: Bool, +op: U32, +payload: List<&2, U32>, +len: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      Done{wsm_show_head.go(fin, op, len, payload, U32.is_le(len, 125), U32.is_le(len, 65535))}
    case False{}:
      Fail{(code, "bad show")}

def wsm_show_frame(+fin: Bool, +op: U32, +payload: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +len = HTTP.x_len32(payload)
  +ok = Bool.and(wsm_is_op_ok(op), Bool.and(wsm_ctrl_ok(op, fin, len), U32.is_le(len, wsm_max_payload())))
  +code = Bool.pick(U32, Bool.not(U32.is_le(len, wsm_max_payload())), 413, 400)
  wsm_show_go(ok, code, fin, op, payload, len)

def wsm_show_masked_small(+fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> List<&2, U32>:
  List.append(&2, U32, [wsm_show_b0(fin, op), (len + 128 : U32), k0, k1, k2, k3], masked)

def wsm_show_masked_med(+fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> List<&2, U32>:
  List.append(&2, U32, [wsm_show_b0(fin, op), 254, U32.div(len, 256), U32.mod(len, 256), k0, k1, k2, k3], masked)

def wsm_show_masked_big(+fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, List.append(&2, U32, [wsm_show_b0(fin, op), 255, 0, 0, 0, 0], HTTP.x_be32(len)), [k0, k1, k2, k3]), masked)

def wsm_show_masked_head.go(fin: Bool, +op: U32, +len: U32, +masked: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, is_small: Bool, is_med: Bool) -> List<&2, U32>:
  match is_small is_med:
    case True{} True{}:
      wsm_show_masked_small(fin, op, len, masked, k0, k1, k2, k3)
    case True{} False{}:
      wsm_show_masked_small(fin, op, len, masked, k0, k1, k2, k3)
    case False{} True{}:
      wsm_show_masked_med(fin, op, len, masked, k0, k1, k2, k3)
    case False{} False{}:
      wsm_show_masked_big(fin, op, len, masked, k0, k1, k2, k3)

def wsm_show_masked.go(fin: Bool, +op: U32, +payload: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      +len = HTTP.x_len32(payload)
      Done{wsm_show_masked_head.go(fin, op, len, wsm_unmask(payload, k0, k1, k2, k3, 0), k0, k1, k2, k3, U32.is_le(len, 125), U32.is_le(len, 65535))}
    case False{}:
      Fail{(400, "bad masked")}

def wsm_show_masked(+fin: Bool, +op: U32, +payload: List<&2, U32>, +k0: U32, +k1: U32, +k2: U32, +k3: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +len = HTTP.x_len32(payload)
  wsm_show_masked.go(fin, op, payload, k0, k1, k2, k3, Bool.and(wsm_is_op_ok(op), Bool.and(wsm_ctrl_ok(op, fin, len), U32.is_le(len, wsm_max_payload()))))

def wsm_mask_key.go(a: Result<&1, &1, U32 & String, U32>, b: Result<&1, &1, U32 & String, U32>) ->
  WSMask:
  match a b:
    case Done{+hi} Done{+lo}:
      WSMask{U32.and(hi, 255), U32.and(U32.shrn(hi, 8n), 255), U32.and(U32.shrn(hi, 16n), 255), U32.and(lo, 255)}
    case _ _:
      WSMask{1, 2, 3, 4}

def wsm_mask_key() -> IO(WSMask):
  do IO<WSMask>:
    a : Result<&1, &1, U32 & String, U32> <- IO.random_u32()
    b : Result<&1, &1, U32 & String, U32> <- IO.random_u32()
    IO.pure(WSMask, wsm_mask_key.go(a, b))

def wsm_show_masked_key(+fin: Bool, +op: U32, +payload: List<&2, U32>, +key: WSMask) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  match key:
    case WSMask{k0, k1, k2, k3}:
      wsm_show_masked(fin, op, payload, k0, k1, k2, k3)

def wsm_show_masked_random(+fin: Bool, +op: U32, +payload: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    +key : WSMask <- wsm_mask_key()
    IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, wsm_show_masked_key(fin, op, payload, key))

def wsm_out_bytes(out: WSOut) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match out:
    case OutMsg{msg}:
      +mm = msg
      wsm_show_frame(True{}, wsm_msg_to_op(mm), wsm_msg_to_bytes(mm))
    case OutOp{op, pay}:
      +oo = op
      +pp = pay
      wsm_show_frame(True{}, oo, wsm_out_op_pay(oo, pp))
    case OutRaw{bs}:
      Done{bs}

def wsm_client_out_bytes(out: WSOut, +key: WSMask) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match out:
    case OutMsg{msg}:
      +mm = msg
      wsm_show_masked_key(True{}, wsm_msg_to_op(mm), wsm_msg_to_bytes(mm), key)
    case OutOp{op, pay}:
      +oo = op
      +pp = pay
      wsm_show_masked_key(True{}, oo, wsm_out_op_pay(oo, pp), key)
    case OutRaw{bs}:
      Done{bs}

def wsm_client_out_bytes_random(out: WSOut) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    +key : WSMask <- wsm_mask_key()
    IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, wsm_client_out_bytes(out, key))

def wsm_recv_pick(msg_res: Result<&1, &1, U32 & String, WSMessage>, fin: Bool, +op: U32, +pay: List<&2, U32>) -> WSIn:
  match msg_res:
    case Done{msg}:
      InMsg{msg}
    case Fail{e}:
      InOp{fin, op, pay}

def wsm_recv_in_of(+fin: Bool, +op: U32, +pay: List<&2, U32>) -> WSIn:
  wsm_recv_pick(wsm_msg_of_frame(fin, op, pay), fin, op, pay)

def wsm_eq_bytes(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  U32.is_eq(HTTP.x_eq(a, b), 1)

# One-shot echo policy (serve_once only; a persistent session runs
# wsm_loop, which reassembles fragments and answers ping via
# wsm_ping_reply). Codes: 1 echo the same op, 2 answer a ping with a
# pong, 0 close. A fragment (fin=false) means a message this path cannot
# answer whole, and control frames may not be fragmented at all, so
# both close instead of echoing a truncated frame. A continuation means
# the same thing one step later, and an unsolicited pong has nothing to
# answer: those close too.
def wsm_echo_op_fin(op: U32) -> U32:
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

def wsm_echo_op(fin: Bool, op: U32) -> U32:
  match fin:
    case True{}:
      wsm_echo_op_fin(op)
    case False{}:
      0

# Transport: the same ~recv/~send/~close triple as the httpx H1 lane,
# instantiated per lane at the entries. Frame isolation is user-land on
# both lanes (TLS has no recv_frame effect, and one loop serves both):
# accumulate into buf and split with the pure codec until one frame is
# complete. The rest past the frame threads back as the next buf (every
# byte consumed exactly once, starting with the handshake's rest).
# Empty read is EOF (Fail 400). unmasked_ok selects the unmasked split
# (client side reads server frames).
# ---------------------------------------------------------------------

def wsm_send_bytes(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{bs}:
      send(s, bs)

def wsm_send_open(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), +is_client: Bool, s: Socket, out: WSOut) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_client:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        fr : Result<&1, &1, U32 & String, List<&2, U32>> <- wsm_client_out_bytes_random(out)
        wsm_send_bytes(~send, (s, fr))
    case False{}:
      wsm_send_bytes(~send, (s, wsm_out_bytes(out)))

# Transport instances (TASK-028 Phase 5.5). The template defs above are
# the real abstraction: the lane is picked at the call site, once, and
# the codec never mentions it. These instances exist so a caller holding
# a raw socket (tests, examples, a scripted peer) does not repeat the
# ~TCPB / ~TLS pair on every send. One instance per lane, never an
# is_wss Bool flag: a Bool would (a) be illegal in the comptime slots the
# lane itself uses (the ~H of on_h1_open), (b) move the ws/wss fork from
# compile time to runtime, and (c) collide with the _insecure (no
# verify) / _plain (cleartext) naming rule.
#
# Dialect note that shapes the shape: a ~ param cannot be mentioned inside
# a do IO<...> block, and an IO(...) expression cannot be handed to a
# runtime binder. So each instance spells its own close once instead of
# forwarding a template through the IO edge.

def wsm_ship_sock(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# send-and-close, the shape ws.send_bytes had: hand it the framed bytes
# (Done/Fail from a builder) and it ships them and drops the socket.
def wsm_ship_plain(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{bs}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCPB.send_bytes(s, bs)
        Socket.close(wsm_ship_sock(sent))

def wsm_ship_tls(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{bs}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, bs)
        TLS.tls_close(wsm_ship_sock(sent))

# Masked client sends (RFC 6455 section 5.3: the key comes from the host
# entropy pool, never a constant).
def send_msg_plain(s: Socket, +msg: WSMessage) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_open(~TCPB.send_bytes, True{}, s, OutMsg{msg})

def send_op_plain(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_open(~TCPB.send_bytes, True{}, s, OutOp{op, pay})

def send_msg_tls(s: Socket, +msg: WSMessage) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_open(~TLS.tls_send_bytes, True{}, s, OutMsg{msg})

def send_op_tls(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_open(~TLS.tls_send_bytes, True{}, s, OutOp{op, pay})

# Unmasked "open" sends (server side of a session): the socket stays
# open, the loop owns the close. Same one-line shape as send_msg_plain /
# send_op_plain above, with is_client=False instead of a flag.
def send_open_op_plain(s: Socket, +op: U32, +pay: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_open(~TCPB.send_bytes, False{}, s, OutOp{op, pay})

def send_open_msg_plain(s: Socket, +msg: WSMessage) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_open(~TCPB.send_bytes, False{}, s, OutMsg{msg})

# Ship a framed-bytes result (Done/Fail from a builder) verbatim, socket
# open — the shape the retired send_open_bytes had.
def send_open_bytes_plain(m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  wsm_send_bytes(~TCPB.send_bytes, m)

def wsm_split_fail(s: Socket, +code: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, (s, Fail{(code, msg)}))

def wsm_split_got(s: Socket, +frame: List<&2, U32>, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, (s, Done{(frame, rest)}))

def wsm_do_split(+buf: List<&2, U32>, unmasked_ok: Bool) -> HTTP.UnitOut:
  match unmasked_ok:
    case True{}:
      wsm_frame_split_unmasked(buf)
    case False{}:
      wsm_frame_split(buf)

# Flatten the reversed chunk list (newest chunk first) into one buffer.
# The recv pile is the 1000 by 1000 shape of test.bend: many small chunks
# and no single big one. List.concat survives that shape and beats a
# hand-rolled fold (1 MiB at 93 ms there; 512 by 8192 chunks, 4 MiB, at
# 803 ms here). Its recursion depth is the chunk count, not the total: 4096
# chunks of 8192 bytes flatten 32 MiB here, so 12800 chunks of an 8192-byte
# recv hold for a 100 MiB message. The pile is newest first, so the reverse
# puts it back into arrival order before the flatten (the chunk spine is
# 12800 cells, not the body). One big chunk would not survive: a single
# 65536-cell chunk dies past about 32768 cells (test.bend).

# Read until the frame is whole. The split answer says how many bytes are
# missing (NeedMore{missing, rest}); instead of appending every recv onto
# a growing buffer and re-splitting the whole thing (O(n) per recv, and
# linear-recursive -- the interp machine stack overflowed past ~48 KB,
# the same hazard x_rev_push's header documents), the later chunks ride
# consed (O(1) per recv, they are lists) and the buffer is flattened and
# split ONCE, when the missing bytes have arrived. `need` is the count
# still missing, so the completion test is a match on a U32 param instead
# of a re-walk of the buffer.
@unsafe
def wsm_fill(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), st: U32, m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +chunks: List<&2, List<&2, U32>>, +need: U32, +unmasked_ok: Bool, +sp: HTTP.UnitOut) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  match st:
    case 0:
      # Completion test on the missing-byte counter: zero flattens the
      # pile and splits once; otherwise one more recv. It comes before
      # the arm that consumes `need` -- the checker reads arms in order,
      # and a match cannot scrutinize a consumed binder.
      (s0, r0) = m
      match need:
        case 0:
          +full = List.concat(&2, U32, List.reverse(&2, List<&2, U32>, chunks))
          wsm_fill(~recv, 2, (s0, Done{Nil{}}), Nil{}, 0, unmasked_ok, wsm_do_split(full, unmasked_ok))
        case n:
          do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>>:
            m0 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 8192)
            wsm_fill(~recv, 1, m0, chunks, n, unmasked_ok, sp)
    case 1:
      # Recv result: cons the chunk onto the pile (O(1), it is a list)
      # and hand the new missing count back to phase 0.
      (s2, r2) = m
      match r2:
        case Fail{e}:
          wsm_split_fail(s2, 400, "recv")
        case Done{+bs}:
          match bs:
            case Nil{}:
              wsm_split_fail(s2, 400, "eof")
            case _ <> _:
              wsm_fill(~recv, 0, (s2, Done{Nil{}}), bs <> chunks, U32.sub(need, HTTP.x_len_upto(need, bs)), unmasked_ok, sp)
    case 2:
      # Split answer: a whole frame answers now; NeedMore starts the
      # accumulate loop with the buffer that was split as the oldest
      # chunk (both NeedMore arms carry the whole buffer).
      (s3, r3) = m
      match sp:
        case HTTP.NeedMore{missing, rest}:
          do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>>:
            m3 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s3, 8192)
            wsm_fill(~recv, 1, m3, rest <> Nil{}, missing, unmasked_ok, sp)
        case HTTP.Got{unit, fin, rest}:
          wsm_split_got(s3, unit, rest)
        case HTTP.End{rest}:
          wsm_split_fail(s3, 400, "impossible")
        case HTTP.Bad{code, msg}:
          wsm_split_fail(s3, code, msg)
    case _:
      (s4, r4) = m
      wsm_split_fail(s4, 400, "bad state")

def wsm_split_more(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  wsm_fill(~recv, 2, (s, Done{Nil{}}), Nil{}, 0, unmasked_ok, wsm_do_split(buf, unmasked_ok))

# One framed frame into the wire triple (fin & op & payload) plus the
# rest past it.

def wsm_recv_frame_got(m: Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>, unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, Fail{e}, []))
    case Done{fr}:
      (frame, rest) = fr
      match unmasked_ok:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, wsm_read_frame_unmasked(frame), rest))
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, (s, wsm_read_frame(frame), rest))

def wsm_recv_frame(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>> <- wsm_split_more(~recv, s, buf, unmasked_ok)
    wsm_recv_frame_got(m, unmasked_ok)

def wsm_recv_in_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Done{wsm_recv_in_of(fin, op, pay)}, rest))

def wsm_recv_in(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- wsm_recv_frame(~recv, s, buf, unmasked_ok)
    wsm_recv_in_got(m)

# Message-level read: like wsm_recv_in, but a control or fragmented frame
# is a Fail (400) instead of an InOp, which is what the retired
# recv_msg_* framed defs answered. wsm_msg_of_frame owns the rule. The
# Result gets its own def: Bend refuses a match on a computed scrutinee.
def wsm_recv_msg_done(s: Socket, p: Result<&1, &1, U32 & String, WSMessage>, rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  match p:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Fail{e}, []))
    case Done{msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Done{msg}, rest))

def wsm_recv_msg_got(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>, (s, Fail{e}, []))
    case Done{t}:
      (fin, op, pay) = t
      wsm_recv_msg_done(s, wsm_msg_of_frame(fin, op, pay), rest)

def wsm_recv_msg(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), s: Socket, +buf: List<&2, U32>, +unmasked_ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  do IO<Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- wsm_recv_frame(~recv, s, buf, unmasked_ok)
    wsm_recv_msg_got(m)

# Compatibility instances (TASK-028 Phase 5.7): the per-side sugar the
# retired lib/ws.bend exposed, so an importer migrates by rename instead
# of rewriting each call site. One line each over wsm_recv_frame /
# wsm_recv_msg; the _plain suffix is the lane, like send_msg_plain.
# unmasked_ok=True means the peer is the client (server frames ride
# unmasked), False means the masked side.
def recv_op_framed_plain(s: Socket, buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  wsm_recv_frame(~TCPB.recv_bytes, s, buf, False{})

def recv_op_client_framed_plain(s: Socket, buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>):
  wsm_recv_frame(~TCPB.recv_bytes, s, buf, True{})

def recv_msg_framed_plain(s: Socket, buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  wsm_recv_msg(~TCPB.recv_bytes, s, buf, False{})

def recv_msg_client_framed_plain(s: Socket, buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, WSMessage> & List<&2, U32>):
  wsm_recv_msg(~TCPB.recv_bytes, s, buf, True{})

# Raw byte read, the shape the retired recv_bytes had (8192 like the lane).
def recv_bytes_plain(s: Socket) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  TCPB.recv_bytes(s, 8192)

def wsm_recv_after(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), m: Socket & Result<&1, &1, U32 & String, Unit>, +buf: List<&2, U32>, +is_client: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, (s, Fail{e}, []))
    case Done{u}:
      wsm_recv_in(~recv, s, buf, is_client)

# The session loop: one self-recursive def for both directions (no
# mutual recursion). is_client picks masked sends + unmasked-ok reads
# (client) versus unmasked sends + masked-required reads (server).
# Same ~H contract both ways: one EvOpen after the handshake, one step
# per complete frame, ping auto-ponged unless overridden, close
# answered and shut, 413 answered with close 1009, anything else
# fail-closed. shut tracks a handler-initiated close (out op 8).

def wsm_close_snd(~close: Socket -> IO(Unit), m: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Unit):
  (s, r) = m
  close(s)

def wsm_loop_fail(~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), is_client: Bool, s: Socket, +code: U32, +msg: String) -> IO(Unit):
  match is_client:
    case True{}:
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        close(s)
    case False{}:
      close(s)

@unsafe
def wsm_loop(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), +is_client: Bool, st: U32, mf: Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32>, step: WsStep, +buf: List<&2, U32>, acc: MsgAcc, shut: Bool) ->
  IO(Unit):
  match st:
    case 1:
      (s, r, rest) = mf
      match r:
        case Fail{(c, m)}:
          match c:
            case 413:
              do IO<Unit>:
                m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wsm_send_open(~send, is_client, s, wsm_cap_close_out())
                wsm_close_snd(~close, m2)
            case _:
              wsm_loop_fail(~close, ~H, is_client, s, c, m)
        case Done{inn}:
          match inn:
            case InMsg{msg}:
              wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), wsm_msg_step(acc, msg), rest, FragIdle{}, shut)
            case InOp{fin, op, pay}:
              match op:
                case 8:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{wsm_close_ev(pay)}, rest, FragIdle{}, shut)
                case 9:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvPing{pay}}, rest, acc, shut)
                case 10:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvPong{pay}}, rest, acc, shut)
                case 0:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), wsm_frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case 1:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), wsm_frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case 2:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), wsm_frag_ev(acc, fin, op, pay), rest, FragIdle{}, shut)
                case _:
                  wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepEv{EvError{400, "bad frame"}}, rest, FragIdle{}, shut)
    case 2:
      (s, r, b) = mf
      match step:
        case StepEv{ev}:
          match ev:
            case EvOpen{}:
              do IO<Unit>:
                out : WSOut <- H(EvOpen{})
                wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvMsg{msg}:
              do IO<Unit>:
                out : WSOut <- H(EvMsg{msg})
                wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvPing{pay}:
              +pp = pay
              do IO<Unit>:
                out : WSOut <- H(EvPing{pp})
                wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{wsm_ping_reply(pp, out)}, buf, acc, shut)
            case EvPong{pay}:
              do IO<Unit>:
                out : WSOut <- H(EvPong{pay})
                wsm_loop(~recv, ~send, ~close, ~H, is_client, 2, (s, Done{InOp{False{}, 0, []}}, []), StepOut{out}, buf, acc, shut)
            case EvClose{pay}:
              match shut:
                case True{}:
                  close(s)
                case False{}:
                  +pp = pay
                  do IO<Unit>:
                    out : WSOut <- H(EvClose{pp})
                    m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wsm_send_open(~send, is_client, s, wsm_close_answer(pp, out))
                    wsm_close_snd(~close, m2)
            case EvError{code, msg}:
              do IO<Unit>:
                out : WSOut <- H(EvError{code, msg})
                close(s)
        case StepFrag{acc2}:
          do IO<Unit>:
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- wsm_recv_in(~recv, s, buf, is_client)
            wsm_loop(~recv, ~send, ~close, ~H, is_client, 1, m3, StepEv{EvError{0, ""}}, [], acc2, shut)
        case StepOut{out2}:
          +o2 = out2
          do IO<Unit>:
            m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wsm_send_open(~send, is_client, s, o2)
            m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- wsm_recv_after(~recv, m2, buf, is_client)
            wsm_loop(~recv, ~send, ~close, ~H, is_client, 1, m3, StepEv{EvError{0, ""}}, [], acc, Bool.or(shut, U32.is_eq(wsm_out_op_of(o2), 8)))
    case _:
      IO.pure(Unit, Unit{})

# Session entry: answer EvOpen once, send it, and enter the loop with
# the handshake's rest as the first buffer (a frame that arrived with
# the 101 is read, never re-asked from the socket).

def wsm_session_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), +is_client: Bool, sock: Socket, +rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    out : WSOut <- H(EvOpen{})
    m2 : Socket & Result<&1, &1, U32 & String, Unit> <- wsm_send_open(~send, is_client, sock, out)
    m3 : Socket & Result<&1, &1, U32 & String, WSIn> & List<&2, U32> <- wsm_recv_after(~recv, m2, rest, is_client)
    wsm_loop(~recv, ~send, ~close, ~H, is_client, 1, m3, StepEv{EvError{0, ""}}, [], FragIdle{}, False{})

# Server handshake answers for the upgrade lane (~H of on_h1_open):
# validate the Request and answer 101 (the lane renders it head-only)
# or 400 (the lane rejoins/closes normally). The session loop never
# sees a bad handshake.

def wsm_srv_h.go(+m: String, vr: Result<&1, &1, U32 & String, String>) -> IO(HTTP.Response):
  match vr:
    case Fail{e}:
      IO.pure(HTTP.Response, HTTP.Response{400, Nil{}, Nil{}})
    case Done{+key}:
      IO.pure(HTTP.Response, HTTP.Response{101, wsm_accept_hdrs(wsm_accept_of(key)), Nil{}})

def wsm_srv_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, path, headers, body}:
      wsm_srv_h.go(method, wsm_validate(method, headers))

def wsm_srv_h_sub.pick(+key: String, picked: Maybe<&2, String>) -> IO(HTTP.Response):
  match picked:
    case None{}:
      IO.pure(HTTP.Response, HTTP.Response{101, wsm_accept_hdrs(wsm_accept_of(key)), Nil{}})
    case Some{+p}:
      IO.pure(HTTP.Response, HTTP.Response{101, wsm_accept_hdrs_sub(wsm_accept_of(key), p), Nil{}})

def wsm_srv_h_sub.go(+m: String, vr: Result<&1, &1, U32 & String, String & Maybe<&2, String>>) -> IO(HTTP.Response):
  match vr:
    case Fail{e}:
      IO.pure(HTTP.Response, HTTP.Response{400, Nil{}, Nil{}})
    case Done{pr}:
      (key, picked) = pr
      wsm_srv_h_sub.pick(key, picked)

def wsm_srv_h_sub(req: HTTP.Request, +wanted: List<&2, String>) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, path, headers, body}:
      wsm_srv_h_sub.go(method, wsm_validate_sub(method, headers, wanted))

# One-shot echo frame policy for serve_once: read one frame (rest-seeded,
# masked-required like any server read), echo or pong it, close. Anything
# else — fragments, pongs, bad frames — closes without answering partial.

def wsm_echo_closed(~close: Socket -> IO(Unit), m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  close(s)

def wsm_echo_reply(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, framed: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  do IO<Unit>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- wsm_send_bytes(~send, (s, framed))
    wsm_echo_closed(~close, m)

def wsm_echo_act(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, act: U32, +op: U32, +pay: List<&2, U32>) -> IO(Unit):
  match act:
    case 1:
      wsm_echo_reply(~send, ~close, s, wsm_show_frame(True{}, op, pay))
    case 2:
      wsm_echo_reply(~send, ~close, s, wsm_show_frame(True{}, 10, pay))
    case _:
      close(s)

def wsm_echo_frame(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Unit):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      close(s)
    case Done{t}:
      (fin, +op, pay) = t
      wsm_echo_act(~send, ~close, s, wsm_echo_op(fin, op), op, pay)

def wsm_echo_one(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- wsm_recv_frame(~recv, sock, rest, False{})
    wsm_echo_frame(~send, ~close, m)

# serve_once lanes: the socket arrives already accepted (TLS-accepted
# for serve_once, TCP-accepted for serve_once_plain) and the upgrade is
# read on it directly — handshake rest seeds the one frame read, exactly
# like the session entries below, instead of the take/drop dance the old
# lanes did around their ASCII handshake.

def wsm_serve_once_k(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  wsm_echo_one(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, sock, rest)

def wsm_serve_once_k_plain(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  wsm_echo_one(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, sock, rest)

def serve_once(sock: Socket) -> IO(Unit):
  HTTP1.x_h1.srv.head_open(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~wsm_srv_h, ~wsm_serve_once_k, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def serve_once_plain(sock: Socket) -> IO(Unit):
  HTTP1.x_h1.srv.head_open(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~wsm_srv_h, ~wsm_serve_once_k_plain, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

# Cleartext echo accept loop (TASK-036 Phase 1): one serve_once_plain per
# accepted socket, no handler to write. Reuse: the body already exists
# above; Fail keeps the listener alive like the module's buffered accept
# event, never dies.
def ws_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- IO.spawn(Unit, serve_once_plain(sock))
        return l

@unsafe
def ws_serve(l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    l2 : Listener <- ws_conn(m)
    ws_serve(l2)

# Session servers: the accept loop stays in the httpx upgrade lane; the
# ~K lambdas close over the caller's ~H (curried single binders — the
# dialect's lambda shape) and enter the shared session with rest.
# _insecure never appears here: these verify nothing to begin with only
# on the cleartext lane, which is reached by name (_plain), never by flag.

@unsafe
def server_on(~H: WSEv -> IO(WSOut), l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTPX.server.on_h1_open(~wsm_srv_h, sock => rest => wsm_session_open(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, False{}, sock, rest), l, cert, key)

@unsafe
def server_on_sub(~H: WSEv -> IO(WSOut), ~wanted: List<&2, String>, l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTPX.server.on_h1_open(req => wsm_srv_h_sub(req, wanted), sock => rest => wsm_session_open(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, False{}, sock, rest), l, cert, key)

@unsafe
def server_on_plain(~H: WSEv -> IO(WSOut), l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_open_plain(~wsm_srv_h, sock => rest => wsm_session_open(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~H, False{}, sock, rest), l)

@unsafe
def server_on_sub_plain(~H: WSEv -> IO(WSOut), ~wanted: List<&2, String>, l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_open_plain(req => wsm_srv_h_sub(req, wanted), sock => rest => wsm_session_open(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~H, False{}, sock, rest), l)

# Session clients: dial, upgrade over the H1 lane, validate 101 + Accept,
# then the shared session with rest. TLS goes through h1_open (which
# closes on Fail); cleartext dials TCP.connect and closes the refused
# handshake itself through h1_open.rewrap — one validated shape after.
# _insecure only switches the TLS dial (chain verification off); the
# cleartext lane is always by name.
# ---------------------------------------------------------------------

def wsm_client_checked(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), sock: Socket, +rest: List<&2, U32>, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      wsm_session_open(~recv, ~send, ~close, ~H, True{}, sock, rest)
    case False{}:
      do IO<Unit>:
        out : WSOut <- H(EvError{400, "bad handshake"})
        close(sock)

def wsm_client_validated(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, +key: String) -> IO(Unit):
  match r:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{t}:
      (sock, resp, rest) = t
      match resp:
        case HTTP.Response{status, headers, body}:
          wsm_client_checked(~recv, ~send, ~close, ~H, sock, rest, wsm_client_ok(status, headers, wsm_accept_of(key)))

def wsm_client_checked_sub(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), sock: Socket, +rest: List<&2, U32>, +offered: List<&2, String>, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      wsm_session_open(~recv, ~send, ~close, ~H, True{}, sock, rest)
    case False{}:
      do IO<Unit>:
        out : WSOut <- H(EvError{400, "bad handshake"})
        close(sock)

def wsm_client_validated_sub(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: WSEv -> IO(WSOut), r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, +key: String, +offered: List<&2, String>) -> IO(Unit):
  match r:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{t}:
      (sock, resp, rest) = t
      match resp:
        case HTTP.Response{status, headers, body}:
          wsm_client_checked_sub(~recv, ~send, ~close, ~H, sock, rest, offered, wsm_client_ok_sub(status, headers, wsm_accept_of(key), offered))

def wsm_client_tls(~H: WSEv -> IO(WSOut), verify: Bool, +host: String, port: U32, +req: HTTP.Request, +key: String) -> IO(Unit):
  match verify:
    case True{}:
      do IO<Unit>:
        r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open(host, port, req)
        wsm_client_validated(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, r, key)
    case False{}:
      do IO<Unit>:
        r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open_insecure(host, port, req)
        wsm_client_validated(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, r, key)

def wsm_client_tls_sub(~H: WSEv -> IO(WSOut), verify: Bool, +host: String, +port: U32, +req: HTTP.Request, +key: String, +offered: List<&2, String>) -> IO(Unit):
  match verify:
    case True{}:
      do IO<Unit>:
        r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open(host, port, req)
        wsm_client_validated_sub(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, r, key, offered)
    case False{}:
      do IO<Unit>:
        r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open_insecure(host, port, req)
        wsm_client_validated_sub(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, r, key, offered)

def wsm_client_plain_sock(~H: WSEv -> IO(WSOut), sock: Socket, +host: String, port: U32, +req: HTTP.Request, +key: String) -> IO(Unit):
  match req:
    case HTTP.Request{method, path, headers, body}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- HTTP1.x_h1.cli.exch.open(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, sock, host, port, method, path, headers, body)
        rw : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open.rewrap(~Socket.close, out)
        wsm_client_validated(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~H, rw, key)

def wsm_client_plain_conn(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, +host: String, port: U32, +req: HTTP.Request, +key: String) -> IO(Unit):
  match conn:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{sock}:
      wsm_client_plain_sock(~H, sock, host, port, req, key)

def wsm_client_plain(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +req: HTTP.Request, +key: String) -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    wsm_client_plain_conn(~H, conn, host, port, req, key)

def wsm_client_plain_sock_sub(~H: WSEv -> IO(WSOut), sock: Socket, +host: String, +port: U32, +req: HTTP.Request, +key: String, +offered: List<&2, String>) -> IO(Unit):
  match req:
    case HTTP.Request{method, path, headers, body}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- HTTP1.x_h1.cli.exch.open(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, sock, host, port, method, path, headers, body)
        rw : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open.rewrap(~Socket.close, out)
        wsm_client_validated_sub(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~H, rw, key, offered)

def wsm_client_plain_conn_sub(~H: WSEv -> IO(WSOut), conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, +req: HTTP.Request, +key: String, +offered: List<&2, String>) -> IO(Unit):
  match conn:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{sock}:
      wsm_client_plain_sock_sub(~H, sock, host, port, req, key, offered)

def wsm_client_plain_sub(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +req: HTTP.Request, +key: String, +offered: List<&2, String>) -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    wsm_client_plain_conn_sub(~H, conn, host, port, req, key, offered)

def wsm_client_start(~H: WSEv -> IO(WSOut), verify: Bool, +host: String, port: U32, +path: String, +key: String, req: Result<&1, &1, U32 & String, HTTP.Request>) -> IO(Unit):
  match req:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{+rr}:
      wsm_client_tls(~H, verify, host, port, rr, key)

def wsm_client_start_sub(~H: WSEv -> IO(WSOut), verify: Bool, +host: String, +port: U32, +path: String, +key: String, +offered: List<&2, String>, req: Result<&1, &1, U32 & String, HTTP.Request>) -> IO(Unit):
  match req:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{+rr}:
      wsm_client_tls_sub(~H, verify, host, port, rr, key, offered)

def wsm_client_start_plain(~H: WSEv -> IO(WSOut), +host: String, port: U32, +path: String, +key: String, req: Result<&1, &1, U32 & String, HTTP.Request>) -> IO(Unit):
  match req:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{+rr}:
      wsm_client_plain(~H, host, port, rr, key)

def wsm_client_start_sub_plain(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +path: String, +key: String, +offered: List<&2, String>, req: Result<&1, &1, U32 & String, HTTP.Request>) -> IO(Unit):
  match req:
    case Fail{e}:
      (code, msg) = e
      do IO<Unit>:
        out : WSOut <- H(EvError{code, msg})
        return Unit{}
    case Done{+rr}:
      wsm_client_plain_sub(~H, host, port, rr, key, offered)

# Session clients. _insecure only turns chain verification off; the
# cleartext lane is always by name (_plain).

def client_on(~H: WSEv -> IO(WSOut), +host: String, port: U32, +path: String, +key: String) ->
  IO(Unit):
  wsm_client_start(~H, True{}, host, port, path, key, wsm_client_request(path, key))

def client_on_insecure(~H: WSEv -> IO(WSOut), +host: String, port: U32, +path: String, +key: String) ->
  IO(Unit):
  wsm_client_start(~H, False{}, host, port, path, key, wsm_client_request(path, key))

def client_on_sub(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +path: String, +key: String, +protos: List<&2, String>) ->
  IO(Unit):
  wsm_client_start_sub(~H, True{}, host, port, path, key, protos, wsm_client_request_sub(path, key, protos))

def client_on_sub_insecure(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +path: String, +key: String, +protos: List<&2, String>) ->
  IO(Unit):
  wsm_client_start_sub(~H, False{}, host, port, path, key, protos, wsm_client_request_sub(path, key, protos))

def client_on_plain(~H: WSEv -> IO(WSOut), +host: String, port: U32, +path: String, +key: String) ->
  IO(Unit):
  wsm_client_start_plain(~H, host, port, path, key, wsm_client_request(path, key))

def client_on_sub_plain(~H: WSEv -> IO(WSOut), +host: String, +port: U32, +path: String, +key: String, +protos: List<&2, String>) ->
  IO(Unit):
  wsm_client_start_sub_plain(~H, host, port, path, key, protos, wsm_client_request_sub(path, key, protos))

# One-shot echo clients (loopback tests and examples): dial, upgrade,
# validate, send one masked frame with a random key, read the unmasked
# echo off the rest-seeded buffer, close. Done carries the decoded echo
# on an exact match — the old lanes hardcoded "Hi" here, which is only
# right when the message IS "Hi".
# ---------------------------------------------------------------------

def wsm_client_echo_score(+pay: List<&2, U32>, ok: Bool) -> IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Done{wsm_utf8_decode(pay)})
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad echo")})

def wsm_client_echo_built(~close: Socket -> IO(Unit), s: Socket, +pay: List<&2, U32>, rebuilt: Result<&1, &1, U32 & String, List<&2, U32>>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match rebuilt:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+bs}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- close(s)
        wsm_client_echo_score(pay, wsm_eq_bytes(bs, want))

def wsm_client_echo_fin(~close: Socket -> IO(Unit), s: Socket, fin: Bool, +op: U32, +pay: List<&2, U32>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  wsm_client_echo_built(~close, s, pay, wsm_show_frame(fin, op, pay), want)

def wsm_client_echo_got(~close: Socket -> IO(Unit), m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (s, r, rest2) = m
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{t}:
      (fin, op, pay) = t
      wsm_client_echo_fin(~close, s, fin, op, pay, want)

def wsm_client_echo_sent(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +rest: List<&2, U32>, +want: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, String>>:
        m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- wsm_recv_frame(~recv, s, rest, True{})
        wsm_client_echo_got(~close, m, want)

def wsm_client_echo_want(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match want:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- close(sock)
        IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+wb}:
      do IO<Result<&1, &1, U32 & String, String>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, framed)
        wsm_client_echo_sent(~recv, ~send, ~close, sent, rest, wb)

def wsm_client_echo_validated(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case False{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- close(sock)
        IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad handshake")})
    case True{}:
      wsm_client_echo_want(~recv, ~send, ~close, sock, rest, framed, want)

def wsm_client_echo_opened(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{t}:
      (sock, resp, rest) = t
      match resp:
        case HTTP.Response{status, headers, body}:
          wsm_client_echo_validated(~recv, ~send, ~close, sock, rest, key, framed, want, wsm_client_ok(status, headers, wsm_accept_of(key)))

def wsm_client_echo_tls_sock(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, port: U32, rr: HTTP.Request, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match rr:
    case HTTP.Request{method, path, headers, body}:
      do IO<Result<&1, &1, U32 & String, String>>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- HTTP1.x_h1.cli.exch.open(~recv, ~send, ~close, sock, host, port, method, path, headers, body)
        rw : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open.rewrap(~close, out)
        wsm_client_echo_opened(~recv, ~send, ~close, rw, key, framed, want)

def wsm_client_echo_conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), conn: Result<&1, &1, U32 & String, Socket>, +host: String, port: U32, rr: HTTP.Request, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      wsm_client_echo_tls_sock(~recv, ~send, ~close, sock, host, port, rr, key, framed, want)

def wsm_client_echo_go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), +host: String, +port: U32, verify: Bool, rr: HTTP.Request, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match verify:
    case True{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn(host, port)
        wsm_client_echo_conn(~recv, ~send, ~close, conn, host, port, rr, key, framed, want)
    case False{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure(host, port)
        wsm_client_echo_conn(~recv, ~send, ~close, conn, host, port, rr, key, framed, want)

def wsm_client_echo_start(+host: String, port: U32, verify: Bool, +path: String, +key: String, req: Result<&1, &1, U32 & String, HTTP.Request>, framed: Result<&1, &1, U32 & String, List<&2, U32>>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match req:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+rr}:
      match framed:
        case Fail{e2}:
          IO.pure(Result<&1, &1, U32 & String, String>, Fail{e2})
        case Done{+fb}:
          wsm_client_echo_go(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, host, port, verify, rr, key, fb, want)

def wsm_client_echo_plain_sock(sock: Socket, +host: String, port: U32, rr: HTTP.Request, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match rr:
    case HTTP.Request{method, path, headers, body}:
      do IO<Result<&1, &1, U32 & String, String>>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- HTTP1.x_h1.cli.exch.open(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, sock, host, port, method, path, headers, body)
        rw : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open.rewrap(~Socket.close, out)
        wsm_client_echo_opened(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, rw, key, framed, want)

def wsm_client_echo_plain_conn(conn: Result<&1, &1, U32 & String, Socket>, +host: String, port: U32, rr: HTTP.Request, +key: String, +framed: List<&2, U32>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      wsm_client_echo_plain_sock(sock, host, port, rr, key, framed, want)

def wsm_client_echo_start_plain(+host: String, +port: U32, +path: String, +key: String, req: Result<&1, &1, U32 & String, HTTP.Request>, framed: Result<&1, &1, U32 & String, List<&2, U32>>, want: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match req:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+rr}:
      match framed:
        case Fail{e2}:
          IO.pure(Result<&1, &1, U32 & String, String>, Fail{e2})
        case Done{+fb}:
          do IO<Result<&1, &1, U32 & String, String>>:
            conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
            wsm_client_echo_plain_conn(conn, host, port, rr, key, fb, want)

def client_echo(+host: String, port: U32, +path: String, +key: String, +msg: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    fr : Result<&1, &1, U32 & String, List<&2, U32>> <- wsm_show_masked_random(True{}, 1, wsm_utf8_encode(msg))
    wsm_client_echo_start(host, port, True{}, path, key, wsm_client_request(path, key), fr, wsm_show_frame(True{}, 1, wsm_utf8_encode(msg)))

def client_echo_insecure(+host: String, port: U32, +path: String, +key: String, +msg: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    fr : Result<&1, &1, U32 & String, List<&2, U32>> <- wsm_show_masked_random(True{}, 1, wsm_utf8_encode(msg))
    wsm_client_echo_start(host, port, False{}, path, key, wsm_client_request(path, key), fr, wsm_show_frame(True{}, 1, wsm_utf8_encode(msg)))

def client_echo_plain(+host: String, port: U32, +path: String, +key: String, +msg: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    fr : Result<&1, &1, U32 & String, List<&2, U32>> <- wsm_show_masked_random(True{}, 1, wsm_utf8_encode(msg))
    wsm_client_echo_start_plain(host, port, path, key, wsm_client_request(path, key), fr, wsm_show_frame(True{}, 1, wsm_utf8_encode(msg)))
