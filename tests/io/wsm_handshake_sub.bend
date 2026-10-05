# lib (wsm_handshake_sub): WS subprotocol + strict handshake golden.
# Phase 2 of task-020: key base64-16, Connection tokenized, Host port,
# Sec-WebSocket-Protocol offer/pick, 101 with/without proto.
import Base
import ../../lib/wsm.bend as WSM

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law is_fail400s:
  for r: Result<&1, &1, U32 & String, String>
  U32

def is_fail400s(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))
    case Done{s}:
      0

law is_done:
  for r: Result<&1, &1, U32 & String, String>
  U32

def is_done(r):
  match r:
    case Fail{e}:
      0
    case Done{s}:
      1

law resp_eq:
  for r: Result<&1, &1, U32 & String, String>
  for want: String
  U32

def resp_eq(r, want):
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, want))

law has_sub:
  for r: Result<&1, &1, U32 & String, String>
  for p: String
  U32

def has_sub(r, p):
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.contains(s, p))

law good_key:
  String

def good_key():
  "dGhlIHNhbXBsZSBub25jZQ=="

law bad_key_req:
  String

def bad_key_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: not-valid!!\r\nSec-WebSocket-Version: 13\r\n\r\n"

law multi_conn_req:
  String

def multi_conn_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

law not_upgrade_req:
  String

def not_upgrade_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: not-upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

law proto_req:
  String

def proto_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: p1, p2\r\nSec-WebSocket-Version: 13\r\n\r\n"

law want_101_proto:
  String

def want_101_proto():
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: p1\r\n\r\n"

law want_101:
  String

def want_101():
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

law chk_bad_key:
  U32

def chk_bad_key():
  is_fail400s(WSM.wsm_handshake(bad_key_req()))

law chk_multi_conn:
  U32

def chk_multi_conn():
  is_done(WSM.wsm_handshake(multi_conn_req()))

law chk_not_upgrade:
  U32

def chk_not_upgrade():
  is_fail400s(WSM.wsm_handshake(not_upgrade_req()))

law chk_key_ok:
  U32

def chk_key_ok():
  b2u(WSM.wsm_key_ok(good_key()))

law chk_key_bad:
  U32

def chk_key_bad():
  b2u(Bool.not(WSM.wsm_key_ok("not-valid!!")))

law chk_host_def:
  U32

def chk_host_def():
  b2u(String.eq(WSM.ws_host_port("s", 80), "s"))

law chk_host_port:
  U32

def chk_host_port():
  b2u(String.eq(WSM.ws_host_port("s", 8080), "s:8080"))

law chk_req_proto:
  U32

def chk_req_proto():
  has_sub(WSM.wsm_client_head_sub("s", 8080, "/chat", good_key(), ["p1", "p2"]), "Sec-WebSocket-Protocol: p1, p2")

law chk_101_proto:
  U32

def chk_101_proto():
  resp_eq(WSM.wsm_show_101_sub("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", Some{"p1"}), want_101_proto())

law chk_101_noproto:
  U32

def chk_101_noproto():
  resp_eq(WSM.wsm_show_101_sub("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", None{}), want_101())

law chk_hs_pick:
  U32

def chk_hs_pick():
  resp_eq(WSM.wsm_handshake_sub(proto_req(), ["p1"]), want_101_proto())

law chk_hs_disjoint:
  U32

def chk_hs_disjoint():
  resp_eq(WSM.wsm_handshake_sub(proto_req(), ["zzz"]), want_101())

law main:
  U32

def main():
  (chk_bad_key() + chk_multi_conn() + chk_not_upgrade() + chk_key_ok() + chk_key_bad() + chk_host_def() + chk_host_port() + chk_req_proto() + chk_101_proto() + chk_101_noproto() + chk_hs_pick() + chk_hs_disjoint() : U32)

#|12
