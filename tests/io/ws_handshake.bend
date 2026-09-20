# lib (ws_handshake): WS handshake golden plus fail-closed paths.
# Golden RFC 6455 section 1.3 plus version, key and method rejects.
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

law good_req:
  String

def good_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

law bad_ver_req:
  String

def bad_ver_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n"

law nokey_req:
  String

def nokey_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"

law post_req:
  String

def post_req():
  "POST /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

law want_101:
  String

def want_101():
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

law chk_good:
  U32

def chk_good():
  resp_eq(WS.handshake(good_req()), want_101())

law chk_ver:
  U32

def chk_ver():
  is_fail400s(WS.handshake(bad_ver_req()))

law chk_key:
  U32

def chk_key():
  is_fail400s(WS.handshake(nokey_req()))

law chk_method:
  U32

def chk_method():
  is_fail400s(WS.handshake(post_req()))

law main:
  U32

def main():
  (chk_good() + chk_ver() + chk_key() + chk_method() : U32)

#|4
