# io (wsm_surface): the pure TEXT surface the WSM exposes for callers
# that speak head text (tests, examples, the old ws.bend API), plus the
# transport instances and the send-and-close shape.
#
# Everything asserted here is a def a caller outside the lane can reach:
#   wsm_handshake / wsm_handshake_sub   raw request head -> the 101 head
#   wsm_show_101 / wsm_show_101_sub     a PINNED accept -> the 101 head
#   wsm_client_head / wsm_client_head_sub  the client head as text
#
# The transport instances (wsm_ship_plain/_tls, send_msg_plain/_tls) are
# one-line delegations to the template defs and are covered where they
# run over a socket: wsm_msg (wsm_ship_plain), ws_server_on /
# ws_server_once (send_msg_plain). This file is the pure half.
#
# Two of these checks exist because of bugs the migration found:
#   - show_101* used to recompute the Accept from an empty key instead of
#     rendering the Accept it was handed, so a pinned vector came back as
#     some other key's Accept (both show checks pin the RFC 6455 1.3
#     vector, and chk_show_ignores_the_accept_arg is the explicit
#     regression: same accept, different output would be a bug).
#   - the client head must ride x_h1.render_req.go with upgrade=True, so
#     Connection/Upgrade survive and no Content-Length appears (a
#     Content-Length: 0 in a handshake is the old show_resp bug in a new
#     coat).
#
# Golden is the sum of the checks below (the subprotocol, client-head,
# scan-length and host-port groups weigh more than one each).
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

law is_fail:
  for r: Result<&1, &1, U32 & String, String>
  U32

def is_fail(r):
  match r:
    case Fail{e}:
      1
    case Done{s}:
      0

law unwrap_str:
  for r: Result<&1, &1, U32 & String, String>
  String

def unwrap_str(r):
  match r:
    case Fail{e}:
      ""
    case Done{s}:
      s

# chk_handshake_sub: the offer is picked from the served list, and a
# disjoint offer still upgrades (RFC 6455 section 4.1: no protocol is
# not an error).

law head_str:
  for r: Result<&1, &1, U32 & String, String>
  String

def head_str(r):
  match r:
    case Fail{e}:
      ""
    case Done{s}:
      s

# chk_client_head_sub: the offer list joins into one protocol header.

law good_key:
  String

def good_key():
  "dGhlIHNhbXBsZSBub25jZQ=="

law rfc_accept:
  String

def rfc_accept():
  "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

law want_101:
  String

def want_101():
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

law want_101_proto:
  String

def want_101_proto():
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: p1\r\n\r\n"

law good_req:
  String

def good_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

law proto_req:
  String

def proto_req():
  "GET /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: p1, p2\r\nSec-WebSocket-Version: 13\r\n\r\n"

law post_req:
  String

def post_req():
  "POST /chat HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

# chk_handshake: the RFC 6455 section 1.3 vector, end to end through the
# H1 parse and the H1 render.
law chk_handshake:
  U32

def chk_handshake():
  resp_eq(WSM.wsm_handshake(good_req()), want_101())

# chk_handshake_fails: fail-closed on a non-GET, same 400 the lane gives.
law chk_handshake_fails:
  U32

def chk_handshake_fails():
  is_fail(WSM.wsm_handshake(post_req()))

# chk_show_101: a pinned accept renders verbatim (no key involved).
law chk_show_101:
  U32

def chk_show_101():
  resp_eq(WSM.wsm_show_101(rfc_accept()), want_101())

# chk_show_101_sub: the picked protocol rides the head.
law chk_show_101_sub:
  U32

def chk_show_101_sub():
  resp_eq(WSM.wsm_show_101_sub(rfc_accept(), Some{"p1"}), want_101_proto())

# chk_show_101_noproto: None picks nothing and adds no header.
law chk_show_101_noproto:
  U32

def chk_show_101_noproto():
  resp_eq(WSM.wsm_show_101_sub(rfc_accept(), None{}), want_101())

# chk_show_ignores_the_accept_arg: the regression. The Accept the caller
# hands in is the one that comes out: an implementation that recomputes
# it from an empty key would render a DIFFERENT accept for the same
# input, and this check is what pins "same accept in, same accept out".
law chk_show_ignores_the_accept_arg:
  U32

def chk_show_ignores_the_accept_arg():
  (b2u(String.eq(unwrap_str(WSM.wsm_show_101(rfc_accept())), want_101()))
   + b2u(Bool.not(String.contains(unwrap_str(WSM.wsm_show_101(rfc_accept())), "Kfh9QIsMVZcl6xEPYxPHzW8SZ8w=")))
   + b2u(Bool.not(String.contains(unwrap_str(WSM.wsm_show_101(rfc_accept())), "==\r\n\r\nHTTP"))) : U32)

law chk_handshake_sub:
  U32

def chk_handshake_sub():
  (resp_eq(WSM.wsm_handshake_sub(proto_req(), ["p1"]), want_101_proto())
   + resp_eq(WSM.wsm_handshake_sub(proto_req(), ["zzz"]), want_101()) : U32)

# chk_client_head: the client head is the H1 render with upgrade=True —
# Upgrade/Connection survive, no Content-Length (that was the show_resp
# bug), and the key we asked for is on the wire.
law chk_client_head:
  U32

def chk_client_head():
  (b2u(String.contains(head_str(WSM.wsm_client_head("s", 8080, "/chat", good_key())), "Host: s:8080\r\n"))
   + b2u(String.contains(head_str(WSM.wsm_client_head("s", 8080, "/chat", good_key())), "Connection: Upgrade\r\n"))
   + b2u(Bool.not(String.contains(head_str(WSM.wsm_client_head("s", 8080, "/chat", good_key())), "Content-Length"))) : U32)

law chk_client_head_sub:
  U32

def chk_client_head_sub():
  b2u(String.contains(head_str(WSM.wsm_client_head_sub("s", 8080, "/chat", good_key(), ["p1", "p2"])), "Sec-WebSocket-Protocol: p1, p2\r\n"))

# chk_client_head_bad: a CRLF in the key fails 400 before any byte.
law chk_client_head_bad:
  U32

def chk_client_head_bad():
  is_fail(WSM.wsm_client_head("s", 8080, "/chat", "a\r\nX: y"))

# chk_scan_len: the compat client_scan_len answers the head length up to
# and including the CRLFCRLF terminator — the three vectors the old
# ws_scan_len pinned (short head, terminator mid-buffer with a byte after
# it, and a coalesced head+frame segment).
law short_head:
  List<&2, U32>

def short_head():
  [65, 66, 13, 10, 13, 10]

law mid_bytes:
  List<&2, U32>

def mid_bytes():
  [65, 13, 10, 13, 10, 66]

law chk_scan_len:
  U32

def chk_scan_len():
  (b2u(U32.is_eq(WSM.client_scan_len(short_head()), 6))
   + b2u(U32.is_eq(WSM.client_scan_len(mid_bytes()), 5))
   + b2u(U32.is_eq(WSM.client_scan_len(List.append(&2, U32, short_head(), [129, 5, 72, 101, 108, 108, 111])), 6)) : U32)

# chk_host_port: the compat formatter keeps the RETIRED rule — the
# default port (80/443) is omitted. It is caller vocabulary only: the
# check right below pins the opposite rule on the wire.
law chk_host_port:
  U32

def chk_host_port():
  (b2u(String.eq(WSM.ws_host_port("s", 80), "s"))
   + b2u(String.eq(WSM.ws_host_port("s", 443), "s"))
   + b2u(String.eq(WSM.ws_host_port("s", 8080), "s:8080")) : U32)

# chk_wire_host_port: the WSM's own client head always renders
# host:port, INCLUDING the default port 80 — the H1 renderer owns the
# Host (same rule pinned for the lane by httpx_h1_upgrade_client, which
# asserts "Host: h:80"). The compat formatter above must never be used
# to build a WSM request.
law chk_wire_host_port:
  U32

def chk_wire_host_port():
  b2u(String.contains(head_str(WSM.wsm_client_head("s", 80, "/chat", good_key())), "Host: s:80\r\n"))

# chk_utf8: the text lane of WSText (TASK-028 Phase 5.9 moved it back
# here from httpx, which never called it). The multi-byte branches are
# the point: every ws_* test sends ASCII, so before this group the
# encoder/decoder were covered only by the (uncommitted) scratch codec
# test. Vectors: "olá" is o,l + a 2-byte á; 8364 (€) is the 3-byte case
# and 128512 (U+1F600) the 4-byte one, both by code point so no literal
# is needed. The two invalid vectors are the classic traps: a truncated
# 2-byte tail and an overlong 0xC0 lead (which must NOT decode to '/').
law chk_utf8:
  U32

def chk_utf8():
  (b2u(U32.is_eq(eq_list(WSM.wsm_utf8_encode("olá"), [111, 108, 195, 161]), 1))
   + b2u(String.eq(WSM.wsm_utf8_decode(WSM.wsm_utf8_encode("olá")), "olá"))
   + b2u(U32.is_eq(eq_list(WSM.wsm_utf8_encode_char(8364), [226, 130, 172]), 1))
   + b2u(U32.is_eq(eq_list(WSM.wsm_utf8_encode_char(128512), [240, 159, 152, 128]), 1))
   + b2u(WSM.wsm_utf8_ok([104, 195, 169]))
   + b2u(Bool.not(WSM.wsm_utf8_ok([104, 195])))
   + b2u(Bool.not(WSM.wsm_utf8_ok([192, 175]))) : U32)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +score : U32 = (chk_handshake() + chk_handshake_fails() + chk_show_101() + chk_show_101_sub() + chk_show_101_noproto() + chk_show_ignores_the_accept_arg() + chk_handshake_sub() + chk_client_head() + chk_client_head_sub() + chk_client_head_bad() + chk_scan_len() + chk_host_port() + chk_wire_host_port() + chk_utf8() : U32)
    w : Unit <- IO.print(U32.show(score))
    return score

#|29