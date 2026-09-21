# bend-net: package entry for BendHub.
# Source: https://github.com/naoeosavio/bend-net.git
#
# HTTP/1.1 and WebSocket (RFC 6455) over TCP for Bend (no TLS), with
# package-local DNS for name hosts. Pure Bend on top of the Base TCP.*
# kit; the only native code is the byte-level socket effects in ./effs/
# (C + JS twins: send_bytes, recv_bytes, recv_frame) plus the A-record
# resolver (dns_resolve). No compiler change.
# Boundaries: fetch reads at most 8 x 8192 bytes (64 KB cap); https:// is
# refused with Fail 501; resolution fails closed with 601-605 and never
# touches the Host header.
#
# Package entry point. Publish with:
#
#   bend lib/package.bend --publish
#
# Then import an API from its own file (imports are not transitive,
# so the entry only marks the bundle ready):
#
#   import 0x<hash>/http.bend as HTTP
#   import 0x<hash>/ws.bend   as WS
#   import 0x<hash>/sha1.bend as SHA1
#   import 0x<hash>/b64.bend  as B64
#   import 0x<hash>/tcp.bend  as TCP
#   import 0x<hash>/dns.bend  as DNS
#
# See README.md for the full guide.
import Base
import ./b64.bend as B64
import ./dns.bend as DNS
import ./http.bend as HTTP
import ./sha1.bend as SHA1
import ./tcp.bend as TCP
import ./ws.bend as WS

# Marks the bundle ready; the API lives in http.bend, ws.bend
# (with sha1.bend and b64.bend for the handshake), tcp.bend, whose
# byte effects WS frames ride, and dns.bend, whose resolve feeds the
# HTTP fetch lane.
def Package.ready() -> Unit:
  Unit{}
