# bend-net: package entry for BendHub.
# Source: https://github.com/naoeosavio/bend-net.git
#
# HTTP/1.1 and WebSocket (RFC 6455) over TCP for Bend, with
# package-local DNS and TLS (client + server, ALPN h2). Pure Bend on
# top of the Base TCP.* kit; the native code is the byte-level socket
# effects in ./effs/ (C + JS twins: send_bytes, recv_bytes, recv_frame),
# the A-record resolver (dns_resolve) and the TLS lane (tls_*: OpenSSL
# via dlopen). No compiler change.
# Boundaries: fetch reads at most 8 x 8192 bytes (64 KB cap); https://
# rides lib/tls.bend (fetch still returns Fail 501 until wired); TLS
# fails closed with 611-616; resolution fails closed with 601-605 and
# never touches the Host header.
#
# Package entry point. Publish with:
#
#   bend lib/package.bend --publish
#
# Then import an API from its own file (imports are not transitive,
# so the entry only marks the bundle ready):
#
#   import 0x<hash>/http.bend as HTTP
#   import 0x<hash>/http2.bend as HTTP2
#   import 0x<hash>/ws.bend   as WS
#   import 0x<hash>/sha1.bend as SHA1
#   import 0x<hash>/b64.bend  as B64
#   import 0x<hash>/tcp.bend  as TCP
#   import 0x<hash>/dns.bend  as DNS
#   import 0x<hash>/tls.bend  as TLS
#
# See README.md for the full guide.
import Base
import ./b64.bend as B64
import ./dns.bend as DNS
import ./http.bend as HTTP
import ./http2.bend as HTTP2
import ./sha1.bend as SHA1
import ./tcp.bend as TCP
import ./tls.bend as TLS
import ./ws.bend as WS

# Marks the bundle ready; the API lives in http.bend, ws.bend
# (with sha1.bend and b64.bend for the handshake), tcp.bend, whose
# byte effects WS frames ride, dns.bend, whose resolve feeds the
# HTTP fetch lane, and tls.bend, whose handshake lane feeds the
# coming HTTP/2.
def Package.ready() -> Unit:
  Unit{}
