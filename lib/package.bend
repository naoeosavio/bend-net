# bend-net: package entry for BendHub.
# Source: https://github.com/naoeosavio/bend-net.git
#
# The bundle is two complete libraries plus the leaf lanes they ride on:
# - HTTPX (./httpx.bend) is the HTTP library: HTTP/1.1 and HTTP/2,
#   client and server, plaintext (`http://`) and TLS (`https://`), ALPN
#   split, streaming in both directions and the H1 `101` upgrade lane.
# - WSM (./wsm.bend) is the WebSocket library (RFC 6455): client and
#   server over `ws://` and `wss://`, riding the HTTPX upgrade lane.
# The other imports are the lanes those two sit on: TLS (accept and
# dial, ALPN), TCP (sockets), DNS (the A-record behind every dial; the
# resolved IP is transport-only, `Host` keeps the original name), and
# SHA1 + B64 behind `Sec-WebSocket-Accept`.
#
# The retired per-protocol modules (http.bend, http1.bend, http2.bend,
# https.bend, https_http1.bend, ws.bend, wss.bend) are out of this bundle:
# HTTPX and WSM replace them, one lib per protocol family.
#
# Boundaries: every lane fails closed — HTTP 400 / 413 / 502 on
# malformed input (never a partial answer), DNS 601-605, TLS 611-616.
# Pure Bend over the Base TCP.* kit; the native code is the byte-level
# socket effects in ./effs/ (C + JS twins), the resolver and the TLS
# lane (OpenSSL via dlopen). No compiler change.
#
# Package entry point. Publish with:
#
#   bend lib/package.bend --publish
#
# Then import an API from its own file (imports are not transitive,
# so the entry only marks the bundle ready):
#
#   import 0x<hash>/httpx.bend as HTTPX
#   import 0x<hash>/wsm.bend   as WSM
#   import 0x<hash>/sha1.bend  as SHA1
#   import 0x<hash>/b64.bend   as B64
#   import 0x<hash>/tcp.bend   as TCP
#   import 0x<hash>/dns.bend   as DNS
#   import 0x<hash>/tls.bend   as TLS
#
# See README.md for the full guide.
import Base
import ./b64.bend as B64
import ./dns.bend as DNS
import ./httpx.bend as HTTPX
import ./sha1.bend as SHA1
import ./tcp.bend as TCP
import ./tls.bend as TLS
import ./wsm.bend as WSM

# Marks the bundle ready; the API lives in httpx.bend (the HTTP library:
# H1 + H2 + HTTPS, client and server, and the upgrade lane wsm.bend
# hands the socket to) and wsm.bend (the WebSocket library: handshake,
# frame codec and the session loop, ws:// + wss://), over tcp.bend for
# the sockets, dns.bend for the dial's name resolution, tls.bend for the
# handshake on both lanes, and sha1.bend + b64.bend for the WebSocket
# accept token.
def Package.ready() -> Unit:
  Unit{}