# bend-net: package entry for BendHub.
# Source: https://github.com/naoeosavio/bend-net.git
#
# The bundle is four HTTP modules plus the WebSocket library and the leaf
# lanes they ride on:
# - HTTP (./http.bend) is the core: the 25 Data types, the byte and text
#   leaves, the string checks and the request validation.
# - HTTP1 (./http1.bend) is the HTTP/1.1 wire: codec, reason table,
#   chunked, keep-alive, the two stream lanes and the `101` machine.
# - HTTP2 (./http2.bend) is the HTTP/2 wire: frames, HPACK, the flow
#   pump and the connection loops.
# - HTTPX (./httpx.bend) is the facade: the public entries, the TLS/TCP
#   dial, the accept and the ALPN split. HTTP/1.1, HTTP/2, plaintext
#   (`http://`) and TLS (`https://`) all enter here.
# - WSM (./wsm.bend) is the WebSocket library (RFC 6455): client and
#   server over `ws://` and `wss://`, riding the HTTPX upgrade lane.
# The other imports are the lanes those sit on: TLS (accept and dial,
# ALPN), TCP (sockets), DNS (the A-record behind every dial; the resolved
# IP is transport-only, `Host` keeps the original name), and SHA1 + B64
# behind `Sec-WebSocket-Accept`.
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
#   import 0x<hash>/http.bend  as HTTP
#   import 0x<hash>/http1.bend as HTTP1
#   import 0x<hash>/http2.bend as HTTP2
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
import ./http.bend as HTTP
import ./http1.bend as HTTP1
import ./http2.bend as HTTP2
import ./httpx.bend as HTTPX
import ./sha1.bend as SHA1
import ./tcp.bend as TCP
import ./tls.bend as TLS
import ./wsm.bend as WSM

# Marks the bundle ready; the API lives in httpx.bend (the facade: the
# entries, the dial, the accept and the ALPN split) over http.bend (the
# core), http1.bend (the H1 wire) and http2.bend (the H2 wire), and in
# wsm.bend (the WebSocket library: handshake, frame codec and the session
# loop, ws:// + wss://), over tcp.bend for the sockets, dns.bend for the
# dial's name resolution, tls.bend for the handshake on both lanes, and
# sha1.bend + b64.bend for the WebSocket accept token.
def Package.ready() -> Unit:
  Unit{}