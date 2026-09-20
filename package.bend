# HTTP/1.1 and WebSocket over TCP for Bend (no TLS, no DNS).
#
# Package entry point. Publish with:
#
#   bend package.bend --publish
#
# Then import an API from its own file (imports are not transitive,
# so the entry only marks the bundle ready):
#
#   import 0x<hash>/lib/http.bend as HTTP
#   import 0x<hash>/lib/ws.bend   as WS
#   import 0x<hash>/lib/sha1.bend as SHA1
#   import 0x<hash>/lib/b64.bend  as B64
#   import 0x<hash>/lib/tcp.bend  as TCP
#
# See README.md for the full guide.
import Base
import ./lib/b64.bend as B64
import ./lib/http.bend as HTTP
import ./lib/sha1.bend as SHA1
import ./lib/tcp.bend as TCP
import ./lib/ws.bend as WS

# Marks the bundle ready; the API lives in lib/http.bend, lib/ws.bend
# (with lib/sha1.bend and lib/b64.bend for the handshake) and in
# lib/tcp.bend, whose byte effects WS frames ride.
def Package.ready() -> Unit:
  Unit{}
