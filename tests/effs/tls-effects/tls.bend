import Base
# Contract file for the native-host `tls` lane this package stages. The
# package ships the JS twins only -- there is no C here to keep in step
# (tls-generic/tls.bend makes the same choice), so each def imports its
# `.js` alone. How the lane was built and why it lost to the portable
# pump: tasks/task-043-js-lane-tls-pure.md.
#
# The raw client handshake: connects to the IPv4 ip, SNIs sni, verifies
# the chain iff verify is 1. ALPN mode: alpn=1 offers and requires h2,
# alpn=2 offers h2/http/1.1, alpn=3 offers only http/1.1, and
# alpn=0 offers nothing. Answers the TLS handle on Done.
def tls_connect_raw(ip: String, sni: String, port: U32, verify: U32, alpn: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  import "./effs/tls_connect.js"

# The raw server handshake returns the selected ALPN protocol beside the
# socket. offer=1 picks h2 when the peer offers it; offer=2 accepts
# h2/http1.1; offer=3 accepts only http/1.1.
def tls_accept_raw(listener: Listener, cert: String, key: String, offer: U32) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket & String>):
  import "./effs/tls_accept.js"

# Sends every byte of the list over the TLS socket, handing it back. A
# value past 255 fails with EINVAL before any byte leaves; WANT_READ /
# WANT_WRITE parks on the underlying fd until ready.
def tls_send_bytes(sock: Socket, data: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/tls_send_bytes.js"

# Receives at most max bytes over the TLS socket as a byte list, handing
# it back; parks on the underlying fd when the peer wants more IO.
def tls_recv_bytes(sock: Socket, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  import "./effs/tls_recv_bytes.js"

# Shuts the session down, frees it and closes the underlying fd. TLS
# sockets must close here, never via Socket.close.
def tls_close(sock: Socket) -> IO(Unit):
  import "./effs/tls_close.js"