import Base
# The raw client handshake: connects to the IPv4 ip, SNIs sni, verifies
# the chain iff verify is 1. ALPN mode: alpn=1 offers and requires h2,
# alpn=2 offers h2/http/1.1, alpn=3 offers only http/1.1, and
# alpn=0 offers nothing. Answers the TLS socket (SSL*) on Done.
def tls_connect_raw(ip: String, sni: String, port: U32, verify: U32, alpn: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  import "./effs/tls_connect.c"
  import "./effs/tls_connect.js" 

# The raw server handshake returns the selected ALPN protocol beside the
# socket. offer=1 requires h2; offer=2 accepts h2/http1.1; offer=3 accepts
# only http/1.1.
def tls_accept_raw(listener: Listener, cert: String, key: String, offer: U32) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket & String>):
  import "./effs/tls_accept.c"
  import "./effs/tls_accept.js"

# Sends every byte of the list over the TLS socket, handing it back. A
# value past 255 fails with EINVAL before any byte leaves; WANT_READ /
# WANT_WRITE parks on the underlying fd until ready.
def tls_send_bytes(sock: Socket, data: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/tls_send_bytes.c"
  import "./effs/tls_send_bytes.js"

# Receives at most max bytes over the TLS socket as a byte list, handing
# it back; parks on the underlying fd when OpenSSL wants more IO.
def tls_recv_bytes(sock: Socket, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  import "./effs/tls_recv_bytes.c"
  import "./effs/tls_recv_bytes.js"

# Shuts the session down, frees it and closes the underlying fd. TLS
# sockets must close here, never via Socket.close.
def tls_close(sock: Socket) -> IO(Unit):
  import "./effs/tls_close.c"
  import "./effs/tls_close.js"