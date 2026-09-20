# TCP byte effects: raw send and recv over the existing Socket handle.
#
# The binary twin of Base's TCP.send / TCP.recv (which speak String), so
# WebSocket frames are not forced through UTF-8.
#
# Import as: import ../lib/tcp.bend as TCP
# Then TCP.send_bytes, TCP.recv_bytes.
import Base

# Sends every byte of the list, handing the socket back. A value past
# 255 fails with EINVAL before any byte leaves; a full socket (non-
# blocking, so EAGAIN) parks until writable.
def send_bytes(sock: Socket, data: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/tcp_send_bytes.c"
  import "./effs/tcp_send_bytes.js"

# Receives at most max bytes as a byte list, handing the socket back;
# parks until the socket is readable.
def recv_bytes(sock: Socket, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  import "./effs/tcp_recv_bytes.c"
  import "./effs/tcp_recv_bytes.js"
