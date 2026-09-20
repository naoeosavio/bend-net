# TCP byte effects: raw send, raw recv and one-frame recv over the
# existing Socket handle.
#
# The binary twins of Base's TCP.send / TCP.recv (which speak String), so
# WebSocket frames are not forced through UTF-8.
#
# Import as: import ./tcp.bend as TCP (from lib) or
# import ../../lib/tcp.bend as TCP (from tests/io).
# Then TCP.send_bytes, TCP.recv_bytes, TCP.recv_frame.
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

# Isolates exactly one WebSocket frame: reads the socket until the length
# prefix says the frame is complete, then answers the frame plus every
# byte already read past it, so the caller threads the rest into the next
# call and no byte is lost. `buf` seeds the read (usually the previous
# rest); `max` caps the frame (a larger total is Fail 413), a partial EOF
# is Fail 400 "eof". The length prefix alone decides the size; the pure
# codec rejects invalid frames out of the isolated bytes.
def recv_frame(sock: Socket, buf: List<&2, U32>, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32> & List<&2, U32>>):
  import "./effs/tcp_recv_frame.c"
  import "./effs/tcp_recv_frame.js"