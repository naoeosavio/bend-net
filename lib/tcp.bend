# TCP byte effects: raw send, raw recv and one-frame recv over the
# existing Socket handle, plus a listener with a real accept-queue depth.
#
# The binary twins of Base's TCP.send / TCP.recv (which speak String), so
# WebSocket frames are not forced through UTF-8.
#
# Import as: import ./tcp.bend as TCP (from lib) or
# import ../../lib/tcp.bend as TCP (from tests/io).
# Then TCP.send_bytes, TCP.recv_bytes, TCP.recv_frame, TCP.listen_backlog.
import Base

# The accept-queue depth used by listen_backlog: Base's TCP.listen fixes
# the queue at 16, so a burst of more dials than that makes the kernel
# drop the excess SYNs and every dropped dial waits out the TCP retry
# (~1s, measured in TASK-041). 128 covers the 20-40 client bursts the
# examples drive with room to spare and stays under the usual
# net.core.somaxconn; pass a bigger number to listen_backlog if a server
# really expects more.
def LISTEN_BACKLOG() -> U32:
  128

# Listens on a port with an explicit accept-queue depth (SO_REUSEADDR,
# 0.0.0.0, non-blocking, like Base's TCP.listen). Answers the same
# Listener handle, so every server entry that takes one accepts it, and
# fails the same way: the errno as the code and its message. Backlog 0
# fails with EINVAL instead of asking the kernel for an unusable queue.
def listen_backlog(port: U32, backlog: U32) ->
  IO(Result<&1, &1, U32 & String, Listener>):
  import "./effs/tcp_listen_backlog.c"
  import "./effs/tcp_listen_backlog.js"

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