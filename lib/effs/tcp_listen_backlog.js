// TCP
// ===

// The JS twin of tcp_listen_backlog.c: the runtime's own listen hardcodes
// an accept-queue depth of 16, so a burst of more dials than that drops
// the excess SYNs and every dropped dial waits out the TCP retry (~1s,
// measured in TASK-041). Same Listener handle, same failure shape as
// io_fail (code + its strerror).
function listen_backlog(port, backlog, k) {
  const sys = io_sys();
  port = Number(port);
  backlog = Number(backlog);
  if (Number.isNaN(port) || port < 0 || port > 65535 || backlog < 1) {
    return io_fail(22);
  }
  const at = io_addr("0.0.0.0", port);
  if (at === null) {
    return io_fail(22);
  }
  const fd = sys.socket(2, 1, 0);
  if (fd < 0) {
    return io_fail(sys.errno());
  }
  const sol_socket = sys.mac ? 0xffff : 1;
  const so_reuseaddr = sys.mac ? 4 : 2;
  const one = Uint8Array.of(1, 0, 0, 0);
  const _rc = sys.setsockopt(fd, sol_socket, so_reuseaddr, sys.ptr(one), 4);
  if (sys.bind(fd, sys.ptr(at), at.length) < 0
    || sys.listen(fd, backlog) < 0
    || sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800)) < 0) {
    const code = sys.errno();
    sys.close(fd);
    return io_fail(code);
  }
  return io_done(fd);
}
