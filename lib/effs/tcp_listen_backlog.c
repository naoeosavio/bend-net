// TCP
// ===

// The runtime's own listen hardcodes an accept-queue depth of 16 (see the
// emitted tcp_listen), so a burst of more dials than that overflows the
// queue, the kernel drops the excess SYNs and every dropped dial waits out
// the TCP retry (~1s, measured in TASK-041). This twin takes the depth as
// an argument, answers the same Listener handle and keeps the runtime's
// failure shape: the errno is the code, io_fail builds the message.
uint32_t tcp_listen_backlog(uint32_t port, uint32_t backlog, int* out) {
  if (backlog == 0) {
    return EINVAL;
  }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return (uint32_t)errno;
  }
  int one = 1;
  int _rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  // Best effort, like the runtime's listen: no REUSEADDR costs a
  // TIME_WAIT rebind, never the listener.
  (void)_rc;
  struct sockaddr_in at;
  if (io_sys_addr("0.0.0.0", port, &at) < 0) {
    close(fd);
    return EINVAL;
  }
  int bound = bind(fd, (struct sockaddr*)&at, sizeof(at));
  if (bound < 0 || listen(fd, (int)backlog) < 0
    || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
    uint32_t code = (uint32_t)errno;
    close(fd);
    return code;
  }
  *out = fd;
  return 0;
}

Term listen_backlog_run(Env e, Term* f, IoWork* w) {
  int out;
  uint32_t q = tcp_listen_backlog((uint32_t)f[0], (uint32_t)f[1], &out);
  if (q != 0) {
    return io_fail(e, q, NULL);
  }
  return io_done(e, io_hand(out));
}

static void __attribute__((constructor)) listen_backlog_use(void) {
  io_eff(CID_LISTEN_BACKLOG, listen_backlog_run, 0);
}
