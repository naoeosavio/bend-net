// TCP
// ===

// Packs the List<&2, U32> body into a byte buffer (a value past 255
// fails with EINVAL before any byte leaves), then sends what is left; a
// full socket (non-blocking, so EAGAIN) parks the computation until the
// socket is writable and the loop resumes here.
static Term send_bytes_more(Env e, IoWork* w) {
  int fd = (int)w->hand;
  while (w->code == 0 && (u64)w->made < w->size) {
    ssize_t n = send(fd, w->data + w->made, w->size - (u64)w->made, 0);
    if (n < 0 && errno == EAGAIN) {
      return io_wait_on(w, fd, POLLOUT, 0, send_bytes_more);
    }
    w->made += io_sys_end(w, n);
  }
  Term r = w->code != 0 ? io_fail(e, w->code, NULL)
    : io_done(e, term_pak(CID_UNIT, 0));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term send_bytes_run(Env e, Term* f, IoWork* w) {
  u64  cap = 64;
  Term xs  = f[1];
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->made = 0;
  w->code = 0;
  w->size = 0;
  w->data = io_mem(malloc(cap));
  while (term_aux(xs) == CID_CON) {
    Term fb[2];
    spare_free(e, cls_fit(2), ctr_take(e, xs, 2, fb));
    if (w->size == cap) {
      cap *= 2;
      w->data = io_mem(realloc(w->data, cap));
    }
    w->code = fb[0] > 255 ? EINVAL : w->code;
    w->data[w->size++] = (char)fb[0];
    xs = fb[1];
  }
  return send_bytes_more(e, w);
}

static void __attribute__((constructor)) send_bytes_use(void) {
  io_eff(CID_SEND_BYTES, send_bytes_run, 0);
}
