// TCP
// ===

// One framed read: bytes already held (buf) plus the socket until exactly
// one WS frame is isolated. The length prefix alone decides the total
// (2 + ext 0/2/8 + mask 0/4 + payload); nothing is validated here, the
// pure codec above rejects bad frames out of the isolated bytes. Answers
// Done{(frame, rest)}: the frame plus every byte read past it, so the
// caller threads the rest into the next call and no byte is lost.
static u64 recv_frame_need(uint8_t* d, u64 n) {
  if (n < 2) {
    return 0;
  }
  u64 len7 = d[1] & 127;
  u64 ext  = len7 == 126 ? 2 : len7 == 127 ? 8 : 0;
  if (n < 2 + ext) {
    return 0;
  }
  u64 pay = len7;
  if (len7 == 126) {
    pay = ((u64)d[2] << 8) | d[3];
  }
  if (len7 == 127) {
    pay = 0;
    for (u64 i = 0; i < 8; i += 1) {
      pay = (pay << 8) | d[2 + i];
    }
  }
  return 2 + ext + ((d[1] & 128) ? 4 : 0) + pay;
}

static Term recv_frame_pack(Env e, IoWork* w, u64 total) {
  Term frame = term_pak(CID_NIL, 0);
  for (u64 i = total; i > 0; i -= 1) {
    frame = io_node(e, CID_CON, ((uint8_t*)w->data)[i - 1], frame);
  }
  Term rest = term_pak(CID_NIL, 0);
  for (u64 i = (u64)w->made; i > total; i -= 1) {
    rest = io_node(e, CID_CON, ((uint8_t*)w->data)[i - 1], rest);
  }
  Term r = io_done(e, io_tup(e, frame, rest));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

static Term recv_frame_fail(Env e, IoWork* w, u32 code, const char* text) {
  free(w->data);
  return io_tup(e, io_hand(w->hand), io_fail(e, code, text));
}

// The header is checked before every recv, so bytes already held that
// complete a frame answer with no syscall; a recv that still finds
// nothing (the socket is non-blocking) parks again; EOF before the
// frame completes fails instead of spinning.
static Term recv_frame_more(Env e, IoWork* w) {
  int fd  = (int)w->hand;
  u64 max = (u64)w->word;
  for (;;) {
    u64 total = recv_frame_need((uint8_t*)w->data, (u64)w->made);
    if (total != 0 && (u64)w->made >= total) {
      if (total > max) {
        return recv_frame_fail(e, w, 413, "frame too large");
      }
      return recv_frame_pack(e, w, total);
    }
    if (total != 0 && total > max) {
      return recv_frame_fail(e, w, 413, "frame too large");
    }
    if ((u64)w->made == w->size) {
      u64 cap = total != 0 ? total : w->size * 2;
      if (total == 0 && cap > max) {
        cap = max;
      }
      if (cap <= (u64)w->made) {
        return recv_frame_fail(e, w, 413, "frame too large");
      }
      w->data = io_mem(realloc(w->data, (size_t)cap));
      w->size = cap;
    }
    ssize_t n = recv(fd, w->data + w->made, w->size - (u64)w->made, 0);
    if (n < 0 && errno == EAGAIN) {
      return io_wait_on(w, fd, POLLIN, 0, recv_frame_more);
    }
    if (n < 0) {
      io_sys_end(w, n);
      return recv_frame_fail(e, w, w->code, NULL);
    }
    if (n == 0) {
      return recv_frame_fail(e, w, 400, "eof");
    }
    w->made += (intptr_t)io_sys_end(w, n);
  }
}

// The bytes as they are (0..255), one List cell each, seed the buffer;
// an empty list starts it empty.
Term recv_frame_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->word = (u32)f[2];
  u64  cap = 256;
  u64  n   = 0;
  char* buf = io_mem(malloc(cap > 0 ? cap : 1));
  Term  s   = f[1];
  while (term_aux(s) == CID_CON) {
    Term fb[2];
    spare_free(e, cls_fit(2), ctr_take(e, s, 2, fb));
    if (n >= cap) {
      cap *= 2;
      buf = io_mem(realloc(buf, cap));
    }
    buf[n] = (char)((uint8_t)(fb[0] & 0xFF));
    n += 1;
    s  = fb[1];
  }
  w->data = buf;
  w->size = cap;
  w->made = (intptr_t)n;
  w->code = 0;
  return recv_frame_more(e, w);
}

static void __attribute__((constructor)) recv_frame_use(void) {
  io_eff(CID_RECV_FRAME, recv_frame_run, IO_READ);
}
