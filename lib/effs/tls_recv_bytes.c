// TLS recv: one SSL_read of at most max bytes, packed as List cells.
// WANT_READ parks on POLLIN, WANT_WRITE on POLLOUT. The handle is a
// TlsConn*; an orderly shutdown (read 0) answers the empty list.
#include <dlfcn.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>

#ifndef TLS_CONN_DEFINED
#define TLS_CONN_DEFINED
struct TlsConn {
  void* ssl;
  void* ctx;
  int   fd;
};
#endif

static void*          tls_r_h = NULL;
static pthread_mutex_t tls_r_gate = PTHREAD_MUTEX_INITIALIZER;
static int            tls_r_ready = 0;
static int   (*r_SSL_read)(void*, void*, int);
static int   (*r_SSL_get_error)(void*, int);

static u32 tls_r_init(void) {
  pthread_mutex_lock(&tls_r_gate);
  if (tls_r_ready) {
    pthread_mutex_unlock(&tls_r_gate);
    return 0;
  }
  tls_r_h = dlopen("libssl.so.3", RTLD_NOW);
  if (tls_r_h == NULL) {
    tls_r_h = dlopen("libssl.so", RTLD_NOW);
  }
  if (tls_r_h == NULL) {
    pthread_mutex_unlock(&tls_r_gate);
    return 616;
  }
#define TLS_R_SYM(n)                                    \
  r_##n = dlsym(tls_r_h, #n);                           \
  if (r_##n == NULL) {                                  \
    pthread_mutex_unlock(&tls_r_gate);                  \
    return 616;                                         \
  }
  TLS_R_SYM(SSL_read)
  TLS_R_SYM(SSL_get_error)
#undef TLS_R_SYM
  tls_r_ready = 1;
  pthread_mutex_unlock(&tls_r_gate);
  return 0;
}

static Term tls_recv_pack(Env e, IoWork* w) {
  Term r;
  if (w->code) {
    r = io_fail(e, w->code, w->code == 616 ? "tls error" : NULL);
  } else {
    Term xs = term_pak(CID_NIL, 0);
    for (u64 i = w->size; i > 0; i -= 1) {
      xs = io_node(e, CID_CON, ((uint8_t*)w->data)[i - 1], xs);
    }
    r = io_done(e, xs);
  }
  free(w->data);
  w->data = NULL;
  return io_tup(e, io_hand(w->hand), r);
}

static Term tls_recv_more(Env e, IoWork* w) {
  struct TlsConn* c = (struct TlsConn*)(intptr_t)w->hand;
  int n = r_SSL_read(c->ssl, w->data, (int)w->made);
  if (n < 0) {
    int err = r_SSL_get_error(c->ssl, n);
    if (err == 2) {
      return io_wait_on(w, c->fd, POLLIN, 0, tls_recv_more);
    }
    if (err == 3) {
      return io_wait_on(w, c->fd, POLLOUT, 0, tls_recv_more);
    }
    w->code = 616;
    w->size = 0;
    return tls_recv_pack(e, w);
  }
  // n == 0 is an orderly shutdown: answer what we hold (empty here,
  // single-shot read), not an error.
  w->size = n < 0 ? 0 : (u64)n;
  w->code = 0;
  return tls_recv_pack(e, w);
}

Term tls_recv_bytes_run(Env e, Term* f, IoWork* w) {
  u32 q = tls_r_init();
  if (q != 0) {
    Term r = io_fail(e, q, "tls error");
    return io_tup(e, f[0], r);
  }
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->made = f[1] < INT32_MAX ? (intptr_t)f[1] : INT32_MAX;
  if (w->made <= 0) {
    w->made = 1;
  }
  w->data = io_mem(malloc((size_t)w->made + 1));
  w->size = 0;
  w->code = 0;
  return tls_recv_more(e, w);
}

static void __attribute__((constructor)) tls_recv_bytes_use(void) {
  io_eff(CID_TLS_RECV_BYTES, tls_recv_bytes_run, 0);
}
