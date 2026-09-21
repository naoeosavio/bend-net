// TLS send: packs List<&2, U32> (a value past 255 fails EINVAL before
// any byte leaves), then SSL_writes it; WANT_READ parks on POLLIN and
// WANT_WRITE on POLLOUT until done. The handle is a TlsConn*.
#include <dlfcn.h>
#include <fcntl.h>
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

static void*          tls_w_h = NULL;
static pthread_mutex_t tls_w_gate = PTHREAD_MUTEX_INITIALIZER;
static int            tls_w_ready = 0;
static int   (*w_SSL_write)(void*, const void*, int);
static int   (*w_SSL_get_error)(void*, int);
static int   (*w_SSL_get_fd)(void*);

static u32 tls_w_init(void) {
  pthread_mutex_lock(&tls_w_gate);
  if (tls_w_ready) {
    pthread_mutex_unlock(&tls_w_gate);
    return 0;
  }
  tls_w_h = dlopen("libssl.so.3", RTLD_NOW);
  if (tls_w_h == NULL) {
    tls_w_h = dlopen("libssl.so", RTLD_NOW);
  }
  if (tls_w_h == NULL) {
    pthread_mutex_unlock(&tls_w_gate);
    return 616;
  }
#define TLS_W_SYM(n)                                    \
  w_##n = dlsym(tls_w_h, #n);                           \
  if (w_##n == NULL) {                                  \
    pthread_mutex_unlock(&tls_w_gate);                  \
    return 616;                                         \
  }
  TLS_W_SYM(SSL_write)
  TLS_W_SYM(SSL_get_error)
  TLS_W_SYM(SSL_get_fd)
#undef TLS_W_SYM
  tls_w_ready = 1;
  pthread_mutex_unlock(&tls_w_gate);
  return 0;
}

static Term tls_send_more(Env e, IoWork* w) {
  struct TlsConn* c = (struct TlsConn*)(intptr_t)w->hand;
  u64 at = (u64)w->made;
  while (at < w->size) {
    int n = w_SSL_write(c->ssl, w->data + at, (int)(w->size - at));
    if (n <= 0) {
      int err = w_SSL_get_error(c->ssl, n);
      if (err == 2) {
        w->made = (intptr_t)at;
        return io_wait_on(w, c->fd, POLLIN, 0, tls_send_more);
      }
      if (err == 3) {
        w->made = (intptr_t)at;
        return io_wait_on(w, c->fd, POLLOUT, 0, tls_send_more);
      }
      w->code = 616;
      break;
    }
    at += (u64)n;
    w->code = 0;
  }
  Term r = w->code != 0 ? io_fail(e, w->code, "tls error")
    : io_done(e, term_pak(CID_UNIT, 0));
  if (w->code != 0 || at >= w->size) {
    free(w->data);
    w->data = NULL;
  } else {
    // Unreachable: loop exits only when done or failed.
    free(w->data);
    w->data = NULL;
  }
  return io_tup(e, io_hand(w->hand), r);
}

Term tls_send_bytes_run(Env e, Term* f, IoWork* w) {
  u32 q = tls_w_init();
  if (q != 0) {
    Term r = io_fail(e, q, "tls error");
    return io_tup(e, f[0], r);
  }
  w->hand = (intptr_t)io_hand_v(f[0]);
  struct TlsConn* c = (struct TlsConn*)(intptr_t)w->hand;
  (void)c;
  u64  cap = 64;
  Term xs  = f[1];
  w->made = 0;
  w->code = 0;
  w->size = 0;
  w->data = io_mem(malloc(cap > 0 ? cap : 1));
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
  if (w->code == EINVAL) {
    Term r = io_fail(e, w->code, NULL);
    free(w->data);
    w->data = NULL;
    return io_tup(e, io_hand(w->hand), r);
  }
  return tls_send_more(e, w);
}

static void __attribute__((constructor)) tls_send_bytes_use(void) {
  io_eff(CID_TLS_SEND_BYTES, tls_send_bytes_run, 0);
}
