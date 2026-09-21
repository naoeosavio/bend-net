// TLS server handshake: accepts one TCP connection (parked, like
// TCP.accept) then handshakes it on the helper thread (blocking, so the
// loop stays free). Answers Listener & Result with an SSL session box
// (TlsConn*), never a raw fd. OpenSSL rides dlopen, no link flags.
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/socket.h>
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

struct TlsServe {
  char* cert;
  u64   cert_len;
  char* key;
  u64   key_len;
  int   fd;
  u32   code;
  void* conn;
};

static void*          tls_s_h = NULL;
static pthread_mutex_t tls_s_gate = PTHREAD_MUTEX_INITIALIZER;
static int            tls_s_ready = 0;
static void* (*s_TLS_server_method)(void);
static void* (*s_SSL_CTX_new)(void*);
static void  (*s_SSL_CTX_free)(void*);
static int   (*s_SSL_CTX_use_certificate_file)(void*, const char*, int);
static int   (*s_SSL_CTX_use_PrivateKey_file)(void*, const char*, int);
static void  (*s_SSL_CTX_set_alpn_select_cb)(void*, void*, void*);
static void* (*s_SSL_new)(void*);
static int   (*s_SSL_set_fd)(void*, int);
static int   (*s_SSL_accept)(void*);
static void  (*s_SSL_get0_alpn_selected)(const void*, const unsigned char**, unsigned*);
static int   (*s_SSL_shutdown)(void*);
static void  (*s_SSL_free)(void*);

static u32 tls_s_init(void) {
  pthread_mutex_lock(&tls_s_gate);
  if (tls_s_ready) {
    pthread_mutex_unlock(&tls_s_gate);
    return 0;
  }
  tls_s_h = dlopen("libssl.so.3", RTLD_NOW);
  if (tls_s_h == NULL) {
    tls_s_h = dlopen("libssl.so", RTLD_NOW);
  }
  if (tls_s_h == NULL) {
    pthread_mutex_unlock(&tls_s_gate);
    return 616;
  }
#define TLS_S_SYM(n)                                    \
  s_##n = dlsym(tls_s_h, #n);                           \
  if (s_##n == NULL) {                                  \
    pthread_mutex_unlock(&tls_s_gate);                  \
    return 616;                                         \
  }
  TLS_S_SYM(TLS_server_method)
  TLS_S_SYM(SSL_CTX_new)
  TLS_S_SYM(SSL_CTX_free)
  TLS_S_SYM(SSL_CTX_use_certificate_file)
  TLS_S_SYM(SSL_CTX_use_PrivateKey_file)
  TLS_S_SYM(SSL_CTX_set_alpn_select_cb)
  TLS_S_SYM(SSL_new)
  TLS_S_SYM(SSL_set_fd)
  TLS_S_SYM(SSL_accept)
  TLS_S_SYM(SSL_get0_alpn_selected)
  TLS_S_SYM(SSL_shutdown)
  TLS_S_SYM(SSL_free)
#undef TLS_S_SYM
  tls_s_ready = 1;
  pthread_mutex_unlock(&tls_s_gate);
  return 0;
}

static const char* tls_s_msg(u32 code) {
  switch (code) {
    case 611: return "bad input";
    case 613: return "handshake failed";
    case 615: return "alpn mismatch";
    case 616: return "tls error";
    default:  return "accept failed";
  }
}

// ALPN select: prefer h2 when the client offers it.
static int tls_alpn_cb(void* ssl, const unsigned char** out,
  unsigned char* outlen, const unsigned char* in, unsigned inlen, void* arg) {
  (void)ssl;
  (void)arg;
  unsigned i = 0;
  while (i + 1 < inlen) {
    unsigned l = in[i];
    if (i + 1 + l > inlen) {
      break;
    }
    if (l == 2 && in[i + 1] == 'h' && in[i + 2] == '2') {
      *out = in + i + 1;
      *outlen = 2;
      return 0;
    }
    i += 1 + l;
  }
  return 3;
}

static void tls_serve_call(IoWork* w) {
  struct TlsServe* s = (struct TlsServe*)w->data;
  s->code = 0;
  s->conn = NULL;
  u32 q = tls_s_init();
  if (q != 0) {
    s->code = q;
    return;
  }
  if (io_nul(s->cert, s->cert_len) || io_nul(s->key, s->key_len)) {
    s->code = 611;
    return;
  }
  // Blocking handshake: drop O_NONBLOCK for its duration.
  int fl = fcntl(s->fd, F_GETFL, 0);
  int nb = (fl >= 0 && (fl & O_NONBLOCK) != 0) ? 1 : 0;
  if (nb) {
    fcntl(s->fd, F_SETFL, fl & ~O_NONBLOCK);
  }
  void* ctx = s_SSL_CTX_new(s_TLS_server_method());
  if (ctx == NULL) {
    if (nb) fcntl(s->fd, F_SETFL, fl);
    close(s->fd);
    s->code = 613;
    return;
  }
  if (s_SSL_CTX_use_certificate_file(ctx, s->cert, 1) != 1
    || s_SSL_CTX_use_PrivateKey_file(ctx, s->key, 1) != 1) {
    s_SSL_CTX_free(ctx);
    if (nb) fcntl(s->fd, F_SETFL, fl);
    close(s->fd);
    s->code = 613;
    return;
  }
  s_SSL_CTX_set_alpn_select_cb(ctx, (void*)tls_alpn_cb, NULL);
  void* ssl = s_SSL_new(ctx);
  if (ssl == NULL) {
    s_SSL_CTX_free(ctx);
    if (nb) fcntl(s->fd, F_SETFL, fl);
    close(s->fd);
    s->code = 613;
    return;
  }
  s_SSL_set_fd(ssl, s->fd);
  int r = s_SSL_accept(ssl);
  if (nb) {
    int fl2 = fcntl(s->fd, F_GETFL, 0);
    if (fl2 >= 0) fcntl(s->fd, F_SETFL, fl2 | O_NONBLOCK);
  }
  if (r <= 0) {
    s_SSL_shutdown(ssl);
    s_SSL_free(ssl);
    s_SSL_CTX_free(ctx);
    close(s->fd);
    s->code = 613;
    return;
  }
  struct TlsConn* c = io_mem(malloc(sizeof(*c)));
  c->ssl = ssl;
  c->ctx = ctx;
  c->fd  = s->fd;
  s->conn = c;
  s->code = 0;
}

static Term tls_serve_pack(Env e, IoWork* w) {
  int lfd = (int)w->hand;
  struct TlsServe* s = (struct TlsServe*)w->data;
  Term r;
  if (s->code == 0) {
    r = io_done(e, io_hand((intptr_t)s->conn));
  } else {
    r = io_fail(e, s->code, tls_s_msg(s->code));
  }
  free(s->cert);
  free(s->key);
  free(s);
  return io_tup(e, io_hand(lfd), r);
}

static Term tls_accept_more2(Env e, IoWork* w);

Term tls_accept_raw_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  // Stash cert/key now: accept_more may park before reading them, and
  // f is only valid on entry, so copy them into the serve box upfront
  // via a pre-box that accept_more picks up through w->size/word.
  // Simpler: copy here into heap and chain through w->data as a pair.
  // accept_more creates the serve box; patch it here instead: create
  // it now with fd=-1 (pending), then accept_more fills fd + works.
  struct TlsServe* s = io_mem(malloc(sizeof(*s)));
  s->cert = io_cstr(e, f[1], &s->cert_len);
  s->key = io_cstr(e, f[2], &s->key_len);
  s->fd = -1;
  s->code = 0;
  s->conn = NULL;
  w->data = (char*)s;
  // Custom entry: try accept now; on EAGAIN park; on fd, reuse s.
  int lfd = (int)w->hand;
  int got = accept(lfd, NULL, NULL);
  if (got >= 0 && fcntl(got, F_SETFL, fcntl(got, F_GETFL) | O_NONBLOCK) < 0) {
    close(got);
    got = -1;
  }
  if (got < 0) {
    if (errno == EAGAIN) {
      // Keep s for the wake: stash it in w->text slot via size hack.
      // w->data already holds s; the wake re-enters below.
      return io_wait_on(w, lfd, POLLIN, 0, tls_accept_more2);
    }
    Term r = io_fail(e, (u32)errno, NULL);
    free(s->cert);
    free(s->key);
    free(s);
    return io_tup(e, io_hand(lfd), r);
  }
  s->fd = got;
  return io_work(w, tls_serve_call, tls_serve_pack);
}

// Wake after listener park: s is already in w->data.
static Term tls_accept_more2(Env e, IoWork* w) {
  int lfd = (int)w->hand;
  struct TlsServe* s = (struct TlsServe*)w->data;
  int got = accept(lfd, NULL, NULL);
  if (got >= 0 && fcntl(got, F_SETFL, fcntl(got, F_GETFL) | O_NONBLOCK) < 0) {
    close(got);
    got = -1;
  }
  if (got < 0) {
    if (errno == EAGAIN) {
      return io_wait_on(w, lfd, POLLIN, 0, tls_accept_more2);
    }
    Term r = io_fail(e, (u32)errno, NULL);
    free(s->cert);
    free(s->key);
    free(s);
    return io_tup(e, io_hand(lfd), r);
  }
  s->fd = got;
  return io_work(w, tls_serve_call, tls_serve_pack);
}

static void __attribute__((constructor)) tls_accept_raw_use(void) {
  io_eff(CID_TLS_ACCEPT_RAW, tls_accept_raw_run, IO_READ);
}
