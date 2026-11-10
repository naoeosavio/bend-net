// TLS server handshake: accepts one TCP connection (parked, like
// TCP.accept) then handshakes it on the helper thread (blocking, so the
// loop stays free). Answers Listener & Result with an SSL session box
// (TlsConn*), never a raw fd. OpenSSL rides dlopen, no link flags.
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

// Nagle holds the second of two small writes until the peer's delayed ACK
// (~40ms per connection, measured on the WSS lane), so every accepted TLS
// fd turns it off. Best effort: a failed setsockopt costs latency, never
// correctness, so the result is deliberately not propagated.
#ifndef TLS_NO_DELAY_DEFINED
#define TLS_NO_DELAY_DEFINED
static void tls_no_delay(int fd) {
  int one = 1;
  int _rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  (void)_rc;
}
#endif

#define TLS_ALPN_H2 1
#define TLS_ALPN_BOTH 2
#define TLS_ALPN_HTTP1 3

struct TlsServe {
  char* cert;
  u64   cert_len;
  char* key;
  u64   key_len;
  int   fd;
  u32   code;
  void* conn;
  char  proto[256];
  u64   proto_len;
  u32   offer;
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
static unsigned long (*s_ERR_peek_last_error)(void);
static void  (*s_ERR_clear_error)(void);

// ERR_GET_REASON(): the low 23 bits of a packed OpenSSL error code.
#define TLS_S_ERR_REASON(e) ((int)((e) & 0x7FFFFF))
// Our own ALPN refusal surfaces as SSL_R_NO_APPLICATION_PROTOCOL (235);
// a peer's alert 120 arrives as 1000 + 120. Both are the ALPN contract
// failing, so they answer 615 like the JS lane, never a generic 613.
#define TLS_S_R_NO_APPLICATION_PROTOCOL       235
#define TLS_S_R_ALERT_NO_APPLICATION_PROTOCOL 1120

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
  TLS_S_SYM(ERR_peek_last_error)
  TLS_S_SYM(ERR_clear_error)
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

// ALPN select: preserve the client's protocol order. A peer that sent no
// extension is not a mismatch -- the handshake continues with no protocol
// selected (RFC 7301 s3.2, SSL_TLSEXT_ERR_NOACK). A peer that DID send a
// list with no overlap must fail with the fatal no_application_protocol
// alert (SSL_TLSEXT_ERR_ALERT_FATAL), which is what the RFC requires and
// what the JS lane already does.
static int tls_alpn_cb(void* ssl, const unsigned char** out,
  unsigned char* outlen, const unsigned char* in, unsigned inlen, void* arg) {
  (void)ssl;
  u32 offer = (u32)(uintptr_t)arg;
  unsigned i = 0;
  while (i + 1 < inlen) {
    unsigned l = in[i];
    if (l == 0 || i + 1 + l > inlen) {
      break;
    }
    if (offer == TLS_ALPN_H2 && l == 2
      && in[i + 1] == 'h' && in[i + 2] == '2') {
      *out = in + i + 1;
      *outlen = 2;
      return 0;
    }
    if (offer == TLS_ALPN_BOTH && l == 2
      && in[i + 1] == 'h' && in[i + 2] == '2') {
      *out = in + i + 1;
      *outlen = 2;
      return 0;
    }
    if ((offer == TLS_ALPN_BOTH || offer == TLS_ALPN_HTTP1) && l == 8
      && memcmp(in + i + 1, "http/1.1", 8) == 0) {
      *out = in + i + 1;
      *outlen = 8;
      return 0;
    }
    i += 1 + l;
  }
  return inlen == 0 ? 3 : 2;
}

static void tls_serve_call(IoWork* w) {
  struct TlsServe* s = (struct TlsServe*)w->data;
  s->code = 0;
  s->conn = NULL;
  s->proto[0] = 0;
  s->proto_len = 0;
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
  s_SSL_CTX_set_alpn_select_cb(ctx, (void*)tls_alpn_cb,
    (void*)(uintptr_t)s->offer);
  void* ssl = s_SSL_new(ctx);
  if (ssl == NULL) {
    s_SSL_CTX_free(ctx);
    if (nb) fcntl(s->fd, F_SETFL, fl);
    close(s->fd);
    s->code = 613;
    return;
  }
  s_SSL_set_fd(ssl, s->fd);
  // The reason peek after the handshake must read only this handshake:
  // a stale error from another SSL object would answer 613/615 wrong.
  s_ERR_clear_error();
  int r = s_SSL_accept(ssl);
  // Read the reason BEFORE shutdown/free: they push their own errors. Our
  // own ALPN refusal surfaces as SSL_R_NO_APPLICATION_PROTOCOL (235), and
  // a buggy peer's alert 120 as 1000 + 120.
  int reason = (int)(TLS_S_ERR_REASON(s_ERR_peek_last_error()));
  if (nb) {
    int fl2 = fcntl(s->fd, F_GETFL, 0);
    if (fl2 >= 0) fcntl(s->fd, F_SETFL, fl2 | O_NONBLOCK);
  }
  if (r <= 0) {
    s_SSL_shutdown(ssl);
    s_SSL_free(ssl);
    s_SSL_CTX_free(ctx);
    close(s->fd);
    s->code = (reason == TLS_S_R_NO_APPLICATION_PROTOCOL
      || reason == TLS_S_R_ALERT_NO_APPLICATION_PROTOCOL) ? 615 : 613;
    return;
  }
  const unsigned char* selected = NULL;
  unsigned selected_len = 0;
  s_SSL_get0_alpn_selected(ssl, &selected, &selected_len);
  if (selected_len > sizeof(s->proto)) {
    s_SSL_shutdown(ssl);
    s_SSL_free(ssl);
    s_SSL_CTX_free(ctx);
    close(s->fd);
    s->code = 616;
    return;
  }
  if (selected_len > 0 && selected != NULL) {
    memcpy(s->proto, selected, selected_len);
  }
  s->proto_len = selected_len;
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
    r = io_done(e, io_tup(e, io_hand((intptr_t)s->conn),
      io_str(e, s->proto, s->proto_len)));
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
  s->proto[0] = 0;
  s->proto_len = 0;
  s->offer = (u32)f[3];
  w->data = (char*)s;
  int lfd = (int)w->hand;
  if (s->offer != TLS_ALPN_H2 && s->offer != TLS_ALPN_BOTH
    && s->offer != TLS_ALPN_HTTP1) {
    free(s->cert);
    free(s->key);
    free(s);
    return io_tup(e, io_hand(lfd), io_fail(e, 611, "bad input"));
  }
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
  tls_no_delay(got);
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
  tls_no_delay(got);
  s->fd = got;
  return io_work(w, tls_serve_call, tls_serve_pack);
}

static void __attribute__((constructor)) tls_accept_raw_use(void) {
  io_eff(CID_TLS_ACCEPT_RAW, tls_accept_raw_run, IO_READ);
}
