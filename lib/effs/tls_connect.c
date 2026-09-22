// TLS client handshake over a blocking connect on the helper thread.
// The handle answers an SSL session box (TlsConn*), never a raw fd:
// send/recv/close unpack it, so no fd->SSL map is needed and every
// twin stays self-contained (OpenSSL rides dlopen, no link flags).
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

// A live session: freed by tls_close only.
#ifndef TLS_CONN_DEFINED
#define TLS_CONN_DEFINED
struct TlsConn {
  void* ssl;
  void* ctx;
  int   fd;
};
#endif

struct TlsDial {
  char* ip;
  u64   ip_len;
  char* sni;
  u64   sni_len;
  u32   port;
  u32   verify;
  u32   alpn;
  u32   code;
  void* conn;
};

// OpenSSL entry points, resolved once per process via dlopen.
static void*          tls_h = NULL;
static pthread_mutex_t tls_gate = PTHREAD_MUTEX_INITIALIZER;
static int            tls_ready = 0;
static void* (*p_TLS_client_method)(void);
static void* (*p_SSL_CTX_new)(void*);
static void  (*p_SSL_CTX_free)(void*);
static void  (*p_SSL_CTX_set_verify)(void*, int, void*);
static int   (*p_SSL_CTX_set_default_verify_paths)(void*);
static int   (*p_SSL_CTX_set_alpn_protos)(void*, const unsigned char*, unsigned);
static void* (*p_SSL_new)(void*);
static int   (*p_SSL_set_fd)(void*, int);
static long  (*p_SSL_ctrl)(void*, int, long, void*);
static int   (*p_SSL_set1_host)(void*, const char*);
static int   (*p_SSL_connect)(void*);
static void  (*p_SSL_get0_alpn_selected)(const void*, const unsigned char**, unsigned*);
static long  (*p_SSL_get_verify_result)(void*);
static int   (*p_SSL_shutdown)(void*);
static void  (*p_SSL_free)(void*);
static int   (*p_SSL_get_error)(void*, int);

static u32 tls_init(void) {
  pthread_mutex_lock(&tls_gate);
  if (tls_ready) {
    pthread_mutex_unlock(&tls_gate);
    return 0;
  }
  tls_h = dlopen("libssl.so.3", RTLD_NOW);
  if (tls_h == NULL) {
    tls_h = dlopen("libssl.so", RTLD_NOW);
  }
  if (tls_h == NULL) {
    pthread_mutex_unlock(&tls_gate);
    return 616;
  }
#define TLS_SYM(n)                                      \
  p_##n = dlsym(tls_h, #n);                             \
  if (p_##n == NULL) {                                  \
    pthread_mutex_unlock(&tls_gate);                    \
    return 616;                                         \
  }
  TLS_SYM(TLS_client_method)
  TLS_SYM(SSL_CTX_new)
  TLS_SYM(SSL_CTX_free)
  TLS_SYM(SSL_CTX_set_verify)
  TLS_SYM(SSL_CTX_set_default_verify_paths)
  TLS_SYM(SSL_CTX_set_alpn_protos)
  TLS_SYM(SSL_new)
  TLS_SYM(SSL_set_fd)
  TLS_SYM(SSL_ctrl)
  TLS_SYM(SSL_set1_host)
  TLS_SYM(SSL_connect)
  TLS_SYM(SSL_get0_alpn_selected)
  TLS_SYM(SSL_get_verify_result)
  TLS_SYM(SSL_shutdown)
  TLS_SYM(SSL_free)
  TLS_SYM(SSL_get_error)
#undef TLS_SYM
  tls_ready = 1;
  pthread_mutex_unlock(&tls_gate);
  return 0;
}

static const char* tls_msg(u32 code) {
  switch (code) {
    case 611: return "bad input";
    case 612: return "dial failed";
    case 613: return "handshake failed";
    case 614: return "verify failed";
    case 615: return "alpn mismatch";
    default:  return "tls error";
  }
}

// Runs on the helper thread: blocking connect + handshake. The loop
// stays free; pack answers on the loop.
static void tls_call(IoWork* w) {
  struct TlsDial* d = (struct TlsDial*)w->data;
  d->code = 0;
  d->conn = NULL;
  u32 q = tls_init();
  if (q != 0) {
    d->code = q;
    return;
  }
  struct sockaddr_in at;
  if (io_nul(d->ip, d->ip_len) || io_nul(d->sni, d->sni_len)
    || io_sys_addr(d->ip, d->port, &at) != 0) {
    d->code = 611;
    return;
  }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    d->code = 612;
    return;
  }
  if (connect(fd, (struct sockaddr*)&at, sizeof(at)) != 0) {
    close(fd);
    d->code = 612;
    return;
  }
  void* ctx = p_SSL_CTX_new(p_TLS_client_method());
  if (ctx == NULL) {
    close(fd);
    d->code = 613;
    return;
  }
  if (d->verify) {
    p_SSL_CTX_set_verify(ctx, 1, NULL);
    p_SSL_CTX_set_default_verify_paths(ctx);
  } else {
    p_SSL_CTX_set_verify(ctx, 0, NULL);
  }
  // ALPN mode: alpn=1 offers h2 and requires it selected (HTTPS);
  // alpn=0 offers nothing and accepts no negotiation (WSS/HTTP/1.1).
  if (d->alpn) {
    const unsigned char alpn[] = {2, 'h', '2'};
    p_SSL_CTX_set_alpn_protos(ctx, alpn, 3);
  }
  void* ssl = p_SSL_new(ctx);
  if (ssl == NULL) {
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = 613;
    return;
  }
  // SSL_set_tlsext_host_name is a macro: SSL_ctrl(ssl, 55, 0, name)
  // with SSL_CTRL_SET_TLSEXT_HOSTNAME = 55, TLSEXT_NAMETYPE_host_name = 0.
  p_SSL_ctrl(ssl, 55, 0, d->sni);
  if (d->verify) {
    p_SSL_set1_host(ssl, d->sni);
  }
  p_SSL_set_fd(ssl, fd);
  if (p_SSL_connect(ssl) <= 0) {
    long vr = d->verify ? p_SSL_get_verify_result(ssl) : 0;
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = (d->verify && vr != 0) ? 614 : 613;
    return;
  }
  if (d->verify && p_SSL_get_verify_result(ssl) != 0) {
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = 614;
    return;
  }
  if (d->alpn) {
    const unsigned char* sel = NULL;
    unsigned sel_len = 0;
    p_SSL_get0_alpn_selected(ssl, &sel, &sel_len);
    if (sel_len != 2 || sel == NULL || sel[0] != 'h' || sel[1] != '2') {
      p_SSL_shutdown(ssl);
      p_SSL_free(ssl);
      p_SSL_CTX_free(ctx);
      close(fd);
      d->code = 615;
      return;
    }
  }
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = 616;
    return;
  }
  struct TlsConn* c = io_mem(malloc(sizeof(*c)));
  c->ssl = ssl;
  c->ctx = ctx;
  c->fd  = fd;
  d->conn = c;
  d->code = 0;
}

static Term tls_pack(Env e, IoWork* w) {
  struct TlsDial* d = (struct TlsDial*)w->data;
  Term r;
  if (d->code == 0) {
    r = io_done(e, io_hand((intptr_t)d->conn));
  } else {
    r = io_fail(e, d->code, tls_msg(d->code));
  }
  free(d->ip);
  free(d->sni);
  free(d);
  return r;
}

Term tls_connect_raw_run(Env e, Term* f, IoWork* w) {
  struct TlsDial* d = io_mem(malloc(sizeof(*d)));
  d->ip     = io_cstr(e, f[0], &d->ip_len);
  d->sni    = io_cstr(e, f[1], &d->sni_len);
  d->port   = (u32)f[2];
  d->verify = (u32)f[3];
  d->alpn   = (u32)f[4];
  d->code   = 0;
  d->conn   = NULL;
  w->data = (char*)d;
  return io_work(w, tls_call, tls_pack);
}

static void __attribute__((constructor)) tls_connect_raw_use(void) {
  io_eff(CID_TLS_CONNECT_RAW, tls_connect_raw_run, 0);
}
