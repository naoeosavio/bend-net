// TLS client handshake over a blocking connect on the helper thread.
// The handle answers an SSL session box (TlsConn*), never a raw fd:
// send/recv/close unpack it, so no fd->SSL map is needed and every
// twin stays self-contained (OpenSSL rides dlopen, no link flags).
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

// Nagle holds the second of two small writes until the peer's delayed ACK
// (~40ms per connection, measured on the WSS lane), so every fresh TLS fd
// turns it off. Best effort: a failed setsockopt costs latency, never
// correctness, so the result is deliberately not propagated.
#ifndef TLS_NO_DELAY_DEFINED
#define TLS_NO_DELAY_DEFINED
static void tls_no_delay(int fd) {
  int one = 1;
  int _rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  (void)_rc;
}
#endif

#define TLS_ALPN_NONE 0
#define TLS_ALPN_H2 1
#define TLS_ALPN_ANY 2
#define TLS_ALPN_HTTP1 3

// The dial belongs to Base.TCP.connect: it hands over a connected
// non-blocking fd, and this thread only runs the handshake on it. That
// keeps a real fd in the effect's first argument, which is what io_park_on
// parks on (the lane reads op.args[0]), the same shape Base's
// TCP.send / TCP.recv / TCP.poll have.
struct TlsDial {
  int   fd;
  char* sni;
  u64   sni_len;
  u32   verify;
  u32   alpn;
  u32   code;
  void* conn;
  char  proto[9];
  u64   proto_len;
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
static unsigned long (*p_ERR_peek_last_error)(void);

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
  TLS_SYM(ERR_peek_last_error)
#undef TLS_SYM
  tls_ready = 1;
  pthread_mutex_unlock(&tls_gate);
  return 0;
}

// ERR_GET_REASON(): the low 23 bits of a packed OpenSSL error code.
#define TLS_ERR_REASON(e) ((int)((e) & 0x7FFFFF))
// A peer that aborts the handshake with the fatal no_application_protocol
// alert (120) reports reason 1000 + 120: that IS the ALPN contract
// failing, so it answers 615 like the JS lane, never a generic 613.
#define TLS_R_ALERT_NO_APPLICATION_PROTOCOL 1120
#define TLS_R_NO_APPLICATION_PROTOCOL       235

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
  d->proto[0] = 0;
  d->proto_len = 0;
  if (d->alpn > TLS_ALPN_HTTP1) {
    d->code = 611;
    return;
  }
  u32 q = tls_init();
  if (q != 0) {
    d->code = q;
    return;
  }
  if (io_nul(d->sni, d->sni_len)) {
    d->code = 611;
    return;
  }
  int fd = d->fd;
  // The handshake runs on a BLOCKING fd: this thread is the one place in
  // the process that is allowed to block (the JS twin parks on the lane
  // instead). Base.TCP.connect hands the fd over non-blocking for life,
  // because its lane parks on it, so it is made blocking here and the
  // success path puts it back -- the byte effects expect non-blocking.
  int fl0 = fcntl(fd, F_GETFL, 0);
  if (fl0 < 0 || fcntl(fd, F_SETFL, fl0 & ~O_NONBLOCK) < 0) {
    d->code = 616;
    return;
  }
  tls_no_delay(fd);
  void* ctx = p_SSL_CTX_new(p_TLS_client_method());
  if (ctx == NULL) {
    fcntl(fd, F_SETFL, fl0);
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
  // ALPN mode: alpn=1 offers h2 and requires it selected;
  // alpn=2 offers h2/http1.1; alpn=3 offers only http/1.1;
  // alpn=0 offers nothing (WSS/HTTP/1.1).
  if (d->alpn == TLS_ALPN_H2) {
    const unsigned char alpn[] = {2, 'h', '2'};
    if (p_SSL_CTX_set_alpn_protos(ctx, alpn, 3) != 0) {
      p_SSL_CTX_free(ctx);
      close(fd);
      d->code = 613;
      return;
    }
  } else if (d->alpn == TLS_ALPN_ANY) {
    const unsigned char alpn[] = {
      2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    if (p_SSL_CTX_set_alpn_protos(ctx, alpn, 12) != 0) {
      p_SSL_CTX_free(ctx);
      close(fd);
      d->code = 613;
      return;
    }
  } else if (d->alpn == TLS_ALPN_HTTP1) {
    const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    if (p_SSL_CTX_set_alpn_protos(ctx, alpn, 9) != 0) {
      p_SSL_CTX_free(ctx);
      close(fd);
      d->code = 613;
      return;
    }
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
  if (p_SSL_ctrl(ssl, 55, 0, d->sni) != 1) {
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = 611;
    return;
  }
  if (d->verify && p_SSL_set1_host(ssl, d->sni) != 1) {
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = 614;
    return;
  }
  p_SSL_set_fd(ssl, fd);
  if (p_SSL_connect(ssl) <= 0) {
    long vr = d->verify ? p_SSL_get_verify_result(ssl) : 0;
    // Read the reason BEFORE shutdown/free: they push their own errors.
    int reason = TLS_ERR_REASON(p_ERR_peek_last_error());
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    d->code = (d->verify && vr != 0) ? 614
      : (reason == TLS_R_ALERT_NO_APPLICATION_PROTOCOL
        || reason == TLS_R_NO_APPLICATION_PROTOCOL) ? 615 : 613;
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
  if (d->alpn != TLS_ALPN_NONE) {
    const unsigned char* sel = NULL;
    unsigned sel_len = 0;
    p_SSL_get0_alpn_selected(ssl, &sel, &sel_len);
    int is_h2 = sel_len == 2 && sel != NULL
      && sel[0] == 'h' && sel[1] == '2';
    int is_http1 = sel_len == 8 && sel != NULL
      && memcmp(sel, "http/1.1", 8) == 0;
    if ((d->alpn == TLS_ALPN_H2 && !is_h2)
      || (d->alpn == TLS_ALPN_ANY && !is_h2 && !is_http1
        && sel_len != 0)
      || (d->alpn == TLS_ALPN_HTTP1 && !is_http1)) {
      p_SSL_shutdown(ssl);
      p_SSL_free(ssl);
      p_SSL_CTX_free(ctx);
      close(fd);
      d->code = 615;
      return;
    }
    if (is_h2) {
      d->proto[0] = 'h';
      d->proto[1] = '2';
      d->proto_len = 2;
    } else if (is_http1) {
      memcpy(d->proto, "http/1.1", 8);
      d->proto_len = 8;
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
    r = io_done(e, io_tup(e, io_hand((intptr_t)d->conn),
      io_str(e, d->proto, d->proto_len)));
  } else {
    r = io_fail(e, d->code, tls_msg(d->code));
  }
  free(d->sni);
  free(d);
  return r;
}

Term tls_connect_raw_run(Env e, Term* f, IoWork* w) {
  struct TlsDial* d = io_mem(malloc(sizeof(*d)));
  d->fd     = (int)f[0];
  d->sni    = io_cstr(e, f[1], &d->sni_len);
  d->verify = (u32)f[2];
  d->alpn   = (u32)f[3];
  d->code   = 0;
  d->conn   = NULL;
  d->proto[0] = 0;
  d->proto_len = 0;
  w->data = (char*)d;
  return io_work(w, tls_call, tls_pack);
}

static void __attribute__((constructor)) tls_connect_raw_use(void) {
  io_eff(CID_TLS_CONNECT_RAW, tls_connect_raw_run, 0);
}
