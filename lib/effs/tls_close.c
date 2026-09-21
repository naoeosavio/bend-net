// TLS close: orderly shutdown, session free and fd close. Best
// effort: always answers Unit. The handle is a TlsConn*.
#include <dlfcn.h>
#include <unistd.h>

#ifndef TLS_CONN_DEFINED
#define TLS_CONN_DEFINED
struct TlsConn {
  void* ssl;
  void* ctx;
  int   fd;
};
#endif

Term tls_close_run(Env e, Term* f, IoWork* w) {
  (void)e;
  (void)w;
  struct TlsConn* c = (struct TlsConn*)(intptr_t)io_hand_v(f[0]);
  if (c != NULL) {
    void* h = dlopen("libssl.so.3", RTLD_NOW);
    if (h == NULL) {
      h = dlopen("libssl.so", RTLD_NOW);
    }
    if (h != NULL) {
      int (*p_shutdown)(void*) = dlsym(h, "SSL_shutdown");
      void (*p_free)(void*) = dlsym(h, "SSL_free");
      void (*p_ctx_free)(void*) = dlsym(h, "SSL_CTX_free");
      if (p_shutdown != NULL && c->ssl != NULL) {
        p_shutdown(c->ssl);
      }
      if (p_free != NULL && c->ssl != NULL) {
        p_free(c->ssl);
      }
      if (p_ctx_free != NULL && c->ctx != NULL) {
        p_ctx_free(c->ctx);
      }
      dlclose(h);
    }
    if (c->fd >= 0) {
      close(c->fd);
    }
    free(c);
  }
  return term_pak(CID_UNIT, 0);
}

static void __attribute__((constructor)) tls_close_use(void) {
  // Unit answer, no handle back: plain effect, not a Result pair.
  io_eff(CID_TLS_CLOSE, tls_close_run, 0);
}
