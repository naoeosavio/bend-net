// TLS close: orderly shutdown, session free and fd close. Best effort,
// always answers Unit. The handle is a TlsConn box.
function tls_close(socket) {
  const conn = socket;
  if (conn && conn.$ === "TlsConn") {
    const lib = tls_lib();
    if (lib !== null) {
      try {
        lib.SSL_shutdown(conn.ssl);
      } catch (e) {}
      try {
        lib.SSL_free(conn.ssl);
      } catch (e) {}
      try {
        lib.SSL_CTX_free(conn.ctx);
      } catch (e) {}
    }
    try {
      io_sys().close(conn.fd);
    } catch (e) {}
    try {
      if (conn._cb) conn._cb.close();
    } catch (e) {}
  }
  return { $: "Unit" };
}

// The libssl symbols this effect needs, dlopened once per process and
// cached in a global slot (the dns_file style).
function tls_lib() {
  if (globalThis.BEND_TLS_CLOSE === undefined) {
    try {
      const ffi = require("bun:ffi");
      const T = { i: "i32", p: "ptr", v: "void" };
      const lib = ffi.dlopen("libssl.so.3", {
        SSL_shutdown: { args: [T.p], returns: T.i },
        SSL_free: { args: [T.p], returns: T.v },
        SSL_CTX_free: { args: [T.p], returns: T.v },
      });
      globalThis.BEND_TLS_CLOSE = { ...lib.symbols };
    } catch (e) {
      globalThis.BEND_TLS_CLOSE = null;
    }
  }
  return globalThis.BEND_TLS_CLOSE;
}