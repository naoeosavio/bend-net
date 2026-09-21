// TLS recv: one SSL_read of at most max bytes as a byte list. WANT_READ
// parks on POLLIN, WANT_WRITE on POLLOUT. The handle is a TlsConn box;
// r == 0 is an orderly shutdown: answer the empty list.
function tls_recv_bytes(socket, max, k) {
  const sys = io_sys();
  const bad = (code, text) => io_tup(socket, { $: "Fail", error: io_tup(code, text) });
  const conn = socket;
  if (!conn || conn.$ !== "TlsConn") {
    return bad(611, "bad input");
  }
  const lib = tls_lib();
  if (lib === null) {
    return bad(616, "tls error");
  }
  const n = Math.max(Number(max), 1);
  const b = new Uint8Array(n);
  const go = () => {
    let r = -1;
    try {
      r = lib.SSL_read(conn.ssl, lib.ptr(b), n);
    } catch (e) {
      return bad(616, "tls error");
    }
    if (r < 0) {
      let err = 0;
      try {
        err = lib.SSL_get_error(conn.ssl, r);
      } catch (e) {
        return bad(616, "tls error");
      }
      if (err === 2) {
        io_park_on(conn.fd, false, k, go);
        return undefined;
      }
      if (err === 3) {
        io_park_on(conn.fd, true, k, go);
        return undefined;
      }
      return bad(616, "tls error");
    }
    let xs = { $: "Nil" };
    for (let i = r; i > 0; i -= 1) {
      xs = { $: "Con", head: b[i - 1], tail: xs };
    }
    return io_tup(socket, io_done(xs));
  };
  return go();
}

// The libssl symbols this effect needs, dlopened once per process and
// cached in a global slot (the dns_file style).
function tls_lib() {
  if (globalThis.BEND_TLS_RECV === undefined) {
    try {
      const ffi = require("bun:ffi");
      const T = { i: "i32", p: "ptr" };
      const lib = ffi.dlopen("libssl.so.3", {
        SSL_read: { args: [T.p, T.p, T.i], returns: T.i },
        SSL_get_error: { args: [T.p, T.i], returns: T.i },
      });
      globalThis.BEND_TLS_RECV = { ...lib.symbols, ptr: ffi.ptr };
    } catch (e) {
      globalThis.BEND_TLS_RECV = null;
    }
  }
  return globalThis.BEND_TLS_RECV;
}