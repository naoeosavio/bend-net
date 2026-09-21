// TLS send: packs List<&2, U32> (a value past 255 fails EINVAL before
// any byte leaves), then SSL_writes it; WANT_READ parks on POLLIN and
// WANT_WRITE on POLLOUT. The handle is a TlsConn box.
function tls_send_bytes(socket, data, k) {
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
  const bytes = [];
  for (let xs = data; xs.$ === "Con"; xs = xs.tail) {
    bytes.push(xs.head);
  }
  if (bytes.some((x) => x > 255)) {
    return io_tup(socket, io_fail(22));
  }
  const b = Uint8Array.from(bytes);
  const go = (at) => {
    while (at < b.length) {
      const part = b.subarray(at);
      let n = -1;
      try {
        n = lib.SSL_write(conn.ssl, lib.ptr(part), part.length);
      } catch (e) {
        return bad(616, "tls error");
      }
      if (n <= 0) {
        let err = 0;
        try {
          err = lib.SSL_get_error(conn.ssl, n);
        } catch (e) {
          return bad(616, "tls error");
        }
        if (err === 2) {
          io_park_on(conn.fd, false, k, () => go(at));
          return undefined;
        }
        if (err === 3) {
          io_park_on(conn.fd, true, k, () => go(at));
          return undefined;
        }
        return bad(616, "tls error");
      }
      at += n;
    }
    return io_tup(socket, io_done({ $: "Unit" }));
  };
  return go(0);
}

// The libssl symbols this effect needs, dlopened once per process and
// cached in a global slot (the dns_file style).
function tls_lib() {
  if (globalThis.BEND_TLS_SEND === undefined) {
    try {
      const ffi = require("bun:ffi");
      const T = { i: "i32", p: "ptr" };
      const lib = ffi.dlopen("libssl.so.3", {
        SSL_write: { args: [T.p, T.p, T.i], returns: T.i },
        SSL_get_error: { args: [T.p, T.i], returns: T.i },
      });
      globalThis.BEND_TLS_SEND = { ...lib.symbols, ptr: ffi.ptr };
    } catch (e) {
      globalThis.BEND_TLS_SEND = null;
    }
  }
  return globalThis.BEND_TLS_SEND;
}