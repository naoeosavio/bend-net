// TLS server handshake: accepts one TCP connection (parked, like
// TCP.accept) then handshakes it with the cert/key files, ALPN h2 via
// a JSCallback select. Answers Listener & Result with a TlsConn box.
function tls_accept_raw(listener, cert, key, k) {
  const sys = io_sys();
  const bad = (code, text) => io_tup(listener, { $: "Fail", error: io_tup(code, text) });
  const lib = tls_lib();
  if (lib === null) {
    return bad(616, "tls error");
  }
  const lfd = listener;
  const go = () => {
    const fd = sys.accept(lfd, null, null);
    if (fd < 0) {
      const code = sys.errno();
      if (code === (sys.mac ? 35 : 11)) {
        io_park_on(lfd, false, k, go);
        return undefined;
      }
      return bad(code, "accept failed");
    }
    if (sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800)) < 0) {
      const code = sys.errno();
      sys.close(fd);
      return bad(code, "accept failed");
    }
    return shake(fd);
  };
  const fail = (code, text, fd, ctx, ses, cb) => {
    try {
      if (ses) lib.SSL_free(ses);
      if (ctx) lib.SSL_CTX_free(ctx);
      if (cb) cb.close();
    } catch (e) {}
    sys.close(fd);
    return bad(code, text);
  };
  const shake = (fd) => {
    let ctx = null;
    let ses = null;
    let cb = null;
    try {
      ctx = lib.SSL_CTX_new(lib.TLS_server_method());
    } catch (e) {
      ctx = null;
    }
    if (!ctx) {
      return fail(613, "handshake failed", fd, null, null, null);
    }
    try {
      const cert_b = io_bytes(cert + "\0");
      const key_b = io_bytes(key + "\0");
      if (lib.SSL_CTX_use_certificate_file(ctx, lib.ptr(cert_b), 1) !== 1) {
        return fail(613, "handshake failed", fd, ctx, null, null);
      }
      if (lib.SSL_CTX_use_PrivateKey_file(ctx, lib.ptr(key_b), 1) !== 1) {
        return fail(613, "handshake failed", fd, ctx, null, null);
      }
      // ALPN select: SSL_select_next_proto does the negotiation and
      // writes the out params itself, so the callback only forwards
      // pointers (no JS writes into native memory). The server list
      // (h2) lives in a global slot so it outlives the handshake.
      if (globalThis.BEND_TLS_SRV_ALPN === undefined) {
        globalThis.BEND_TLS_SRV_ALPN = new Uint8Array([2, 104, 50]);
      }
      const srv = globalThis.BEND_TLS_SRV_ALPN;
      cb = new lib.JSCallback((s, out, outlen, inp, inlen, arg) => {
        try {
          // 1 = OPENSSL_NPN_NEGOTIATED -> SSL_TLSEXT_ERR_OK (0);
          // 2 = NO_OVERLAP -> NOACK (3).
          const rv = lib.SSL_select_next_proto(out, outlen, lib.ptr(srv), 3, inp, Number(inlen));
          return rv === 1 ? 0 : 3;
        } catch (e) {
          return 3;
        }
      }, { args: ["ptr", "ptr", "ptr", "ptr", "u32", "ptr"], returns: "i32" });
      lib.SSL_CTX_set_alpn_select_cb(ctx, cb.ptr, null);
      ses = lib.SSL_new(ctx);
      if (!ses) {
        return fail(613, "handshake failed", fd, ctx, null, cb);
      }
      lib.SSL_set_fd(ses, fd);
    } catch (e) {
      return fail(613, "handshake failed", fd, ctx, ses, cb);
    }
    const step = () => {
      let r = -1;
      try {
        r = lib.SSL_accept(ses);
      } catch (e) {
        return fail(613, "handshake failed", fd, ctx, ses, cb);
      }
      if (r === 1) {
        // The callback rides the box so it outlives the handshake.
        const box = { $: "TlsConn", ssl: ses, ctx: ctx, fd: fd, _cb: cb };
        return io_tup(listener, io_done(box));
      }
      let err = 0;
      try {
        err = lib.SSL_get_error(ses, r);
      } catch (e) {
        return fail(613, "handshake failed", fd, ctx, ses, cb);
      }
      if (err === 2) {
        io_park_on(fd, false, k, step);
        return undefined;
      }
      if (err === 3) {
        io_park_on(fd, true, k, step);
        return undefined;
      }
      return fail(613, "handshake failed", fd, ctx, ses, cb);
    };
    return step();
  };
  return go();
}

function tls_accept_raw_need() {
  return { read: true };
}

// The libssl symbols this effect needs, dlopened once per process and
// cached in a global slot (the dns_file style).
function tls_lib() {
  if (globalThis.BEND_TLS_ACC === undefined) {
    try {
      const ffi = require("bun:ffi");
      const T = { i: "i32", u: "u32", p: "ptr", v: "void" };
      const lib = ffi.dlopen("libssl.so.3", {
        TLS_server_method: { args: [], returns: T.p },
        SSL_CTX_new: { args: [T.p], returns: T.p },
        SSL_CTX_free: { args: [T.p], returns: T.v },
        SSL_CTX_use_certificate_file: { args: [T.p, T.p, T.i], returns: T.i },
        SSL_CTX_use_PrivateKey_file: { args: [T.p, T.p, T.i], returns: T.i },
        SSL_CTX_set_alpn_select_cb: { args: [T.p, T.p, T.p], returns: T.v },
        SSL_new: { args: [T.p], returns: T.p },
        SSL_free: { args: [T.p], returns: T.v },
        SSL_set_fd: { args: [T.p, T.i], returns: T.i },
        SSL_accept: { args: [T.p], returns: T.i },
        SSL_get_error: { args: [T.p, T.i], returns: T.i },
        SSL_select_next_proto: { args: [T.p, T.p, T.p, T.u, T.p, T.u], returns: T.i },
      });
      globalThis.BEND_TLS_ACC = {
        ...lib.symbols,
        ptr: ffi.ptr,
        JSCallback: ffi.JSCallback,
      };
    } catch (e) {
      globalThis.BEND_TLS_ACC = null;
    }
  }
  return globalThis.BEND_TLS_ACC;
}