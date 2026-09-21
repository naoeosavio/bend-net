// TLS client handshake: OpenSSL over a non-blocking fd via bun:ffi,
// with WANT_READ / WANT_WRITE parks on the underlying fd. The handle
// answers a session box {ssl, ctx, fd} (never a raw fd): send/recv/
// close unpack it. SSL_set_tlsext_host_name is a macro in OpenSSL, so
// the hostname rides SSL_ctrl (SSL_CTRL_SET_TLSEXT_HOSTNAME).
function tls_connect_raw(ip, sni, port, verify, k) {
  const sys = io_sys();
  const bad = (code, text) => ({ $: "Fail", error: io_tup(code, text) });
  const lib = tls_lib();
  if (lib === null) {
    return bad(616, "tls error");
  }
  port = Number(port);
  verify = Number(verify);
  if (!(port >= 1 && port <= 65535) || Number.isNaN(port)) {
    return bad(611, "bad input");
  }
  const at = io_addr(ip, port);
  if (at === null) {
    return bad(611, "bad input");
  }
  const fd = sys.socket(2, 1, 0);
  if (fd < 0) {
    return bad(612, "dial failed");
  }
  // The fd is non-blocking for life: SSL_connect parks on WANT_READ /
  // WANT_WRITE instead of stalling the loop.
  if (sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800)) < 0) {
    sys.close(fd);
    return bad(612, "dial failed");
  }
  const fail = (code, text, ctx, ses) => {
    try {
      if (ses) lib.SSL_free(ses);
      if (ctx) lib.SSL_CTX_free(ctx);
    } catch (e) {}
    sys.close(fd);
    return bad(code, text);
  };
  const set_host = (ses, name) => {
    // SSL_CTRL_SET_TLSEXT_HOSTNAME = 55, TLSEXT_NAMETYPE_host_name = 0
    const p = lib.ptr(io_bytes(name + "\0"));
    return lib.SSL_ctrl(ses, 55, 0, p);
  };
  const start_tls = () => {
    let ctx = null;
    let ses = null;
    try {
      ctx = lib.SSL_CTX_new(lib.TLS_client_method());
    } catch (e) {
      ctx = null;
    }
    if (!ctx) {
      return fail(613, "handshake failed", null, null);
    }
    try {
      lib.SSL_CTX_set_verify(ctx, verify ? 1 : 0, null);
      if (verify) lib.SSL_CTX_set_default_verify_paths(ctx);
      const alpn = new Uint8Array([2, 104, 50]);
      lib.SSL_CTX_set_alpn_protos(ctx, lib.ptr(alpn), 3);
      ses = lib.SSL_new(ctx);
      if (!ses) {
        return fail(613, "handshake failed", ctx, null);
      }
      lib.SSL_set_fd(ses, fd);
      set_host(ses, sni);
      if (verify) lib.SSL_set1_host(ses, lib.ptr(io_bytes(sni + "\0")));
    } catch (e) {
      return fail(613, "handshake failed", ctx, ses);
    }
    const step = () => {
      let r = -1;
      try {
        r = lib.SSL_connect(ses);
      } catch (e) {
        return fail(613, "handshake failed", ctx, ses);
      }
      if (r === 1) {
        // ALPN: the client offers only h2 (SSL_CTX_set_alpn_protos
        // above), so OpenSSL itself aborts the handshake when the
        // server selects anything else: r === 1 already proves h2.
        let ok_verify = true;
        try {
          ok_verify = !verify || lib.SSL_get_verify_result(ses) === 0;
        } catch (e) {
          ok_verify = false;
        }
        if (!ok_verify) return fail(614, "verify failed", ctx, ses);
        return io_done({ $: "TlsConn", ssl: ses, ctx: ctx, fd: fd });
      }
      let err = 0;
      try {
        err = lib.SSL_get_error(ses, r);
      } catch (e) {
        return fail(613, "handshake failed", ctx, ses);
      }
      if (err === 2) {
        io_park_on(fd, false, k, step);
        return undefined;
      }
      if (err === 3) {
        io_park_on(fd, true, k, step);
        return undefined;
      }
      let vr = 0;
      try {
        vr = verify ? lib.SSL_get_verify_result(ses) : 0;
      } catch (e) {}
      if (verify && vr !== 0) return fail(614, "verify failed", ctx, ses);
      return fail(613, "handshake failed", ctx, ses);
    };
    return step();
  };
  const again = sys.mac ? 36 : 115;
  const ok = sys.connect(fd, sys.ptr(at), 16) >= 0;
  const code = ok ? 0 : sys.errno();
  if (!ok && code !== again) {
    sys.close(fd);
    return bad(612, "dial failed");
  }
  if (!ok && code === again) {
    const error = () => {
      const v = new Int32Array([0]);
      const l = new Uint32Array([4]);
      return sys.getsockopt(fd, sys.mac ? 0xffff : 1, sys.mac ? 0x1007 : 4,
        sys.ptr(v), sys.ptr(l)) < 0 ? sys.errno() : v[0];
    };
    io_park_on(fd, true, k, () => {
      const ec = error();
      if (ec !== 0) {
        sys.close(fd);
        return bad(612, "dial failed");
      }
      return start_tls();
    });
    return undefined;
  }
  return start_tls();
}

// The libssl symbols this effect needs, dlopened once per process and
// cached in a global slot (the dns_file style). SSL_ctrl replaces the
// set-hostname macro (SSL_set_tlsext_host_name is a macro, not a
// symbol, so dlopen cannot resolve it).
function tls_lib() {
  if (globalThis.BEND_TLS_CONN === undefined) {
    try {
      const ffi = require("bun:ffi");
      const T = { i: "i32", u: "u32", p: "ptr", v: "void" };
      const lib = ffi.dlopen("libssl.so.3", {
        TLS_client_method: { args: [], returns: T.p },
        SSL_CTX_new: { args: [T.p], returns: T.p },
        SSL_CTX_free: { args: [T.p], returns: T.v },
        SSL_CTX_set_verify: { args: [T.p, T.i, T.p], returns: T.v },
        SSL_CTX_set_default_verify_paths: { args: [T.p], returns: T.i },
        SSL_CTX_set_alpn_protos: { args: [T.p, T.p, T.u], returns: T.i },
        SSL_new: { args: [T.p], returns: T.p },
        SSL_free: { args: [T.p], returns: T.v },
        SSL_set_fd: { args: [T.p, T.i], returns: T.i },
        SSL_set1_host: { args: [T.p, T.p], returns: T.i },
        SSL_connect: { args: [T.p], returns: T.i },
        SSL_get_error: { args: [T.p, T.i], returns: T.i },
        SSL_get_verify_result: { args: [T.p], returns: T.i },
        SSL_ctrl: { args: [T.p, T.i, T.i, T.p], returns: T.i },
      });
      globalThis.BEND_TLS_CONN = { ...lib.symbols, ptr: ffi.ptr };
    } catch (e) {
      globalThis.BEND_TLS_CONN = null;
    }
  }
  return globalThis.BEND_TLS_CONN;
}