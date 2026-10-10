// TLS server handshake: accepts one TCP connection (parked, like
// TCP.accept) then handshakes it with the cert/key files and returns the
// negotiated ALPN protocol. Answers Listener & Result with a TlsConn box.
// Nagle holds the second of two small writes until the peer's delayed ACK
// (~40ms per connection, measured on the WSS lane), so every accepted TLS
// fd turns it off. Best effort: a failed setsockopt costs latency, never
// correctness, so the result is deliberately not propagated.
function tls_accept_no_delay(sys, fd) {
  const one = Uint8Array.of(1, 0, 0, 0);
  // The result is deliberately dropped: `_rc` marks it as checked-and-
  // ignored, the same way the C twin does with (void)_rc.
  const _rc = sys.setsockopt(fd, 6, 1, sys.ptr(one), 4);
}

function tls_accept_raw(listener, cert, key, offer, k) {
  const sys = io_sys();
  const bad = (code, text) => io_tup(listener, { $: "Fail", error: io_tup(code, text) });
  const lib = tls_lib();
  if (lib === null) {
    return bad(616, "tls error");
  }
  offer = Number(offer);
  if (offer !== 1 && offer !== 2 && offer !== 3) {
    return bad(611, "bad input");
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
    tls_accept_no_delay(sys, fd);
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
    let selected = "";
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
      cb = new lib.JSCallback((s, out, outlen, inp, inlen, arg) => {
        try {
          const len = Number(inlen);
          if (!inp || len === 0) {
            selected = "";
            return 3;
          }
          const wire = lib.buffer(inp, 0, len);
          let at = 0;
          while (at < len) {
            const size = wire[at];
            if (size === 0 || at + 1 + size > len) {
              break;
            }
            const name = wire.subarray(at + 1, at + 1 + size);
            const is_h2 = name.length === 2
              && name[0] === 104 && name[1] === 50;
            const is_http1 = name.length === 8
              && name[0] === 104 && name[1] === 116
              && name[2] === 116 && name[3] === 112
              && name[4] === 47 && name[5] === 49
              && name[6] === 46 && name[7] === 49;
            if ((offer === 1 && is_h2)
              || (offer === 2 && (is_h2 || is_http1))
              || (offer === 3 && is_http1)) {
              const srv = new Uint8Array(size + 1);
              srv[0] = size;
              srv.set(name, 1);
              selected = is_h2 ? "h2" : "http/1.1";
              return lib.SSL_select_next_proto(
                out, outlen, lib.ptr(srv), srv.length, inp, len
              ) === 1 ? 0 : 3;
            }
            at += size + 1;
          }
          selected = "";
          return 3;
        } catch (e) {
          selected = "";
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
        return io_tup(listener, io_done(io_tup(box, selected)));
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
        buffer: ffi.toBuffer,
        JSCallback: ffi.JSCallback,
      };
    } catch (e) {
      globalThis.BEND_TLS_ACC = null;
    }
  }
  return globalThis.BEND_TLS_ACC;
}