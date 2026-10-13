// TLS client handshake: OpenSSL over a non-blocking fd via bun:ffi,
// with WANT_READ / WANT_WRITE parks on the underlying fd. The handle
// answers a session box {ssl, ctx, fd} (never a raw fd): send/recv/
// close unpack it. SSL_set_tlsext_host_name is a macro in OpenSSL, so
// the hostname rides SSL_ctrl (SSL_CTRL_SET_TLSEXT_HOSTNAME).
//
// The dial is NOT this effect's job: the fd arrives already connected
// from Base.TCP.connect, so the first parameter is the socket itself.
// That is what puts a real fd in op.args[0], which is what io_park_on
// parks on -- the same shape Base's TCP.send / TCP.recv / TCP.poll have,
// and the reason a Promise-returning twin could never resume here.
// Nagle holds the second of two small writes until the peer's delayed ACK
// (~40ms per connection, measured on the WSS lane), so every fresh TLS fd
// turns it off. Best effort: a failed setsockopt costs latency, never
// correctness, so the result is deliberately not propagated.
function tls_connect_no_delay(sys, fd) {
  const one = Uint8Array.of(1, 0, 0, 0);
  // The result is deliberately dropped: `_rc` marks it as checked-and-
  // ignored, the same way the C twin does with (void)_rc.
  const _rc = sys.setsockopt(fd, 6, 1, sys.ptr(one), 4);
}

function tls_connect_raw(sock, sni, verify, alpn, k) {
  const sys = io_sys();
  const bad = (code, text) => ({ $: "Fail", error: io_tup(code, text) });
  const lib = tls_lib();
  if (lib === null) {
    return bad(616, "tls error");
  }
  // Base.TCP.connect hands over a connected fd that is non-blocking for
  // life; this effect only runs the handshake on it. A caller that
  // invented its own handle fails 611 here, before any library work.
  const fd = Number(sock);
  if (!Number.isInteger(fd) || fd < 0) {
    return bad(611, "bad input");
  }
  verify = Number(verify);
  alpn = Number(alpn);
  tls_connect_no_delay(sys, fd);
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
  const selected_alpn = (ses) => {
    const code = lib.alpn_code(ses);
    if (code === 1) {
      return "h2";
    }
    if (code === 2) {
      return "http/1.1";
    }
    return "";
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
      if (alpn > 3) {
        return fail(611, "bad input", ctx, null);
      }
      if (alpn === 1) {
        const offer = new Uint8Array([2, 104, 50]);
        if (lib.SSL_CTX_set_alpn_protos(ctx, lib.ptr(offer), 3) !== 0) {
          return fail(613, "handshake failed", ctx, null);
        }
      } else if (alpn === 2) {
        const offer = new Uint8Array([
          2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49,
        ]);
        if (lib.SSL_CTX_set_alpn_protos(ctx, lib.ptr(offer), 12) !== 0) {
          return fail(613, "handshake failed", ctx, null);
        }
      } else if (alpn === 3) {
        const offer = new Uint8Array([
          8, 104, 116, 116, 112, 47, 49, 46, 49,
        ]);
        if (lib.SSL_CTX_set_alpn_protos(ctx, lib.ptr(offer), 9) !== 0) {
          return fail(613, "handshake failed", ctx, null);
        }
      }
      ses = lib.SSL_new(ctx);
      if (!ses) {
        return fail(613, "handshake failed", ctx, null);
      }
      lib.SSL_set_fd(ses, fd);
      if (set_host(ses, sni) !== 1) {
        return fail(611, "bad input", ctx, ses);
      }
      if (verify && lib.SSL_set1_host(
        ses, lib.ptr(io_bytes(sni + "\0"))
      ) !== 1) {
        return fail(614, "verify failed", ctx, ses);
      }
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
        let ok_verify = true;
        try {
          ok_verify = !verify || lib.SSL_get_verify_result(ses) === 0;
        } catch (e) {
          ok_verify = false;
        }
        if (!ok_verify) return fail(614, "verify failed", ctx, ses);
        if (alpn === 1 || alpn === 2 || alpn === 3) {
          let selected = "";
          try {
            selected = selected_alpn(ses);
          } catch (e) {
            return fail(615, "alpn mismatch", ctx, ses);
          }
          if (alpn === 1 && selected !== "h2") {
            return fail(615, "alpn mismatch", ctx, ses);
          }
          if (alpn === 2 && selected !== ""
            && selected !== "h2" && selected !== "http/1.1") {
            return fail(615, "alpn mismatch", ctx, ses);
          }
          if (alpn === 3 && selected !== "http/1.1") {
            return fail(615, "alpn mismatch", ctx, ses);
          }
          const box = { $: "TlsConn", ssl: ses, ctx: ctx, fd: fd };
          return io_done(io_tup(box, selected));
        }
        const box = { $: "TlsConn", ssl: ses, ctx: ctx, fd: fd };
        return io_done(io_tup(box, ""));
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
  // The fd is connected and non-blocking for life, so SSL_connect parks
  // on WANT_READ / WANT_WRITE inside step and resumes on this same fd.
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
      const helper = ffi.cc({
        source: "lib/effs/tls_alpn.c",
        library: ["ssl"],
        symbols: {
          bend_tls_alpn_code: { args: [T.p], returns: T.i },
        },
      });
      globalThis.BEND_TLS_CONN = {
        ...lib.symbols,
        alpn_code: helper.symbols.bend_tls_alpn_code,
        ptr: ffi.ptr,
      };
    } catch (e) {
      globalThis.BEND_TLS_CONN = null;
    }
  }
  return globalThis.BEND_TLS_CONN;
}