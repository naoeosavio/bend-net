// TLS server accept effect for the Bend JS target.
// Preferred input: a runtime-native plain TCP server/listener object that emits
// `connection`. Numeric legacy FDs are supported only where io_sys() can accept
// them; this fallback still depends on the existing TCP runtime layer.
// Promise-returning effects require the async dispatch hook recorded in
// tasks/task-043-js-lane-tls-pure.md.

// True when the host is reporting "the peer would not agree on a
// protocol": node answers a client with no protocol in common by sending
// alert 120 and then failing the socket with ERR_SSL_NO_APPLICATION_PROTOCOL.
// Each effect file carries its own copy because the compiler wraps every
// file in its own closure.
function tls_is_alpn_error(error) {
  if (!error) return false;
  const code = String(error.code || "");
  const reason = String(error.reason || "");
  return code.includes("NO_APPLICATION_PROTOCOL") ||
    code.includes("ALPN_CALLBACK") || reason.includes("application protocol");
}

function tls_accept_raw(listener, cert, key, offer, k) {
  const bad = (code, text) => io_tup(listener, { $: "Fail", error: io_tup(code, text) });
  const policy = Number(offer);
  if (policy !== 1 && policy !== 2 && policy !== 3) return bad(611, "bad input");
  if (typeof window !== "undefined" && typeof process === "undefined") {
    return bad(616, "browser cannot accept inbound TCP/TLS connections");
  }

  let tls;
  let net;
  let fs;
  try {
    tls = require("tls");
    net = require("net");
    fs = require("fs");
  } catch (_) { return bad(616, "TLS runtime module unavailable"); }

  const protocols = policy === 1 ? ["h2"] : policy === 2 ? ["h2", "http/1.1"] : ["http/1.1"];
  const readPem = (value, label) => {
    if (value instanceof Uint8Array) return value;
    if (typeof value !== "string" || value.length === 0) throw new TypeError(label + " must be a file path or PEM data");
    return value.includes("-----BEGIN ") ? value : fs.readFileSync(value);
  };

  const acceptPlain = async () => {
    if (listener && typeof listener.once === "function" && typeof listener.on === "function") {
      return new Promise((resolve, reject) => {
        const onConnection = (socket) => { cleanup(); resolve(socket); };
        const onError = (error) => { cleanup(); reject(error); };
        const cleanup = () => { listener.removeListener("connection", onConnection); listener.removeListener("error", onError); };
        listener.once("connection", onConnection);
        listener.once("error", onError);
      });
    }
    // Compatibility path for the previous Bend TCP ABI (listener = fd).
    // This calls the existing syscall layer, but TLS itself no longer uses FFI.
    if (Number.isInteger(listener)) {
      const sys = io_sys();
      for (;;) {
        const fd = sys.accept(listener, null, null);
        if (fd >= 0) {
          if (sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800)) < 0) {
            const errorCode = sys.errno();
            sys.close(fd);
            const error = new Error("accept failed"); error.code = errorCode; throw error;
          }
          return new net.Socket({ fd, readable: true, writable: true });
        }
        const code = sys.errno();
        if (code !== (sys.mac ? 35 : 11)) {
          const error = new Error("accept failed"); error.code = code; throw error;
        }
        // Yield to the host event loop between non-blocking accept attempts.
        await new Promise((resolve) => setTimeout(resolve, 1));
      }
    }
    throw new TypeError("listener must be a TCP server/listener object or a legacy raw FD");
  };

  const wrapIncoming = (plain, certBytes, keyBytes) => new Promise((resolve, reject) => {
    let secureSocket;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      try { secureSocket ? secureSocket.destroy() : plain.destroy(); } catch (_) {}
      reject(error);
    };
    const onSecure = () => {
      if (settled) return;
      settled = true;
      const selected = String(secureSocket.alpnProtocol || "");
      const state = { chunks: [], waiters: [], ended: false, error: null };
      const satisfy = () => {
        while (state.waiters.length) {
          const waiter = state.waiters[0];
          if (state.chunks.length) {
            let chunk = state.chunks.shift();
            if (chunk.byteLength > waiter.max) { state.chunks.unshift(chunk.subarray(waiter.max)); chunk = chunk.subarray(0, waiter.max); }
            state.waiters.shift().resolve(chunk);
          } else if (state.ended) {
            const w = state.waiters.shift();
            if (state.error) w.reject(state.error); else w.resolve(null);
          } else break;
        }
      };
      secureSocket.on("data", (chunk) => { state.chunks.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength).slice()); satisfy(); });
      secureSocket.on("end", () => { state.ended = true; satisfy(); });
      secureSocket.on("close", () => { state.ended = true; satisfy(); });
      secureSocket.on("error", (error) => { state.error = error; state.ended = true; satisfy(); });
      const conn = {
        $: "TlsConn", runtime: typeof process !== "undefined" && process.versions && process.versions.bun ? "bun" : "node",
        socket: secureSocket, alpnProtocol: selected, authorized: true, _readerState: state,
        _readRaw(max) {
          if (!Number.isSafeInteger(max) || max < 1) return Promise.reject(new RangeError("max must be positive"));
          if (state.chunks.length) {
            let chunk = state.chunks.shift();
            if (chunk.byteLength > max) { state.chunks.unshift(chunk.subarray(max)); chunk = chunk.subarray(0, max); }
            return Promise.resolve(chunk);
          }
          if (state.ended) return state.error ? Promise.reject(state.error) : Promise.resolve(null);
          return new Promise((resolveRead, rejectRead) => state.waiters.push({ max, resolve: resolveRead, reject: rejectRead }));
        },
        sendRaw(bytes) {
          if (secureSocket.destroyed || secureSocket.writable === false) return Promise.reject(new Error("TLS connection is not writable"));
          return new Promise((resolveWrite, rejectWrite) => secureSocket.write(bytes, (error) => error ? rejectWrite(error) : resolveWrite()));
        },
        closeRaw() {
          if (secureSocket.destroyed || secureSocket.closed) return Promise.resolve();
          return new Promise((done) => {
            const finish = () => { secureSocket.removeListener("finish", finish); secureSocket.removeListener("close", finish); done(); };
            secureSocket.once("finish", finish); secureSocket.once("close", finish); secureSocket.end();
          });
        }
      };
      resolve({ conn, selected });
    };
    try {
      const secureContext = tls.createSecureContext({ cert: certBytes, key: keyBytes, minVersion: "TLSv1.2" });
      secureSocket = new tls.TLSSocket(plain, {
        isServer: true, secureContext, ALPNProtocols: protocols,
        requestCert: false, rejectUnauthorized: false
      });
      secureSocket.once("secure", onSecure);
      secureSocket.once("error", fail);
    } catch (error) { fail(error); }
  });

  return (async () => {
    let plain;
    try {
      const certBytes = readPem(cert, "cert");
      const keyBytes = readPem(key, "key");
      plain = await acceptPlain();
      const { conn, selected } = await wrapIncoming(plain, certBytes, keyBytes);
      // The old server-side ALPN callback declines unsupported names instead
      // of failing the TLS handshake; an empty selection is therefore valid.
      return io_tup(listener, io_done(io_tup(conn, selected)));
    } catch (error) {
      if (tls_is_alpn_error(error)) {
        return bad(615, "alpn mismatch");
      }
      const code = error && (error.code === "ECONNRESET" || error.code === "EPIPE") ? 613 : 612;
      return bad(code, code === 613 ? "handshake failed" : "accept failed");
    }
  })();
}

function tls_accept_raw_need() {
  return { read: true };
}
