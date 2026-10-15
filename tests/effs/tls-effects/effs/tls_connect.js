// TLS client effect for the Bend JS target.
// Node/Bun: native `tls` + `net`.
// Browser: accepts an explicit wss:// URL in `ip`; this is WebSocket framing,
// not a raw TCP/TLS byte stream. Promise-returning effects require the async
// effect-dispatch hook documented in ../README.md.

// True when the host is reporting "the peer would not agree on a
// protocol". Node rejects the connection before `secureConnect` when the
// peer answers the ALPN extension with alert 120 no_application_protocol,
// and bun maps its own check to 615 already. Without this the refusal
// arrived as 613 handshake failed, a generic code that hides the one
// cause the `alpn` argument exists to report. Each effect file carries its
// own copy because the compiler wraps every file in its own closure.
function tls_is_alpn_error(error) {
  if (!error) return false;
  const code = String(error.code || "");
  const reason = String(error.reason || "");
  return code.includes("NO_APPLICATION_PROTOCOL") ||
    code.includes("ALPN_CALLBACK") || reason.includes("application protocol");
}

function tls_connect_raw(ip, sni, port, verify, alpn, k) {
  const bad = (code, text) => ({ $: "Fail", error: io_tup(code, text) });
  const policy = Number(alpn);
  const secure = Number(verify) !== 0;

  if (![0, 1, 2, 3].includes(policy)) return bad(611, "bad input");

  const protocols = policy === 1 ? ["h2"]
    : policy === 2 ? ["h2", "http/1.1"]
    : policy === 3 ? ["http/1.1"] : undefined;

  // Browsers cannot create arbitrary TCP sockets or run TLS directly. WSS is
  // the browser-safe byte-message transport and must be requested explicitly.
  if (typeof window !== "undefined" && typeof process === "undefined") {
    if (typeof ip !== "string" || !ip.startsWith("wss://")) {
      return bad(616, "browser requires a wss:// URL; raw TCP/TLS is unavailable");
    }
    if (typeof WebSocket !== "function") return bad(616, "WebSocket unavailable");
    if (policy === 1 || policy === 3) {
      return bad(615, "browser does not expose TLS ALPN; use policy 0 or 2");
    }
    return new Promise((resolve) => {
      let ws;
      try {
        ws = new WebSocket(ip);
        ws.binaryType = "arraybuffer";
      } catch (_) {
        resolve(bad(613, "handshake failed"));
        return;
      }
      const state = { chunks: [], waiters: [], ended: false, error: null };
      const satisfy = () => {
        while (state.waiters.length) {
          const waiter = state.waiters[0];
          if (state.chunks.length) {
            let chunk = state.chunks.shift();
            if (chunk.byteLength > waiter.max) {
              state.chunks.unshift(chunk.subarray(waiter.max));
              chunk = chunk.subarray(0, waiter.max);
            }
            state.waiters.shift().resolve(chunk);
          } else if (state.ended) {
            state.waiters.shift()[state.error ? "reject" : "resolve"](state.error || null);
          } else break;
        }
      };
      const conn = {
        $: "TlsConn", runtime: "browser", transport: "websocket", socket: ws,
        alpnProtocol: "", authorized: true,
        _readRaw(max) {
          if (!Number.isSafeInteger(max) || max < 1) return Promise.reject(new RangeError("max must be positive"));
          if (state.chunks.length) {
            let chunk = state.chunks.shift();
            if (chunk.byteLength > max) {
              state.chunks.unshift(chunk.subarray(max));
              chunk = chunk.subarray(0, max);
            }
            return Promise.resolve(chunk);
          }
          if (state.ended) return state.error ? Promise.reject(state.error) : Promise.resolve(null);
          return new Promise((resolveRead, rejectRead) => state.waiters.push({ max, resolve: resolveRead, reject: rejectRead }));
        },
        _readerState: state,
        sendRaw(bytes) {
          if (ws.readyState !== WebSocket.OPEN) return Promise.reject(new Error("WebSocket is not open"));
          const copy = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
          ws.send(copy);
          return Promise.resolve();
        },
        closeRaw() {
          if (ws.readyState === WebSocket.CLOSED) return Promise.resolve();
          return new Promise((done) => {
            ws.addEventListener("close", done, { once: true });
            ws.close();
          });
        }
      };
      ws.addEventListener("message", async (event) => {
        try {
          let bytes;
          if (event.data instanceof ArrayBuffer) bytes = new Uint8Array(event.data);
          else if (ArrayBuffer.isView(event.data)) bytes = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
          else if (typeof Blob !== "undefined" && event.data instanceof Blob) bytes = new Uint8Array(await event.data.arrayBuffer());
          else if (typeof event.data === "string") bytes = new TextEncoder().encode(event.data);
          else throw new TypeError("unsupported WebSocket frame");
          if (bytes.byteLength) state.chunks.push(bytes.slice());
          satisfy();
        } catch (error) { state.error = error; state.ended = true; satisfy(); }
      });
      ws.addEventListener("error", () => { state.error = new Error("WebSocket transport error"); state.ended = true; satisfy(); });
      ws.addEventListener("close", () => { state.ended = true; satisfy(); });
      ws.addEventListener("open", () => resolve(io_done(io_tup(conn, ""))), { once: true });
      ws.addEventListener("error", () => resolve(bad(613, "handshake failed")), { once: true });
    });
  }

  let tls;
  let net;
  try {
    tls = require("tls");
    net = require("net");
  } catch (_) {
    return bad(616, "TLS runtime module unavailable");
  }

  const host = String(ip || "");
  const portNum = Number(port);
  if (!host || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    return bad(611, "bad input");
  }

  return new Promise((resolve) => {
    let socket;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      try { if (socket) socket.destroy(); } catch (_) {}
      const code = error && (error.code === "ECONNREFUSED" || error.code === "ENOTFOUND" || error.code === "EHOSTUNREACH" || error.code === "ETIMEDOUT")
        ? 612
        : error && (String(error.code || "").includes("CERT") || String(error.code || "").includes("HOSTNAME") || String(error.code || "").includes("ALTNAME"))
          ? 614
          : tls_is_alpn_error(error)
            ? 615 : 613;
      const text = code === 612 ? "dial failed"
        : code === 614 ? "verify failed"
        : code === 615 ? "alpn mismatch" : "handshake failed";
      resolve(bad(code, text));
    };
    const onSecure = () => {
      if (settled) return;
      if (secure && socket.authorized === false) return fail(Object.assign(new Error("certificate verification failed"), { code: "CERT_VERIFY_FAILED" }));
      const selected = String(socket.alpnProtocol || "");
      if ((policy === 1 && selected !== "h2") ||
          (policy === 2 && selected !== "" && selected !== "h2" && selected !== "http/1.1") ||
          (policy === 3 && selected !== "http/1.1")) {
        try { socket.destroy(); } catch (_) {}
        settled = true;
        resolve(bad(615, "alpn mismatch"));
        return;
      }
      settled = true;
      socket.removeListener("error", fail);
      const state = { chunks: [], waiters: [], ended: false, error: null };
      const satisfy = () => {
        while (state.waiters.length) {
          const waiter = state.waiters[0];
          if (state.chunks.length) {
            let chunk = state.chunks.shift();
            if (chunk.byteLength > waiter.max) {
              state.chunks.unshift(chunk.subarray(waiter.max));
              chunk = chunk.subarray(0, waiter.max);
            }
            state.waiters.shift().resolve(chunk);
          } else if (state.ended) {
            const waiterDone = state.waiters.shift();
            if (state.error) waiterDone.reject(state.error); else waiterDone.resolve(null);
          } else break;
        }
      };
      socket.on("data", (chunk) => { state.chunks.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength).slice()); satisfy(); });
      socket.on("end", () => { state.ended = true; satisfy(); });
      socket.on("close", () => { state.ended = true; satisfy(); });
      socket.on("error", (error) => { state.error = error; state.ended = true; satisfy(); });
      const conn = {
        $: "TlsConn", runtime: typeof process !== "undefined" && process.versions && process.versions.bun ? "bun" : "node",
        socket, alpnProtocol: selected, authorized: socket.authorized !== false,
        _readerState: state,
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
          if (socket.destroyed || socket.writable === false) return Promise.reject(new Error("TLS connection is not writable"));
          return new Promise((resolveWrite, rejectWrite) => socket.write(bytes, (error) => error ? rejectWrite(error) : resolveWrite()));
        },
        closeRaw() {
          if (socket.destroyed || socket.closed) return Promise.resolve();
          return new Promise((done) => {
            const finish = () => { socket.removeListener("finish", finish); socket.removeListener("close", finish); done(); };
            socket.once("finish", finish); socket.once("close", finish); socket.end();
          });
        }
      };
      resolve(io_done(io_tup(conn, selected)));
    };

    try {
      const opts = {
        host, port: portNum, rejectUnauthorized: secure, minVersion: "TLSv1.2",
        ...(protocols ? { ALPNProtocols: protocols } : {}),
        ...(sni && !(typeof net.isIP === "function" && net.isIP(String(sni))) ? { servername: String(sni) } : {})
      };
      socket = tls.connect(opts);
      socket.once("secureConnect", onSecure);
      socket.once("error", fail);
    } catch (error) { fail(error); }
  });
}
