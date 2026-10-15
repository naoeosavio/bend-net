// TLS receive effect. Returns the Bend List<U32> used by the original effect.
// Empty list represents EOF, matching the original SSL_read implementation.
// Promise-returning effects require the async effect-dispatch hook in README.md.
async function tls_recv_bytes(socket, max, k) {
  const bad = (code, text) => io_tup(socket, { $: "Fail", error: io_tup(code, text) });
  const conn = socket;
  if (!conn || conn.$ !== "TlsConn") return bad(611, "bad input");
  const n = Math.max(Number(max), 1);
  if (!Number.isSafeInteger(n) || n > 0x7fffffff) return bad(611, "bad input");
  try {
    let bytes;
    if (typeof conn._readRaw === "function") {
      bytes = await conn._readRaw(n);
    } else if (conn.socket && typeof conn.socket.read === "function") {
      // This branch is for streams where data is explicitly buffered by the
      // connection adapter; direct Node stream.read() is not a waiting API.
      bytes = conn.socket.read(n);
      if (bytes === null) return bad(616, "connection adapter has no async read queue");
    } else {
      return bad(611, "invalid TLS transport");
    }
    const view = bytes == null ? new Uint8Array(0) : (bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    let xs = { $: "Nil" };
    for (let i = view.byteLength; i > 0; i -= 1) {
      xs = { $: "Con", head: view[i - 1], tail: xs };
    }
    return io_tup(socket, io_done(xs));
  } catch (_) {
    return bad(616, "tls error");
  }
}
