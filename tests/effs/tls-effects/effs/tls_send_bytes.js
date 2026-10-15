// TLS send effect. Supports native TLS sockets and the Browser WSS adapter
// returned by tls_connect_raw when passed an explicit wss:// URL.
// Promise-returning effects require the async effect-dispatch hook in README.md.
async function tls_send_bytes(socket, data, k) {
  const bad = (code, text) => io_tup(socket, { $: "Fail", error: io_tup(code, text) });
  const conn = socket;
  if (!conn || conn.$ !== "TlsConn") return bad(611, "bad input");

  const bytes = [];
  for (let xs = data; xs && xs.$ === "Con"; xs = xs.tail) {
    const value = Number(xs.head);
    if (!Number.isInteger(value) || value < 0 || value > 255) return io_tup(socket, io_fail(22));
    bytes.push(value);
  }
  const payload = Uint8Array.from(bytes);
  try {
    if (typeof conn.sendRaw === "function") {
      await conn.sendRaw(payload);
    } else if (conn.socket && typeof conn.socket.write === "function") {
      await new Promise((resolve, reject) => conn.socket.write(payload, (error) => error ? reject(error) : resolve()));
    } else if (conn.socket && typeof conn.socket.send === "function") {
      if (typeof WebSocket !== "undefined" && conn.socket.readyState !== WebSocket.OPEN) throw new Error("WebSocket is not open");
      conn.socket.send(payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength));
    } else {
      return bad(611, "invalid TLS transport");
    }
    return io_tup(socket, io_done({ $: "Unit" }));
  } catch (_) {
    return bad(616, "tls error");
  }
}
