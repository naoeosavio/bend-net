// TLS close effect. Ends the TLS stream so the runtime can send close_notify,
// then destroys the transport once shutdown finishes.
// Promise-returning effects require the async effect-dispatch hook in
// tasks/task-043-js-lane-tls-pure.md.
async function tls_close(socket) {
  const conn = socket;
  if (!conn || conn.$ !== "TlsConn") return { $: "Unit" };
  try {
    if (typeof conn.closeRaw === "function") {
      await conn.closeRaw();
    } else if (conn.socket && typeof conn.socket.end === "function") {
      const stream = conn.socket;
      if (!stream.destroyed && !stream.closed) {
        await new Promise((resolve) => {
          const done = () => { stream.removeListener("finish", done); stream.removeListener("close", done); resolve(); };
          stream.once("finish", done);
          stream.once("close", done);
          stream.end();
        });
      }
      if (typeof stream.destroy === "function" && !stream.destroyed) stream.destroy();
    } else if (conn.socket && typeof conn.socket.close === "function") {
      conn.socket.close();
    }
  } catch (_) {
    try { if (conn.socket && typeof conn.socket.destroy === "function") conn.socket.destroy(); } catch (_) {}
  }
  return { $: "Unit" };
}
