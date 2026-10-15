// TLS close: queues close_notify (encrypted with the active write keys,
// 1.2 or 1.3 alike), flushes it best-effort, then closes the fd. Always
// answers Unit, like the C twin, because a close that fails to notify is
// still a close -- the peer's next read ends either way.
//
// TLS sockets must close HERE, never via Socket.close: the pump owns the
// only close path for this fd, and closing it behind the pump's back
// leaves the record layer holding a dead socket. No tls_rt() loader is
// needed -- everything rides the handle.
function tls_close(socket) {
  const conn = socket;
  if (conn && conn.$ === "TlsConn") {
    const sys = io_sys();
    const pump = conn.pump;
    if (pump) {
      pump.shutdown();
      try {
        const b = pump.drain();
        if (b !== null) {
          sys.send(conn.fd, sys.ptr(b), b.length);
        }
      } catch (e) {}
    }
    try {
      sys.close(conn.fd);
    } catch (e) {}
  }
  return { $: "Unit" };
}