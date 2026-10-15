// TLS recv: answers at most max bytes as a byte list, handing the socket
// back beside the result. Already-decrypted application data goes out
// without touching the fd; otherwise one read parks on POLLIN until more
// arrives. The empty list is the orderly shutdown answer -- TCP FIN, with
// or without close_notify, delivers whatever was buffered FIRST and only
// then reports the end, so a peer that writes and closes in one breath
// never loses its last bytes.
function tls_rt() {
  if (globalThis.BEND_TLS_RT === undefined) {
    try {
      globalThis.BEND_TLS_RT
        = require(process.cwd() + "/lib/effs/tls_rt.js");
    } catch (e) {
      globalThis.BEND_TLS_RT = null;
    }
  }
  return globalThis.BEND_TLS_RT;
}

function tls_recv_bytes(socket, max, k) {
  const sys = io_sys();
  const rt = tls_rt();
  const bad = (code, text) =>
    io_tup(socket, { $: "Fail", error: io_tup(code, text) });
  const conn = socket;
  if (!conn || conn.$ !== "TlsConn") {
    return bad(611, "bad input");
  }
  if (rt === null) {
    return bad(616, "tls error");
  }
  // Same window as the C twin: floor at 1, clamp at INT32_MAX (the C
  // twin casts to int, so a larger max would go negative there).
  const MAX_RECV = 0x7FFFFFFF;
  const nmax = Math.min(Math.max(Number(max), 1), MAX_RECV);
  const pump = conn.pump;
  const EAGAIN = sys.mac ? 35 : 11;
  let eof = false; // FIN seen: deliver the backlog, then stop reading
  const as_list = (b) => {
    let xs = { $: "Nil" };
    for (let i = b.length; i > 0; i -= 1) {
      xs = { $: "Con", head: b[i - 1], tail: xs };
    }
    return xs;
  };
  const deliver = () => {
    const b = pump.take_app(nmax);
    if (b !== null) {
      return io_tup(socket, io_done(as_list(b)));
    }
    if (pump.closed || eof) {
      return io_tup(socket, io_done({ $: "Nil" }));
    }
    return read_more();
  };
  const read_more = () => {
    const buf = new Uint8Array(16384);
    // recv answers the byte count as i64, so it is coerced the way the
    // runtime's own byte effects do (tcp_recv_bytes.js).
    const n = Number(sys.recv(conn.fd, sys.ptr(buf), 16384));
    if (n < 0) {
      if (sys.errno() === EAGAIN) {
        io_park_on(conn.fd, false, k, read_more);
        return undefined;
      }
      return bad(616, "tls error");
    }
    if (n === 0) {
      // FIN without close_notify: recv on an EOF fd returns 0 forever,
      // so without this flag the park loop would spin.
      eof = true;
      return deliver();
    }
    pump.feed(buf.subarray(0, n));
    if (pump.fail !== null) {
      return bad(pump.fail.code, pump.fail.text);
    }
    return deliver();
  };
  return deliver();
}