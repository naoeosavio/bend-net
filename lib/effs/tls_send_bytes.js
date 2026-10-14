// TLS send: packs List<&2, U32> and seals it as application data, one
// record per 16383-byte chunk, so any list size works. A value past 255
// fails with EINVAL (22) BEFORE any byte leaves -- the caller handed us
// something that is not a byte, and half-sending it would be worse than
// refusing. The flush parks on POLLOUT while the fd's buffer is full and
// resumes mid-buffer, so a send larger than the socket buffer completes
// rather than truncating.
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

function tls_send_bytes(socket, data, k) {
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
  const bytes = [];
  for (let xs = data; xs.$ === "Con"; xs = xs.tail) {
    bytes.push(xs.head);
  }
  if (bytes.some((x) => x > 255)) {
    return io_tup(socket, io_fail(22)); // EINVAL, before any byte leaves
  }
  const pump = conn.pump;
  if (!pump.seal_app(Buffer.from(bytes))) {
    const f = pump.fail || { code: 616, text: "tls error" };
    return bad(f.code, f.text);
  }
  const b = pump.drain();
  if (b === null) {
    return io_tup(socket, io_done({ $: "Unit" }));
  }
  const EAGAIN = sys.mac ? 35 : 11;
  const go = (at) => {
    // send answers the byte count as i64; the runtime's own byte effects
    // coerce it the same way (tcp_send_bytes.js).
    const n = Number(sys.send(conn.fd, sys.ptr(b.subarray(at)),
      b.length - at));
    if (n > 0) {
      if (at + n >= b.length) {
        return io_tup(socket, io_done({ $: "Unit" }));
      }
      return go(at + n);
    }
    if (n === 0 || sys.errno() === EAGAIN) {
      io_park_on(conn.fd, true, k, () => go(at));
      return undefined;
    }
    return bad(616, "tls error");
  };
  return go(0);
}