// TLS client handshake (the connect effect). One code path, two protocol
// versions: the runtime's client offers TLS 1.3 and 1.2 in a single
// ClientHello and the peer's ServerHello picks the version, so this
// effect never learns which one ran. Only the cwd-absolute require (the
// one that resolves in every lane) and guarded loads -- which is what
// keeps the page bundle alive.
//
// The compiler wraps each effect file in its own closure, so this loader
// repeats per file: the global slot makes the module body run once per
// process regardless.
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

// The handshake over an fd that is ALREADY connected: the dial belongs to
// Base.TCP.connect, which owns the fd and its non-blocking mode, so this
// effect neither opens a socket nor validates a port. The answer is a
// TlsConn box {pump, fd} -- never a raw fd, and no SSL* either: send,
// recv and close unpack it. Fail codes: 611 bad input, 613 handshake
// failed, 614 verify failed, 615 alpn mismatch, 616 tls error. The
// negotiated ALPN string rides back beside the handle. 612 (dial failed)
// is NOT this effect's anymore: it stays with the Transport connect.
//
// alpn mirrors tls.bend: 1 offers and requires h2, 2 offers h2/http1.1,
// 3 offers only http/1.1, 0 offers nothing. Modes 1 and 3 are strict --
// a selection that does not match fails 615 rather than returning a
// handle the caller cannot use for the protocol it asked for, and the
// peer's fatal no_application_protocol alert (120) maps to 615 too.
function tls_connect_raw(sock, sni, verify, alpn, k) {
  const sys = io_sys();
  const bad = (code, text) => ({ $: "Fail", error: io_tup(code, text) });
  const rt = tls_rt();
  verify = Number(verify);
  alpn = Number(alpn);
  // The fd arrives connected and non-blocking for life from the
  // Transport connect; the handshake parks on WANT_READ / WANT_WRITE
  // instead of stalling the loop. A caller that invented its own handle
  // fails 611 here, before any protocol work.
  const fd = Number(sock);
  if (!Number.isInteger(fd) || fd < 0) {
    return bad(611, "bad input");
  }
  if (!Number.isInteger(alpn) || alpn > 3) {
    return bad(611, "bad input");
  }
  if (rt === null) {
    return bad(616, "tls error");
  }
  const EAGAIN = sys.mac ? 35 : 11;
  // Nagle holds the second of two small writes until the peer's delayed
  // ACK (~40ms per connection), so every fresh fd turns it off. Best
  // effort: a failed setsockopt costs latency, never correctness, so the
  // result is deliberately not propagated.
  rt.no_delay(sys, fd);
  const fail = (code, text) => {
    sys.close(fd);
    return bad(code, text);
  };
  const pump = rt.make_client(sni, verify, alpn);
  // The ClientHello (1.3 and 1.2 offers in one record) is already in
  // pump.out. send_all parks on EAGAIN and resumes mid-buffer; the
  // same helper flushes every later flight, including the client
  // Finished the runtime queues when the server's verifies.
  const send_all = (buf, at, next) => {
    if (at >= buf.length) {
      return next();
    }
    // send answers the byte count as i64; the runtime's own byte effects
    // coerce it the same way (tcp_send_bytes.js), because Number is what
    // the loop arithmetic below is written for.
    const n = Number(sys.send(fd, sys.ptr(buf.subarray(at)),
      buf.length - at));
    if (n > 0) {
      return send_all(buf, at + n, next);
    }
    if (n === 0 || sys.errno() === EAGAIN) {
      io_park_on(fd, true, k, () => send_all(buf, at, next));
      return undefined;
    }
    return fail(616, "tls error");
  };
  const flush = (next) => {
    const b = pump.drain();
    if (b === null) {
      return next();
    }
    return send_all(b, 0, next);
  };
  const read_step = () => {
    const buf = new Uint8Array(16384);
    // recv answers the byte count as i64, so it is coerced the way the
    // runtime's own byte effects do (tcp_recv_bytes.js).
    const n = Number(sys.recv(fd, sys.ptr(buf), 16384));
    if (n < 0) {
      if (sys.errno() === EAGAIN) {
        io_park_on(fd, false, k, read_step);
        return undefined;
      }
      return fail(616, "tls error");
    }
    if (n === 0) {
      return fail(613, "handshake failed"); // EOF mid-handshake
    }
    pump.feed(buf.subarray(0, n));
    return settle();
  };
  const settle = () => {
    if (pump.fail !== null) {
      return fail(pump.fail.code, pump.fail.text);
    }
    // Flush FIRST, then test done: the client Finished (and, in 1.2,
    // the ChangeCipherSpec) ride pump.out when done turns true, and
    // testing done first would never send them.
    return flush(() => {
      if (pump.fail !== null) {
        return fail(pump.fail.code, pump.fail.text);
      }
      if (pump.done) {
        const sel = pump.alpn;
        if (alpn === 1 && sel !== "h2") {
          return fail(615, "alpn mismatch");
        }
        if (alpn === 3 && sel !== "http/1.1") {
          return fail(615, "alpn mismatch");
        }
        const box = { $: "TlsConn", pump: pump, fd: fd,
                      ssl: null, ctx: null };
        return io_done(io_tup(box, sel));
      }
      // ServerHello..Finished rarely lands in one flight; park, read on.
      io_park_on(fd, false, k, read_step);
      return undefined;
    });
  };
  return flush(read_step);
}
