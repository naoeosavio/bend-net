// TLS server handshake (the accept effect). One code path, two protocol
// versions: the runtime's server reads the ClientHello and answers 1.3
// or 1.2 by what the peer offered. The listener comes back on every
// path, like TCP.accept -- including the failure paths, so a caller that
// loops on accept cannot lose its listener to one bad handshake.
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

// cert and key are PEM PATHS on disk, not PEM data: the runtime reads
// them and answers 613 when either is unreadable, which is the code this
// def has always answered. offer mirrors tls.bend -- 1 picks h2 when the
// peer offers it, 2 accepts h2/http1.1, 3 accepts only http/1.1 -- and a
// peer whose list has no overlap fails 615, but only after the fatal
// no_application_protocol alert (120) has been flushed, so the peer
// learns why instead of seeing a bare close. A peer that offers NO ALPN
// is not a mismatch: it completes with an empty protocol (RFC 7301 s3.2).
//
// TLS 1.2 and 1.3 are the same code path: the ClientHello decides the
// version. Our own client sends one x25519 share; a peer whose shares
// skip every group we serve is answered with a HelloRetryRequest, and
// the retry completes (task-051 A6 fixed the server half, which used to
// hash a null suite and refuse the second ClientHello).
function tls_accept_raw(listener, cert, key, offer, k) {
  const sys = io_sys();
  const rt = tls_rt();
  const bad = (code, text) =>
    io_tup(listener, { $: "Fail", error: io_tup(code, text) });
  if (rt === null) {
    return bad(616, "tls error");
  }
  offer = Number(offer);
  if (offer !== 1 && offer !== 2 && offer !== 3) {
    return bad(611, "bad input");
  }
  let server;
  try {
    server = rt.make_server(cert, key, offer);
  } catch (e) {
    return bad(613, "handshake failed"); // unreadable cert/key paths
  }
  const EAGAIN = sys.mac ? 35 : 11;
  const lfd = listener;
  const fail = (fd, code, text) => {
    // Best-effort flush of whatever is queued (an alert the runtime
    // pushed before failing), then close. The fd always closes.
    try {
      const b = server.drain();
      if (b !== null) {
        sys.send(fd, sys.ptr(b), b.length);
      }
    } catch (e) {}
    sys.close(fd);
    return bad(code, text);
  };
  const send_all = (fd, buf, at, next) => {
    if (at >= buf.length) {
      return next();
    }
    const n = Number(sys.send(fd, sys.ptr(buf.subarray(at)), buf.length - at));
    if (n > 0) {
      return send_all(fd, buf, at + n, next);
    }
    if (n === 0 || sys.errno() === EAGAIN) {
      io_park_on(fd, true, k, () => send_all(fd, buf, at, next));
      return undefined;
    }
    return fail(fd, 616, "tls error");
  };
  // Drain first, THEN test done: in TLS 1.2 the final flight carries
  // the server ChangeCipherSpec + Finished in pump.out when done turns
  // true, and testing done first would drop them.
  const flush_then = (fd, next) => {
    const b = server.drain();
    if (b === null) {
      return next();
    }
    return send_all(fd, b, 0, next);
  };
  const step = (fd) => {
    const buf = new Uint8Array(16384);
    const n = Number(sys.recv(fd, sys.ptr(buf), 16384));
    if (n < 0) {
      if (sys.errno() === EAGAIN) {
        io_park_on(fd, false, k, () => step(fd));
        return undefined;
      }
      return fail(fd, 616, "tls error");
    }
    if (n === 0) {
      return fail(fd, 613, "handshake failed"); // EOF mid-handshake
    }
    server.feed(buf.subarray(0, n));
    if (server.fail !== null) {
      return fail(fd, server.fail.code, server.fail.text);
    }
    return flush_then(fd, () => {
      if (server.done) {
        const box = { $: "TlsConn", pump: server, fd: fd,
                      ssl: null, ctx: null };
        return io_tup(listener, io_done(io_tup(box, server.alpn)));
      }
      io_park_on(fd, false, k, () => step(fd));
      return undefined;
    });
  };
  const go = () => {
    const fd = sys.accept(lfd, null, null);
    if (fd < 0) {
      const code = sys.errno();
      if (code === EAGAIN) {
        io_park_on(lfd, false, k, go);
        return undefined;
      }
      return bad(code, "accept failed");
    }
    if (sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800)) < 0) {
      const code = sys.errno();
      sys.close(fd);
      return bad(code, "accept failed");
    }
    rt.no_delay(sys, fd);
    return step(fd);
  };
  return go();
}

function tls_accept_raw_need() {
  return { read: true };
}