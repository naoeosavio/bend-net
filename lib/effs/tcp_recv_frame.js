// TCP
// ===

// One framed read: bytes already held (buf) plus the socket until exactly
// one WS frame is isolated. The length prefix alone decides the total
// (2 + ext 0/2/8 + mask 0/4 + payload); nothing is validated here, the
// pure codec above rejects bad frames out of the isolated bytes. Answers
// Done{(frame, rest)}: the frame plus every byte read past it, so the
// caller threads the rest into the next call and no byte is lost.
// Fail texts are built by hand: io_fail only knows strerror codes.
function recv_frame(socket, buf, max, k) {
  const sys = io_sys();
  const fd = socket;
  const lim = Number(max);
  const bytes = [];
  for (let t = buf; t.$ === "Con"; t = t.tail) {
    bytes.push(Number(t.head) & 255);
  }
  const again = sys.mac ? 35 : 11;
  const fail = (code, text) =>
    io_tup(socket, { $: "Fail", error: io_tup(code, text) });
  const need = () => {
    if (bytes.length < 2) {
      return 0;
    }
    const len7 = bytes[1] & 127;
    const ext = len7 === 126 ? 2 : len7 === 127 ? 8 : 0;
    if (bytes.length < 2 + ext) {
      return 0;
    }
    let pay = len7;
    if (len7 === 126) {
      pay = (bytes[2] << 8) | bytes[3];
    }
    if (len7 === 127) {
      pay = 0;
      for (let i = 0; i < 8; i += 1) {
        pay = pay * 256 + bytes[2 + i];
      }
    }
    return 2 + ext + ((bytes[1] & 128) ? 4 : 0) + pay;
  };
  const pack = (total) => {
    let frame = { $: "Nil" };
    for (let i = total; i > 0; i -= 1) {
      frame = { $: "Con", head: bytes[i - 1], tail: frame };
    }
    let rest = { $: "Nil" };
    for (let i = bytes.length; i > total; i -= 1) {
      rest = { $: "Con", head: bytes[i - 1], tail: rest };
    }
    return io_tup(socket, io_done(io_tup(frame, rest)));
  };
  const chunk = new Uint8Array(8192);
  const go = () => {
    for (;;) {
      const total = need();
      if (total !== 0 && bytes.length >= total) {
        if (total > lim) {
          return fail(413, "frame too large");
        }
        return pack(total);
      }
      if (total !== 0 && total > lim) {
        return fail(413, "frame too large");
      }
      if (total === 0 && bytes.length >= lim) {
        return fail(413, "frame too large");
      }
      const n = Number(sys.recv(fd, sys.ptr(chunk), chunk.length, 0));
      if (n < 0) {
        const code = sys.errno();
        if (code === again) {
          io_park_on(fd, false, k, go);
          return undefined;
        }
        return io_tup(socket, io_fail(code));
      }
      if (n === 0) {
        return fail(400, "eof");
      }
      for (let i = 0; i < n; i += 1) {
        bytes.push(chunk[i]);
      }
    }
  };
  return go();
}

function recv_frame_need() {
  return { read: true };
}
