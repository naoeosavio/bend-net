// TCP
// ===

// Packs the List<&2, U32> body into a byte buffer (a value past 255
// fails with EINVAL before any byte leaves), then sends what is left; a
// full socket parks the computation until the socket is writable.
function send_bytes(socket, data, k) {
  const sys = io_sys();
  const fd = socket;
  const bytes = [];
  for (let xs = data; xs.$ === "Con"; xs = xs.tail) {
    bytes.push(xs.head);
  }
  if (bytes.some((x) => x > 255)) {
    return io_tup(socket, io_fail(22));
  }
  const b = Uint8Array.from(bytes);
  const again = sys.mac ? 35 : 11;
  const go = (at) => {
    while (at < b.length) {
      const part = b.subarray(at);
      const n = Number(sys.send(fd, sys.ptr(part), part.length, 0));
      if (n < 0) {
        const code = sys.errno();
        if (code === again) {
          io_park_on(fd, true, k, () => go(at));
          return undefined;
        }
        return io_tup(socket, io_fail(code));
      }
      at += n;
    }
    return io_tup(socket, io_done({ $: "Unit" }));
  };
  return go(0);
}
