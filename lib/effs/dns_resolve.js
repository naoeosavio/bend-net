// DNS
// ===

// One A query over UDP, off the loop: the nameserver comes from
// /etc/resolv.conf (read with require("fs"), the way the runtime's own
// file effects read a file; fallback 127.0.0.53), the request parks on
// the socket with a 3 s deadline (io_park_on), one retry on silence
// (the second timeout answers 603), and the answer is the first A
// record of a 512-byte reply -- no TCP retry for a truncated one.
// Stable fail codes (the C twin's getaddrinfo maps to the same table):
// 601 bad host (a label this twin re-rejects), 602 NXDOMAIN, 603
// SERVFAIL or the second timeout, 604 an answer with no A record, 605
// every socket or malformed-answer path. lib/dns.bend refuses an address
// form that is not a canonical quad (01.2.3.4, 127.1, 0x7f.1, 256.1.1.1)
// with 601 before the effect, so this query only ever sees real names
// (task-051 A2).
// Fail tuples are built by hand: io_fail only knows strerror codes.

function dns_lookup(host, k) {
  const sys = io_sys();
  const ms = 3000;
  const again = sys.mac ? 35 : 11;
  const bad = (code, text) => ({ $: "Fail", error: io_tup(code, text) });
  const ns = dns_ns();
  if (ns === null) {
    return bad(605, "resolve error");
  }
  const id = (Math.random() * 65536) | 0;
  const q = dns_query(id, host);
  if (q === null) {
    return bad(601, "bad host");
  }
  const fd = sys.socket(2, 2, 0);
  const fail = (code, text) => {
    sys.close(fd);
    return bad(code, text);
  };
  if (fd < 0) {
    return fail(605, "resolve error");
  }
  const set = sys.fcntl(fd, 4, sys.fcntl(fd, 3, 0) | (sys.mac ? 4 : 0x800));
  if (set < 0) {
    return fail(605, "resolve error");
  }
  const buf = new Uint8Array(512);
  let tries = 0;
  let deadline = performance.now() + ms;
  if (sys.sendto(fd, sys.ptr(q), q.length, 0, sys.ptr(ns), 16) < 0) {
    return fail(605, "resolve error");
  }
  const step = () => {
    const n = Number(sys.recv(fd, sys.ptr(buf), buf.length, 0));
    if (n < 0) {
      const code = sys.errno();
      if (code !== again) {
        return fail(605, "resolve error");
      }
    } else {
      const r = dns_parse(id, buf, n);
      if (typeof r === "string") {
        sys.close(fd);
        return io_done(r);
      }
      if (r !== 0) {
        return fail(r, dns_msg(r));
      }
    }
    if (performance.now() >= deadline) {
      tries += 1;
      if (tries > 1) {
        return fail(603, "resolve failed, try again");
      }
      if (sys.sendto(fd, sys.ptr(q), q.length, 0, sys.ptr(ns), 16) < 0) {
        return fail(605, "resolve error");
      }
      deadline = performance.now() + ms;
    }
    io_park_on(fd, false, k, step, deadline);
    return undefined;
  };
  return step();
}

// The first IPv4 nameserver of /etc/resolv.conf; without one,
// 127.0.0.53 (the common local resolver). The dotted quad and the
// sockaddr come from the runtime's io_addr(), the same door every
// effect in the runtime's own effs uses (tcp_listen.js:13).
function dns_ns() {
  const text = dns_file();
  for (const line of (text === null ? "" : text).split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length > 1 && parts[0] === "nameserver") {
      const at = io_addr(parts[1], 53);
      if (at !== null) {
        return at;
      }
    }
  }
  return io_addr("127.0.0.53", 53);
}

// /etc/resolv.conf through require("fs"), the host-neutral way the
// runtime reads a file (file_open.js:13, file_read.js:5). The libc
// dlopen that used to live here was the only unguarded
// require("bun:ffi") in the lib, and the page bundler aborts on an
// unguarded one (a guarded require becomes a stub that throws), so this
// one function took lib/dns.bend, lib/wsm.bend and lib/httpx.bend out
// of the browser.
function dns_file() {
  try {
    return require("fs").readFileSync("/etc/resolv.conf", "utf8");
  } catch (e) {
    return null;
  }
}

// Header + QNAME + QTYPE A + QCLASS IN; a label past 63 or empty
// makes the host bad (the pure layer already capped the rest).
function dns_query(id, host) {
  const parts = host.split(".");
  let size = 12 + 1 + 4;
  for (const p of parts) {
    if (p.length === 0 || p.length > 63) {
      return null;
    }
    size += p.length + 1;
  }
  const q = new Uint8Array(size);
  q[0] = id >> 8;
  q[1] = id & 255;
  q[2] = 1;
  q[5] = 1;
  let i = 12;
  for (const p of parts) {
    q[i] = p.length;
    i += 1;
    for (const c of p) {
      q[i] = c.charCodeAt(0);
      i += 1;
    }
  }
  q[i + 2] = 1;
  q[i + 4] = 1;
  return q;
}

// "ip" on the first A record; 0 to keep waiting (wrong id, garbage);
// a stable fail code otherwise. Names are skipped, not decompressed:
// the answer is the rdata, not the name.
function dns_parse(id, b, n) {
  if (n < 12 || b[0] !== (id >> 8) || b[1] !== (id & 255)) {
    return 0;
  }
  const rcode = b[3] & 15;
  if (rcode === 3) {
    return 602;
  }
  if (rcode !== 0) {
    return rcode === 2 ? 603 : 605;
  }
  const skip = (i) => {
    for (;;) {
      if (i >= n) {
        return -1;
      }
      const len = b[i];
      if ((len & 192) === 192) {
        return i + 2 <= n ? i + 2 : -1;
      }
      if (len === 0) {
        return i + 1;
      }
      i += len + 1;
    }
  };
  let i = skip(12);
  if (i < 0) {
    return 605;
  }
  i += 4;
  const answers = (b[6] << 8) | b[7];
  for (let a = 0; a < answers; a += 1) {
    const j = skip(i);
    if (j < 0 || j + 10 > n) {
      return 605;
    }
    const type = (b[j] << 8) | b[j + 1];
    const cls = (b[j + 2] << 8) | b[j + 3];
    const rdlen = (b[j + 8] << 8) | b[j + 9];
    const at = j + 10;
    if (type === 1 && cls === 1 && rdlen === 4 && at + 4 <= n) {
      return b[at] + "." + b[at + 1] + "." + b[at + 2] + "." + b[at + 3];
    }
    i = at + rdlen;
  }
  return 604;
}

// The same texts the C twin's dns_msg answers.
function dns_msg(code) {
  if (code === 601) {
    return "bad host";
  }
  if (code === 602) {
    return "host not found";
  }
  if (code === 603) {
    return "resolve failed, try again";
  }
  if (code === 604) {
    return "no ipv4 address";
  }
  return "resolve error";
}
