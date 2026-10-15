// Hermetic unit vectors for the TLS recv window.
//
// Both twins answer at most INT32_MAX bytes per read and at least one:
// the C twin casts max to int (a larger value would go negative there),
// and the JS twin mirrors the window (task-051, recv clamp). This probe
// loads the JS twin the way the compiler does, feeds it a pump with
// buffered application data, and pins the floor, a middle value, the
// clamp, and the two fail-closed paths. No sockets, no handshake.
//
// Run: node tests/effs/eff-unit-clamp.js (via tests/effs/eff-unit.sh).
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const twin_src = fs.readFileSync(path.join(__dirname, "..", "..", "lib",
  "effs", "tls_recv_bytes.js"), "utf8");

// The runtime doors the twin uses on the buffered path: io_sys for the
// mac flag only, io_tup/io_done as transparent wrappers.
const io_sys = () => ({ mac: false });
const io_tup = (a, b) => ({ tup: [a, b] });
const io_done = (x) => ({ done: x });

const box = { io_sys, io_tup, io_done, io_park_on: () => {
  throw new Error("parked: no buffered data");
} };
vm.createContext(box);
vm.runInContext(twin_src
  + "\nglobalThis.__recv = { tls_recv_bytes };", box);
const recv = box.__recv.tls_recv_bytes;
// A present runtime: the twin's loader would require() it, which the
// sandbox has no door for, so the slot is primed directly.
box.BEND_TLS_RT = {};

let pass = 0;
let fail = 0;
const check = (name, cond) => {
  if (cond) {
    pass += 1;
    console.log("PASS " + name);
  } else {
    fail += 1;
    console.log("FAIL " + name);
  }
};

// A handle whose pump always has application data, recording the window
// the twin asked for.
const seen = [];
const conn = {
  $: "TlsConn",
  fd: 9,
  pump: { take_app: (n) => {
    seen.push(n);
    return [7];
  } },
};

const fail_code = (out) => out.tup[1].error.tup[0];
const done_head = (out) => out.tup[1].done;

recv(conn, 0, null);
check("max 0 is floored to 1", seen[seen.length - 1] === 1);
recv(conn, 100, null);
check("max 100 passes through", seen[seen.length - 1] === 100);
recv(conn, Math.pow(2, 40), null);
check("max past int is clamped to INT32_MAX",
  seen[seen.length - 1] === 0x7FFFFFFF);
check("buffered data answers a one-byte list",
  JSON.stringify(done_head(recv(conn, 8, null)))
  === JSON.stringify({ $: "Con", head: 7, tail: { $: "Nil" } }));
check("a foreign handle fails 611",
  fail_code(recv({ $: "Socket" }, 8, null)) === 611);
box.BEND_TLS_RT = null;
check("no runtime fails 616",
  fail_code(recv(conn, 8, null)) === 616);

console.log("=== " + pass + " passed, " + fail + " failed ===");
process.exit(fail === 0 ? 0 : 1);
