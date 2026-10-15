// scratch/eff_contract_probe.js -- hermetic: the five effects' contracts.
//
// The effects are what ships in lib/effs/. Every other probe of this
// package drives the runtime directly and never loads one of them, so
// before this rung a twin could be broken in a way no gate could see: the
// candidates sat unanswered (616) until this task installed the runtime,
// and the first thing that answered them hit three real bugs (see
// tasks/task-046-tls-js-lane-into-lib.md, D44-D46).
//
// This probe loads each twin the way the compiler does -- new Function
// over the file, with the runtime constructors in scope -- and asserts
// the contracts that need no socket: a handle that is not a connected fd
// answers 611, an ALPN mode outside 0..3 answers 611, a byte past 255
// answers 22 BEFORE any byte leaves, and close always answers Unit and
// closes the fd. The handshake itself is exercised by the Bend rung the
// same gate runs (tests/io/tls_alpn_none.bend), which drives these exact
// files through the real runtime with a real fd.
//
// Usage: eff_contract_probe.js [effs-dir]
//        BEND_EFFS_DIR=lib/effs eff_contract_probe.js
// Prints one PASS/FAIL line per case; exit 0 when every case holds.
// The value helpers come from the sibling package's harness instead of a
// local copy: it is the one place that already spells the Bend value
// shapes a twin hands back, and two spellings of io_tup would drift.
const path = require("path");
const fs = require("fs");
const { io_tup, io_done, io_fail, result_of } =
  require("../../tls-effects/scratch/eff_harness.js");

// Which copy of the five twins to load: the argument, BEND_EFFS_DIR, or
// this package's own effs/ -- the same default the whole gate uses, so one
// knob selects both. Note that the twins STILL require the runtime from
// lib/effs/: a cwd-absolute path is the one require that resolves in every
// lane, which is why this probe has to run from the repo root (exactly
// where the gate and check.sh run it) whichever copy it loads.
const effs_dir = path.resolve(process.argv[2] || process.env.BEND_EFFS_DIR
  || path.join(__dirname, "..", "effs"));

// The scope the compiler gives a twin: three result constructors, the
// syscall layer, and the park that hands control back to the runtime. A
// contract case must never park, so io_park_on throws instead -- a silent
// park here would mean the case under test is not the one it claims.
const closed = [];
function io_sys() {
  return {
    mac: false,
    ptr: (b) => b,
    setsockopt: () => 0,
    send: () => -1,
    recv: () => -1,
    // 9 = EBADF: a send that fails for a reason that is NOT "would block",
    // so no case below parks and the one that reaches the wire reports a
    // tls error instead.
    errno: () => 9,
    accept: () => -1,
    fcntl: () => 0,
    close: (fd) => { closed.push(fd); return 0; },
  };
}
function io_park_on() {
  throw new Error("a contract case must not park");
}
function io_bytes(text) {
  return new TextEncoder().encode(text);
}
function io_addr(host, port) {
  return null;
}

// The same trick the harness uses, with the fuller scope these effects
// need: they call io_sys() and io_park_on() where the native-tls twins of
// the tls-effects package do not, so the harness's three-constructor
// scope is not enough here.
function load_effect(file, fn_name) {
  const src = fs.readFileSync(path.join(effs_dir, file), "utf8");
  const build = new Function("require", "io_tup", "io_done", "io_fail",
    "io_sys", "io_park_on", "io_bytes", "io_addr",
    src + "\nreturn " + fn_name + ";");
  return build(require, io_tup, io_done, io_fail, io_sys, io_park_on,
    io_bytes, io_addr);
}

const k = () => {
  throw new Error("a contract case must not resume");
};

// The (code, text) a Fail answers, or null when the case did not fail.
function fail_code(res) {
  const r = result_of(res);
  if (r && r.$ === "Fail") {
    return r.error.fst;
  }
  return null;
}

let pass = 0;
let fail = 0;
function is(label, got, want) {
  if (got === want) {
    pass += 1;
    console.log("PASS " + label);
  } else {
    fail += 1;
    console.log("FAIL " + label + ": want " + want + ", got " + got);
  }
}

// -- tls_connect_raw: the handle is a connected fd, and nothing else --------
const connect = load_effect("tls_connect.js", "tls_connect_raw");

is("connect: a handle that is not an fd answers 611",
  fail_code(connect({}, "localhost", 0, 1, k)), 611);
is("connect: a negative fd answers 611",
  fail_code(connect(-1, "localhost", 0, 1, k)), 611);
is("connect: a fractional fd answers 611",
  fail_code(connect(1.5, "localhost", 0, 1, k)), 611);
// alpn_names(NaN) silently falls through to mode 0 -- no offer at all --
// so a NaN mode would hand back a handle the caller cannot use for the
// protocol it asked for. Bad input, not a default.
is("connect: an ALPN mode past 3 answers 611",
  fail_code(connect(3, "localhost", 0, 4, k)), 611);
is("connect: a NaN ALPN mode answers 611, not mode 0",
  fail_code(connect(3, "localhost", 0, NaN, k)), 611);
// The dial is NOT this effect's anymore: 612 belongs to Base.TCP.connect.
// This case drives a valid fd all the way to the write and fails there,
// which is what proves the 612 path is gone rather than merely unmentioned.
is("connect: a dead socket answers 616, never a dial 612",
  fail_code(connect(3, "localhost", 0, 1, k)), 616);

// -- tls_accept_raw: offer is one of the three documented modes ------------
const accept = load_effect("tls_accept.js", "tls_accept_raw");

is("accept: offer 0 answers 611",
  fail_code(accept(7, "cert.pem", "key.pem", 0, k)), 611);
is("accept: offer 4 answers 611",
  fail_code(accept(7, "cert.pem", "key.pem", 4, k)), 611);

// -- tls_send_bytes: byte range, and the socket handed back -----------------
const send_bytes = load_effect("tls_send_bytes.js", "tls_send_bytes");
const not_a_conn = {};
// A live-looking session: the pump is a stub because the cases below stop
// before anything would be sealed or read.
const box = {
  $: "TlsConn",
  pump: { shutdown: () => {}, drain: () => null },
  fd: 9,
};

is("send: a handle that is not a TlsConn answers 611",
  fail_code(send_bytes(not_a_conn, { $: "Nil" }, k)), 611);
// The list is walked before anything is sealed, so a past-255 value costs
// an EINVAL and not a half-sent record. The socket rides back beside it,
// like every byte effect of this lane.
const bad_byte = send_bytes(box,
  { $: "Con", head: 1, tail: { $: "Con", head: 256, tail: { $: "Nil" } } }, k);
is("send: a byte past 255 answers 22 before any byte leaves",
  fail_code(bad_byte), 22);

// -- tls_recv_bytes --------------------------------------------------------
const recv_bytes = load_effect("tls_recv_bytes.js", "tls_recv_bytes");

is("recv: a handle that is not a TlsConn answers 611",
  fail_code(recv_bytes(not_a_conn, 8, k)), 611);

// -- tls_close: always Unit, and the fd always closes ----------------------
const close = load_effect("tls_close.js", "tls_close");

// Every failure path above closed the fd it was holding: a handshake that
// dies with the socket open leaks it, and the runtime never reaps it.
is("connect: a failed handshake closes its fd",
  JSON.stringify(closed), "[3]");

is("close: a handle that is not a TlsConn still answers Unit",
  close(not_a_conn).$, "Unit");
closed.length = 0; // the close effect is measured on its own
is("close: a live session answers Unit",
  close(box).$, "Unit");
is("close: a live session closes its fd exactly once",
  JSON.stringify(closed), "[9]");

// The runtime the effects require has to load: without it every one of the
// five answers 616, which is the state this task found the lane in. The
// require inside a twin is cwd-absolute (the only path that resolves in
// every lane), so this asks the twin itself -- it looks in lib/effs/.
const loaded = load_effect("tls_connect.js", "tls_rt")();
is("the runtime the effects require resolves",
  typeof loaded.make_client === "function"
    && typeof loaded.make_server === "function"
    && typeof loaded.no_delay === "function", true);

// The copy the door cases below actually exercise: the effs directory this
// probe was pointed at, not the one the twins hard-wire, so BEND_EFFS_DIR
// selects it just like it selects the twins.
const rt = require(path.join(effs_dir, "tls_rt.js"));

// -- the runtime's byte doorway ---------------------------------------------
// The probes hand feed() the Buffer net gives them; an effect hands it the
// Uint8Array it allocated itself (new Uint8Array(16384), then subarray).
// The pump has to answer the same bytes the same way whichever one arrives:
// a TypeError escaping feed() takes the whole process down, not just the
// connection. That is D45, and no gate saw it until an effect was wired up.
const server_hello = Buffer.concat([
  Buffer.from([22, 3, 3, 0, 44]),   // one handshake record, 44 bytes
  Buffer.from([2, 0, 0, 40]),       // handshake type 2, 40-byte body
  Buffer.from([3, 3]),              // legacy_version 1.2
  Buffer.alloc(32, 7),              // random: not the HelloRetryRequest magic
  Buffer.from([0]),                 // no session id
  Buffer.from([0x13, 0x01]),        // TLS_AES_128_GCM_SHA256
  Buffer.from([0]),                 // no compression
  Buffer.from([0, 0]),              // no extensions
]);
const as_buffer = rt.make_client("localhost", 0, 1);
as_buffer.feed(server_hello);
const as_bytes = rt.make_client("localhost", 0, 1);
as_bytes.feed(Uint8Array.from(server_hello));
is("door: a Uint8Array record answers exactly what a Buffer answers",
  JSON.stringify(as_bytes.fail) === JSON.stringify(as_buffer.fail)
    && as_buffer.fail !== null
    && typeof as_buffer.fail.code === "number", true);

console.log("effs: " + effs_dir);
console.log((pass + fail) + " cases, " + fail + " failed");
if (fail > 0) {
  process.exit(1);
}
