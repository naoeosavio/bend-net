// Phase 0 gate probe: can this runtime wrap an already connected TCP fd
// in net.Socket and move bytes on it? The fd is created by the harness
// (python opens a loopback pair) and inherited, which is exactly the fd
// an io_sys() dial would hand over.
//
// Bun refuses it (1.2.15: "Socket is closed"; 1.4.3: same), which is why
// the TLS bridge has the worker dial its own socket instead of adopting
// one. Node accepts it. Usage:
//   P0_FD=3 node tests/effs/bridge/fd_adopt.js
const net = require("net");

const fd = Number(process.env.P0_FD || 3);
const report = {
  runtime: process.versions.bun ? `bun ${process.versions.bun}`
    : `node ${process.versions.node}`,
  fd: fd,
  adopted: false,
  wrote: false,
  bytes: 0,
  head: "",
};

let sock = null;
try {
  sock = new net.Socket({ fd: fd, readable: true, writable: true });
  report.adopted = true;
} catch (e) {
  report.error = `wrap: ${e.message}`;
}

if (sock !== null) {
  sock.on("data", (b) => {
    report.bytes = b.length;
    report.head = b.toString("latin1");
    console.log(JSON.stringify(report));
    process.exit(0);
  });
  sock.on("error", (e) => {
    report.error = e.message;
    console.log(JSON.stringify(report));
    process.exit(1);
  });
  try {
    sock.write("ping");
    report.wrote = true;
  } catch (e) {
    report.error = `write: ${e.message}`;
  }
  setTimeout(() => {
    report.timeout = true;
    console.log(JSON.stringify(report));
    process.exit(2);
  }, 4000);
} else {
  console.log(JSON.stringify(report));
}
