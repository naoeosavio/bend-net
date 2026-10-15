// scratch/expired_probe.js — <root.pem> <int.pem> <leaf.pem> [host]
//
// Hermetic rung for task-051 A8: the validity window counts for EVERY
// certificate of the chain, not only the leaf. The caller (gen_expired in
// tls-generic.sh) builds a root that lives ten years, an intermediate
// that lives ONE day and a leaf that lives ten years.
//
// The probe asks verify_chain twice:
//   control  now              -> must verify (the leaf and the
//                                intermediate are both valid)
//   shifted  now + 2 days     -> the intermediate is expired, the leaf is
//                                not: must refuse with CERT_HAS_EXPIRED
//
// Prints "PASS ..." / "FAIL ..." like the other probes, and exits 0 only
// when the control verifies AND the shifted chain is refused that way.
// No sockets, no network, no host store: `roots` is the generated root.
const fs = require("fs");
const crypto = require("crypto");
const rt = require("./rt_path.js");

const rootPath = process.argv[2];
const intPath = process.argv[3];
const leafPath = process.argv[4];
const host = process.argv[5] || "expired.test";

if (!rootPath || !intPath || !leafPath) {
  console.log("FAIL usage: expired_probe.js <root.pem> <int.pem> <leaf.pem> [host]");
  process.exit(1);
}

const read = (p) => fs.readFileSync(p);
const ders = [read(leafPath), read(intPath)];
const roots = [new crypto.X509Certificate(read(rootPath))];
const DAY_MS = 24 * 60 * 60 * 1000;

// The verdict verify_chain gives: "ok", or the message it refused with.
// verify_chain throws, so a refusal is the value here.
const verdict = (now) => {
  try {
    rt.verify_chain(ders, host, now, roots);
    return "ok";
  } catch (e) {
    return e && e.message ? e.message : String(e);
  }
};

const control = verdict(Date.now());
const shifted = verdict(Date.now() + 2 * DAY_MS);

if (control !== "ok") {
  console.log("FAIL control chain did not verify: " + control);
  process.exit(1);
}
if (shifted !== "CERT_HAS_EXPIRED") {
  console.log("FAIL expired intermediate answered " + shifted
    + " (want CERT_HAS_EXPIRED)");
  process.exit(1);
}
console.log("PASS expired intermediate refused, leaf window untouched");
