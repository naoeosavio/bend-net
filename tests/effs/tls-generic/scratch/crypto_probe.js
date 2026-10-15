// scratch/crypto_probe.js — rodar com node E bun E no interp.
//
// Reports what THIS host's crypto can actually do, one line per
// capability, instead of asserting a single cipher works. The old
// version ended with an unconditional chacha20 round-trip, which meant
// the probe could only ever be run on a host that has chacha20 -- and
// on bun it died with ERR_CRYPTO_UNKNOWN_CIPHER, hiding every other
// line's result behind a stack trace.
//
// The cipher matrix is the load-bearing part: tls_rt.js filters its
// suite table by exactly these capabilities (see cipher_supported), so a
// host that reports a cipher missing MUST NOT see it offered.
const crypto = require("crypto");
const tls = require("tls");
const fs = require("fs");

console.log("runtime", typeof Bun !== "undefined" ? "bun " + Bun.version
  : "node " + process.versions.node);
console.log("fs", typeof fs.readFileSync === "function");

console.log("keytype", crypto.createPrivateKey(
  crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey.export({ type: "sec1", format: "pem" })).asymmetricKeyType);

const a = crypto.generateKeyPairSync("x25519");
const b = crypto.generateKeyPairSync("x25519");
console.log("x25519", crypto.diffieHellman(
  { privateKey: a.privateKey, publicKey: b.publicKey }).length === 32);

const c = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const d = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
console.log("p256", crypto.diffieHellman(
  { privateKey: c.privateKey, publicKey: d.publicKey }).length === 32);

const x = new crypto.X509Certificate(tls.rootCertificates[0]);
console.log("checkHost", typeof x.checkHost === "function",
  "| validFromDate", x.validFromDate !== undefined,
  "| verify", typeof x.verify === "function");
console.log("roots", tls.rootCertificates.length);

// A cipher is "ok" only if it round-trips WITH the tag verified: a
// cipher that encrypts but cannot open is unusable for TLS either way.
const probe_cipher = (name, key_len, aead) => {
  const key = crypto.randomBytes(key_len);
  const iv = crypto.randomBytes(aead ? 12 : 16);
  const opts = aead ? { authTagLength: 16 } : undefined;
  const pt = aead ? Buffer.from("probe") : Buffer.alloc(16, 7);
  try {
    const enc = crypto.createCipheriv(name, key, iv, opts);
    if (aead) {
      enc.setAAD(Buffer.from("aad"));
    } else {
      enc.setAutoPadding(false);
    }
    const ct = Buffer.concat([enc.update(pt), enc.final()]);
    const tag = aead ? enc.getAuthTag() : null;
    const dec = crypto.createDecipheriv(name, key, iv, opts);
    if (aead) {
      dec.setAAD(Buffer.from("aad"));
      dec.setAuthTag(tag);
    } else {
      dec.setAutoPadding(false);
    }
    const out = Buffer.concat([dec.update(ct), dec.final()]);
    return out.equals(pt) ? "ok" : "BROKEN";
  } catch (e) {
    return "absent (" + (e.code || e.message) + ")";
  }
};

const ciphers = [
  ["aes-128-gcm", 16, true],
  ["aes-256-gcm", 32, true],
  ["chacha20-poly1305", 32, true],
  ["aes-128-cbc", 16, false],
  ["aes-256-cbc", 32, false],
];
for (const [name, key_len, aead] of ciphers) {
  console.log("cipher " + name.padEnd(20) + probe_cipher(name, key_len, aead));
}

// What the runtime will therefore offer. A suite in this list whose
// cipher reads "absent" above would be a bug in the filter.
const rt = require("./rt_path.js");
const SUITE_NAME = { 0x1301: "aes-128-gcm", 0x1302: "aes-256-gcm",
  0x1303: "chacha20-poly1305", 0xc02f: "aes-128-gcm",
  0xc030: "aes-256-gcm", 0xc02b: "aes-128-gcm",
  0xc02c: "aes-256-gcm", 0xc027: "aes-128-cbc", 0xc023: "aes-128-cbc" };
console.log("offered 1.3", rt.offered_suites()
  .map((id) => "0x" + id.toString(16) + "(" + SUITE_NAME[id] + ")").join(" "));
console.log("offered 1.2", rt.offered_suites12()
  .map((id) => "0x" + id.toString(16) + "(" + SUITE_NAME[id] + ")").join(" "));