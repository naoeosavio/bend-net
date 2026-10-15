// scratch/padlen_probe.js — TLS 1.2 CBC record layer, no network.
//
// Builds records the way OpenSSL does and hands them to open12. The
// case that matters is padding_length == 0: when content+MAC lands one
// octet short of a block, the length octet alone completes it. RFC 5246
// s6.2.3.2 says "Legal values range from 0 to 255", and OpenSSL emits
// it -- a validator that requires plen >= 1 rejects those records with
// a "bad record mac" that reads like a key problem.
//
// It only shows up on payload sizes whose length mod 16 lands right, so
// an end-to-end test catches it at random. This is the deterministic
// version.
//
// Prints "OK <n> records" and exits 0, or "FAIL <why>" and exits 1.
const crypto = require("crypto");
const rt = require("./rt_path.js");

const KEY = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
const MAC_KEY = Buffer.from(
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "hex");

// One record, built the way OpenSSL builds it: given padlen may be 0.
const build = (data, padlen) => {
  const seq = Buffer.alloc(8);
  seq[7] = 0;
  const mac = crypto.createHmac("sha256", MAC_KEY).update(Buffer.concat([
    seq, Buffer.from([23, 3, 3]),
    Buffer.from([(data.length >> 8) & 255, data.length & 255]), data,
  ])).digest();
  const iv = crypto.randomBytes(16);
  const plain = Buffer.concat([
    data, mac, Buffer.alloc(padlen, padlen), Buffer.from([padlen]),
  ]);
  const enc = crypto.createCipheriv("aes-128-cbc", KEY, iv);
  enc.setAutoPadding(false);
  const body = Buffer.concat([iv, enc.update(plain), enc.final()]);
  return { hdr: Buffer.from([23, 3, 3, (body.length >> 8) & 255,
    body.length & 255]), body: body, mac: mac };
};

// A pump with only the fields open12 and seal12 touch.
const pump_for = () => {
  const p = rt.make_client("127.0.0.1", false, 0);
  p.suite = { name: "aes-128-cbc", hash: "sha256", klen: 16,
    aead: false, mlen: 32 };
  p.readKeys = { key: KEY, mac: MAC_KEY, iv: Buffer.alloc(16) };
  p.writeKeys = { key: KEY, mac: MAC_KEY, iv: Buffer.alloc(16) };
  p.fail = null;
  p.seqIn = 0;
  p.seqOut = 0;
  p.done = true;
  return p;
};

// Each case: data length, and the padding openssl would choose for it.
const cases = [
  // data % 16 == 15 -> content+MAC+1 is already a block multiple, so
  // openssl pads with nothing at all. This is the regression.
  { data_len: 15, padlen: 0, why: "content+MAC one octet short of a block" },
  { data_len: 31, padlen: 0, why: "same residue, longer payload" },
  { data_len: 175, padlen: 0, why: "same residue, multi-record length" },
  // The ordinary cases must keep working.
  { data_len: 16, padlen: 15, why: "full pad block" },
  { data_len: 0, padlen: 15, why: "empty application data" },
  { data_len: 100, padlen: 11, why: "ordinary payload" },
  { data_len: 4096, padlen: 15, why: "long payload" },
];

let failures = 0;
for (const c of cases) {
  const data = Buffer.alloc(c.data_len);
  for (let i = 0; i < c.data_len; i += 1) {
    data[i] = (i * 7) & 255;
  }
  const rec = build(data, c.padlen);
  const p = pump_for();
  const got = p.open12(rec.hdr, rec.body);
  if (got === null || !got.equals(data)) {
    failures += 1;
    console.log("FAIL data_len=" + c.data_len + " padlen=" + c.padlen
      + " (" + c.why + "): " + (p.fail ? p.fail.text : "wrong plaintext"));
  } else {
    console.log("ok   data_len=" + String(c.data_len).padStart(4)
      + " padlen=" + String(c.padlen).padStart(2) + "  " + c.why);
  }
}

// The SEAL side, which the open-side cases above cannot reach: padlen
// == 0 is just as much a send-side decision as a receive-side one, and
// getting it wrong produces a record one block too long. Decrypted here
// with the plain host crypto -- independent of the runtime -- so this
// asserts what a conformant PEER would see, not a round trip with
// ourselves (which would pass even if both sides were wrong together).
for (const c of cases) {
  const data = Buffer.alloc(c.data_len);
  for (let i = 0; i < c.data_len; i += 1) {
    data[i] = (i * 7) & 255;
  }
  const p = pump_for();
  const rec = p.seal12(23, data);
  const body = rec.subarray(5);
  const dec = crypto.createDecipheriv("aes-128-cbc", KEY, body.subarray(0, 16));
  dec.setAutoPadding(false);
  const pt = Buffer.concat([dec.update(body.subarray(16)), dec.final()]);
  const pad = pt[pt.length - 1];
  const all_equal = pt.subarray(pt.length - 1 - pad, pt.length)
    .every((b) => b === pad);
  const aligned = pt.length % 16 === 0;
  // The plaintext must be exactly what RFC 5246 s6.2.3.2 prescribes:
  // data + MAC + padlen octets + the length octet, block-aligned, with
  // padlen chosen so that it is.
  const expect_pl = c.data_len + 32 + c.padlen + 1;
  if (!aligned || !all_equal || pt.length !== expect_pl
      || pad !== c.padlen) {
    failures += 1;
    console.log("FAIL seal data_len=" + c.data_len + ": padlen=" + pad
      + " (want " + c.padlen + "), plaintext=" + pt.length
      + " (want " + expect_pl + "), aligned=" + aligned
      + " padOctetsUniform=" + all_equal);
  } else {
    console.log("ok   seal data_len=" + String(c.data_len).padStart(4)
      + " padlen=" + String(pad).padStart(2)
      + " plaintext=" + String(pt.length).padStart(5) + "  " + c.why);
  }
}

// And the negative: a record whose padding octets lie must still fail.
// The MAC here is CORRECT on purpose -- only the padding octets are
// wrong -- so the only thing that can reject this record is the padding
// check itself. A corrupted MAC would be rejected either way and would
// prove nothing about padding.
const liar = (() => {
  const data = Buffer.alloc(16, 0x78);
  const seq = Buffer.alloc(8);
  const mac = crypto.createHmac("sha256", MAC_KEY).update(Buffer.concat([
    seq, Buffer.from([23, 3, 3]),
    Buffer.from([0, data.length]), data,
  ])).digest();
  // Declares padlen 15 but fills the octets with 14: a peer that never
  // looks at them would accept this.
  const iv = crypto.randomBytes(16);
  const plain = Buffer.concat([data, mac, Buffer.alloc(15, 14),
    Buffer.from([15])]);
  const enc = crypto.createCipheriv("aes-128-cbc", KEY, iv);
  enc.setAutoPadding(false);
  const body = Buffer.concat([iv, enc.update(plain), enc.final()]);
  return { hdr: Buffer.from([23, 3, 3, (body.length >> 8) & 255,
    body.length & 255]), body: body };
})();
const p2 = pump_for();
const leaked = p2.open12(liar.hdr, liar.body);
if (leaked !== null) {
  failures += 1;
  console.log("FAIL padding octets that lie were accepted (valid MAC)");
} else {
  console.log("ok   padding octets that lie are refused (valid MAC)");
}

// A second negative: a MAC that is wrong but whose padding is perfect.
// Without this, a record layer that rejected everything for the wrong
// reason would pass the case above.
const bad = build(Buffer.from("x".repeat(16)), 15);
bad.body[bad.body.length - 1] ^= 0xff;
const p = pump_for();
if (p.open12(bad.hdr, bad.body) !== null) {
  failures += 1;
  console.log("FAIL corrupt record was accepted");
} else {
  console.log("ok   corrupt record is refused");
}

if (failures > 0) {
  console.log("FAIL " + failures + " record-layer case(s)");
  process.exit(1);
}
console.log("OK " + (cases.length * 2 + 2) + " CBC record cases");
process.exit(0);