// scratch/framing_probe.js — TLS 1.3 record framing on the SEND side.
//
// The `bulk` rung covers the receive side over a real socket. This covers
// the half nobody was checking: what WE put on the wire when a write is
// larger than one record. seal_app splits at 16383 so that plaintext plus
// the inner content type stays inside the 2^14 ceiling of RFC 8446 s5.1 --
// one byte over and a conformant peer must reject the record outright.
//
// Both directions of the claim are asserted, and neither uses our own
// open(): the records are decrypted with the HOST's crypto, so this
// answers "what would a peer reassemble", not "do we agree with
// ourselves". A round trip between our own seal and our own open would
// pass even if both halves were wrong together -- the trap behind D21.
//
// Prints "OK <n> framing cases" and exits 0, or "FAIL <why>" and exits 1.
const crypto = require("crypto");
const rt = require("./rt_path.js");

const KEY = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
const IV = Buffer.from("101112131415161718191a1b1c1d1e1f", "hex");

// RFC 8446 s5.1: the record plaintext MUST NOT exceed 2^14 bytes.
const MAX_PLAINTEXT = 16384;
// seal_app's chunk size: the largest content that still leaves room for
// the one-byte inner content type inside MAX_PLAINTEXT.
const CHUNK = MAX_PLAINTEXT - 1;
const TAG_LEN = 16;
const INNER_APP = 23;

// nonce = static iv XOR 64-bit big-endian sequence (RFC 8446 s5.3).
// Written out longhand rather than imported, so a mistake here shows up
// as a failed case instead of cancelling out against the runtime's.
const nonce_for = (seq) => {
  const out = Buffer.from(IV);
  const be = Buffer.alloc(8);
  be.writeBigUInt64BE(BigInt(seq));
  for (let i = 0; i < 8; i += 1) out[out.length - 8 + i] ^= be[i];
  return out;
};

// A pump with only the fields seal_app touches.
const pump_for = () => {
  const p = rt.make_client("127.0.0.1", false, 0);
  p.suite = { name: "aes-128-gcm", hash: "sha256", klen: 16,
    aead: true, mlen: 0 };
  p.writeKeys = { key: KEY, iv: IV };
  p.fail = null;
  p.seqOut = 0;
  p.done = true;
  // make_client queues the ClientHello, so the buffer is not empty yet.
  // Counting it would make every case report one record too many.
  p.drain();
  return p;
};

// Walk the bytes seal_app produced and hand back one entry per record:
// the header as it appeared on the wire, and the body.
const split_records = (wire) => {
  const out = [];
  let at = 0;
  while (at < wire.length) {
    if (at + 5 > wire.length) {
      throw new Error("truncated header at " + at);
    }
    const len = wire.readUInt16BE(at + 3);
    if (at + 5 + len > wire.length) {
      throw new Error("truncated body at " + at);
    }
    out.push({
      hdr: wire.subarray(at, at + 5),
      body: wire.subarray(at + 5, at + 5 + len),
    });
    at += 5 + len;
  }
  return out;
};

// Decrypt one record with the host's AES-GCM, straight from the spec:
// AAD is the header AS RECEIVED, the nonce is iv XOR sequence, and the
// last 16 bytes are the tag.
const decrypt_record = (rec, seq) => {
  const d = crypto.createDecipheriv("aes-128-gcm", KEY, nonce_for(seq),
    { authTagLength: TAG_LEN });
  d.setAAD(rec.hdr);
  d.setAuthTag(rec.body.subarray(rec.body.length - TAG_LEN));
  return Buffer.concat([
    d.update(rec.body.subarray(0, rec.body.length - TAG_LEN)),
    d.final(),
  ]);
};

// Distinct bytes, so a reorder or a duplicated chunk cannot hide behind
// a sum that happens to match.
const payload_of = (n) => {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i += 1) b[i] = (i * 31 + (i >> 8) * 7) & 255;
  return b;
};

const CASES = [
  { n: 0, why: "empty write still emits one record" },
  { n: 1, why: "one byte" },
  { n: CHUNK - 1, why: "one octet under the chunk boundary" },
  { n: CHUNK, why: "exactly one chunk" },
  { n: CHUNK + 1, why: "one octet over: must spill into a second record" },
  { n: 2 * CHUNK, why: "exactly two chunks" },
  { n: 4 * CHUNK, why: "four chunks, the `bulk` rung's payload size" },
  { n: 4 * CHUNK + 123, why: "four chunks and a remainder" },
];

let failures = 0;

for (const c of CASES) {
  const data = payload_of(c.n);
  const p = pump_for();
  p.seal_app(data);
  const wire = p.drain();
  if (wire === null) {
    failures += 1;
    console.log("FAIL n=" + c.n + ": seal_app put nothing on the wire");
    continue;
  }
  let recs;
  try {
    recs = split_records(wire);
  } catch (e) {
    failures += 1;
    console.log("FAIL n=" + c.n + ": " + e.message);
    continue;
  }
  // An empty write must still produce exactly one record; anything else
  // must produce ceil(n / CHUNK) of them.
  const want = c.n === 0 ? 1 : Math.ceil(c.n / CHUNK);
  if (recs.length !== want) {
    failures += 1;
    console.log("FAIL n=" + c.n + ": " + recs.length + " records, want " + want);
    continue;
  }
  // Every record must stay inside the ceiling, or a peer rejects it
  // before it ever looks at the content.
  let too_big = 0;
  for (const rec of recs) {
    if (rec.body.length - TAG_LEN > MAX_PLAINTEXT) too_big += 1;
  }
  if (too_big > 0) {
    failures += 1;
    console.log("FAIL n=" + c.n + ": " + too_big + " record(s) exceed the "
      + MAX_PLAINTEXT + "-byte plaintext ceiling");
    continue;
  }
  // Reassemble what a peer would see, and require it to equal the input.
  const got = [];
  let inner_bad = 0;
  for (let i = 0; i < recs.length; i += 1) {
    let pt;
    try {
      pt = decrypt_record(recs[i], i);
    } catch (e) {
      failures += 1;
      console.log("FAIL n=" + c.n + ": record " + i
        + " did not decrypt under the host AES-GCM: " + e.message);
      break;
    }
    if (pt[pt.length - 1] !== INNER_APP) inner_bad += 1;
    got.push(pt.subarray(0, pt.length - 1));
  }
  if (inner_bad > 0) {
    failures += 1;
    console.log("FAIL n=" + c.n + ": " + inner_bad
      + " record(s) do not end in the inner content type 23");
    continue;
  }
  const back = Buffer.concat(got);
  if (!back.equals(data)) {
    failures += 1;
    console.log("FAIL n=" + c.n + ": peer reassembles " + back.length
      + " bytes that differ from the input");
    continue;
  }
  console.log("ok   n=" + String(c.n).padStart(6) + " records="
    + String(recs.length).padStart(2) + "  " + c.why);
}

if (failures > 0) {
  console.log("FAIL " + failures + " framing case(s)");
  process.exit(1);
}
console.log("OK " + CASES.length + " framing cases");
process.exit(0);
