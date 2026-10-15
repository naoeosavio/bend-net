// lib/effs/tls_rt.js -- shared TLS runtime for the five TLS effects.
//
// The compiler wraps each effect file in its own closure, so a helper
// defined in one file is invisible to the next: every effect loads THIS
// module once via the only require that resolves in every lane (a
// cwd-absolute path) and caches it in one global slot. Only bare
// "crypto", "tls" and "fs" are imported -- no bun:ffi, no libssl, no C
// compiler, no JSCallback.
//
// One code path, two protocol versions: the client offers TLS 1.3 and
// 1.2 in a single ClientHello and the peer's ServerHello picks the
// version; the server reads the ClientHello and answers by what the
// peer offered. Effects never learn which one ran -- they see only
// fail / done / alpn on the pump.
//
//   TLS 1.3 -- key schedule per RFC 8446 s7.1, AEAD record layer
//     (aes-128-gcm, aes-256-gcm, chacha20-poly1305), ECDHE over
//     x25519 / P-256, ALPN read from EncryptedExtensions (client) /
//     ClientHello (server), KeyUpdate honored, NewSessionTicket
//     ignored.
//   TLS 1.2 -- PRF per RFC 5246 s5, ECDHE-only suites (GCM preferred,
//     CBC-SHA256 kept for old peers), key block per s6.3, ChangeCipherSpec
//     keyed per direction, renegotiation refused (fatal).
//
// Verification (dates, hostname, chain to the roots the host ships)
// rides the Certificate message of either version and fails with 614 --
// this is what rejects the self-signed and untrusted-root cases.
//
// Fail codes are stable numbers, never error text: 611 bad input, 612
// dial failed, 613 handshake failed, 614 verify failed, 615 alpn
// mismatch, 616 tls error.
//
// Out of scope, failing 613 (documented): TLS 1.0/1.1, static RSA and
// DHE key exchange, SHA1-MAC suites, session resumption, renegotiation,
// client certificates, HelloRetryRequest (the client offers key shares
// for BOTH groups, so honest servers never send one), SHA-384 ECDSA
// certs (P-256 only).
"use strict";

const crypto = require("crypto");
const host_tls = require("tls"); // rootCertificates only: the trust store
const fs = require("fs");

// -- wire helpers ---------------------------------------------------------

// The one place bytes from outside the pump are typed. `net` hands the
// probes a Buffer; an effect hands the Uint8Array it allocated itself.
// Both enter feed(), and the handshake code uses Buffer methods (see
// server_hello's HRR_RANDOM comparison), so an adopted Uint8Array has to
// become a Buffer here -- and as a VIEW, since the record layer would
// copy every byte otherwise. A plain Array or string is accepted too,
// which keeps feed() a doorway rather than a minefield.
function as_buf(b) {
  if (Buffer.isBuffer(b)) {
    return b;
  }
  if (b instanceof Uint8Array) {
    return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  }
  return Buffer.from(b);
}

function u16(n) { return Buffer.from([(n >> 8) & 255, n & 255]); }
function u24(n) {
  return Buffer.from([(n >> 16) & 255, (n >> 8) & 255, n & 255]);
}
function ext(type, data) {
  return Buffer.concat([u16(type), u16(data.length), data]);
}
function hmac(h, key, data) {
  return crypto.createHmac(h, key).update(data).digest();
}
function seq8(n) {
  const b = Buffer.alloc(8);
  b.writeUInt32BE(Math.floor(n / 0x100000000), 0);
  b.writeUInt32BE(n >>> 0, 4);
  return b;
}
function plain_rec(type, payload) {
  return Buffer.concat([Buffer.from([type, 3, 3]), u16(payload.length),
    payload]);
}
function alert_record(level, desc) {
  return Buffer.from([21, 3, 3, 0, 2, level, desc]);
}

// -- suites ----------------------------------------------------------------

// Which ciphers the HOST can actually do, asked once at load.
//
// OpenSSL does the same thing (ssl_ciph.c:329): it fetches every cipher
// at SSL_CTX_new and marks the ones that come back NULL in
// disabled_enc_mask -- it does not abort, and it does not assume. That
// detail matters here because the hosts genuinely differ: bun's crypto
// has no chacha20-poly1305 at all (ERR_CRYPTO_UNKNOWN_CIPHER, measured
// on 1.2.15 and 1.4.3), so a table that offers it unconditionally makes
// createCipheriv THROW inside feed() -- which kills the process, not the
// connection, on both roles.
//
// Both directions are probed, not just encryption: a cipher that encrypts
// but cannot verify a tag is useless to us, and the AEAD path round-trips
// through both.
const CIPHER_OK = new Map();

const PROBE_AAD = Buffer.from("bend");
const PROBE_PT = Buffer.from("cipher capability probe");

// CBC seals a whole block per record and takes no tag; the AEAD ciphers
// take a 12-byte nonce and a 16-byte tag. Probing with the wrong shape
// reports a cipher as unusable when it is merely configured differently,
// so the shape follows the suite.
function cipher_supported(suite) {
  const name = suite.name;
  if (CIPHER_OK.has(name)) return CIPHER_OK.get(name);
  const aead = suite.aead !== false;
  const key = Buffer.alloc(suite.klen);
  const iv = Buffer.alloc(aead ? 12 : 16);
  // Block ciphers need block-aligned input and no auto padding.
  const probe = aead ? PROBE_PT : Buffer.alloc(suite.block || 16, 7);
  let ok = false;
  try {
    const opts = aead ? { authTagLength: 16 } : undefined;
    const enc = crypto.createCipheriv(name, key, iv, opts);
    if (aead) {
      enc.setAAD(PROBE_AAD);
    } else {
      enc.setAutoPadding(false);
    }
    const ct = Buffer.concat([enc.update(probe), enc.final()]);
    const tag = aead ? enc.getAuthTag() : null;
    const dec = crypto.createDecipheriv(name, key, iv, opts);
    if (aead) {
      dec.setAAD(PROBE_AAD);
      dec.setAuthTag(tag);
    } else {
      dec.setAutoPadding(false);
    }
    ok = Buffer.concat([dec.update(aead ? ct : ct), dec.final()])
      .equals(probe);
  } catch (e) {
    // An unknown cipher, a rejected key size, or no provider behind it:
    // all mean the same thing here -- not offerable.
    ok = false;
  }
  CIPHER_OK.set(name, ok);
  return ok;
}

// Every suite the host can seal AND open, in preference order. Suites
// whose cipher is missing are simply absent, so neither the client's
// offer nor the server's preference-order intersection can ever name one.
// This is what makes "no common cipher" unreachable in practice, the
// same invariant OpenSSL gets from filtering at SSL_CTX_new.
function usable(list, table) {
  const out = list.filter((id) => {
    const s = table[id];
    return s !== undefined && cipher_supported(s);
  });
  if (out.length === 0) {
    // The OpenSSL analogue is SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS (ssl_lib.c
    // :680): losing EVERY cipher is a load-time library fault, not a
    // handshake outcome, and must not be reported as one.
    throw new Error("no usable cipher: the host crypto has none of " +
      list.map((id) => table[id].name).join(", "));
  }
  return out;
}

const SUITES = {
  0x1301: { name: "aes-128-gcm", hash: "sha256", hlen: 32, klen: 16 },
  0x1302: { name: "aes-256-gcm", hash: "sha384", hlen: 48, klen: 32 },
  0x1303: { name: "chacha20-poly1305", hash: "sha256", hlen: 32, klen: 32 },
};
const OFFERED = usable([0x1301, 0x1302, 0x1303], SUITES);

// The wire id back from a suite entry. The server picks its suite by
// scanning OFFERED and then has to write the id it picked -- comparing
// objects by identity here would break the moment a suite table grows a
// shared entry.
const SUITE_ID = new Map(Object.keys(SUITES).map((k) => [SUITES[k], Number(k)]));
function cipher_of(suite) {
  const id = SUITE_ID.get(suite);
  if (id === undefined) throw new Error("unknown cipher suite");
  return id;
}

// ECDHE only, AEAD preferred over CBC (the CBC path carries pragmatic
// Lucky-13 hardening, not the full double-decrypt construction, so GCM
// goes first in the preference order).
const SUITES12 = {
  0xc02f: { name: "aes-128-gcm", hash: "sha256", klen: 16, aead: true },
  0xc030: { name: "aes-256-gcm", hash: "sha384", klen: 32, aead: true },
  0xc02b: { name: "aes-128-gcm", hash: "sha256", klen: 16, aead: true },
  0xc02c: { name: "aes-256-gcm", hash: "sha384", klen: 32, aead: true },
  0xc027: { name: "aes-128-cbc", hash: "sha256", klen: 16,
            aead: false, mlen: 32 },
  0xc023: { name: "aes-128-cbc", hash: "sha256", klen: 16,
            aead: false, mlen: 32 },
};
const OFFERED12 = usable(
  [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xc027, 0xc023], SUITES12);
const PREF12 = OFFERED12;

const MAX_RECORD = 18432; // 2^14 + CBC slack
const HRR_RANDOM = Buffer.from(
  "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c", "hex");

// -- TLS 1.3 key schedule (RFC 8446 s7.1) ------------------------------------

// HKDF-Expand-Label. One HMAC block always suffices: every requested
// length (hash, key, iv) is <= the hash size.
function expand_label(h, secret, label, context, len) {
  const l = Buffer.concat([Buffer.from("tls13 "), Buffer.from(label, "ascii")]);
  const info = Buffer.concat([
    u16(len), Buffer.from([l.length]), l,
    Buffer.from([context.length]), context,
  ]);
  return hmac(h, secret, Buffer.concat([info, Buffer.from([1])])).subarray(0, len);
}

// nonce = static iv XOR 64-bit big-endian sequence (RFC 8446 s5.3).
function xor_seq(iv, seq) {
  const out = Buffer.from(iv);
  const hi = Math.floor(seq / 0x100000000);
  const lo = seq >>> 0;
  const w = [hi >>> 24, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255,
             lo >>> 24, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255];
  for (let i = 0; i < 8; i += 1) out[out.length - 8 + i] ^= w[i];
  return out;
}

// -- TLS 1.2 PRF (RFC 5246 s5) -------------------------------------------------

function prf(h, secret, label, seed, len) {
  const s = Buffer.concat([Buffer.from(label, "ascii"), seed]);
  const out = [];
  let a = s;
  let total = 0;
  while (total < len) {
    a = hmac(h, secret, a);
    out.push(hmac(h, secret, Buffer.concat([a, s])));
    total += out[out.length - 1].length;
  }
  return Buffer.concat(out).subarray(0, len);
}

// -- ECDHE groups -------------------------------------------------------------

// Preference order matches OpenSSL's supported_groups_default (t1_lib.c
// :196) for the four groups we serve: x25519, secp256r1, secp384r1,
// secp521r1. x448 is deliberately absent -- bun's crypto cannot do it
// (ERR_OSSL_UNSUPPORTED_ALGORITHM measured on 1.2.15 and 1.4.3), and
// offering a group the host cannot compute is the bug the cipher filter
// above already had to fix.
//
// `plen` is the length of the raw public key on the wire: 32 for
// x25519, and 1 + 2*fieldsize for the NIST curves (the 0x04 uncompressed
// marker). It exists because the SPKI header is NOT a fixed size --
// measured 12 (x25519), 26 (P-256), 23 (P-384), 25 (P-521) -- so slicing
// a constant offset, which is what this code used to do, silently
// produced garbage for every curve after P-256.
const GROUPS = [
  { id: 0x001d, name: "x25519", plen: 32 },
  { id: 0x0017, name: "P-256", plen: 65 },
  { id: 0x0018, name: "P-384", plen: 97 },
  { id: 0x0019, name: "P-521", plen: 133 },
];

const group_of = (id) => GROUPS.find((g) => g.id === id) || null;

// RFC 8446 s4.4.1: when a HelloRetryRequest happens, ClientHello1 is NOT
// kept in the transcript -- it is replaced by a synthetic handshake
// message of type message_hash carrying Hash(ClientHello1):
//
//   Transcript-Hash(CH1, HRR, ... Mn) =
//     Hash(254 || 00 00 len || Hash(CH1) || HRR || ... || Mn)
//
// The reason is statelessness (the server stores only a hash), and the
// consequence is concrete: a transcript of CH1||HRR||CH2 computes a
// different handshake secret and the peer answers with a bad record MAC
// on its first encrypted flight. OpenSSL does exactly this
// (create_synthetic_message_hash, statem_lib.c:2214: msghdr[0]=254,
// msghdr[3]=hashlen, then the bare digest -- no HashType wrapper).
function synthetic_message_hash(hash) {
  return Buffer.concat([
    Buffer.from([254, 0, 0, hash.length]), hash,
  ]);
}

// A group is offerable only if the host can generate a key AND complete
// a Diffie-Hellman on it -- the same two-sided probe the ciphers get.
const GROUP_OK = new Map();

function group_supported(g) {
  if (GROUP_OK.has(g.id)) return GROUP_OK.get(g.id);
  let ok = false;
  try {
    const opts = g.name === "x25519" ? undefined : { namedCurve: g.name };
    const a = crypto.generateKeyPairSync(g.name === "x25519" ? "x25519" : "ec",
      opts);
    const b = crypto.generateKeyPairSync(g.name === "x25519" ? "x25519" : "ec",
      opts);
    const shared = crypto.diffieHellman({
      privateKey: a.privateKey, publicKey: b.publicKey,
    });
    ok = shared.length === (g.plen === 32 ? 32 : (g.plen - 1) / 2);
  } catch (e) {
    ok = false;
  }
  GROUP_OK.set(g.id, ok);
  return ok;
}

// Same shape as usable(): a missing group is ABSENT from the offer, not
// an error, and losing every group is a load-time library fault.
function usable_groups() {
  const out = GROUPS.filter(group_supported);
  if (out.length === 0) {
    throw new Error("no usable group: the host crypto has none of "
      + GROUPS.map((g) => g.name).join(", "));
  }
  return out;
}

const OFFERED_GROUPS = usable_groups();

// The raw point is the TAIL of the SPKI, and the head is everything
// before it -- so no per-group prefix table is needed and the same code
// rebuilds a peer's key for any curve we serve.
function make_share(group) {
  const g = group_of(group);
  const opts = g.name === "x25519" ? undefined : { namedCurve: g.name };
  const kp = crypto.generateKeyPairSync(g.name === "x25519" ? "x25519" : "ec",
    opts);
  const der = kp.publicKey.export({ type: "spki", format: "der" });
  return { group: group, priv: kp.privateKey,
           pub: Buffer.from(der.subarray(der.length - g.plen)),
           spki_head: Buffer.from(der.subarray(0, der.length - g.plen)) };
}
function peer_pub(group, raw) {
  const g = group_of(group);
  const point = Buffer.from(raw);
  if (point.length !== g.plen) {
    throw new Error("bad key share length for " + g.name);
  }
  // Reuse the head we measured when we made our own key for this group:
  // it is the SPKI prefix for that curve, so head+peerpoint is a valid
  // SPKI and no hard-coded hex is involved.
  return crypto.createPublicKey({
    key: Buffer.concat([spki_head_for(g), point]),
    format: "der", type: "spki",
  });
}

const HEADS = new Map();

function spki_head_for(g) {
  if (!HEADS.has(g.id)) {
    const opts = g.name === "x25519" ? undefined : { namedCurve: g.name };
    const kp = crypto.generateKeyPairSync(g.name === "x25519" ? "x25519" : "ec",
      opts);
    const der = kp.publicKey.export({ type: "spki", format: "der" });
    HEADS.set(g.id, Buffer.from(der.subarray(0, der.length - g.plen)));
  }
  return HEADS.get(g.id);
}

// TLS 1.3 ECDSA signatures are raw r||s; node wants DER (and gives DER).
function ecdsa_raw_to_der(raw) {
  const half = raw.length >> 1;
  const trim = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i += 1;
    let v = b.subarray(i);
    if ((v[0] & 0x80) !== 0) v = Buffer.concat([Buffer.from([0]), v]);
    return v;
  };
  const r = trim(raw.subarray(0, half));
  const s = trim(raw.subarray(half));
  return Buffer.concat([
    Buffer.from([0x30, r.length + s.length + 4, 0x02, r.length]),
    r, Buffer.from([0x02, s.length]), s,
  ]);
}
function ecdsa_der_to_raw(der, size) {
  let p = 2;
  const take = () => {
    const l = der[p + 1];
    let v = der.subarray(p + 2, p + 2 + l);
    p += 2 + l;
    if (v.length > 0 && v[0] === 0) v = v.subarray(1);
    const out = Buffer.alloc(size);
    v.copy(out, size - v.length);
    return out;
  };
  return Buffer.concat([take(), take()]);
}

// -- ALPN ----------------------------------------------------------------------

// The bend contract's modes: 1 requires h2, 2 offers h2/http/1.1, 3
// requires http/1.1, 0 offers nothing.
function alpn_names(mode) {
  return mode === 1 ? ["h2"]
    : mode === 2 ? ["h2", "http/1.1"]
    : mode === 3 ? ["http/1.1"] : [];
}

// The same modes, from the server side: which of the peer's list we are
// willing to pick.
//
// A client that offers NOTHING is not a mismatch: RFC 7301 s3.2 says the
// extension is then simply not used, and every other lane in this repo
// lets the handshake carry on with no protocol selected -- the retired
// OpenSSL twin answered SSL_TLSEXT_ERR_NOACK, and the native tls twin
// does the same. Failing 615 there would refuse every
// WebSocket-over-TLS client, which offers nothing on purpose
// (tls_connect_noalpn); the WSS loopback golden measured that. A peer
// that DID offer a list we share nothing with stays 615.
function alpn_select(list, offer) {
  if (list.length === 0) {
    return "";
  }
  const want = offer === 1 ? ["h2"]
    : offer === 3 ? ["http/1.1"] : ["h2", "http/1.1"];
  for (let i = 0; i < want.length; i += 1) {
    if (list.indexOf(want[i]) >= 0) return want[i];
  }
  return null;
}

// -- ClientHello (client, both versions in one hello) ---------------------------

// `cookie` is only set on the second hello of an HRR round (RFC 8446
// s4.1.2), and `random`/`sid` come from the caller so a retry reuses the
// same values the way the spec requires.
function build_client_hello(host, alpnProtos, share, random, cookie) {
  const suites = OFFERED.concat(OFFERED12);
  const exts = [];
  if (host.length > 0) {
    const name = Buffer.from(host, "ascii");
    exts.push(ext(0x0000, Buffer.concat([
      u16(name.length + 3), Buffer.from([0]), u16(name.length), name,
    ])));
  }
  // Several TLS 1.2-only servers require ec_point_formats for ECDHE.
  exts.push(ext(0x000b, Buffer.from([1, 0])));
  exts.push(ext(0xff01, Buffer.from([0]))); // RFC 5746 renegotiation_info
  // supported_groups: every group this host can actually compute, in
// preference order -- NOT a hardcoded pair. A peer that asks for one we
// dropped must get 613 from us rather than a key we cannot seal.
exts.push(ext(0x000a, Buffer.concat([u16(OFFERED_GROUPS.length * 2)]
  .concat(OFFERED_GROUPS.map((g) => u16(g.id))))));
  // rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, rsa_pkcs1_sha256.
  exts.push(ext(0x000d, Buffer.concat([
    u16(6), u16(0x0804), u16(0x0403), u16(0x0401),
  ])));
  if (alpnProtos.length > 0) {
    const list = Buffer.concat(alpnProtos.map((n) =>
      Buffer.concat([Buffer.from([n.length]), Buffer.from(n, "ascii")])));
    exts.push(ext(0x0010, Buffer.concat([u16(list.length), list])));
  }
  exts.push(ext(0x002b, Buffer.from([4, 3, 4, 3, 3]))); // 1.3 and 1.2
  // Exactly ONE key share, the same policy as OpenSSL
  // (tls_construct_ctos_key_share: "For now, we just send one"). The
  // cost of one share is that a server wanting a different group needs a
  // HelloRetryRequest, which the client handles in server_hello.
  const ks = Buffer.concat([u16(share.group), u16(share.pub.length),
    share.pub]);
  exts.push(ext(0x0033, Buffer.concat([u16(ks.length), ks])));
  if (cookie !== null && cookie !== undefined) {
    // HRR echo (RFC 8446 s4.1.2): 2-byte length prefix, opaque bytes.
    exts.push(ext(0x002c, Buffer.concat([u16(cookie.length), cookie])));
  }
  const body = Buffer.concat([
    Buffer.from([3, 3]),
    random,
    Buffer.from([0]),                    // empty legacy_session_id
    u16(suites.length * 2),
    Buffer.concat(suites.map(u16)),
    Buffer.from([1, 0]),                 // null compression
    u16(exts.reduce((n, e) => n + e.length, 0)),
    Buffer.concat(exts),
  ]);
  return { hello: Buffer.concat([Buffer.from([1]), u24(body.length), body]) };
}

// -- verification: dates, hostname, chain to the node:tls roots -----------------

let ROOT_CACHE = null;
function root_store() {
  if (ROOT_CACHE === null) {
    ROOT_CACHE = host_tls.rootCertificates.map(
      (p) => new crypto.X509Certificate(p));
  }
  return ROOT_CACHE;
}
const signs = (a, b) => {
  try { return b.verify(a.publicKey); } catch (e) { return false; }
};

// A trust anchor is an IDENTITY, not one exact certificate. A root that
// re-issues its own subject under a different issuer -- a cross-sign, the
// way a CA migrates its root without breaking the peers that already
// trust it -- has to end the chain too: OpenSSL and node both match an
// anchor by subject + public key. Matching the raw bytes instead leaves
// the last certificate of a cross-signed chain with no findable issuer,
// and the handshake fails 614 UNABLE_TO_GET_ISSUER_CERT_LOCALLY on hosts
// that would otherwise verify: cloudflare.com was measured doing exactly
// that, its chain ending in a cross-signed SSL.com root whose issuer
// (AAA) is in no current store.
const spki = (c) => c.publicKey.export({ format: "der", type: "spki" });
function anchor_of(roots, c) {
  const id = spki(c);
  return roots.find((r) => r.subject === c.subject && spki(r).equals(id));
}

function openssl_date(s) {
  // "Nov 12 14:00:00 2024 GMT" -- not ISO; Date.parse is unreliable here.
  const m = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT$/
    .exec(String(s));
  if (m === null) {
    const t = Date.parse(s);
    return new Date(Number.isNaN(t) ? 0 : t);
  }
  const mo = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6,
               Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 }[m[1]];
  return new Date(Date.UTC(+m[6], mo, +m[2], +m[3], +m[4], +m[5]));
}
function cert_expired(c, now) {
  const f = c.validFromDate || openssl_date(c.validFrom);
  const t = c.validToDate || openssl_date(c.validTo);
  return !(f.getTime() <= now && now <= t.getTime());
}

// `roots` is injectable so the hermetic rung (scratch/xsign_probe.js) can
// build a cross-signed chain and its trust store without the network: it
// defaults to the host's store, which is what production uses. `store` is
// the resolved one, and EVERY read below must go through it: reading the
// parameter instead silently answers 614 "Cannot read properties of
// undefined (reading 'find')" on every verified handshake, because
// production passes three arguments. The `host store` case of that probe
// is what keeps this honest.
function verify_chain(ders, host, now, roots) {
  const at = now === undefined ? Date.now() : now;
  const chain = ders.map((d) => new crypto.X509Certificate(d));
  const leaf = chain[0];
  if (cert_expired(leaf, at)) throw new Error("CERT_HAS_EXPIRED");
  if (typeof leaf.checkHost !== "function") {
    throw new Error("NO_HOSTNAME_CHECK_AVAILABLE"); // fail closed
  }
  if (!leaf.checkHost(host)) {
    throw new Error("ERR_TLS_CERT_ALTNAME_INVALID");
  }
  const store = roots === undefined ? root_store() : roots;
  const pool = chain.slice(1);
  let cur = leaf;
  for (let d = 0; d < 10; d += 1) {
    if (anchor_of(store, cur) !== undefined) return leaf;
    let iss = pool.find((c) => c.subject === cur.issuer && signs(c, cur));
    if (iss === undefined) {
      iss = store.find((r) => r.subject === cur.issuer && signs(r, cur));
    }
    if (iss === undefined) {
      throw new Error(cur.subject === cur.issuer
        ? "SELF_SIGNED_CERT_IN_CHAIN"
        : "UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
    }
    pool.splice(pool.indexOf(iss), 1);
    cur = iss;
  }
  throw new Error("CERT_CHAIN_TOO_LONG");
}

// -- cert/key loading (server) ---------------------------------------------------

function load_chain(path) {
  const pem = fs.readFileSync(path, "utf8");
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m = re.exec(pem);
  while (m !== null) {
    out.push(Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
    m = re.exec(pem);
  }
  if (out.length === 0) throw new Error("no certificate in " + path);
  return out;
}
function load_key(path) {
  const priv = crypto.createPrivateKey(fs.readFileSync(path, "utf8"));
  const kt = priv.asymmetricKeyType;
  if (kt !== "rsa" && kt !== "ec") {
    throw new Error("key type " + kt + " unsupported");
  }
  if (kt === "ec") {
    // P-256 only: the raw<->DER ECDSA shims are sized for it.
    const crv = priv.asymmetricKeyDetails
      && priv.asymmetricKeyDetails.namedCurve;
    if (crv !== "prime256v1") throw new Error("ec curve " + crv + " unsupported");
  }
  return priv;
}

// -- the pump: shared record layer + demux for both roles and versions -----------

class Pump {
  constructor(role) {
    this.role = role;            // "c" | "s"
    this.ver = "1.3";
    this.suite = null;
    this.out = [];               // sealed records waiting for the wire
    this.app = [];               // decrypted application bytes
    // Application RECORDS decrypted, not bytes. A byte count cannot tell
    // a fragmented stream from a single fat one, so a test that claims to
    // cover multi-record delivery has to measure this.
    this.app_records = 0;
    this.fail = null;            // { code, text } -- first failure wins
    this.done = false;
    this.closed = false;
    this.alpn = "";
    this.phase = "plain";        // 1.3 read phase: plain -> enc after SH
    this.pending = null;         // partial record bytes from the wire
    this.hsbuf = null;           // handshake message reassembly
    this.transcript = [];
    this.stage = 0;
    this.readSw = false;         // 1.2: read direction switched (CCS seen)
    this.readKeys = null;
    this.writeKeys = null;
    this.seqIn = 0;
    this.seqOut = 0;
    this.clientRandom = null;
    this.serverRandom = null;
    this.master = null;
    this.kb = null;              // 1.2 key block
    this.hsWrite = null;         // 1.3 handshake traffic secrets
    this.hsRead = null;
    this.apWrite = null;         // 1.3 application traffic secrets
    this.apRead = null;
    this.leaf = null;
    this.eph = null;
    // HelloRetryRequest bookkeeping: one retry per connection, and the
    // transcript has a documented reset point around it.
    this.hrr_sent = false;         // server sent an HRR
    this.hrr_done = false;         // server got the post-HRR ClientHello
    this.hrr_group = null;         // group the retry asked for
  }

  bomb(code, text) {
    if (this.fail === null) this.fail = { code: code, text: text };
  }

  th() {
    return crypto.createHash(this.suite.hash)
      .update(Buffer.concat(this.transcript)).digest();
  }
  keysFor(secret) {
    return {
      key: expand_label(this.suite.hash, secret, "key",
        Buffer.alloc(0), this.suite.klen),
      iv: expand_label(this.suite.hash, secret, "iv",
        Buffer.alloc(0), 12),
    };
  }
  finKey(secret) {
    return expand_label(this.suite.hash, secret, "finished",
      Buffer.alloc(0), this.suite.hlen);
  }

  // -- sealing ----------------------------------------------------------------

  // 1.3: the OUTER type is ALWAYS 23 once encrypted; the real type
  // rides inside as the last plaintext byte. 1.2: the outer type is the
  // real type. Both take (type, payload) -- the routing is the point.
  seal(inner, payload) {
    if (this.ver === "1.2") return this.seal12(inner, payload);
    const pt = Buffer.concat([payload, Buffer.from([inner])]);
    const len = pt.length + 16;
    const hdr = Buffer.from([23, 3, 3, (len >> 8) & 255, len & 255]);
    const c = crypto.createCipheriv(this.suite.name, this.writeKeys.key,
      xor_seq(this.writeKeys.iv, this.seqOut), { authTagLength: 16 });
    c.setAAD(hdr);
    this.seqOut += 1;
    return Buffer.concat([hdr, c.update(pt), c.final(), c.getAuthTag()]);
  }

  open(hdr, body) { // 1.3 only
    if (body.length < 17) { this.bomb(613, "short record"); return null; }
    const d = crypto.createDecipheriv(this.suite.name, this.readKeys.key,
      xor_seq(this.readKeys.iv, this.seqIn), { authTagLength: 16 });
    d.setAAD(hdr); // AAD is the header AS RECEIVED, not rebuilt
    d.setAuthTag(body.subarray(body.length - 16));
    let pt;
    try {
      pt = Buffer.concat([d.update(body.subarray(0, body.length - 16)),
        d.final()]);
    } catch (e) {
      this.bomb(613, "bad record mac");
      return null;
    }
    this.seqIn += 1;
    return pt;
  }

  // RFC 5246 s6.3: client_MAC || server_MAC || client_key || server_key
  // || client_IV || server_IV. GCM has no MAC key (take(0) keeps the
  // order honest) and its IV is the 4-byte implicit salt.
  keyblock12(master) {
    const s = this.suite;
    const ml = s.aead ? 0 : s.mlen;
    const need = 2 * (ml + s.klen + (s.aead ? 4 : 16));
    // SERVER random first here -- the reverse of the "master secret"
    // seed. Do not "fix" one to match the other (RFC 5246 s6.3 vs s8.1).
    const kb = prf(s.hash, master, "key expansion",
      Buffer.concat([this.serverRandom, this.clientRandom]), need);
    let at = 0;
    const take = (n) => { const b = kb.subarray(at, at + n); at += n; return b; };
    take(ml); take(ml);
    const ck = take(s.klen);
    const sk = take(s.klen);
    const ci = take(s.aead ? 4 : 16);
    const si = take(s.aead ? 4 : 16);
    return s.aead
      ? { client: { key: ck, salt: ci }, server: { key: sk, salt: si } }
      : { client: { key: ck, mac: kb.subarray(0, ml), iv: ci },
          server: { key: sk, mac: kb.subarray(ml, 2 * ml), iv: si } };
  }

  // 1.2 seal. GCM (s6.2.3.3): fragment = explicit_nonce(8) || ct || tag;
  // IV = salt(4) || explicit; AAD length counts explicit+ct+tag.
  // CBC (s6.2.3.2): MAC-then-encrypt; padlen is 1..16 with a full
  // block when aligned -- never 0.
  seal12(type, payload) {
    const s = this.suite;
    const k = this.writeKeys;
    if (s.aead) {
      const explicit = seq8(this.seqOut);
      // RFC 5246 s6.2.3.3: additional_data = seq_num || type ||
      // version || TLSCompressed.length, and TLSCompressed.length is the
      // PLAINTEXT length. The wire fragment (explicit_nonce || ct ||
      // tag) is a different number -- feeding it here authenticates a
      // value the peer never computes, and every record fails the tag.
      const aad = Buffer.concat([seq8(this.seqOut),
        Buffer.from([type, 3, 3]), u16(payload.length)]);
      const c = crypto.createCipheriv(s.name, k.key,
        Buffer.concat([k.salt, explicit]), { authTagLength: 16 });
      c.setAAD(aad);
      const frag = Buffer.concat([explicit, c.update(payload), c.final(),
        c.getAuthTag()]);
      this.seqOut += 1;
      return Buffer.concat([Buffer.from([type, 3, 3]), u16(frag.length),
        frag]);
    }
    const mac = hmac(s.hash, k.mac, Buffer.concat([
      seq8(this.seqOut), Buffer.from([type, 3, 3]),
      u16(payload.length), payload]));
    // RFC 5246 s6.2.3.2: the padding is a run of padlen octets ALL EQUAL
    // TO padlen, followed by ONE octet holding padlen -- so the record
    // carries padlen+1 padding octets. And padlen is allowed to be ZERO
    // ("Legal values range from zero to 255, inclusive"), which is what
    // happens when the content is already block-aligned; the trailing
    // %16 is what produces that zero. Dropping it makes every record
    // whose length lands on a block boundary one block too long, and the
    // peer answers bad record MAC on exactly those lengths.
    const padlen = (16 - ((payload.length + mac.length + 1) % 16)) % 16;
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv(s.name, k.key, iv);
    c.setAutoPadding(false);
    const ct = Buffer.concat([c.update(Buffer.concat([payload, mac,
      Buffer.concat([Buffer.alloc(padlen, padlen), Buffer.from([padlen])])])),
      c.final()]);
    this.seqOut += 1;
    return Buffer.concat([Buffer.from([type, 3, 3]),
      u16(16 + ct.length), iv, ct]);
  }

  open12(hdr, body) {
    const s = this.suite;
    const k = this.readKeys;
    const type = hdr[0];
    if (s.aead) {
      if (body.length < 8 + 17) { this.bomb(613, "short record"); return null; }
      const d = crypto.createDecipheriv(s.name, k.key,
        Buffer.concat([k.salt, body.subarray(0, 8)]), { authTagLength: 16 });
      d.setAAD(Buffer.concat([seq8(this.seqIn),
        Buffer.from([type, 3, 3]),
        u16(body.length - 8 - 16)])); // plaintext length, as seal12
      d.setAuthTag(body.subarray(body.length - 16));
      let pt;
      try {
        pt = Buffer.concat([d.update(body.subarray(8, body.length - 16)),
          d.final()]);
      } catch (e) {
        this.bomb(613, "bad record mac");
        return null;
      }
      this.seqIn += 1;
      return pt;
    }
    // CBC: the MAC is computed and compared even when the padding is
    // malformed, folded through timingSafeEqual so both failure paths
    // look alike (pragmatic Lucky-13 hardening).
    if (body.length < 16 + 17 || (body.length - 16) % 16 !== 0) {
      this.bomb(613, "bad cbc record");
      return null;
    }
    const d = crypto.createDecipheriv(s.name, k.key, body.subarray(0, 16));
    d.setAutoPadding(false);
    let dec;
    try { dec = Buffer.concat([d.update(body.subarray(16)), d.final()]); }
    catch (e) { this.bomb(613, "bad cbc record"); return null; }
    const plen = dec[dec.length - 1];
    // RFC 5246 s6.2.3.2: padding_length is "zero to 255, inclusive" and
    // counts the padding EXCLUSIVE of this length octet. Zero is legal
    // and common (the content was already block-aligned), so a `>= 1`
    // check here rejects exactly the records OpenSSL emits for those
    // lengths -- bad record MAC on every payload where
    // (len + mac) % 16 == 15.
    let padOk = plen <= 255 && plen + 1 + s.mlen <= dec.length;
    if (padOk) {
      for (let i = dec.length - 1 - plen; i < dec.length - 1; i += 1) {
        if (dec[i] !== plen) padOk = false;
      }
    }
    const end = padOk ? dec.length - 1 - plen - s.mlen : 0;
    const data = dec.subarray(0, Math.max(end, 0));
    const got = padOk ? dec.subarray(end, end + s.mlen)
      : Buffer.alloc(s.mlen);
    const want = hmac(s.hash, k.mac, Buffer.concat([
      seq8(this.seqIn), Buffer.from([type, 3, 3]),
      u16(data.length), data]));
    const ok = crypto.timingSafeEqual(got, want) && padOk;
    if (!ok) { this.bomb(613, "bad record mac"); return null; }
    this.seqIn += 1;
    return data;
  }

  // -- demux ------------------------------------------------------------------

  record(type, hdr, body) {
    if (this.ver === "1.2") return this.record12(type, hdr, body);
    if (type === 20) return;            // legacy CCS shim: consume, ignore
    if (type === 21) return this.alert(body);
    if (this.phase === "plain") {
      if (type !== 22) { this.bomb(613, "record " + type); return; }
      return this.handshake_frag(body);
    }
    if (type !== 23) { this.bomb(613, "record " + type); return; }
    const pt = this.open(hdr, body);
    if (pt === null || pt.length < 1) return;
    // RFC 8446 s5.4: the LAST NON-ZERO byte is the inner content type --
    // every content type (20/21/22/23) is non-zero, so the zeros behind it
    // are exactly the padding. Reading pt[last] as the type and then
    // stripping zeros off the CONTENT is wrong twice over: it types a
    // padded record as 0, and it eats real content bytes whenever the
    // content ends in zero -- which a DER certificate or an RSA signature
    // does constantly, desynchronising every later handshake message.
    let end = pt.length - 1;
    while (end >= 0 && pt[end] === 0) end -= 1;
    if (end < 0) return this.bomb(613, "empty inner plaintext");
    const inner = pt[end];
    const payload = pt.subarray(0, end);
    if (inner === 22) return this.handshake_frag(payload);
    if (inner === 23) { this.app.push(Buffer.from(payload)); this.app_records += 1; return; }
    if (inner === 21) return this.alert(payload);
    this.bomb(613, "inner " + inner);
  }

  // 1.2: CCS switches each direction independently (own CCS, own seq
  // reset); before that, handshake records are plaintext and the OUTER
  // type is the real type; after, records are encrypted in place.
  record12(type, hdr, body) {
    if (type === 20) {
      if (!this.readSw) {
        if (!this.ccsOk12()) return this.bomb(613, "ccs too early");
        this.readKeys = this.role === "c"
          ? this.kb.server : this.kb.client;
        this.seqIn = 0;
        this.readSw = true;
      }
      return;
    }
    if (!this.readSw) {
      if (type === 22) return this.handshake_frag(body);
      if (type === 21) return this.alert(body);
      return this.bomb(613, "record " + type);
    }
    const pt = this.open12(hdr, body);
    if (pt === null || pt.length < 1) return;
    if (type === 22) return this.handshake_frag(pt);
    if (type === 23) { this.app.push(Buffer.from(pt)); this.app_records += 1; return; }
    if (type === 21) return this.alert(pt);
    return this.bomb(613, "record " + type);
  }

  ccsOk12() {
    // Client: may see the server's CCS only after its own flight 2 (CKE
    // + CCS + Finished) is out. Server: only after the ClientKeyExchange.
    return this.role === "c" ? this.stage >= 4 : this.stage === 2;
  }

  alert(payload) {
    const desc = payload.length >= 2 ? payload[1] : 0;
    if (desc === 0) {
      if (this.done) this.closed = true;
      else this.bomb(613, "close_notify in handshake");
      return;
    }
    const code = (desc === 42 || desc === 46 || desc === 48) ? 614
      // 120 = no_application_protocol. That IS the ALPN contract failing,
      // so it answers 615 like our own server does -- mapping it to the
      // generic 616 would tell the caller "some TLS error" when the one
      // true cause is that the peer offered no protocol in common.
      : desc === 120 ? 615
      : (desc === 10 || desc === 20 || desc === 40 || desc === 47
         || desc === 112) ? 613 : 616;
    this.bomb(code, "alert " + desc);
  }

  handshake_frag(frag) {
    this.hsbuf = this.hsbuf === null ? frag
      : Buffer.concat([this.hsbuf, frag]);
    if (this.hsbuf.length > 262144) {
      this.bomb(613, "handshake flood");
      return;
    }
    for (;;) {
      if (this.hsbuf.length < 4) return;
      const t = this.hsbuf[0];
      const len = (this.hsbuf[1] << 16) | (this.hsbuf[2] << 8)
        | this.hsbuf[3];
      if (this.hsbuf.length < 4 + len) return; // fragmented: wait
      const msg = this.hsbuf.subarray(0, 4 + len);
      this.hsbuf = this.hsbuf.subarray(4 + len);
      this.msg(t, msg);
      if (this.fail !== null) return;
    }
  }

  msg(t, m) {
    if (this.done) {
      if (this.ver === "1.2") {
        // A plaintext HelloRequest between encrypted records would
        // already have failed the AEAD/CBC open above; a renegotiation
        // attempt dies here either way. Refusing is the safe answer.
        if (t === 0) return this.bomb(613, "renegotiation unsupported");
        return this.bomb(613, "unexpected post-handshake " + t);
      }
      if (t === 4) return;                    // NewSessionTicket: ignore
      if (t === 24) return this.key_update();
      return this.bomb(613, "unexpected post-handshake " + t);
    }
    if (this.role === "s") {
      if (this.stage === 0) {
        return t === 1 ? this.client_hello(m)
          : this.bomb(613, "expected ClientHello, got " + t);
      }
      if (this.ver === "1.2") {
        if (this.stage === 1 && t === 16) return this.msg12s(m);
        if (this.stage === 2 && t === 20) return this.client_fin12(m);
        return this.bomb(613, "unexpected " + t);
      }
      if (this.stage === 1 && t === 20) return this.client_finished(m);
      return this.bomb(613, "expected Finished, got " + t);
    }
    if (this.ver === "1.2") return this.msg12(t, m);
    const expect = [2, 8, 11, 15, 20][this.stage];
    if (t !== expect) {
      return this.bomb(613, "expected hs " + expect + ", got " + t);
    }
    if (t === 2) return this.server_hello(m);
    if (t === 8) return this.encrypted_extensions(m);
    if (t === 11) return this.certificate(m);
    if (t === 15) return this.cert_verify(m);
    return this.server_finished(m);
  }

  // -- driven by the effects ----------------------------------------------------

  feed(bytes) {
    if (this.fail !== null) return;
    // The one doorway for bytes from outside the pump. `net` hands over a
    // Buffer, an effect hands over the Uint8Array it allocated itself, and
    // the handshake below uses Buffer methods (subarray().equals against
    // HRR_RANDOM, for one) -- so a plain Uint8Array is adopted here, once,
    // as a Buffer VIEW (no copy) instead of throwing a TypeError into the
    // runtime, which takes the whole process down.
    const got = as_buf(bytes);
    const buf = this.pending === null ? got
      : Buffer.concat([this.pending, got]);
    this.pending = null;
    let i = 0;
    while (buf.length - i >= 5) {
      const len = (buf[i + 3] << 8) | buf[i + 4];
      // Legacy record version must be 3.x: 1.2 peers may still label
      // early records 0x0301, so only the major byte is enforced.
      if (buf[i + 1] !== 3 || len > MAX_RECORD) {
        this.bomb(613, "bad record");
        return;
      }
      if (buf.length - i < 5 + len) break;   // incomplete: keep the tail
      const type = buf[i];
      const hdr = buf.subarray(i, i + 5);
      const body = buf.subarray(i + 5, i + 5 + len);
      i += 5 + len;
      this.record(type, hdr, body);
      if (this.fail !== null) return;
    }
    if (buf.length - i > 0) this.pending = buf.subarray(i);
  }

  drain() {
    if (this.out.length === 0) return null;
    const b = Buffer.concat(this.out);
    this.out = [];
    return b;
  }
  take_app(max) {
    if (this.app.length === 0) return null;
    const all = Buffer.concat(this.app);
    this.app = [];
    if (all.length <= max) return all;
    this.app.push(all.subarray(max));
    return all.subarray(0, max);
  }
  // Chunks past 16383: 1.3 fits inner type + tag inside MAX_RECORD; 1.2
  // CBC fits MAC + pad inside the 2^14+2048 ceiling. Empty sends still
  // carry one (empty) application record.
  seal_app(bytes) {
    if (!this.done) { this.bomb(616, "not ready"); return false; }
    if (this.fail !== null || this.closed) return false;
    for (let at = 0; at < bytes.length; at += 16383) {
      this.out.push(this.seal(23, bytes.subarray(at, at + 16383)));
    }
    if (bytes.length === 0) this.out.push(this.seal(23, bytes));
    return true;
  }
  shutdown() {
    if (this.done && !this.closed && this.fail === null
        && this.writeKeys !== null) {
      try { this.out.push(this.seal(21, Buffer.from([1, 0]))); } catch (e) {}
    }
    this.closed = true;
  }

  // RFC 8446 s4.6.1, both roles: the PEER rotated its write side, which
  // is our read side. Derive from the current read secret with an empty
  // transcript and reset the sequence.
  key_update() {
    const h = this.suite.hash;
    const empty = crypto.createHash(h).digest();
    this.apRead = expand_label(h, this.apRead, "traffic upd", empty,
      this.suite.hlen);
    this.readKeys = this.keysFor(this.apRead);
    this.seqIn = 0;
  }
}

// -- the portable client --------------------------------------------------------

class PortableClient extends Pump {
  constructor(host, verify, alpnProtos) {
    super("c");
    this.host = host;
    this.verify = !!verify;
    this.alpnProtos = alpnProtos;
    this.serverPoint = null;
    // One share only, the first group we offer -- the OpenSSL policy.
    this.share = make_share(OFFERED_GROUPS[0].id);
    this.clientRandom = crypto.randomBytes(32);
    this.cookie = null;
    this.hrr_count = 0;
    this.send_hello();
  }

  send_hello() {
    const built = build_client_hello(this.host, this.alpnProtos,
      this.share, this.clientRandom, this.cookie);
    this.transcript.push(built.hello);
    this.out.push(Buffer.concat([
      Buffer.from([22, 3, 3]), u16(built.hello.length), built.hello,
    ]));
  }

  // HelloRetryRequest (RFC 8446 s4.1.4). The server picked a group we did
  // not put a share for, so we build a share for THAT group and re-hello.
  // The transcript is CH1 || HRR || CH2 || ... (s4.4.1) -- nothing is
  // dropped, which is why a "clean up" here shows up later as a bad
  // record MAC on the server's Finished. The client random is unchanged,
  // and a second HRR is refused rather than looped.
  hello_retry(m) {
    if (this.ver !== "1.3") {
      return this.bomb(613, "hello retry in tls 1.2");
    }
    this.hrr_count += 1;
    if (this.hrr_count > 1) return this.bomb(613, "too many hello retries");
    let group = null;
    let cookie = null;
    let sid = Buffer.from([0]);
    const sidl = m[38];
    if (sidl > 32) return this.bomb(613, "bad session id");
    sid = Buffer.from(m.subarray(39, 39 + sidl));
    const q = 39 + sidl;
    if (m.length < q + 5) return this.bomb(613, "short hello retry");
    const xl = (m[q + 3] << 8) | m[q + 4];
    let e = q + 5;
    const end = Math.min(e + xl, m.length);
    while (e + 4 <= end) {
      const t = (m[e] << 8) | m[e + 1];
      const l = (m[e + 2] << 8) | m[e + 3];
      if (e + 4 + l > end) break;
      const d = m.subarray(e + 4, e + 4 + l);
      // key_share in an HRR is a BARE KeyShareEntry (no u16 wrapper),
      // unlike the ClientHello's vector.
      if (t === 51 && l >= 2) group = (d[0] << 8) | d[1];
      if (t === 44 && l >= 2) cookie = Buffer.from(d.subarray(2, 2 + ((d[0] << 8) | d[1])));
      e += 4 + l;
    }
    if (group === null) return this.bomb(613, "hello retry without a group");
    const g = group_of(group);
    if (g === null || !OFFERED_GROUPS.some((o) => o.id === group)) {
      return this.bomb(613, "hello retry asks for an unoffered group");
    }
    if (group === this.share.group) {
      // The server retried the group we already offered: a loop, not a
      // correction. Refuse instead of re-helloing forever.
      return this.bomb(613, "hello retry on the same group");
    }
    this.cookie = cookie;
    this.share = make_share(group);
    // CH1 is REPLACED, not kept: the transcript restarts from the
    // synthetic message_hash of CH1, then the HRR, then CH2 (which
    // send_hello appends).
    const hrr_suite = SUITES[(m[q] << 8) | m[q + 1]];
    const th1 = crypto.createHash(hrr_suite ? hrr_suite.hash : "sha256")
      .update(Buffer.concat(this.transcript)).digest();
    this.transcript = [synthetic_message_hash(th1), m];
    return this.send_hello();
  }

  server_hello(m) {
    if (m.length < 40) return this.bomb(613, "short ServerHello");
    if (m.subarray(6, 38).equals(HRR_RANDOM)) {
      return this.hello_retry(m);
    }
    // Both 1.2 and 1.3 ServerHellos carry legacy_version 0x0303 (1.3
    // hides its real version in supported_versions), so one check
    // covers both branches.
    const legacy = (m[4] << 8) | m[5];
    if (legacy !== 0x0303) {
      return this.bomb(613, "peer speaks tls 1.0/1.1");
    }
    const sidl = m[38];
    if (sidl > 32) return this.bomb(613, "bad session id");
    const q = 39 + sidl;
    if (m.length < q + 5) return this.bomb(613, "short ServerHello");
    const suite = (m[q] << 8) | m[q + 1];
    if (m[q + 2] !== 0) return this.bomb(613, "bad compression");
    const xl = (m[q + 3] << 8) | m[q + 4];
    if (m.length < q + 5 + xl) return this.bomb(613, "short ServerHello");
    let have13 = false;
    let kse = null;
    for (let e = q + 5; e + 4 <= q + 5 + xl;) {
      const t = (m[e] << 8) | m[e + 1];
      const l = (m[e + 2] << 8) | m[e + 3];
      if (e + 4 + l > q + 5 + xl) break;
      const d = m.subarray(e + 4, e + 4 + l);
      if (t === 43 && l >= 2) have13 = ((d[0] << 8) | d[1]) === 0x0304;
      if (t === 51 && l >= 4) kse = d;
      // ALPN in 1.2 rides the ServerHello (there is no
      // EncryptedExtensions); in 1.3 it rides EE instead.
      if (t === 16 && l >= 5) {
        this.alpn = d.subarray(3, 3 + d[2]).toString("ascii");
      }
      if (t === 0xff01 && !(l === 1 && d[0] === 0)) {
        return this.bomb(613, "bad renegotiation info");
      }
      e += 4 + l;
    }
    if (have13) return this.sh13(m, suite, kse);
    return this.sh12(m, suite);
  }

  sh13(m, suite, kse) {
    const s13 = SUITES[suite];
    if (s13 === undefined) {
      return this.bomb(613, "cipher " + suite.toString(16));
    }
    if (kse === null) return this.bomb(613, "no key share");
    const sgroup = (kse[0] << 8) | kse[1];
    const sl = (kse[2] << 8) | kse[3];
    const sraw = kse.subarray(4, 4 + sl);
    const peer = group_of(sgroup);
    // The share must be for the group WE sent, and its length must match
    // that group's wire size -- checked against the table instead of a
    // hardcoded pair, so every served curve is covered.
    if (peer === null || peer.plen !== sl) {
      return this.bomb(613, "bad key share");
    }
    const share = this.share;
    if (share.group !== sgroup) {
      return this.bomb(613, "group " + sgroup.toString(16));
    }
    this.ver = "1.3";
    this.suite = s13;
    this.serverRandom = Buffer.from(m.subarray(6, 38));
    this.transcript.push(m);
    let shared;
    try {
      shared = crypto.diffieHellman({
        privateKey: share.priv,
        publicKey: peer_pub(sgroup, sraw),
      });
    } catch (e) {
      return this.bomb(613, "ecdhe failed");
    }
    const h = this.suite.hash;
    const hl = this.suite.hlen;
    const Z = Buffer.alloc(hl);        // RFC 8446 s7.1: 0 = zeros(hlen)
    const empty = crypto.createHash(h).digest();
    const extract = (salt, ikm) => hmac(h, salt, ikm);
    const dsec = (secret, label, thx) => expand_label(h, secret, label, thx, hl);
    const early = extract(Z, Z);
    const hsSec = extract(dsec(early, "derived", empty), shared);
    const thSH = this.th();
    this.hsWrite = dsec(hsSec, "c hs traffic", thSH);
    this.hsRead = dsec(hsSec, "s hs traffic", thSH);
    this.master = extract(dsec(hsSec, "derived", empty), Z);
    this.readKeys = this.keysFor(this.hsRead);
    this.writeKeys = this.keysFor(this.hsWrite);
    this.seqIn = 0;
    this.seqOut = 0;
    this.phase = "enc";
    this.stage = 1;
  }

  sh12(m, suite) {
    const s12 = SUITES12[suite];
    if (s12 === undefined) {
      return this.bomb(613, "cipher " + suite.toString(16));
    }
    this.ver = "1.2";
    this.suite = s12;
    this.serverRandom = Buffer.from(m.subarray(6, 38));
    this.transcript.push(m);
    this.stage = 1;
  }

  encrypted_extensions(m) {
    if (m.length < 6) return this.bomb(613, "short EncryptedExtensions");
    const l = (m[4] << 8) | m[5];
    const end = Math.min(6 + l, m.length);
    for (let e = 6; e + 4 <= end;) {
      const t = (m[e] << 8) | m[e + 1];
      const xl = (m[e + 2] << 8) | m[e + 3];
      if (e + 4 + xl > end) break;
      if (t === 16 && xl >= 3) {         // list len(2) + entry len(1) + name
        this.alpn = m.subarray(e + 7, e + 7 + m[e + 6]).toString("ascii");
      }
      e += 4 + xl;
    }
    this.transcript.push(m);
    this.stage = 2;
  }

  // 1.3 Certificate: request_context(1 byte -- RFC 8446 s4.4.2, NOT a
  // u24) + list_len(3) + entries, each entry cert_len(3) + cert +
  // extensions(2). Reading the context as 3 bytes swallows two bytes of
  // the list length and every 1.3 server answers "bad certificate entry".
  certificate(m) {
    let p = 4;
    if (m.length < p + 1) return this.bomb(613, "short Certificate");
    p += 1 + m[p];
    if (m.length < p + 3) return this.bomb(613, "short Certificate");
    const listl = (m[p] << 16) | (m[p + 1] << 8) | m[p + 2];
    p += 3;
    const end = Math.min(p + listl, m.length);
    const ders = [];
    while (p + 3 <= end) {
      const cl = (m[p] << 16) | (m[p + 1] << 8) | m[p + 2];
      p += 3;
      if (p + cl > end) return this.bomb(613, "bad certificate entry");
      ders.push(Buffer.from(m.subarray(p, p + cl)));
      p += cl;
      if (p + 2 > end) return this.bomb(613, "bad cert extensions");
      p += 2 + ((m[p] << 8) | m[p + 1]);
    }
    if (ders.length === 0) return this.bomb(613, "empty certificate");
    if (this.verify) {
      try { this.leaf = verify_chain(ders, this.host); }
      catch (e) { return this.bomb(614, e.message); }
    } else {
      try { this.leaf = new crypto.X509Certificate(ders[0]); }
      catch (e) { return this.bomb(613, "bad certificate"); }
    }
    this.transcript.push(m);
    this.stage = 3;
  }

  // 1.2 Certificate: list_len(3) + entries, each cert_len(3) + cert.
  cert12(m) {
    const listl = (m[4] << 16) | (m[5] << 8) | m[6];
    const end = Math.min(7 + listl, m.length);
    const ders = [];
    for (let p = 7; p + 3 <= end;) {
      const cl = (m[p] << 16) | (m[p + 1] << 8) | m[p + 2];
      p += 3;
      if (p + cl > end) return this.bomb(613, "bad certificate entry");
      ders.push(Buffer.from(m.subarray(p, p + cl)));
      p += cl;
    }
    if (ders.length === 0) return this.bomb(613, "empty certificate");
    if (this.verify) {
      try { this.leaf = verify_chain(ders, this.host); }
      catch (e) { return this.bomb(614, e.message); }
    } else {
      try { this.leaf = new crypto.X509Certificate(ders[0]); }
      catch (e) { return this.bomb(613, "bad certificate"); }
    }
    this.stage = 2;
  }

  cert_verify(m) {
    if (m.length < 8) return this.bomb(613, "short CertificateVerify");
    const scheme = (m[4] << 8) | m[5];
    const sl = (m[6] << 8) | m[7];
    if (m.length < 8 + sl) return this.bomb(613, "short CertificateVerify");
    const sig = m.subarray(8, 8 + sl);
    const content = Buffer.concat([
      Buffer.alloc(64, 0x20),
      Buffer.from("TLS 1.3, server CertificateVerify\0", "ascii"),
      this.th(),
    ]);
    const key = this.leaf.publicKey;
    let ok = false;
    try {
      if (scheme === 0x0804) {
        ok = crypto.verify("sha256", content, {
          key: key,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 32,
        }, sig);
      } else if (scheme === 0x0403) {
        ok = crypto.verify("sha256", content, key,
          sl === 64 ? ecdsa_raw_to_der(sig) : sig);
      } else if (scheme === 0x0401) {
        ok = crypto.verify("sha256", content, {
          key: key, padding: crypto.constants.RSA_PKCS1_PADDING,
        }, sig);
      } else {
        return this.bomb(613, "cv scheme " + scheme.toString(16));
      }
    } catch (e) { ok = false; }
    if (!ok) return this.bomb(613, "bad certificate verify");
    this.transcript.push(m);
    this.stage = 4;
  }

  server_finished(m) {
    const h = this.suite.hash;
    const hl = this.suite.hlen;
    if (m.length < 4 + hl) return this.bomb(613, "short Finished");
    const got = m.subarray(4, 4 + hl);
    const want = hmac(h, this.finKey(this.hsRead), this.th());
    if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
      return this.bomb(613, "bad finished");
    }
    this.transcript.push(m);
    const thFin = this.th();
    this.apWrite = expand_label(h, this.master, "c ap traffic", thFin, hl);
    this.apRead = expand_label(h, this.master, "s ap traffic", thFin, hl);
    // The client Finished rides the CLIENT HANDSHAKE keys; the app keys
    // take over only after it is sealed (sequences reset on the switch).
    const fin = hmac(h, this.finKey(this.hsWrite), thFin);
    // The OUTER record type of a sealed record is always 23; `seal`'s
    // argument is the INNER content type, and a Finished is handshake (22).
    // Passing 20 here stamped the inner type as change_cipher_spec, which
    // the peer rejects as a bad record type (openssl:
    // ssl3_get_record:bad record type) after the MAC already verified.
    this.out.push(this.seal(22,
      Buffer.concat([Buffer.from([20]), u24(fin.length), fin])));
    this.writeKeys = this.keysFor(this.apWrite);
    this.readKeys = this.keysFor(this.apRead);
    this.seqOut = 0;
    this.seqIn = 0;
    this.done = true;
    this.stage = 5;
  }

  // -- TLS 1.2 client machine ---------------------------------------------------

  msg12(t, m) {
    if (t === 13) {
      return this.bomb(613, "client certificates unsupported");
    }
    if (this.stage === 4) {
      // NewSessionTicket enters the transcript: the server's Finished
      // COVERS it (the asymmetry that breaks naive implementations).
      if (t === 4) { this.transcript.push(m); return; }
      if (t === 20) return this.server_fin12(m);
      return this.bomb(613, "unexpected " + t);
    }
    const expect = [11, 12, 14][this.stage - 1];
    if (t !== expect) {
      return this.bomb(613, "expected " + expect + ", got " + t);
    }
    this.transcript.push(m);
    if (t === 11) return this.cert12(m);
    if (t === 12) return this.ske12(m);
    return this.flight12();
  }

  // ServerKeyExchange: curve_type(1)=named_curve, curve(2), point_len(1),
  // point, then hash(1)+alg(1)+sig_len(2)+sig over
  // client_random || server_random || params -- a DIFFERENT role from
  // the 1.3 CertificateVerify content string.
  ske12(m) {
    if (m.length < 13) return this.bomb(613, "short ServerKeyExchange");
    if (m[4] !== 3) return this.bomb(613, "not a named curve");
    const group = (m[5] << 8) | m[6];
    // Any group we can compute, checked against the table. In 1.2 the
    // SERVER picks the curve, so this is the path where an unsupported
    // group would actually arrive.
    if (!OFFERED_GROUPS.some((g) => g.id === group)) {
      return this.bomb(613, "group " + group.toString(16));
    }
    const pl = m[7];
    if (m.length < 8 + pl) return this.bomb(613, "short key exchange");
    this.serverPoint = Buffer.from(m.subarray(8, 8 + pl));
    const params = m.subarray(4, 8 + pl);
    const p = 8 + pl;
    if (m.length < p + 4) return this.bomb(613, "short ServerKeyExchange");
    const ha = m[p];
    const sa = m[p + 1];
    const sl = (m[p + 2] << 8) | m[p + 3];
    if (m.length < p + 4 + sl) return this.bomb(613, "short signature");
    const sig = m.subarray(p + 4, p + 4 + sl);
    const content = Buffer.concat([
      this.clientRandom, this.serverRandom, params,
    ]);
    // The 1.2 ECDHE ephemeral is generated HERE: the server picks the
    // group, so the pre-made hello shares stay unused in this branch.
    this.eph = make_share(group);
    let ok = false;
    try {
      if (ha === 4 && sa === 1) {
        ok = crypto.verify("sha256", content, {
          key: this.leaf.publicKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        }, sig);
      } else if (ha === 8 && sa === 4) {
        ok = crypto.verify("sha256", content, {
          key: this.leaf.publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 32,
        }, sig);
      } else if (ha === 4 && sa === 3) {
        ok = crypto.verify("sha256", content, this.leaf.publicKey,
          sl === 64 ? ecdsa_raw_to_der(sig) : sig);
      }
    } catch (e) { ok = false; }
    if (!ok) return this.bomb(613, "bad server key exchange");
    this.stage = 3;
  }

  flight12() {
    // ClientKeyExchange + ChangeCipherSpec (plaintext) + Finished
    // (encrypted with the fresh client keys).
    const cke_body = Buffer.concat([Buffer.from([this.eph.pub.length]),
      this.eph.pub]);
    const cke = Buffer.concat([Buffer.from([16]),
      u24(cke_body.length), cke_body]);
    this.out.push(plain_rec(22, cke));
    this.transcript.push(cke);
    let shared;
    try {
      shared = crypto.diffieHellman({
        privateKey: this.eph.priv,
        publicKey: peer_pub(this.eph.group, this.serverPoint),
      });
    } catch (e) {
      return this.bomb(613, "ecdhe failed");
    }
    const h = this.suite.hash;
    // client random FIRST here -- the reverse of "key expansion".
    this.master = prf(h, shared, "master secret",
      Buffer.concat([this.clientRandom, this.serverRandom]), 48);
    this.kb = this.keyblock12(this.master);
    this.out.push(plain_rec(20, Buffer.from([1])));
    this.writeKeys = this.kb.client;
    this.seqOut = 0;
    const th = crypto.createHash(h)
      .update(Buffer.concat(this.transcript)).digest();
    const fin = prf(h, this.master, "client finished", th, 12);
    const fin_msg = Buffer.concat([Buffer.from([20]), u24(12), fin]);
    this.transcript.push(fin_msg); // the server's Finished covers ours
    this.out.push(this.seal12(22, fin_msg));
    this.stage = 4;
  }

  server_fin12(m) {
    const h = this.suite.hash;
    if (m.length < 16) return this.bomb(613, "short Finished");
    const th = crypto.createHash(h)
      .update(Buffer.concat(this.transcript)).digest();
    if (!crypto.timingSafeEqual(m.subarray(4, 16),
        prf(h, this.master, "server finished", th, 12))) {
      return this.bomb(613, "bad finished");
    }
    this.done = true;
    // 1.2 derives no separate application keys: the handshake keys ARE
    // the application keys.
  }
}

// -- the portable server ---------------------------------------------------------

class PortableServer extends Pump {
  constructor(certPath, keyPath, offer) {
    super("s");
    this.certs = load_chain(certPath);   // throws: answers 613 upstream
    this.priv = load_key(keyPath);
    this.offer = offer;
    this.keyType = this.priv.asymmetricKeyType === "ec" ? "ec" : "rsa";
  }

  // HelloRetryRequest (RFC 8446 s4.1.4). Sent when the peer's key share
  // is for a group we do not have: the first HRR must carry the same
  // cipher suite as the peer's ClientHello, only supported_versions,
  // key_share (bare entry) and cookie are allowed, and the transcript
  // resets afterwards.
  send_hrr(groups, sid) {
    const want = OFFERED_GROUPS.find((g) => groups.indexOf(g.id) >= 0);
    if (want === undefined) return this.bomb(613, "no common group");
    if (groups.indexOf(0x001d) < 0 && groups.indexOf(0x0017) < 0
        && groups.indexOf(0x0018) < 0 && groups.indexOf(0x0019) < 0) {
      return this.bomb(613, "no common group");
    }
    // Already retried for this group: a loop, refuse it.
    if (this.hrr_sent && this.hrr_group === want.id) {
      return this.bomb(613, "too many hello retries");
    }
    this.hrr_sent = true;
    this.hrr_group = want.id;
    const ks = Buffer.concat([u16(want.id), u16(want.plen),
      Buffer.alloc(want.plen, 0)]); // placeholder length only
    const sh_exts = Buffer.concat([ext(43, u16(0x0304)), ext(51, ks)]);
    const body = Buffer.concat([Buffer.from([3, 3]), HRR_RANDOM,
      Buffer.from([sid.length]), Buffer.from(sid),
      u16(this.negotiated_suite === undefined ? 0x1301 : this.negotiated_suite),
      Buffer.from([0]),
      u16(sh_exts.length), sh_exts]);
    const sh = Buffer.concat([Buffer.from([2]), u24(body.length), body]);
    this.out.push(plain_rec(22, sh));
    // Same rule as the client: CH1 is replaced by the synthetic
    // message_hash, so the transcript becomes [synthetic(CH1), HRR] and
    // the peer's second ClientHello is appended after it.
    const th1 = crypto.createHash(this.suite.hash)
      .update(Buffer.concat(this.transcript)).digest();
    this.transcript = [synthetic_message_hash(th1), sh];
  }

  client_hello(m) {
    if (m.length < 43) return this.bomb(613, "short ClientHello");
    if (this.hrr_sent) return this.bomb(613, "second ClientHello after retry");
    const legacyVer = (m[4] << 8) | m[5];
    const sidl = m[38];
    if (sidl > 32) return this.bomb(613, "bad session id");
    const sid = m.subarray(39, 39 + sidl);
    let p = 39 + sidl;
    if (m.length < p + 2) return this.bomb(613, "bad ClientHello");
    const sl = (m[p] << 8) | m[p + 1];
    p += 2;
    if (m.length < p + sl) return this.bomb(613, "bad ClientHello");
    const suites = [];
    let scsv = false;
    for (let i = 0; i + 1 < sl; i += 2) {
      const s = (m[p + i] << 8) | m[p + i + 1];
      suites.push(s);
      if (s === 0x00ff) scsv = true;     // SCSV = renegotiation request
    }
    p += sl;
    if (m.length < p + 1) return this.bomb(613, "bad ClientHello");
    p += 1 + m[p];                       // legacy compression
    if (m.length < p + 2) return this.bomb(613, "bad ClientHello");
    const xl = (m[p] << 8) | m[p + 1];
    p += 2;
    const xend = Math.min(p + xl, m.length);
    let have13 = false;
    const shares = [];
    const groups = [];
    const sigalgs = [];
    const protos = [];
    let renego = scsv;
    for (let e = p; e + 4 <= xend;) {
      const t = (m[e] << 8) | m[e + 1];
      const l = (m[e + 2] << 8) | m[e + 3];
      if (e + 4 + l > xend) break;
      const d = m.subarray(e + 4, e + 4 + l);
      if (t === 43) {
        for (let i = 1; i + 1 < d.length; i += 2) {
          if (((d[i] << 8) | d[i + 1]) === 0x0304) have13 = true;
        }
      } else if (t === 51 && d.length >= 2) {
        const cl = (d[0] << 8) | d[1];
        for (let i = 2; i + 4 <= 2 + cl;) {
          const g = (d[i] << 8) | d[i + 1];
          const kl = (d[i + 2] << 8) | d[i + 3];
          if (i + 4 + kl > 2 + cl) break;
          if (group_of(g) !== null) {
            shares.push({ group: g,
              raw: Buffer.from(d.subarray(i + 4, i + 4 + kl)) });
          }
          i += 4 + kl;
        }
      } else if (t === 10 && d.length >= 2) {
        const gl = (d[0] << 8) | d[1];
        for (let i = 2; i + 1 < 2 + gl; i += 2) {
          groups.push((d[i] << 8) | d[i + 1]);
        }
      } else if (t === 13 && d.length >= 2) {
        const gl = (d[0] << 8) | d[1];
        for (let i = 2; i + 1 < 2 + gl; i += 2) {
          sigalgs.push((d[i] << 8) | d[i + 1]);
        }
      } else if (t === 16 && d.length >= 2) {
        const ll = (d[0] << 8) | d[1];
        for (let i = 2; i + 1 < 2 + ll;) {
          const n = d[i];
          if (i + 1 + n > 2 + ll) break;
          protos.push(d.subarray(i + 1, i + 1 + n).toString("ascii"));
          i += 1 + n;
        }
      } else if (t === 0xff01) {
        renego = true;
      }
      e += 4 + l;
    }
    if (!have13) {
      // A client that sent legacy 0x0301/0x0300 without the versions
      // extension tops out below 1.2.
      if (legacyVer !== 0x0303) {
        return this.bomb(613, "peer speaks tls 1.0/1.1");
      }
      return this.client_hello12(m, suites, groups, sigalgs, protos,
        renego);
    }
    // After our HRR the peer's second ClientHello arrives; the transcript
    // keeps [CH1, HRR] and this hello is appended, then the real
    // ServerHello replaces everything (RFC 8446 s4.4.1).
    if (this.hrr_sent) {
      this.transcript.push(m);
      this.hrr_done = true;
    } else {
      this.transcript.push(m);
    }
    // Our group preference, intersected with what the peer offered a
    // share for. With one share per hello a mismatch is NORMAL and the
    // answer is a HelloRetryRequest (RFC 8446 s4.1.4), not a failure --
    // refusing here is what would make the single-share client unusable
    // against a server with a different group order.
    const usable_g = OFFERED_GROUPS.find((g) =>
      shares.some((s) => s.group === g.id));
    if (usable_g === undefined) return this.send_hrr(groups, sid);
    // After a retry the share must be for the group WE asked for, or the
    // peer is ignoring our HRR.
    if (this.hrr_sent && this.hrr_group !== undefined
        && usable_g.id !== this.hrr_group) {
      return this.bomb(613, "peer ignored the hello retry");
    }
    const share = shares.find((s) => s.group === usable_g.id);
    const suite = OFFERED.find((s) => suites.indexOf(s) >= 0);
    if (suite === undefined) return this.bomb(613, "no common cipher");
    const picked = alpn_select(protos, this.offer);
    if (picked === null) {
      // Same contract as the old ffi callback: no overlap fails the
      // handshake with a fatal no_application_protocol (120) alert.
      this.out.push(alert_record(2, 120));
      return this.bomb(615, "alpn mismatch");
    }
    this.alpn = picked;
    this.ver = "1.3";
    this.suite = SUITES[suite];
    // RFC 8446 s4.4.1: when a HelloRetryRequest happened, the transcript
    // for the real handshake is [CH2, ServerHello, ...] -- CH1 and the
    // HRR are dropped. Resetting here (before flight13 pushes the
    // ServerHello) is exactly that boundary.
    if (this.hrr_done) this.transcript = [m];
    return this.flight13(share, sid);
  }

  // ServerHello (plaintext) + flight 2 (EE, Certificate,
  // CertificateVerify, Finished) sealed under the server handshake keys.
  flight13(share, sid) {
    const h = this.suite.hash;
    const hl = this.suite.hlen;
    this.eph = make_share(share.group);
    const ks = Buffer.concat([u16(share.group),
      u16(this.eph.pub.length), this.eph.pub]);
    const sh_exts = Buffer.concat([
      ext(43, u16(0x0304)),
      // RFC 8446 s4.1.2: the ServerHello carries a BARE KeyShareEntry
      // ("struct { KeyShareEntry server_share; }"), while the ClientHello
      // wraps its shares in a u16 vector. Emitting the vector length here
      // makes the peer read that length as the NamedGroup and the group
      // as the key length -- the peer answers illegal_parameter.
      ext(51, ks),
    ]);
    const sh_body = Buffer.concat([
      Buffer.from([3, 3]), crypto.randomBytes(32),
      Buffer.from([sid.length]), sid,
      u16(cipher_of(this.suite)),
      Buffer.from([0]),
      u16(sh_exts.length), sh_exts,
    ]);
    const sh = Buffer.concat([Buffer.from([2]), u24(sh_body.length),
      sh_body]);
    this.out.push(Buffer.concat([Buffer.from([22, 3, 3]), u16(sh.length),
      sh]));
    this.transcript.push(sh);
    // Key schedule, roles mirrored: we WRITE with "s hs traffic".
    let shared;
    try {
      shared = crypto.diffieHellman({
        privateKey: this.eph.priv,
        publicKey: peer_pub(share.group, share.raw),
      });
    } catch (e) {
      return this.bomb(613, "ecdhe failed");
    }
    const Z = Buffer.alloc(hl);
    const empty = crypto.createHash(h).digest();
    const dsec = (secret, label, thx) => expand_label(h, secret, label, thx, hl);
    const early = hmac(h, Z, Z);
    const hsSec = hmac(h, dsec(early, "derived", empty), shared);
    const thSH = this.th();
    this.hsWrite = dsec(hsSec, "s hs traffic", thSH);
    this.hsRead = dsec(hsSec, "c hs traffic", thSH);
    this.master = hmac(h, dsec(hsSec, "derived", empty), Z);
    this.writeKeys = this.keysFor(this.hsWrite);
    this.readKeys = this.keysFor(this.hsRead);
    this.seqIn = 0;
    this.seqOut = 0;
    this.phase = "enc";
    // EncryptedExtensions carries the ALPN answer in 1.3 -- and carries NO
    // ALPN extension when nothing was selected: an empty ProtocolName is
    // not a valid one (RFC 7301 s3.2), so the extension is omitted whole.
    // The extensions block is the u16 length followed by the extension
    // itself, so the + 4 the old code added was the ext() header, which
    // ext() has already built by the time it is counted here.
    const alpn_ext = this.alpn === "" ? Buffer.alloc(0)
      : ext(16, Buffer.concat([u16(picked_len(this.alpn)),
        Buffer.from([this.alpn.length]),
        Buffer.from(this.alpn, "ascii")]));
    const ee_body = Buffer.concat([u16(alpn_ext.length), alpn_ext]);
    const ee = Buffer.concat([Buffer.from([8]), u24(ee_body.length),
      ee_body]);
    const entries = this.certs.map((d) =>
      Buffer.concat([u24(d.length), d, Buffer.from([0, 0])]));
    const list = Buffer.concat(entries);
    const cert_body = Buffer.concat([Buffer.from([0]), u24(list.length),
      list]);
    const cert = Buffer.concat([Buffer.from([11]),
      u24(cert_body.length), cert_body]);
    this.transcript.push(ee);
    this.transcript.push(cert);
    const content = Buffer.concat([
      Buffer.alloc(64, 0x20),
      Buffer.from("TLS 1.3, server CertificateVerify\0", "ascii"),
      this.th(),                           // through Certificate
    ]);
    let scheme;
    let sig;
    if (this.keyType === "rsa") {
      scheme = 0x0804;
      sig = crypto.sign("sha256", content, {
        key: this.priv,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      });
    } else {
      scheme = 0x0403;
      sig = ecdsa_der_to_raw(crypto.sign("sha256", content, this.priv), 32);
    }
    const cv_body = Buffer.concat([u16(scheme), u16(sig.length), sig]);
    const cv = Buffer.concat([Buffer.from([15]), u24(cv_body.length),
      cv_body]);
    this.transcript.push(cv);
    const fin = hmac(h, this.finKey(this.hsWrite), this.th());
    const fin_msg = Buffer.concat([Buffer.from([20]), u24(fin.length),
      fin]);
    // One sealed record per message, in flight order.
    this.out.push(this.seal(22, ee));
    this.out.push(this.seal(22, cert));
    this.out.push(this.seal(22, cv));
    this.out.push(this.seal(22, fin_msg));
    this.transcript.push(fin_msg);
    this.stage = 1;
  }

  // The client Finished covers CH..server Finished; the application
  // secrets derive from the transcript THROUGH the server Finished --
  // the same hash the verification above used.
  client_finished(m) {
    const h = this.suite.hash;
    const hl = this.suite.hlen;
    if (m.length < 4 + hl) return this.bomb(613, "short Finished");
    const thFin = this.th();
    const got = m.subarray(4, 4 + hl);
    const want = hmac(h, this.finKey(this.hsRead), thFin);
    if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
      return this.bomb(613, "bad finished");
    }
    this.transcript.push(m);
    this.apWrite = expand_label(h, this.master, "s ap traffic", thFin, hl);
    this.apRead = expand_label(h, this.master, "c ap traffic", thFin, hl);
    this.writeKeys = this.keysFor(this.apWrite);
    this.readKeys = this.keysFor(this.apRead);
    this.seqIn = 0;
    this.seqOut = 0;
    this.done = true;
    this.stage = 2;
  }

  // -- TLS 1.2 server machine -----------------------------------------------------

  client_hello12(m, suites, groups, sigalgs, protos, renego) {
    const suite = PREF12.find((s) => suites.indexOf(s) >= 0);
    if (suite === undefined) return this.bomb(613, "no common cipher");
    const picked = alpn_select(protos, this.offer);
    if (picked === null) {
      this.out.push(alert_record(2, 120));
      return this.bomb(615, "alpn mismatch");
    }
    this.alpn = picked;
    this.ver = "1.2";
    this.suite = SUITES12[suite];
    this.clientRandom = Buffer.from(m.subarray(6, 38));
    this.transcript.push(m);

    // ServerHello: ALPN echoes here (1.2 has no EncryptedExtensions);
    // renegotiation_info echoes empty iff the client asked.
    this.serverRandom = crypto.randomBytes(32);
    // The ALPN extension is omitted when nothing was selected, for the
    // same reason as the 1.3 EncryptedExtensions above.
    const alpn_ext = picked === "" ? Buffer.alloc(0)
      : ext(16, Buffer.concat([u16(picked.length + 1),
        Buffer.from([picked.length]), Buffer.from(picked, "ascii")]));
    const sh_exts = Buffer.concat([
      renego ? ext(0xff01, Buffer.from([0])) : Buffer.alloc(0),
      alpn_ext,
    ]);
    const sh_body = Buffer.concat([Buffer.from([3, 3]), this.serverRandom,
      Buffer.from([0]), u16(suite), Buffer.from([0]),
      u16(sh_exts.length), sh_exts]);
    const sh = Buffer.concat([Buffer.from([2]), u24(sh_body.length),
      sh_body]);
    this.out.push(plain_rec(22, sh));
    this.transcript.push(sh);

    const list = Buffer.concat(this.certs.map((d) =>
      Buffer.concat([u24(d.length), d])));
    const cert_body = Buffer.concat([u24(list.length), list]);
    const cert_msg = Buffer.concat([Buffer.from([11]),
      u24(cert_body.length), cert_body]);
    this.transcript.push(cert_msg);
    this.out.push(plain_rec(22, cert_msg));

    // In 1.2 there is no HRR (it is a 1.3 mechanism), so the group has to
    // already be common: pick our first group the peer also listed. A
    // peer that wants a different one gets 613, which is the honest
    // answer for a protocol without a retry.
    const want_g = OFFERED_GROUPS.find((g) => groups.indexOf(g.id) >= 0);
    if (want_g === undefined) return this.bomb(613, "no common group");
    const group = want_g.id;
    this.eph = make_share(group);
    const params = Buffer.concat([Buffer.from([3]), u16(group),
      Buffer.from([this.eph.pub.length]), this.eph.pub]);
    const content = Buffer.concat([
      this.clientRandom, this.serverRandom, params,
    ]);
    // Empty sigalgs extension = client accepts the defaults.
    const hasPss = sigalgs.length === 0 || sigalgs.indexOf(0x0804) >= 0;
    const hasPkcs1 = sigalgs.length === 0 || sigalgs.indexOf(0x0401) >= 0;
    const hasEcdsa = sigalgs.length === 0 || sigalgs.indexOf(0x0403) >= 0;
    let ha;
    let sa;
    let sig;
    if (this.keyType === "rsa") {
      if (hasPss) {
        ha = 8; sa = 4;
        sig = crypto.sign("sha256", content, {
          key: this.priv,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 32,
        });
      } else if (hasPkcs1) {
        ha = 4; sa = 1;
        sig = crypto.sign("sha256", content, {
          key: this.priv,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        });
      } else {
        return this.bomb(613, "no rsa sigalg");
      }
    } else {
      if (!hasEcdsa) return this.bomb(613, "no ecdsa sigalg");
      ha = 4; sa = 3;
      sig = ecdsa_der_to_raw(crypto.sign("sha256", content, this.priv), 32);
    }
    const ske_body = Buffer.concat([params,
      Buffer.from([ha, sa]), u16(sig.length), sig]);
    const ske = Buffer.concat([Buffer.from([12]),
      u24(ske_body.length), ske_body]);
    this.transcript.push(ske);
    this.out.push(plain_rec(22, ske));
    const shd = Buffer.from([14, 0, 0, 0]);
    this.transcript.push(shd);
    this.out.push(plain_rec(22, shd));
    this.stage = 1;
  }

  msg12s(m) {
    if (m.length < 5) return this.bomb(613, "short ClientKeyExchange");
    const pl = m[4];
    if (m.length < 5 + pl) {
      return this.bomb(613, "short ClientKeyExchange");
    }
    this.transcript.push(m);
    let shared;
    try {
      shared = crypto.diffieHellman({
        privateKey: this.eph.priv,
        publicKey: peer_pub(this.eph.group, m.subarray(5, 5 + pl)),
      });
    } catch (e) {
      return this.bomb(613, "ecdhe failed");
    }
    const h = this.suite.hash;
    this.master = prf(h, shared, "master secret",
      Buffer.concat([this.clientRandom, this.serverRandom]), 48);
    this.kb = this.keyblock12(this.master);
    this.stage = 2; // the client's ChangeCipherSpec may now arrive
  }

  client_fin12(m) {
    const h = this.suite.hash;
    // The client's Finished covers CH..CKE (not itself): the transcript
    // here holds exactly that. Ours, below, covers through theirs.
    const th = crypto.createHash(h)
      .update(Buffer.concat(this.transcript)).digest();
    if (m.length < 16 || !crypto.timingSafeEqual(m.subarray(4, 16),
        prf(h, this.master, "client finished", th, 12))) {
      return this.bomb(613, "bad finished");
    }
    this.transcript.push(m);
    const th2 = crypto.createHash(h)
      .update(Buffer.concat(this.transcript)).digest();
    const fin = prf(h, this.master, "server finished", th2, 12);
    this.writeKeys = this.kb.server;
    this.seqOut = 0;
    this.out.push(plain_rec(20, Buffer.from([1])));
    const fin_msg = Buffer.concat([Buffer.from([20]), u24(12), fin]);
    this.transcript.push(fin_msg);
    this.out.push(this.seal12(22, fin_msg));
    this.done = true;
  }
}

// picked_len: u16 helper used once above (kept local to avoid a forward
// reference at module load).
function picked_len(s) { return s.length + 1; }

// -- Nagle ---------------------------------------------------------------------

// Nagle holds the second of two small writes until the peer's delayed
// ACK (~40ms per connection, measured on the WSS lane), so every fresh
// TLS fd turns it off. Best effort: a failed setsockopt costs latency,
// never correctness, so the result is deliberately not propagated.
function tls_no_delay(sys, fd) {
  const one = Uint8Array.of(1, 0, 0, 0);
  const _rc = sys.setsockopt(fd, 6, 1, sys.ptr(one), 4);
}

// -- factories (the only surface the five effects touch) -------------------------

function make_client(host, verify, alpn) {
  return new PortableClient(host, verify, alpn_names(alpn));
}
function make_server(cert, key, offer) {
  return new PortableServer(cert, key, offer);
}

module.exports = {
  no_delay: tls_no_delay,
  make_client: make_client,
  make_server: make_server,
  verify_chain: verify_chain,
  // Exposed for the gate, which has to assert that the filtered offer
  // actually reflects this host: "the peer asked for chacha20 and the
  // handshake still completed" is only a real check if the suite list
  // is visible from outside.
  cipher_available: cipher_supported,
  offered_suites: () => OFFERED.slice(),
  offered_suites12: () => OFFERED12.slice(),
  group_available: group_supported,
  offered_groups: () => OFFERED_GROUPS.map((g) => g.id),
  group_name: (id) => (group_of(id) || { name: "?" }).name,
};