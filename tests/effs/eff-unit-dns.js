// Hermetic unit vectors for the DNS twin's code table.
//
// lib/effs/dns_resolve.js answers five stable codes (601-605), but the
// only Bend golden (tests/io/dns_resolve.bend) is hermetic by design:
// every case dies in the pure layer with 601, so 602-605 had no test
// at all (task-050 A3). This probe loads the twin the way the compiler
// does (top-level functions, no exports) with stubbed doors and pins
// the query builder, the reply parser, the message table and the
// nameserver pick -- including the IPv6 skip and the 127.0.0.53
// fallback (task-050 A4). No sockets, no network, no resolv.conf read.
//
// Run: node tests/effs/eff-unit-dns.js (also via tests/effs/eff-unit.sh).
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const twin_path = path.join(__dirname, "..", "..", "lib", "effs",
  "dns_resolve.js");
const twin_src = fs.readFileSync(twin_path, "utf8");

// Stubbed doors: io_addr answers quads only (like the runtime, which
// only converts 4-part dotted quads), so an IPv6 nameserver reads as
// unusable and is skipped. resolv_text stands in for /etc/resolv.conf.
let resolv_text = "";
const io_addr = (host, port) => {
  const parts = String(host).split(".");
  if (parts.length !== 4) {
    return null;
  }
  for (const p of parts) {
    if (!/^[0-9]{1,3}$/.test(p) || Number(p) > 255) {
      return null;
    }
  }
  return { host: String(host), port: Number(port) };
};
const stub_require = (name) => {
  if (name === "fs") {
    return {
      readFileSync: (p, _enc) => {
        if (p === "/etc/resolv.conf") {
          return resolv_text;
        }
        throw new Error("unexpected file " + p);
      },
    };
  }
  throw new Error("unexpected require " + name);
};

const box = { require: stub_require, io_addr };
vm.createContext(box);
vm.runInContext(twin_src
  + "\nglobalThis.__dns = { dns_query, dns_parse, dns_msg, dns_ns };",
  box);
const twin = box.__dns;

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

// A minimal reply: 12-byte header + one question + crafted answers.
// The parser skips the question by length, so its content is fixed.
const qname = [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0];
const qtail = [0, 1, 0, 1];
const answer = (type, rdata) => [
  0xC0, 0x0C, (type >> 8) & 255, type & 255, 0, 1,
  0, 0, 0, 60, (rdata.length >> 8) & 255, rdata.length & 255,
  ...rdata,
];
const reply = (id, rcode, answers) => {
  const body = [...qname, ...qtail];
  for (const a of answers) {
    body.push(...a);
  }
  const head = [(id >> 8) & 255, id & 255, 0x81, 0x80 | rcode,
    0, 1, 0, answers.length, 0, 0, 0, 0];
  return Buffer.from([...head, ...body]);
};

// Query builder: one A question, and null for what the pure layer
// would already have refused (A3: 601 lives here too).
const q_ok = twin.dns_query(0x1234, "example.com");
check("query builds one A question",
  q_ok !== null && q_ok[5] === 1 && q_ok[q_ok.length - 4] === 0
  && q_ok[q_ok.length - 3] === 1 && q_ok[q_ok.length - 1] === 1);
check("query refuses the empty label", twin.dns_query(1, "") === null);
check("query refuses a label past 63",
  twin.dns_query(1, "x." + "y".repeat(64)) === null);

// Reply parser: the 602-605 table no golden reaches (A3).
const id = 0x1234;
const a_record = answer(1, [1, 2, 3, 4]);
const aaaa_record = answer(28, new Array(16).fill(1));
const a_reply = reply(id, 0, [a_record]);
check("parse answers the first A record",
  twin.dns_parse(id, a_reply, a_reply.length) === "1.2.3.4");
check("parse maps NXDOMAIN to 602",
  twin.dns_parse(id, reply(id, 3, []), reply(id, 3, []).length) === 602);
check("parse maps SERVFAIL to 603",
  twin.dns_parse(id, reply(id, 2, []), reply(id, 2, []).length) === 603);
check("parse maps other rcodes to 605",
  twin.dns_parse(id, reply(id, 1, []), reply(id, 1, []).length) === 605);
check("parse maps an answer with no A record to 604",
  twin.dns_parse(id, reply(id, 0, []), reply(id, 0, []).length) === 604);
check("parse maps a non-A answer to 604",
  twin.dns_parse(id, reply(id, 0, [aaaa_record]),
    reply(id, 0, [aaaa_record]).length) === 604);
const foreign = reply(id + 1, 0, [a_record]);
check("parse ignores a reply for another id",
  twin.dns_parse(id, foreign, foreign.length) === 0);
check("parse ignores a truncated reply", twin.dns_parse(id,
  Buffer.from([1, 2, 3]), 3) === 0);

// Message table: the same texts the C twin's dns_msg answers.
check("messages match the C twin",
  twin.dns_msg(601) === "bad host"
  && twin.dns_msg(602) === "host not found"
  && twin.dns_msg(603) === "resolve failed, try again"
  && twin.dns_msg(604) === "no ipv4 address"
  && twin.dns_msg(605) === "resolve error"
  && twin.dns_msg(999) === "resolve error");
const c_src = fs.readFileSync(path.join(__dirname, "..", "..", "lib",
  "effs", "dns_resolve.c"), "utf8");
// The C twin spells 605 as `default:` (any other gai error) and spells
// the texts in dns_msg -- the shape differs, the table must not.
const c_has = (s) => c_src.includes(s);
check("C twin maps the same five codes",
  c_has("case 601:") && c_has("case 602:") && c_has("case 603:")
  && c_has("case 604:") && c_has("EAI_NONAME") && c_has("return 602")
  && c_has("EAI_AGAIN") && c_has("return 603") && c_has("return 604")
  && c_has("return 605") && c_has('"bad host"')
  && c_has('"host not found"') && c_has('"resolve failed, try again"')
  && c_has('"no ipv4 address"') && c_has('"resolve error"'));

// Nameserver pick: IPv6 lines are skipped, never used (A4).
resolv_text = "nameserver 2001:db8::1\nnameserver 9.9.9.9\n";
check("IPv6 nameserver is skipped for the first IPv4 one",
  twin.dns_ns().host === "9.9.9.9");
resolv_text = "nameserver 2001:db8::1\n";
check("IPv6-only file falls back to 127.0.0.53",
  twin.dns_ns().host === "127.0.0.53");
resolv_text = "";
check("empty file falls back to 127.0.0.53",
  twin.dns_ns().host === "127.0.0.53");

console.log("=== " + pass + " passed, " + fail + " failed ===");
process.exit(fail === 0 ? 0 : 1);
