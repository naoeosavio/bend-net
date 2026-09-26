// Node port of examples/https_real.bend: the same live-site smoke
// against the same four targets, over TLS+HTTP/2 with node:http2.
// Manual smoke only (like the .bend twin) — never runs in check.sh:
// it needs a working resolver and the public internet.
//
// Why the twin exists: the Bend side is fail-closed by design
// (README "HTTP/2"), so a live host answers FAIL 400/413/502 when its
// HPACK block is huffman-coded, split over CONTINUATION or bigger than
// 16384. Node has the full codec, so the very same requests here must
// answer DONE — a FAIL below is a host/transport problem, not a
// protocol gap on our side. Bend:  bend examples/https_real.bend
// Node:   node examples/https_real.js
//
// Compared to the .bend output, this port:
//   - prints the :status too (live hosts answer non-2xx to POST /post,
//     which the Bend "Done" hides);
//   - prints the Node failure code instead of a Bend Fail number —
//     ENOTFOUND/EAI_AGAIN is the DNS lane (Bend 601-605), the
//     SELF_SIGNED_CERT_IN_CHAIN family is the verify lane (Bend 614),
//     a numeric code is an HTTP/2 error code (RST_STREAM/GOAWAY);
//   - never decodes content-encoding: node:http2 has no gunzip, the
//     Bend lib does not decode either, so a gzip peer looks the same
//     mojibake on both sides.
//
// Observed (2026-09-26, node 22, DONE 3/4):
//   example.com      OK 200 / POST /post OK 405 (no such route, but a
//                    whole response — the Bend "Done" hides the code)
//   www.cloudflare.com OK 200 (huffman + dynamic table, the subset the
//                    Bend lib fails closed on: 400/413/502 there)
//   info.cern.ch     FAIL ERR_SSL_BAD_EXTENSION (tls_parse_stoc_alpn:
//                    the host answers a bad ALPN extension, so the h2
//                    lane never opens — curl degrades to HTTP/1.1 and
//                    gets 200; Bend answers 413 frame too large)

import { connect } from "node:http2";

const HTTPS_PORT = 443;
const REQUEST_TIMEOUT_MS = 20000;
const BODY_TAKE_CHARS = 240;
const BODY_CAP_BYTES = 65536;
const NO_CODE = "-";
const POST_BODY = "bend";

// Same order and labels as the .bend twin, so the two runs diff by eye.
const TARGETS = [
  {
    label: "GET example.com (fetch)",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: {},
    body: null,
  },
  {
    label: "POST example.com/post (send_request)",
    host: "example.com",
    method: "POST",
    path: "/post",
    headers: { "content-type": "text/plain" },
    body: POST_BODY,
  },
  {
    label: "GET cloudflare.com (fetch)",
    host: "www.cloudflare.com",
    method: "GET",
    path: "/",
    headers: {},
    body: null,
  },
  {
    label: "GET info.cern.ch (fetch)",
    host: "info.cern.ch",
    method: "GET",
    path: "/",
    headers: {},
    body: null,
  },
];

// Failure code as the Bend Fail column shows it: the numeric HTTP/2
// error code when Node gives one, the errno string otherwise.
function code_of(error) {
  if (typeof error.code === "number") {
    return String(error.code);
  } else {
    return String(error.code ?? NO_CODE);
  }
}

// First BODY_TAKE_CHARS of the collected body; the cap keeps a heavy
// page from piling up in memory (only the head is ever printed).
function take_body(chunks) {
  return Buffer.concat(chunks).toString().slice(0, BODY_TAKE_CHARS);
}

// One target, one fresh connection — the Node twin of the single-shot
// HTTPS.fetch/send_request. Never hangs: a guard answers on timeout.
function run_target(target) {
  return new Promise((resolve) => {
    const client = connect(`https://${target.host}:${HTTPS_PORT}/`);
    const chunks = [];
    let is_settled = false;
    let guard = null;

    // Resolves once and tears the session down; the late events of a
    // finished session (error/close) are dropped, not double-answered.
    const finish = (outcome) => {
      if (is_settled) {
        return;
      } else {
        is_settled = true;
        if (guard !== null) {
          clearTimeout(guard);
        }
        try {
          // GOAWAY first, then destroy: a session that never reached
          // "connect" (DNS/ALPN dead) would keep its socket open and
          // hang the process after DONE.
          client.close();
          client.destroy();
        } catch {
          // socket already gone — nothing to do here
        }
        resolve(outcome);
      }
    };

    guard = setTimeout(() => {
      finish({ is_ok: false, detail: `${NO_CODE} timeout` });
    }, REQUEST_TIMEOUT_MS);

    client.on("error", (error) => {
      finish({ is_ok: false, detail: `${code_of(error)} ${error.message}` });
    });

    client.on("connect", () => {
      const stream = client.request({
        ":method": target.method,
        ":path": target.path,
        ...target.headers,
      });
      let status = 0;
      let taken = 0;

      stream.on("response", (headers) => {
        status = Number(headers[":status"]);
      });

      stream.on("data", (chunk) => {
        if (taken < BODY_CAP_BYTES) {
          chunks.push(chunk);
          taken += chunk.length;
        }
      });

      stream.on("error", (error) => {
        finish({ is_ok: false, detail: `${code_of(error)} ${error.message}` });
      });

      stream.on("end", () => {
        const head = take_body(chunks);
        finish({ is_ok: true, detail: `status=${status} ${head}` });
      });

      // Fail-closed on a reset stream: a close without a whole body
      // is a peer failure, and it must not wait for the guard.
      stream.on("close", () => {
        finish({ is_ok: false, detail: `${NO_CODE} stream closed` });
      });

      if (target.body === null) {
        stream.end();
      } else {
        stream.end(target.body);
      }
    });
  });
}

// Prints one line per target in the .bend shape, then the DONE tally.
function emit(label, outcome) {
  if (outcome.is_ok) {
    console.log(`${label} OK ${outcome.detail}`);
  } else {
    console.log(`${label} FAIL ${outcome.detail}`);
  }
}

// Walks the target list in order, one connection at a time, and exits
// non-zero when any target never answered with a whole response.
async function main() {
  let score = 0;
  for (const target of TARGETS) {
    const outcome = await run_target(target);
    emit(target.label, outcome);
    if (outcome.is_ok) {
      score += 1;
    }
  }
  console.log(`DONE ${score}/${TARGETS.length}`);
  if (score !== TARGETS.length) {
    process.exitCode = 1;
  }
}

main();
