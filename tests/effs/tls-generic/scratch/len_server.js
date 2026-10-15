// scratch/len_server.js — <n> <port>
//
// A Node `tls` server that answers every request with exactly N bytes,
// TLS 1.2 CBC only. It exists to pin the CBC record layer at payload
// lengths where the content is ALREADY block-aligned -- those are the
// ones that get padding_length == 0 (RFC 5246 s6.2.3.2), which is a
// legal encoding and the one a naive implementation refuses.
//
// Run under node specifically: bun's tls server rejects
// ECDHE-RSA-AES128-SHA256 ("No cipher match"), and this file is the
// peer, not the code under test.
const tls = require("tls");
const fs = require("fs");

const n = Number(process.argv[2]);
const port = Number(process.argv[3]);

const srv = tls.createServer({
  cert: fs.readFileSync(process.env.P0_CERT),
  key: fs.readFileSync(process.env.P0_KEY),
  ciphers: "ECDHE-RSA-AES128-SHA256",
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.2",
  ALPNProtocols: ["h2"],
}, (s) => {
  s.on("error", () => {});
  s.on("data", () => {
    s.write(Buffer.alloc(n, 0x42));
  });
});

srv.listen(port, "127.0.0.1", () => console.log("up"));