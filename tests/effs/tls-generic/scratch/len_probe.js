// scratch/len_probe.js — <host> <port> <want-bytes>
//
// Receives until `want` bytes have arrived, then reports. A failure to
// deliver the exact count is the regression this guards: a record layer
// that mishandles padding_length == 0 loses every payload whose length
// puts the content on a block boundary.
const net = require("net");
const rt = require("./rt_path.js");

const host = process.argv[2];
const port = Number(process.argv[3]);
const want = Number(process.argv[4]);
const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 15000);

if (!host || !Number.isInteger(port) || !Number.isInteger(want)) {
  console.log("FAIL 611 usage: len_probe.js <host> <port> <want>");
  process.exit(1);
}

const pump = rt.make_client(host, false, 1);
let got = 0;
let has_sent_request = false;

const finish = (code) => {
  try { sock.destroy(); } catch (e) {}
  process.exit(code);
};

const sock = net.connect(port, host, () => {
  const first = pump.drain();
  if (first !== null) {
    sock.write(first);
  }
});

sock.on("data", (d) => {
  pump.feed(d);
  if (pump.fail !== null) {
    console.log("FAIL " + pump.fail.code + " " + pump.fail.text + " got=" + got);
    finish(1);
    return;
  }
  const out = pump.drain();
  if (out !== null) {
    sock.write(out);
  }
  if (pump.done && !has_sent_request) {
    has_sent_request = true;
    pump.seal_app(Buffer.from("go\n"));
    const req = pump.drain();
    if (req !== null) {
      sock.write(req);
    }
  }
  const app = pump.take_app(65536);
  if (app !== null) {
    got += app.length;
  }
  if (got >= want) {
    console.log("OK got=" + got + " suite=" + pump.suite.name);
    finish(0);
  }
});

sock.on("error", (e) => {
  console.log("ERR " + (e.code || e.message) + " got=" + got);
  finish(2);
});

setTimeout(() => {
  console.log("TIMEOUT got=" + got + " want=" + want
    + " fail=" + JSON.stringify(pump.fail));
  finish(3);
}, TIMEOUT_MS).unref?.();