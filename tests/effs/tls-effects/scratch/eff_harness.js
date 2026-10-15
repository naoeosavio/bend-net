// scratch/eff_harness.js — shared loader and value helpers.
//
// The Bend compiler wraps each effect twin in its own closure and hands it
// the three result constructors, so a twin has no exports and cannot be
// require()d. Loading it through `new Function` reproduces exactly the
// scope the lane runs -- no host-specific syntax, the same bytes on every
// host.

const fs = require("fs");
const path = require("path");

// The effects directory a probe loads a twin from.
//
// BEND_EFFS_DIR overrides it, resolved against the cwd (the repo root for
// both this package's gate and check.sh) so a relative path works. The
// `tls-generic` gate uses it to run its whole ladder against the copy
// installed in lib/effs/ -- the files that actually ship -- instead of
// the staged twin in this package, which is otherwise all any gate would
// ever see. See tests/effs/tls-generic.sh.
const effs_dir = process.env.BEND_EFFS_DIR
  ? path.resolve(process.env.BEND_EFFS_DIR)
  : path.join(__dirname, "..", "effs");

// The constructors the runtime injects around an effect. Defined here in
// the same shape the runtime uses, so a probe reads the twin's values
// instead of re-encoding them.
function io_tup(...xs) {
  return xs.reduceRight((snd, fst) => ({ $: "Tuple", fst, snd }));
}

function io_done(value) {
  return { $: "Done", value };
}

function io_fail(code) {
  return { $: "Fail", error: io_tup(code, "error") };
}

// Reads `file` out of the package's effs/ directory and returns the host
// function named `fn_name` from it. $1 is the twin, $2 the function.
function load_effect(file, fn_name) {
  const src = fs.readFileSync(path.join(effs_dir, file), "utf8");
  const build = new Function("require", "io_tup", "io_done", "io_fail",
    src + "\nreturn " + fn_name + ";");
  return build(require, io_tup, io_done, io_fail);
}

// The Result an effect returned. tls_connect_raw answers the Result
// itself; the byte effects hand the socket back beside it, as
// io_tup(sock, Result), because their type is `Socket & Result<...>`.
// The probes read both shapes through this one place.
function result_of(res) {
  return res && res.$ === "Tuple" ? res.snd : res;
}

// Bytes as the Bend List<U32> that tls_send_bytes takes.
function bytes_to_list(bytes) {
  let xs = { $: "Nil" };
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    xs = { $: "Con", head: bytes[i], tail: xs };
  }
  return xs;
}

// The Bend List<U32> a def returned, back as a Uint8Array.
function list_to_bytes(xs) {
  const out = [];
  for (; xs && xs.$ === "Con"; xs = xs.tail) out.push(xs.head);
  return Uint8Array.from(out);
}

// The TLS version of a live socket as "1.3" / "1.2", the spelling the
// gate asserts and openssl prints. Empty string when the host socket
// refuses to say (a handshake that never completed).
function version_tag(socket) {
  let name = "";
  try {
    name = String(socket && typeof socket.getProtocol === "function"
      ? socket.getProtocol() : "");
  } catch (_) {
    return "";
  }
  return name.replace(/^TLSv/, "");
}

// The negotiated cipher of a live socket, "-" when the host has no name
// for it. The gate prints it; it does not assert on it, because the
// cipher is the peer's choice.
function cipher_tag(socket) {
  try {
    const cipher = socket && typeof socket.getCipher === "function"
      ? socket.getCipher() : null;
    const name = cipher && (cipher.standardName || cipher.name);
    return name ? String(name) : "-";
  } catch (_) {
    return "-";
  }
}

// True when `text` holds a complete HTTP head. Both line endings are
// accepted on purpose: a probe that waits for CRLF alone hangs on a peer
// that sends bare LF, which looks like a broken server instead of a
// sloppy test.
function has_head_end(text) {
  return /\r?\n\r?\n/.test(text);
}

// The host name a probe is running on: "bun" or "node". The effects put
// the same tag on every connection they hand back.
function host_tag() {
  return process.versions && process.versions.bun ? "bun" : "node";
}

module.exports = {
  io_tup,
  io_done,
  io_fail,
  load_effect,
  result_of,
  bytes_to_list,
  list_to_bytes,
  version_tag,
  cipher_tag,
  has_head_end,
  host_tag,
};