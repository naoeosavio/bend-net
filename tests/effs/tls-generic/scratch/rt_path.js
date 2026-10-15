// scratch/rt_path.js -- which tls_rt.js the probes of this package load.
//
// The package stages a copy of the runtime; lib/effs/ holds the copy that
// ships. By default a probe loads the staged twin, which keeps the ladder
// measuring the package in front of it. BEND_EFFS_DIR points the whole
// ladder at another copy -- the gate uses it to run all ~90 rungs against
// the files installed in lib/effs/, so the ladder can prove what goes out
// the door instead of a twin of it. The gate also asserts, byte for byte,
// that the two copies are the same file, so the choice is never silent.
const path = require("path");

module.exports = require(process.env.BEND_EFFS_DIR
  ? path.resolve(process.env.BEND_EFFS_DIR, "tls_rt.js")
  : path.join(__dirname, "..", "effs", "tls_rt.js"));
