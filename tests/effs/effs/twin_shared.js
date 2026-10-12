// Twin
// ====

// Shared module state: the two defs in twin_shared.bend both import this
// file, and the compiler emits it once per program, so the counter runs
// across them. A copy per def would restart it (2, 10, 2) instead of
// running on (2, 20, 4) -- which is what tests/effs/twin_shared.bend
// pins with its golden.
let twin_calls = 0;

function twin_one(x) {
  twin_calls += 1;
  return x + twin_calls;
}

function twin_two(x) {
  twin_calls += 1;
  return x * twin_calls;
}
