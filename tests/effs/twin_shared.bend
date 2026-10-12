# effs (twin_shared): one .js serves two defs, and the module state it
# holds is shared between them. The runtime's own effs group related defs
# in one file (file_read.js serves four, chan.js serves four) because
# that is the only reuse the JS lane has: each effect file becomes its own
# closure in the emitted bundle, so a helper defined in one file is
# invisible to the next -- and a relative require does not resolve at all.
# Both defs below hit the same counter in tests/effs/effs/twin_shared.js,
# so the sum proves the file was emitted once: with a copy per def the
# counter would restart (2 + 10 + 2 = 14) instead of running on
# (2 + 20 + 4). Golden 26.
import Base

# Adds one call to the shared counter and adds it to x.
def Twin.one(x: U32) -> IO(U32):
  import "./effs/twin_shared.js"

# Adds one call to the shared counter and multiplies by it.
def Twin.two(x: U32) -> IO(U32):
  import "./effs/twin_shared.js"

def main() -> IO(Unit):
  do IO<Unit>:
    a : U32 <- Twin.one(1)
    b : U32 <- Twin.two(10)
    c : U32 <- Twin.one(1)
    IO.print(U32.show((a + b + c : U32)))

#|26
