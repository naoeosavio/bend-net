# SHA-1 pure in Bend (FIPS 180-4, no IO).
#
# Import as: import ./sha1.bend as SHA1
# Then SHA1.sha1(bytes) -> 20 bytes as List<U32>.
# Input is a byte list (each 0..255); output is 20 bytes.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
# - helpers above drivers are leaves: they never call back down.
# - state threads as Lists (no 4+ tuples), single-def recursion only.
import Base

# Rotates (or of both shifts).

def rotl1(+x: U32) -> U32:
  U32.or(U32.shln(x, 1n), U32.shrn(x, 31n))

def rotl5(+x: U32) -> U32:
  U32.or(U32.shln(x, 5n), U32.shrn(x, 27n))

def rotl30(+x: U32) -> U32:
  U32.or(U32.shln(x, 30n), U32.shrn(x, 2n))

# Choice and majority.

def ch(+x: U32, +y: U32, +z: U32) -> U32:
  U32.or(U32.and(x, y), U32.and(U32.not(x), z))

def maj(+x: U32, +y: U32, +z: U32) -> U32:
  U32.or(U32.or(U32.and(x, y), U32.and(x, z)), U32.and(y, z))

def par(+x: U32, +y: U32, +z: U32) -> U32:
  U32.xor(U32.xor(x, y), z)

# Maybe unwrap for List.get (None -> 0).

def get_or0(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{v}:
      v

def list_get(+xs: List<&2, U32>, n: Nat) -> U32:
  get_or0(List.get(&2, U32, xs, n))

# Four bytes big-endian to one word.

def word_of4(+b0: U32, +b1: U32, +b2: U32, +b3: U32) -> U32:
  (((b0 * 16777216 + b1 * 65536 : U32) + b2 * 256 : U32) + b3 : U32)

# One word to four bytes big-endian.

def bytes_of_word(+w: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(w, 24n), 255), U32.and(U32.shrn(w, 16n), 255), U32.and(U32.shrn(w, 8n), 255), U32.and(w, 255)]

# Round constant by index 0..79.

def k_of.go(is20: Bool, is40: Bool, is60: Bool) -> U32:
  match is20 is40 is60:
    case True{} True{} True{}:
      1518500249
    case True{} True{} False{}:
      1518500249
    case True{} False{} True{}:
      1518500249
    case True{} False{} False{}:
      1518500249
    case False{} True{} True{}:
      1859775393
    case False{} True{} False{}:
      1859775393
    case False{} False{} True{}:
      2400959708
    case False{} False{} False{}:
      3395469782

def k_of(+idx: Nat) -> U32:
  k_of.go(Nat.is_lt(idx, 20n), Nat.is_lt(idx, 40n), Nat.is_lt(idx, 60n))

# Round function by index (uses b, c, d).

def f_of.go(is20: Bool, is40: Bool, is60: Bool, +b: U32, +c: U32, +d: U32) -> U32:
  match is20 is40 is60:
    case True{} True{} True{}:
      ch(b, c, d)
    case True{} True{} False{}:
      ch(b, c, d)
    case True{} False{} True{}:
      ch(b, c, d)
    case True{} False{} False{}:
      ch(b, c, d)
    case False{} True{} True{}:
      par(b, c, d)
    case False{} True{} False{}:
      par(b, c, d)
    case False{} False{} True{}:
      maj(b, c, d)
    case False{} False{} False{}:
      par(b, c, d)

def f_of(+idx: Nat, +b: U32, +c: U32, +d: U32) -> U32:
  f_of.go(Nat.is_lt(idx, 20n), Nat.is_lt(idx, 40n), Nat.is_lt(idx, 60n), b, c, d)

# Temp = rotl5(a) + f + e + k + w (mod 2^32 via U32.add).

def temp_of(+a: U32, +f: U32, +e: U32, +k: U32, +w: U32) -> U32:
  +t = rotl5(a)
  ((((t + f : U32) + e : U32) + k : U32) + w : U32)

# Sixteen words from sixty-four bytes (single def, nested patterns).

def words_of_bytes(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case b0 <> r1:
      match r1:
        case Nil{}:
          Nil{}
        case b1 <> r2:
          match r2:
            case Nil{}:
              Nil{}
            case b2 <> r3:
              match r3:
                case Nil{}:
                  Nil{}
                case b3 <> rest:
                  word_of4(b0, b1, b2, b3) <> words_of_bytes(rest)

# Schedule word i from four earlier words.

def sched_word(+a: U32, +b: U32, +c: U32, +d: U32) -> U32:
  rotl1(U32.xor(U32.xor(a, b), U32.xor(c, d)))

# Expand sixteen to eighty (fuel structural first, idx tracks position).

def expand_go(fuel: Nat, +idx: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      +i3 = Nat.sub(idx, 3n)
      +i8 = Nat.sub(idx, 8n)
      +i14 = Nat.sub(idx, 14n)
      +i16 = Nat.sub(idx, 16n)
      +nw = sched_word(list_get(acc, i3), list_get(acc, i8), list_get(acc, i14), list_get(acc, i16))
      +nacc = List.append(&2, U32, acc, [nw])
      expand_go(f, 1n+idx, nacc)

def expand(w16: List<&2, U32>) -> List<&2, U32>:
  expand_go(64n, 16n, w16)

# Add working vars back into hash (five element lists).

def add5.go(+h: List<&2, U32>, +s: List<&2, U32>) -> List<&2, U32>:
  [U32.add(list_get(h, 0n), list_get(s, 0n)), U32.add(list_get(h, 1n), list_get(s, 1n)), U32.add(list_get(h, 2n), list_get(s, 2n)), U32.add(list_get(h, 3n), list_get(s, 3n)), U32.add(list_get(h, 4n), list_get(s, 4n))]

def add5(+h: List<&2, U32>, +s: List<&2, U32>) -> List<&2, U32>:
  add5.go(h, s)

# One round step as a new five list (leaf for rounds).

def step_list(+st: List<&2, U32>, +w: U32, +idx: Nat) -> List<&2, U32>:
  +a = list_get(st, 0n)
  +b = list_get(st, 1n)
  +c = list_get(st, 2n)
  +d = list_get(st, 3n)
  +e = list_get(st, 4n)
  +f = f_of(idx, b, c, d)
  +k = k_of(idx)
  +t = temp_of(a, f, e, k, w)
  [t, a, rotl30(b), c, d]

# Eighty rounds over the schedule (structural on the word list).

def rounds(ws: List<&2, U32>, +st: List<&2, U32>, +idx: Nat) -> List<&2, U32>:
  match ws:
    case Nil{}:
      st
    case w <> rest:
      rounds(rest, step_list(st, w, idx), 1n+idx)

# Initial hash words.

def h_init() -> List<&2, U32>:
  [1732584193, 4023233417, 2562383102, 271733878, 3285377520]

# One sixty-four byte block updates the hash.

def block_go(+h: List<&2, U32>, +blk: List<&2, U32>) -> List<&2, U32>:
  +w80 = expand(words_of_bytes(blk))
  add5(h, rounds(w80, h, 0n))

# Take and drop sixty-four (wrappers so the driver stays linear).

def take64(+bs: List<&2, U32>) -> List<&2, U32>:
  List.take(&2, U32, bs, 64n)

def drop64(+bs: List<&2, U32>) -> List<&2, U32>:
  List.drop(&2, U32, bs, 64n)

def is_nil(bs: List<&2, U32>) -> Bool:
  match bs:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

# All blocks (fuel is the block count, structural).

def blocks_go(fuel: Nat, +h: List<&2, U32>, +bs: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      h
    case 1n+f:
      +nh = block_go(h, take64(bs))
      +rest = drop64(bs)
      blocks_go(f, nh, rest)

# Padding: message ++ 0x80 ++ k zeros ++ eight byte bit length.
# Bit length fits thirty-two bits here (WS keys are short).

def pad_lenbytes(+bitlen: U32) -> List<&2, U32>:
  [0, 0, 0, 0, U32.and(U32.shrn(bitlen, 24n), 255), U32.and(U32.shrn(bitlen, 16n), 255), U32.and(U32.shrn(bitlen, 8n), 255), U32.and(bitlen, 255)]

def pad_zeros(k: Nat) -> List<&2, U32>:
  List.replicate(U32, k, 0)

def pad_count(+len: Nat) -> Nat:
  Nat.mod(Nat.sub(120n, Nat.mod(1n+len, 64n)), 64n)

def padded(+bs: List<&2, U32>) -> List<&2, U32>:
  +len = List.length(&2, U32, bs)
  +blen = U32.mul(U32.from_nat(len), 8)
  List.append(&2, U32, List.append(&2, U32, List.append(&2, U32, bs, [128]), pad_zeros(pad_count(len))), pad_lenbytes(blen))

# Words to bytes (five words to twenty bytes).

def words_to_bytes(ws: List<&2, U32>) -> List<&2, U32>:
  match ws:
    case Nil{}:
      Nil{}
    case w <> rest:
      List.append(&2, U32, bytes_of_word(w), words_to_bytes(rest))

# Top driver: pad, count blocks, run, flatten.

def block_count(+bs: List<&2, U32>) -> Nat:
  Nat.div(List.length(&2, U32, bs), 64n)

def sha1.go(+padded: List<&2, U32>) -> List<&2, U32>:
  words_to_bytes(blocks_go(block_count(padded), h_init(), padded))

def sha1(+bs: List<&2, U32>) -> List<&2, U32>:
  sha1.go(padded(bs))
