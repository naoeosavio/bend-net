# Base64 over byte lists (no IO, no TLS).
#
# Import as: import ./b64.bend as B64
# Then B64.encode, B64.decode.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
# - helpers above drivers are leaves: they never call back down.
import Base

# Sextet to ASCII code (0..63 -> A-Za-z0-9+/).
# One lazy table: each arm holds no recursion, so it runs linear.

def enc_char(s: U32) -> U32:
  match s:
    case 0:
      65
    case 1:
      66
    case 2:
      67
    case 3:
      68
    case 4:
      69
    case 5:
      70
    case 6:
      71
    case 7:
      72
    case 8:
      73
    case 9:
      74
    case 10:
      75
    case 11:
      76
    case 12:
      77
    case 13:
      78
    case 14:
      79
    case 15:
      80
    case 16:
      81
    case 17:
      82
    case 18:
      83
    case 19:
      84
    case 20:
      85
    case 21:
      86
    case 22:
      87
    case 23:
      88
    case 24:
      89
    case 25:
      90
    case 26:
      97
    case 27:
      98
    case 28:
      99
    case 29:
      100
    case 30:
      101
    case 31:
      102
    case 32:
      103
    case 33:
      104
    case 34:
      105
    case 35:
      106
    case 36:
      107
    case 37:
      108
    case 38:
      109
    case 39:
      110
    case 40:
      111
    case 41:
      112
    case 42:
      113
    case 43:
      114
    case 44:
      115
    case 45:
      116
    case 46:
      117
    case 47:
      118
    case 48:
      119
    case 49:
      120
    case 50:
      121
    case 51:
      122
    case 52:
      48
    case 53:
      49
    case 54:
      50
    case 55:
      51
    case 56:
      52
    case 57:
      53
    case 58:
      54
    case 59:
      55
    case 60:
      56
    case 61:
      57
    case 62:
      43
    case 63:
      47
    case _:
      65

# ASCII code to sextet value.
# Returns 64 for pad (=), 255 for invalid.

def dec_digit(c: U32) -> U32:
  match c:
    case 65:
      0
    case 66:
      1
    case 67:
      2
    case 68:
      3
    case 69:
      4
    case 70:
      5
    case 71:
      6
    case 72:
      7
    case 73:
      8
    case 74:
      9
    case 75:
      10
    case 76:
      11
    case 77:
      12
    case 78:
      13
    case 79:
      14
    case 80:
      15
    case 81:
      16
    case 82:
      17
    case 83:
      18
    case 84:
      19
    case 85:
      20
    case 86:
      21
    case 87:
      22
    case 88:
      23
    case 89:
      24
    case 90:
      25
    case 97:
      26
    case 98:
      27
    case 99:
      28
    case 100:
      29
    case 101:
      30
    case 102:
      31
    case 103:
      32
    case 104:
      33
    case 105:
      34
    case 106:
      35
    case 107:
      36
    case 108:
      37
    case 109:
      38
    case 110:
      39
    case 111:
      40
    case 112:
      41
    case 113:
      42
    case 114:
      43
    case 115:
      44
    case 116:
      45
    case 117:
      46
    case 118:
      47
    case 119:
      48
    case 120:
      49
    case 121:
      50
    case 122:
      51
    case 48:
      52
    case 49:
      53
    case 50:
      54
    case 51:
      55
    case 52:
      56
    case 53:
      57
    case 54:
      58
    case 55:
      59
    case 56:
      60
    case 57:
      61
    case 43:
      62
    case 47:
      63
    case 61:
      64
    case _:
      255

# True when the digit is a real sextet (not pad, not invalid).

def dec_is_data(v: U32) -> Bool:
  U32.is_lt(v, 64)

# True when the digit is invalid (255).

def dec_is_bad(v: U32) -> Bool:
  U32.is_eq(v, 255)

# Sextets of a 24-bit group.

def sext0(n: U32) -> U32:
  U32.and(U32.shrn(n, 18n), 63)

def sext1(n: U32) -> U32:
  U32.and(U32.shrn(n, 12n), 63)

def sext2(n: U32) -> U32:
  U32.and(U32.shrn(n, 6n), 63)

def sext3(n: U32) -> U32:
  U32.and(n, 63)

# One byte to its two sextets (single byte tail, padded ==).

def tail1.s1(+b0: U32) -> U32:
  U32.and(U32.shln(b0, 4n), 63)

def tail1.s0(+b0: U32) -> U32:
  U32.shrn(b0, 2n)

def tail1.emit(+b0: U32) -> String:
  String.from_list([Chr{enc_char(tail1.s0(b0))}, Chr{enc_char(tail1.s1(b0))}, Chr{61}, Chr{61}])

# Two bytes to three sextets (two byte tail, padded =).

def tail2.s0(+b0: U32) -> U32:
  U32.shrn(b0, 2n)

def tail2.s1(+b0: U32, +b1: U32) -> U32:
  U32.or(U32.and(U32.shln(b0, 4n), 63), U32.shrn(b1, 4n))

def tail2.s2(+b1: U32) -> U32:
  U32.and(U32.shln(b1, 2n), 63)

def tail2.emit(+b0: U32, +b1: U32) -> String:
  String.from_list([Chr{enc_char(tail2.s0(b0))}, Chr{enc_char(tail2.s1(b0, b1))}, Chr{enc_char(tail2.s2(b1))}, Chr{61}])

# Three bytes to one 24-bit group.

def group3(+b0: U32, +b1: U32, +b2: U32) -> U32:
  ((b0 * 65536 + b1 * 256 : U32) + b2 : U32)

# Four chars of a full group.

def emit4(+n: U32) -> String:
  String.from_list([Chr{enc_char(sext0(n))}, Chr{enc_char(sext1(n))}, Chr{enc_char(sext2(n))}, Chr{enc_char(sext3(n))}])

# Encode driver: single def, nested matches on pattern-bound vars only.
# Helpers above are leaves; only self-recursion below.

def encode(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      ""
    case b0 <> r0:
      match r0:
        case Nil{}:
          tail1.emit(b0)
        case b1 <> r1:
          match r1:
            case Nil{}:
              tail2.emit(b0, b1)
            case b2 <> rest:
              emit4(group3(b0, b1, b2)) ++ encode(rest)

# Decode: chars to codes.

def chars_of(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{h, t}:
      match h:
        case Chr{code}:
          code <> chars_of(t)

# One quad to bytes, fail-closed on bad digits and bad padding.

def quad_is_bad(v0: U32, v1: U32, v2: U32, v3: U32) -> Bool:
  Bool.or(dec_is_bad(v0), Bool.or(dec_is_bad(v1), Bool.or(dec_is_bad(v2), dec_is_bad(v3))))

def quad_pad_ok.go(is2: Bool, is3: Bool) -> Bool:
  match is2 is3:
    case True{} True{}:
      True{}
    case True{} False{}:
      False{}
    case False{} True{}:
      True{}
    case False{} False{}:
      True{}

def quad_pad_ok(v2: U32, v3: U32) -> Bool:
  quad_pad_ok.go(U32.is_eq(v2, 64), U32.is_eq(v3, 64))

def quad_n(v0: U32, v1: U32, v2: U32, v3: U32, pad2: Bool) -> U32:
  match pad2:
    case True{}:
      ((v0 * 262144 + v1 * 4096 : U32))
    case False{}:
      ((v0 * 262144 + v1 * 4096 + v2 * 64 + v3 : U32))

def quad_bytes(+n: U32, pad: U32) -> List<&2, U32>:
  match pad:
    case 2:
      [U32.shrn(n, 16n)]
    case 1:
      [U32.and(U32.shrn(n, 16n), 255), U32.and(U32.shrn(n, 8n), 255)]
    case _:
      [U32.and(U32.shrn(n, 16n), 255), U32.and(U32.shrn(n, 8n), 255), U32.and(n, 255)]

def quad_pad_count.go(is2: Bool, is3: Bool) -> U32:
  match is2 is3:
    case True{} True{}:
      2
    case False{} True{}:
      1
    case True{} False{}:
      0
    case False{} False{}:
      0

def quad_pad_count(v2: U32, v3: U32) -> U32:
  quad_pad_count.go(U32.is_eq(v2, 64), U32.is_eq(v3, 64))

def quad_done(v0: U32, v1: U32, +v2: U32, +v3: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  Done{quad_bytes(quad_n(v0, v1, v2, v3, U32.is_eq(v2, 64)), quad_pad_count(v2, v3))}

def quad_chk1(v0: U32, v1: U32, +v2: U32, +v3: U32, is1: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match is1:
    case True{}:
      quad_done(v0, v1, v2, v3)
    case False{}:
      Fail{(400, "bad base64 pad")}

def quad_chk0(v0: U32, +v1: U32, +v2: U32, +v3: U32, is0: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match is0:
    case True{}:
      quad_chk1(v0, v1, v2, v3, dec_is_data(v1))
    case False{}:
      Fail{(400, "bad base64 pad")}

def quad_chkpad(+v0: U32, +v1: U32, +v2: U32, +v3: U32, ok: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match ok:
    case True{}:
      quad_chk0(v0, v1, v2, v3, dec_is_data(v0))
    case False{}:
      Fail{(400, "bad base64 pad")}

def quad_go(+v0: U32, +v1: U32, +v2: U32, +v3: U32, bad: Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match bad:
    case True{}:
      Fail{(400, "bad base64")}
    case False{}:
      quad_chkpad(v0, v1, v2, v3, quad_pad_ok(v2, v3))

def quad(c0: U32, c1: U32, c2: U32, c3: U32) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +v0 = dec_digit(c0)
  +v1 = dec_digit(c1)
  +v2 = dec_digit(c2)
  +v3 = dec_digit(c3)
  quad_go(v0, v1, v2, v3, quad_is_bad(v0, v1, v2, v3))

def decode_quads.put(head: Result<&1, &1, U32 & String, List<&2, U32>>, tail: Result<&1, &1, U32 & String, List<&2, U32>>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match head:
    case Fail{e}:
      Fail{e}
    case Done{bs}:
      match tail:
        case Fail{e}:
          Fail{e}
        case Done{rest}:
          Done{List.append(&2, U32, bs, rest)}

# Quad list driver: single def with nested pattern matches.
# Exactly 4 codes per step, tail must be empty.

def decode_quads(cs: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  match cs:
    case Nil{}:
      Done{Nil{}}
    case c0 <> r1:
      match r1:
        case Nil{}:
          Fail{(400, "bad base64 len")}
        case c1 <> r2:
          match r2:
            case Nil{}:
              Fail{(400, "bad base64 len")}
            case c2 <> r3:
              match r3:
                case Nil{}:
                  Fail{(400, "bad base64 len")}
                case c3 <> rest:
                  decode_quads.put(quad(c0, c1, c2, c3), decode_quads(rest))

def decode(s: String) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  decode_quads(chars_of(s))
