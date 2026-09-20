# HTTP lib over the existing TCP kit (no TLS, no DNS).
#
# Reuses Base (String/List/U32/Nat/TCP/Socket/IO) and the two demos:
# - io_http_fetch's blank-line cut (window word 218762506 = "\r\n\r\n")
# - io_http_server's per-connection spawn + response shape.
#
# Import as: import ../lib/http.bend as HTTP
# Then HTTP.read_url, HTTP.get_header, HTTP.fetch, ...
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
# - helpers above drivers are leaves: they never call back down.
#
# Security policy (fail-closed):
# - show_* rejects CRLF in every field (injection) with Fail 400.
# - read_* caps the head at 16KB; oversize is Fail 413.
# - ports must be 1..65535; hosts reject whitespace and controls.
# - https:// parses but fetch refuses with 501 (no TLS yet).
# - fetch reads at most 8x8192 bytes (64KB cap), then truncates.
# - TCP kit has no DNS: use IPs or localhost (see demos/io_http_fetch).
import Base

# Bytes
# -----
# A Bytes value is List<&2, U32> of UTF-8 bytes (reuses Base List/U32).

def encode.go2(+code: U32) -> List<&2, U32>:
  b1 = (192 + U32.shrn(code, 6n) : U32)
  b2 = (128 + U32.and(code, 63) : U32)
  [b1, b2]

def encode.go3(+code: U32) -> List<&2, U32>:
  b1 = (224 + U32.shrn(code, 12n) : U32)
  b2 = (128 + U32.and(U32.shrn(code, 6n), 63) : U32)
  b3 = (128 + U32.and(code, 63) : U32)
  [b1, b2, b3]

def encode.go4(+code: U32) -> List<&2, U32>:
  b1 = (240 + U32.shrn(code, 18n) : U32)
  b2 = (128 + U32.and(U32.shrn(code, 12n), 63) : U32)
  b3 = (128 + U32.and(U32.shrn(code, 6n), 63) : U32)
  b4 = (128 + U32.and(code, 63) : U32)
  [b1, b2, b3, b4]

def encode.big(code: U32, is2: Bool, is3: Bool) -> List<&2, U32>:
  match is2 is3:
    case True{} _:
      encode.go2(code)
    case False{} True{}:
      encode.go3(code)
    case False{} False{}:
      encode.go4(code)

def encode.small(code: U32, is1: Bool, is2: Bool, is3: Bool) -> List<&2, U32>:
  match is1:
    case True{}:
      [code]
    case False{}:
      encode.big(code, is2, is3)

def encode_char(+code: U32) -> List<&2, U32>:
  encode.small(code, U32.is_lt(code, 128), U32.is_lt(code, 2048), U32.is_lt(code, 65536))

def encode.one(c: Char) -> List<&2, U32>:
  match c:
    case Chr{code}:
      encode_char(code)

def encode(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{h, t}:
      List.append(&2, U32, encode.one(h), encode(t))

# Total UTF-8 decode: every match is structural (U32 literals nest
# under the byte-list cons), every arm holds at most one recursive
# call, so it runs in linear time. A bad sequence emits U+FFFD and
# resumes at the next byte, never Fail.

def decode.is_cont(+b: U32) -> Bool:
  Bool.and(U32.is_ge(b, 128), U32.is_le(b, 191))

def decode.bad(+code: U32) -> Bool:
  Bool.and(U32.is_ge(code, 55296), U32.is_le(code, 57343))

def decode.code2(+b1: U32, +b2: U32) -> U32:
  ((U32.and(b1, 31) * 64 + U32.and(b2, 63) : U32))

def decode.ok2(+b1: U32, +b2: U32) -> Bool:
  Bool.and(decode.is_cont(b2),
    Bool.and(U32.is_ge(decode.code2(b1, b2), 128), U32.is_lt(decode.code2(b1, b2), 2048)))

def decode.code3(+b1: U32, +b2: U32, +b3: U32) -> U32:
  ((U32.and(b1, 15) * 4096 + U32.and(b2, 63) * 64 + U32.and(b3, 63) : U32))

def decode.ok3(+b1: U32, +b2: U32, +b3: U32) -> Bool:
  Bool.and(decode.is_cont(b2),
    Bool.and(decode.is_cont(b3),
      Bool.and(Bool.and(U32.is_ge(decode.code3(b1, b2, b3), 2048),
        U32.is_lt(decode.code3(b1, b2, b3), 65536)),
        Bool.not(decode.bad(decode.code3(b1, b2, b3))))))

def decode.code4(+b1: U32, +b2: U32, +b3: U32, +b4: U32) -> U32:
  ((U32.and(b1, 7) * 262144 + U32.and(b2, 63) * 4096 + U32.and(b3, 63) * 64 + U32.and(b4, 63) : U32))

def decode.ok4(+b1: U32, +b2: U32, +b3: U32, +b4: U32) -> Bool:
  Bool.and(decode.is_cont(b2),
    Bool.and(decode.is_cont(b3),
      Bool.and(decode.is_cont(b4),
        Bool.and(U32.is_ge(decode.code4(b1, b2, b3, b4), 65536),
          U32.is_le(decode.code4(b1, b2, b3, b4), 1114111)))))

def decode.put(ok: Bool, code: U32, rec: String) -> String:
  match ok:
    case True{}:
      SCon{Chr{code}, rec}
    case False{}:
      SCon{Chr{65533}, rec}

def decode(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case b1 <> rest:
      match b1:
        case 194:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(194, b2), decode.code2(194, b2), decode(rest2))
        case 195:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(195, b2), decode.code2(195, b2), decode(rest2))
        case 196:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(196, b2), decode.code2(196, b2), decode(rest2))
        case 197:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(197, b2), decode.code2(197, b2), decode(rest2))
        case 198:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(198, b2), decode.code2(198, b2), decode(rest2))
        case 199:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(199, b2), decode.code2(199, b2), decode(rest2))
        case 200:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(200, b2), decode.code2(200, b2), decode(rest2))
        case 201:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(201, b2), decode.code2(201, b2), decode(rest2))
        case 202:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(202, b2), decode.code2(202, b2), decode(rest2))
        case 203:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(203, b2), decode.code2(203, b2), decode(rest2))
        case 204:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(204, b2), decode.code2(204, b2), decode(rest2))
        case 205:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(205, b2), decode.code2(205, b2), decode(rest2))
        case 206:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(206, b2), decode.code2(206, b2), decode(rest2))
        case 207:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(207, b2), decode.code2(207, b2), decode(rest2))
        case 208:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(208, b2), decode.code2(208, b2), decode(rest2))
        case 209:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(209, b2), decode.code2(209, b2), decode(rest2))
        case 210:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(210, b2), decode.code2(210, b2), decode(rest2))
        case 211:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(211, b2), decode.code2(211, b2), decode(rest2))
        case 212:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(212, b2), decode.code2(212, b2), decode(rest2))
        case 213:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(213, b2), decode.code2(213, b2), decode(rest2))
        case 214:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(214, b2), decode.code2(214, b2), decode(rest2))
        case 215:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(215, b2), decode.code2(215, b2), decode(rest2))
        case 216:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(216, b2), decode.code2(216, b2), decode(rest2))
        case 217:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(217, b2), decode.code2(217, b2), decode(rest2))
        case 218:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(218, b2), decode.code2(218, b2), decode(rest2))
        case 219:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(219, b2), decode.code2(219, b2), decode(rest2))
        case 220:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(220, b2), decode.code2(220, b2), decode(rest2))
        case 221:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(221, b2), decode.code2(221, b2), decode(rest2))
        case 222:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(222, b2), decode.code2(222, b2), decode(rest2))
        case 223:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              decode.put(decode.ok2(223, b2), decode.code2(223, b2), decode(rest2))
        case 224:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(224, b2, b3), decode.code3(224, b2, b3), decode(rest3))
        case 225:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(225, b2, b3), decode.code3(225, b2, b3), decode(rest3))
        case 226:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(226, b2, b3), decode.code3(226, b2, b3), decode(rest3))
        case 227:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(227, b2, b3), decode.code3(227, b2, b3), decode(rest3))
        case 228:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(228, b2, b3), decode.code3(228, b2, b3), decode(rest3))
        case 229:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(229, b2, b3), decode.code3(229, b2, b3), decode(rest3))
        case 230:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(230, b2, b3), decode.code3(230, b2, b3), decode(rest3))
        case 231:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(231, b2, b3), decode.code3(231, b2, b3), decode(rest3))
        case 232:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(232, b2, b3), decode.code3(232, b2, b3), decode(rest3))
        case 233:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(233, b2, b3), decode.code3(233, b2, b3), decode(rest3))
        case 234:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(234, b2, b3), decode.code3(234, b2, b3), decode(rest3))
        case 235:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(235, b2, b3), decode.code3(235, b2, b3), decode(rest3))
        case 236:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(236, b2, b3), decode.code3(236, b2, b3), decode(rest3))
        case 237:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(237, b2, b3), decode.code3(237, b2, b3), decode(rest3))
        case 238:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(238, b2, b3), decode.code3(238, b2, b3), decode(rest3))
        case 239:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  decode.put(decode.ok3(239, b2, b3), decode.code3(239, b2, b3), decode(rest3))
        case 240:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  match rest3:
                    case Nil{}:
                      SCon{Chr{65533}, SNil{}}
                    case +b4 <> rest4:
                      decode.put(decode.ok4(240, b2, b3, b4), decode.code4(240, b2, b3, b4), decode(rest4))
        case 241:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  match rest3:
                    case Nil{}:
                      SCon{Chr{65533}, SNil{}}
                    case +b4 <> rest4:
                      decode.put(decode.ok4(241, b2, b3, b4), decode.code4(241, b2, b3, b4), decode(rest4))
        case 242:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  match rest3:
                    case Nil{}:
                      SCon{Chr{65533}, SNil{}}
                    case +b4 <> rest4:
                      decode.put(decode.ok4(242, b2, b3, b4), decode.code4(242, b2, b3, b4), decode(rest4))
        case 243:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  match rest3:
                    case Nil{}:
                      SCon{Chr{65533}, SNil{}}
                    case +b4 <> rest4:
                      decode.put(decode.ok4(243, b2, b3, b4), decode.code4(243, b2, b3, b4), decode(rest4))
        case 244:
          match rest:
            case Nil{}:
              SCon{Chr{65533}, SNil{}}
            case +b2 <> rest2:
              match rest2:
                case Nil{}:
                  SCon{Chr{65533}, SNil{}}
                case +b3 <> rest3:
                  match rest3:
                    case Nil{}:
                      SCon{Chr{65533}, SNil{}}
                    case +b4 <> rest4:
                      decode.put(decode.ok4(244, b2, b3, b4), decode.code4(244, b2, b3, b4), decode(rest4))
        case _:
          SCon{Chr{b1}, decode(rest)}

def body_length.go(bs: List<&2, U32>, acc: U32) -> U32:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      body_length.go(t, (acc + 1 : U32))

def body_length(bs: List<&2, U32>) -> U32:
  body_length.go(bs, 0)

def from_string(s: String) -> U32 & List<&2, U32>:
  +bs = encode(s)
  (body_length(bs), bs)

def to_string(bs: List<&2, U32>) -> String:
  decode(bs)

# Small string helpers (reuse Base String.* everywhere else)

def has_crlf(+s: String) -> Bool:
  Bool.or(String.contains(s, "\r"), String.contains(s, "\n"))

def has_crlf3(a: String, b: String, c: String) -> Bool:
  Bool.or(has_crlf(a), Bool.or(has_crlf(b), has_crlf(c)))

def nul1() -> String:
  String.from_list([Chr{0}])

def has_nul(s: String) -> Bool:
  String.contains(s, nul1())

def strip_cr.go(h: Char, t: String, is_cr: Bool) -> String:
  match is_cr:
    case True{}:
      t
    case False{}:
      SCon{h, t}

def strip_cr(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      strip_cr.go(h, t, Char.is_eq(h, Chr{13}))

def eq_ci(a: String, b: String) -> Bool:
  String.eq(String.to_lower(a), String.to_lower(b))

# Blank-line cut, reused from demos/io_http_fetch (window = "\r\n\r\n").

def body_of.go(s: String, e: Bool, w: U32) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{a}, t}:
      match e:
        case True{}:
          SCon{Chr{a}, t}
        case False{}:
          +w2 = (w * 256 + a : U32)
          body_of.go(t, U32.is_eq(w2, 218762506), w2)

def body_of(s: String) -> String:
  body_of.go(s, False{}, 0)

def head_of.go(s: String, acc: String, e: Bool, w: U32) -> String:
  match s:
    case SNil{}:
      acc
    case SCon{Chr{+a}, t}:
      match e:
        case True{}:
          acc
        case False{}:
          +w2 = (w * 256 + a : U32)
          head_of.go(t, acc ++ Char.show(Chr{a}), U32.is_eq(w2, 218762506), w2)

def head_of(s: String) -> String:
  head_of.go(s, SNil{}, False{}, 0)

def blank_win.end(found: Bool) -> U32:
  match found:
    case True{}:
      1
    case False{}:
      0

def blank_win(s: String, e: Bool, w: U32) -> U32:
  match s:
    case SNil{}:
      blank_win.end(e)
    case SCon{Chr{a}, t}:
      match e:
        case True{}:
          1
        case False{}:
          +w2 = (w * 256 + a : U32)
          blank_win(t, U32.is_eq(w2, 218762506), w2)

def has_blank(s: String) -> Bool:
  U32.is_ne(blank_win(s, False{}, 0), 0)

# URL
# ---
# Result is secure & host & port & path.

def default_port(secure: Bool) -> U32:
  match secure:
    case True{}:
      443
    case False{}:
      80

def valid_port(+p: U32) -> Bool:
  Bool.and(U32.is_ge(p, 1), U32.is_le(p, 65535))

def has_host_bad(+h: String) -> Bool:
  Bool.or(String.contains(h, "/"),
    Bool.or(String.contains(h, "?"),
      Bool.or(String.contains(h, "#"), String.contains(h, "@"))))

def valid_host.put4(sp: Bool) -> Bool:
  match sp:
    case True{}:
      False{}
    case False{}:
      True{}

def valid_host.put3(bad: Bool, sp: Bool) -> Bool:
  match bad:
    case True{}:
      False{}
    case False{}:
      valid_host.put4(sp)

def valid_host.put2(crlf: Bool, bad: Bool, sp: Bool) -> Bool:
  match crlf:
    case True{}:
      False{}
    case False{}:
      valid_host.put3(bad, sp)

def valid_host.put(empty: Bool, crlf: Bool, bad: Bool, sp: Bool) -> Bool:
  match empty:
    case True{}:
      False{}
    case False{}:
      valid_host.put2(crlf, bad, sp)

def valid_host(+h: String) -> Bool:
  valid_host.put(String.is_empty(h), Bool.or(has_crlf(h), has_nul(h)), has_host_bad(h), String.contains(h, " "))

def valid_path.put3(sp: Bool) -> Bool:
  match sp:
    case True{}:
      False{}
    case False{}:
      True{}

def valid_path.put2(crlf: Bool, sp: Bool) -> Bool:
  match crlf:
    case True{}:
      False{}
    case False{}:
      valid_path.put3(sp)

def valid_path.put(slash: Bool, crlf: Bool, sp: Bool) -> Bool:
  match slash:
    case True{}:
      valid_path.put2(crlf, sp)
    case False{}:
      False{}

def valid_path(+p: String) -> Bool:
  valid_path.put(String.starts_with(p, "/"), Bool.or(has_crlf(p), has_nul(p)), String.contains(p, " "))

def strip_host(h: String) -> String:
  String.trim(h)

def split_host_port.put(h: Char, t: String, host: String, port: String, rec: String & String, is_colon: Bool) -> String & String:
  match is_colon:
    case True{}:
      (host, t)
    case False{}:
      rec

def split_host_port.go(s: String, +host: String, +port: String) -> String & String:
  match s:
    case SNil{}:
      (host, port)
    case SCon{+h, +t}:
      split_host_port.put(h, t, host, port, split_host_port.go(t, host ++ Char.show(h), port), Char.is_eq(h, ':'))

def split_host_port(s: String) -> String & String:
  split_host_port.go(s, SNil{}, SNil{})

def split_host_path.put(h: Char, t: String, acc: String, rec: String & String, is_slash: Bool) -> String & String:
  match is_slash:
    case True{}:
      (acc, SCon{h, t})
    case False{}:
      rec

def split_host_path.go(s: String, +acc: String) -> String & String:
  match s:
    case SNil{}:
      (acc, SNil{})
    case SCon{+h, +t}:
      split_host_path.put(h, t, acc, split_host_path.go(t, acc ++ Char.show(h)), Char.is_eq(h, '/'))

def split_host_path(s: String) -> String & String:
  split_host_path.go(s, SNil{})

def norm_path(p: String) -> String:
  match p:
    case SNil{}:
      "/"
    case SCon{h, t}:
      p

def read_url.done(secure: Bool, host: String, port: U32, path: String, ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match ok:
    case True{}:
      Done{(secure, host, port, path)}
    case False{}:
      Fail{(400, "bad url")}

def read_url.explicit.put(secure: Bool, host: String, +path: String, port: Maybe<&2, U32>) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match port:
    case None{}:
      Fail{(400, "bad port")}
    case Some{p}:
      +c = p
      read_url.done(secure, host, c, path, Bool.and(valid_port(c), valid_path(path)))

def read_url.explicit(secure: Bool, host: String, portstr: String, path: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  read_url.explicit.put(secure, host, path, U32.read(portstr))

def read_url.port.go(+secure: Bool, host: String, portstr: String, +path: String, no_port: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match no_port:
    case True{}:
      read_url.done(secure, host, default_port(secure), path, valid_path(path))
    case False{}:
      read_url.explicit(secure, host, portstr, path)

def read_url.port(secure: Bool, host: String, +portstr: String, path: String, host_ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match host_ok:
    case False{}:
      Fail{(400, "bad host")}
    case True{}:
      read_url.port.go(secure, host, portstr, path, String.is_empty(portstr))

def read_url.host.go(secure: Bool, path: String, hp: String & String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  (host, portstr) = hp
  +h1 = strip_host(host)
  read_url.port(secure, h1, portstr, path, valid_host(h1))

def read_url.host(secure: Bool, +hostport: String, path: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  read_url.host.go(secure, path, split_host_port(hostport))

def read_url.split(hp: String & String, secure: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  (hostport, path0) = hp
  read_url.host(secure, hostport, norm_path(path0))

def read_url.rest(+rest: String, secure: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  read_url.split(split_host_path(rest), secure)

def read_url.http(url: String, is_http: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match is_http:
    case True{}:
      read_url.rest(String.drop(url, 7n), False{})
    case False{}:
      Fail{(400, "bad scheme")}

def read_url.scheme(url: String, is_https: Bool, is_http: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match is_https:
    case True{}:
      read_url.rest(String.drop(url, 8n), True{})
    case False{}:
      read_url.http(url, is_http)

def read_url(+url: String) -> Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  read_url.scheme(url, String.starts_with(url, "https://"), String.starts_with(url, "http://"))

# Headers
# -------
# Headers are List<&1, String & String> of name & value (values trimmed).

def get_header.put(dflt: String, v: String, rec: String, hit: Bool) -> String:
  match hit:
    case True{}:
      v
    case False{}:
      rec

def get_header(+dflt: String, +name: String, hs: List<&1, String & String>) -> String:
  match hs:
    case Nil{}:
      dflt
    case (n, v) <> t:
      get_header.put(dflt, String.trim(v), get_header(dflt, name, t), eq_ci(n, name))

def drop_conn.put(n: String, v: String, rec: List<&1, String & String>, is_conn: Bool) ->
  List<&1, String & String>:
  match is_conn:
    case True{}:
      rec
    case False{}:
      (n, v) <> rec

def drop_conn(hs: List<&1, String & String>) -> List<&1, String & String>:
  match hs:
    case Nil{}:
      Nil{}
    case (n, v) <> t:
      +nn = n
      +vv = v
      drop_conn.put(nn, vv, drop_conn(t), eq_ci(nn, "Connection"))

def show_headers.ok(n: String, v: String, hs: Result<&1, &1, U32 & String, String>) ->
  Result<&1, &1, U32 & String, String>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{t}:
      Done{n ++ ": " ++ String.trim(v) ++ "\r\n" ++ t}

def show_headers.put(n: String, v: String, hs: Result<&1, &1, U32 & String, String>, bad: Bool) ->
  Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad header")}
    case False{}:
      show_headers.ok(n, v, hs)

def show_headers(hs: List<&1, String & String>) -> Result<&1, &1, U32 & String, String>:
  match hs:
    case Nil{}:
      Done{SNil{}}
    case (n, v) <> t:
      +nn = n
      +vv = v
      show_headers.put(nn, vv, show_headers(t), Bool.or(has_crlf3(nn, vv, SNil{}), Bool.or(has_nul(nn), has_nul(vv))))

def parse_headers.tail(n: String, v: String, rec: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, List<&1, String & String>>:
  match rec:
    case Fail{e}:
      Fail{e}
    case Done{t}:
      Done{(n, v) <> t}

def parse_headers.named(n: String, v: String, rec: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, List<&1, String & String>>:
  match n:
    case SNil{}:
      Fail{(400, "bad header")}
    case SCon{h3, t3}:
      parse_headers.tail(n, v, rec)

def parse_headers.put(l1: String, n: String, v: String, rec: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, List<&1, String & String>>:
  match l1:
    case SNil{}:
      rec
    case SCon{h2, t2}:
      parse_headers.named(n, v, rec)

def split_header.join(parts: List<&2, String>, acc: String) -> String:
  match parts:
    case Nil{}:
      acc
    case h <> t:
      split_header.join(t, acc ++ ":" ++ h)

def split_header.rest(x: String, rest: List<&2, String>, l1: String, t: List<&2, String>, rec: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, List<&1, String & String>>:
  match rest:
    case Nil{}:
      parse_headers.put(l1, String.trim(x), SNil{}, rec)
    case y <> ys:
      parse_headers.put(l1, String.trim(x), String.trim(split_header.join(ys, y)), rec)

def split_header.put(parts: List<&2, String>, +l1: String, t: List<&2, String>, rec: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, List<&1, String & String>>:
  match parts:
    case Nil{}:
      parse_headers.put(l1, l1, SNil{}, rec)
    case x <> rest:
      split_header.rest(x, rest, l1, t, rec)

def parse_headers(lines: List<&2, String>) -> Result<&1, &1, U32 & String, List<&1, String & String>>:
  match lines:
    case Nil{}:
      Done{Nil{}}
    case +h <> +t:
      +l1 = String.trim(strip_cr(h))
      split_header.put(String.split(l1, ':'), l1, t, parse_headers(t))

def content_length(hs: List<&1, String & String>) -> U32:
  Maybe.default(&2, U32, U32.read(get_header("0", "Content-Length", hs)), 0)

def body_len.show(body: String) -> String:
  Nat.show(String.length(body))

# Requests and responses
# ----------------------
# Request = method & path & headers & body. Response = status & headers & body.

def no_body() -> String:
  SNil{}

def valid_req_line.spp(spp: Bool) -> Bool:
  match spp:
    case True{}:
      False{}
    case False{}:
      True{}

def valid_req_line.sp(spm: Bool, spp: Bool) -> Bool:
  match spm:
    case True{}:
      False{}
    case False{}:
      valid_req_line.spp(spp)

def valid_req_line.slash(slash: Bool, spm: Bool, spp: Bool) -> Bool:
  match slash:
    case True{}:
      valid_req_line.sp(spm, spp)
    case False{}:
      False{}

def valid_req_line.put(empty: Bool, slash: Bool, spm: Bool, spp: Bool) -> Bool:
  match empty:
    case True{}:
      False{}
    case False{}:
      valid_req_line.slash(slash, spm, spp)

def valid_req_line(+m: String, +p: String) -> Bool:
  valid_req_line.put(String.is_empty(m), String.starts_with(p, "/"), Bool.or(String.contains(m, " "), has_nul(m)), Bool.or(String.contains(p, " "), has_nul(p)))

def show_request.hs(m: String, p: String, +body: String, hs: Result<&1, &1, U32 & String, String>) ->
  Result<&1, &1, U32 & String, String>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      Done{m ++ " " ++ p ++ " HTTP/1.1\r\n" ++ h ++ "Content-Length: " ++ body_len.show(body) ++ "\r\nConnection: close\r\n\r\n" ++ body}

def show_request.head(m: String, p: String, hs: List<&1, String & String>, body: String, ok: Bool) ->
  Result<&1, &1, U32 & String, String>:
  match ok:
    case False{}:
      Fail{(400, "bad request line")}
    case True{}:
      show_request.hs(m, p, body, show_headers(hs))

def show_request.put(+m: String, +p: String, hs: List<&1, String & String>, body: String, bad: Bool) ->
  Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad request field")}
    case False{}:
      show_request.head(m, p, hs, body, valid_req_line(m, p))

def show_request(+m: String, +p: String, hs: List<&1, String & String>, +body: String) ->
  Result<&1, &1, U32 & String, String>:
  show_request.put(m, p, hs, body, Bool.or(has_crlf3(m, p, body), Bool.or(has_nul(m), has_nul(p))))

def read_request.emit(m: String, p: String, body: String, hs: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      Done{(m, p, h, body)}

def read_request.put(m: String, p: String, body: String, hs: Result<&1, &1, U32 & String, List<&1, String & String>>, ok: Bool) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match ok:
    case False{}:
      Fail{(400, "bad request line")}
    case True{}:
      read_request.emit(m, p, body, hs)

def read_request.ver(+m: String, +p: String, v: String, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  read_request.put(m, p, body, parse_headers(rest), valid_req_line(m, p))

def read_request.tail(m: String, p: String, v: String, tail: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match tail:
    case Nil{}:
      read_request.ver(m, p, v, rest, body)
    case h <> t:
      Fail{(400, "bad request line")}

def read_request.parts3(m: String, p: String, pv: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match pv:
    case Nil{}:
      Fail{(400, "bad request line")}
    case v <> tail:
      read_request.tail(m, p, v, tail, rest, body)

def read_request.parts2(m: String, pm: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match pm:
    case Nil{}:
      Fail{(400, "bad request line")}
    case p <> pv:
      read_request.parts3(m, p, pv, rest, body)

def read_request.parts(parts: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match parts:
    case Nil{}:
      Fail{(400, "bad request line")}
    case m <> pm:
      read_request.parts2(m, pm, rest, body)

def split_spaces(s: String) -> List<&2, String>:
  String.split(s, ' ')

def read_request.line(rl: String, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  read_request.parts(split_spaces(rl), rest, body)

def read_request.lines(lines: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match lines:
    case Nil{}:
      Fail{(400, "empty request")}
    case rl <> rest:
      read_request.line(strip_cr(rl), rest, body)

def read_request.head(head: String, body: String) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  read_request.lines(String.lines(head), body)

def read_request.blank(+s: String, has: Bool) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match has:
    case False{}:
      Fail{(400, "no blank line")}
    case True{}:
      read_request.head(head_of(s), body_of(s))

def read_request.capped(+s: String, ok: Bool) ->
  Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  match ok:
    case False{}:
      Fail{(413, "head too large")}
    case True{}:
      read_request.blank(s, has_blank(s))

def read_request(+s: String) -> Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>:
  read_request.capped(s, Nat.is_le(String.length(s), 16384n))

def reason.nf(st: U32, is_nf: Bool) -> String:
  match is_nf:
    case True{}:
      "Not Found"
    case False{}:
      "Status"

def reason.go(st: U32, is_ok: Bool, is_nf: Bool) -> String:
  match is_ok:
    case True{}:
      "OK"
    case False{}:
      reason.nf(st, is_nf)

def reason(+st: U32) -> String:
  reason.go(st, U32.is_eq(st, 200), U32.is_eq(st, 404))

def show_response.tail(+st: U32, +body: String, hs: Result<&1, &1, U32 & String, String>) ->
  Result<&1, &1, U32 & String, String>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      Done{"HTTP/1.1 " ++ U32.show(st) ++ " " ++ reason(st) ++ "\r\n" ++ h ++ "Content-Length: " ++ body_len.show(body) ++ "\r\nConnection: close\r\n\r\n" ++ body}

def show_response.hs(st: U32, body: String, hs: Result<&1, &1, U32 & String, String>, bad: Bool) ->
  Result<&1, &1, U32 & String, String>:
  match bad:
    case True{}:
      Fail{(400, "bad body")}
    case False{}:
      show_response.tail(st, body, hs)

def show_response.code(st: U32, hs: List<&1, String & String>, +body: String, ok: Bool) ->
  Result<&1, &1, U32 & String, String>:
  match ok:
    case False{}:
      Fail{(400, "bad status")}
    case True{}:
      show_response.hs(st, body, show_headers(hs), has_crlf(body))

def show_response(+st: U32, hs: List<&1, String & String>, +body: String) ->
  Result<&1, &1, U32 & String, String>:
  show_response.code(st, hs, body, Bool.and(U32.is_ge(st, 100), U32.is_le(st, 599)))

def read_response.done(st: U32, body: String, hs: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      Done{(st, h, body)}

def read_response.emit(st: U32, body: String, hs: Result<&1, &1, U32 & String, List<&1, String & String>>, ok: Bool) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match ok:
    case False{}:
      Fail{(400, "bad status")}
    case True{}:
      read_response.done(st, body, hs)

def read_response.code.go(rest: List<&2, String>, body: String, vok: Bool, st: Maybe<&2, U32>) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match st:
    case None{}:
      Fail{(400, "bad status")}
    case Some{code}:
      +c = code
      read_response.emit(c, body, parse_headers(rest), Bool.and(vok, Bool.and(U32.is_ge(c, 100), U32.is_le(c, 599))))

def read_response.code(v: String, cs: String, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  read_response.code.go(rest, body, String.eq(v, "HTTP/1.1"), U32.read(cs))

def read_response.parts2(v: String, pv: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match pv:
    case Nil{}:
      Fail{(400, "bad status line")}
    case cs <> tail:
      read_response.code(v, cs, rest, body)

def read_response.parts(parts: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match parts:
    case Nil{}:
      Fail{(400, "bad status line")}
    case v <> pv:
      read_response.parts2(v, pv, rest, body)

def read_response.line(sl: String, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  read_response.parts(split_spaces(sl), rest, body)

def read_response.lines(lines: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match lines:
    case Nil{}:
      Fail{(400, "empty response")}
    case sl <> rest:
      read_response.line(strip_cr(sl), rest, body)

def read_response.head(head: String, body: String) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  read_response.lines(String.lines(head), body)

def read_response.blank(+s: String, has: Bool) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match has:
    case False{}:
      Fail{(400, "no blank line")}
    case True{}:
      read_response.head(head_of(s), body_of(s))

def read_response.capped(+s: String, ok: Bool) ->
  Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  match ok:
    case False{}:
      Fail{(413, "head too large")}
    case True{}:
      read_response.blank(s, has_blank(s))

def read_response(+s: String) -> Result<&1, &1, U32 & String, U32 & List<&1, String & String> & String>:
  read_response.capped(s, Nat.is_le(String.length(s), 16384n))

def read_head.emit(is11: Bool, m: String, p: String, body: String, hs: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      Done{(is11, (m, p, h, body))}

def read_head.put(is11: Bool, m: String, p: String, body: String, hs: Result<&1, &1, U32 & String, List<&1, String & String>>) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  read_head.emit(is11, m, p, body, hs)

def read_head.chk(is11: Bool, m: String, p: String, rest: List<&2, String>, body: String, ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match ok:
    case False{}:
      Fail{(400, "bad request line")}
    case True{}:
      read_head.put(is11, m, p, body, parse_headers(rest))

def read_head.ver(+m: String, +p: String, v: String, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  read_head.chk(String.eq(v, "HTTP/1.1"), m, p, rest, body, valid_req_line(m, p))

def read_head.parts4(m: String, p: String, v: String, tail: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match tail:
    case Nil{}:
      read_head.ver(m, p, v, rest, body)
    case h <> t:
      Fail{(400, "bad request line")}

def read_head.parts3(m: String, p: String, pv: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match pv:
    case Nil{}:
      Fail{(400, "bad request line")}
    case v <> tail:
      read_head.parts4(m, p, v, tail, rest, body)

def read_head.parts2(m: String, pm: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match pm:
    case Nil{}:
      Fail{(400, "bad request line")}
    case p <> pv:
      read_head.parts3(m, p, pv, rest, body)

def read_head.parts(parts: List<&2, String>, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match parts:
    case Nil{}:
      Fail{(400, "bad request line")}
    case m <> pm:
      read_head.parts2(m, pm, rest, body)

def read_head.line(rl: String, rest: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  read_head.parts(split_spaces(rl), rest, body)

def read_head.lines(lines: List<&2, String>, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match lines:
    case Nil{}:
      Fail{(400, "empty request")}
    case rl <> rest:
      read_head.line(strip_cr(rl), rest, body)

def read_head.head(head: String, body: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  read_head.lines(String.lines(head), body)

def read_head.blank(+s: String, has: Bool) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match has:
    case False{}:
      Fail{(400, "no blank line")}
    case True{}:
      read_head.head(head_of(s), body_of(s))

def read_head.capped(+s: String, ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  match ok:
    case False{}:
      Fail{(413, "head too large")}
    case True{}:
      read_head.blank(s, has_blank(s))

def read_head(+s: String) ->
  Result<&1, &1, U32 & String, Bool & (String & String & List<&1, String & String> & String)>:
  read_head.capped(s, Nat.is_le(String.length(s), 16384n))

# Keep-alive
# ----------

def keep_alive.open.go(is11: Bool, ka: Bool) -> Bool:
  match ka:
    case True{}:
      True{}
    case False{}:
      is11

def keep_alive.open(conn: String, is11: Bool) -> Bool:
  keep_alive.open.go(is11, String.eq(conn, "keep-alive"))

def keep_alive.conn.go(conn: String, is11: Bool, closed: Bool) -> Bool:
  match closed:
    case True{}:
      False{}
    case False{}:
      keep_alive.open(conn, is11)

def keep_alive.conn(+conn: String, is11: Bool) -> Bool:
  keep_alive.conn.go(conn, is11, String.eq(conn, "close"))

def keep_alive(is11: Bool, hs: List<&1, String & String>) -> Bool:
  keep_alive.conn(String.to_lower(String.trim(get_header("", "Connection", hs))), is11)

def with_connection.go(st: U32, hs: List<&1, String & String>, body: String, keep: Bool) ->
  U32 & List<&1, String & String> & String:
  match keep:
    case True{}:
      (st, ("Connection", "keep-alive") <> hs, body)
    case False{}:
      (st, ("Connection", "close") <> hs, body)

def with_connection(keep: Bool, resp: U32 & List<&1, String & String> & String) ->
  U32 & List<&1, String & String> & String:
  (st, hs, body) = resp
  with_connection.go(st, drop_conn(hs), body, keep)



# Chunked
# -------
# One state machine over Nat fuel: 0 reads a hex size, 1 skips
# extensions, 2 reads data, 3 and 4 eat the data CRLF, 5 and 6 eat
# the final CRLF. Every arm holds one recursive call, so it is
# linear; validity ANDs through and gates the answer at the end.

def length_nat.go(bs: List<&2, U32>, acc: Nat) -> Nat:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      length_nat.go(t, 1n+acc)

def length_nat(bs: List<&2, U32>) -> Nat:
  length_nat.go(bs, 0n)

def unchunk.put(r: List<&2, U32> & Bool) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  (acc, ok) = r
  match ok:
    case True{}:
      Done{List.reverse(&2, U32, acc)}
    case False{}:
      Fail{(400, "bad chunked")}

def unchunk.go(fuel: Nat, st: U32, rem: Nat, size: U32, acc: List<&2, U32>, valid: Bool, bs: List<&2, U32>) ->
  List<&2, U32> & Bool:
  match fuel:
    case 0n:
      (acc, False{})
    case 1n+f:
      match st:
        case 0:
          match bs:
            case Nil{}:
              (acc, False{})
            case b <> rest:
              match b:
                case 48:
                  unchunk.go(f, 0, 0n, 0, acc, valid, rest)
                case 49:
                  unchunk.go(f, 7, 0n, 1, acc, valid, rest)
                case 50:
                  unchunk.go(f, 7, 0n, 2, acc, valid, rest)
                case 51:
                  unchunk.go(f, 7, 0n, 3, acc, valid, rest)
                case 52:
                  unchunk.go(f, 7, 0n, 4, acc, valid, rest)
                case 53:
                  unchunk.go(f, 7, 0n, 5, acc, valid, rest)
                case 54:
                  unchunk.go(f, 7, 0n, 6, acc, valid, rest)
                case 55:
                  unchunk.go(f, 7, 0n, 7, acc, valid, rest)
                case 56:
                  unchunk.go(f, 7, 0n, 8, acc, valid, rest)
                case 57:
                  unchunk.go(f, 7, 0n, 9, acc, valid, rest)
                case 65:
                  unchunk.go(f, 7, 0n, 10, acc, valid, rest)
                case 66:
                  unchunk.go(f, 7, 0n, 11, acc, valid, rest)
                case 67:
                  unchunk.go(f, 7, 0n, 12, acc, valid, rest)
                case 68:
                  unchunk.go(f, 7, 0n, 13, acc, valid, rest)
                case 69:
                  unchunk.go(f, 7, 0n, 14, acc, valid, rest)
                case 70:
                  unchunk.go(f, 7, 0n, 15, acc, valid, rest)
                case 97:
                  unchunk.go(f, 7, 0n, 10, acc, valid, rest)
                case 98:
                  unchunk.go(f, 7, 0n, 11, acc, valid, rest)
                case 99:
                  unchunk.go(f, 7, 0n, 12, acc, valid, rest)
                case 100:
                  unchunk.go(f, 7, 0n, 13, acc, valid, rest)
                case 101:
                  unchunk.go(f, 7, 0n, 14, acc, valid, rest)
                case 102:
                  unchunk.go(f, 7, 0n, 15, acc, valid, rest)
                case 59:
                  unchunk.go(f, 1, 0n, 0, acc, valid, rest)
                case 13:
                  match rest:
                    case 10 <> rest2:
                      unchunk.go(f, 5, 0n, 0, acc, valid, rest2)
                    case _:
                      (acc, False{})
                case _:
                  unchunk.go(f, 0, 0n, 0, acc, False{}, rest)
        case 7:
          match bs:
            case Nil{}:
              (acc, False{})
            case b <> rest:
              match b:
                case 48:
                  unchunk.go(f, 7, 0n, (size * 16 + 0 : U32), acc, valid, rest)
                case 49:
                  unchunk.go(f, 7, 0n, (size * 16 + 1 : U32), acc, valid, rest)
                case 50:
                  unchunk.go(f, 7, 0n, (size * 16 + 2 : U32), acc, valid, rest)
                case 51:
                  unchunk.go(f, 7, 0n, (size * 16 + 3 : U32), acc, valid, rest)
                case 52:
                  unchunk.go(f, 7, 0n, (size * 16 + 4 : U32), acc, valid, rest)
                case 53:
                  unchunk.go(f, 7, 0n, (size * 16 + 5 : U32), acc, valid, rest)
                case 54:
                  unchunk.go(f, 7, 0n, (size * 16 + 6 : U32), acc, valid, rest)
                case 55:
                  unchunk.go(f, 7, 0n, (size * 16 + 7 : U32), acc, valid, rest)
                case 56:
                  unchunk.go(f, 7, 0n, (size * 16 + 8 : U32), acc, valid, rest)
                case 57:
                  unchunk.go(f, 7, 0n, (size * 16 + 9 : U32), acc, valid, rest)
                case 65:
                  unchunk.go(f, 7, 0n, (size * 16 + 10 : U32), acc, valid, rest)
                case 66:
                  unchunk.go(f, 7, 0n, (size * 16 + 11 : U32), acc, valid, rest)
                case 67:
                  unchunk.go(f, 7, 0n, (size * 16 + 12 : U32), acc, valid, rest)
                case 68:
                  unchunk.go(f, 7, 0n, (size * 16 + 13 : U32), acc, valid, rest)
                case 69:
                  unchunk.go(f, 7, 0n, (size * 16 + 14 : U32), acc, valid, rest)
                case 70:
                  unchunk.go(f, 7, 0n, (size * 16 + 15 : U32), acc, valid, rest)
                case 97:
                  unchunk.go(f, 7, 0n, (size * 16 + 10 : U32), acc, valid, rest)
                case 98:
                  unchunk.go(f, 7, 0n, (size * 16 + 11 : U32), acc, valid, rest)
                case 99:
                  unchunk.go(f, 7, 0n, (size * 16 + 12 : U32), acc, valid, rest)
                case 100:
                  unchunk.go(f, 7, 0n, (size * 16 + 13 : U32), acc, valid, rest)
                case 101:
                  unchunk.go(f, 7, 0n, (size * 16 + 14 : U32), acc, valid, rest)
                case 102:
                  unchunk.go(f, 7, 0n, (size * 16 + 15 : U32), acc, valid, rest)
                case 59:
                  unchunk.go(f, 1, 0n, size, acc, valid, rest)
                case 13:
                  match rest:
                    case 10 <> rest2:
                      unchunk.go(f, 2, U32.to_nat(size), 0, acc, valid, rest2)
                    case _:
                      (acc, False{})
                case _:
                  unchunk.go(f, 7, 0n, size, acc, False{}, rest)
        case 1:
          match bs:
            case Nil{}:
              (acc, False{})
            case b <> rest:
              match b:
                case 13:
                  match rest:
                    case 10 <> rest2:
                      unchunk.go(f, 2, U32.to_nat(size), 0, acc, valid, rest2)
                    case _:
                      (acc, False{})
                case _:
                  unchunk.go(f, 1, 0n, size, acc, valid, rest)
        case 2:
          match rem:
            case 0n:
              unchunk.go(f, 3, 0n, size, acc, valid, bs)
            case 1n+c:
              match bs:
                case Nil{}:
                  (acc, False{})
                case h <> t:
                  unchunk.go(f, 2, c, size, h <> acc, valid, t)
        case 3:
          match bs:
            case Nil{}:
              (acc, False{})
            case 13 <> t:
              unchunk.go(f, 4, 0n, size, acc, valid, t)
            case _:
              (acc, False{})
        case 4:
          match bs:
            case Nil{}:
              (acc, False{})
            case 10 <> t:
              unchunk.go(f, 0, 0n, 0, acc, valid, t)
            case _:
              (acc, False{})
        case 5:
          match bs:
            case Nil{}:
              (acc, False{})
            case 13 <> t:
              unchunk.go(f, 6, 0n, size, acc, valid, t)
            case _:
              (acc, False{})
        case 6:
          match bs:
            case Nil{}:
              (acc, False{})
            case 10 <> t:
              match t:
                case Nil{}:
                  (acc, valid)
                case _:
                  (acc, False{})
            case _:
              (acc, False{})
        case _:
          (acc, False{})

def unchunk(+bs: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  unchunk.put(unchunk.go(1n+length_nat(bs), 0, 0n, 0, Nil{}, True{}, bs))

# Router
# ------
# A router is a handler beside its next thunk, kept as a plain tuple
# (a law would stay an open claim and fail the check). Route runs once.

def route_status(resp: U32 & List<&1, String & String> & String) -> U32:
  (st, hs, body) = resp
  st

def dispatch(route: String & String & List<&1, String & String> & String -> IO(U32 & List<&1, String & String> & String), req: String & String & List<&1, String & String> & String) ->
  IO(U32 & List<&1, String & String> & String):
  route(req)

# IO: fetch and serve
# -------------------

law fetch:
  for url: String
  IO(Result<&1, &1, U32 & String, String>)

def fetch.fail(sock: Socket, e: U32 & String) -> IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    x : Unit <- Socket.close(sock)
    return Fail{e}

def fetch.finish(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    x : Unit <- Socket.close(sock)
    return Done{body_of(acc)}

def fetch.after8fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.finish(sock2, acc ++ part)

def fetch.recv8(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after8fn(acc, m))

def fetch.after7fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv8(sock2, acc ++ part)

def fetch.recv7(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after7fn(acc, m))

def fetch.after6fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv7(sock2, acc ++ part)

def fetch.recv6(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after6fn(acc, m))

def fetch.after5fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv6(sock2, acc ++ part)

def fetch.recv5(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after5fn(acc, m))

def fetch.after4fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv5(sock2, acc ++ part)

def fetch.recv4(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after4fn(acc, m))

def fetch.after3fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv4(sock2, acc ++ part)

def fetch.recv3(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after3fn(acc, m))

def fetch.after2fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv3(sock2, acc ++ part)

def fetch.recv2(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after2fn(acc, m))

def fetch.after1fn(acc: String, m: Socket & Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock2, r) = m
  match r:
    case Fail{e}:
      fetch.fail(sock2, e)
    case Done{part}:
      match part:
        case SNil{}:
          fetch.finish(sock2, acc)
        case SCon{h, t}:
          fetch.recv2(sock2, acc ++ part)

def fetch.recv1(sock: Socket, acc: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.bind(Socket & Result<&1, &1, U32 & String, String>, Result<&1, &1, U32 & String, String>, TCP.recv(sock, 8192), m => fetch.after1fn(acc, m))

def fetch.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Result<&1, &1, U32 & String, String>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      fetch.fail(sock, e)
    case Done{u}:
      fetch.recv1(sock, SNil{})

def fetch.sock(sock: Socket, host: String, path: String) -> IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, "GET " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ "\r\nConnection: close\r\n\r\n")
    fetch.sent(sent)

def fetch.conn(conn: Result<&1, &1, U32 & String, Socket>, host: String, path: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{sock}:
      fetch.sock(sock, host, path)

def fetch.go(+host: String, port: U32, path: String) -> IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
    fetch.conn(conn, host, path)

def fetch.port(host: String, port: U32, path: String, ok: Bool) -> IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad port")})
    case True{}:
      fetch.go(host, port, path)

def fetch.host(host: String, +port: U32, path: String, ok: Bool) -> IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad host")})
    case True{}:
      fetch.port(host, port, path, valid_port(port))

def fetch.url.go(secure: Bool, +host: String, port: U32, path: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match secure:
    case True{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(501, "tls missing")})
    case False{}:
      fetch.host(host, port, path, valid_host(host))

def fetch.url(u: Bool & String & U32 & String) -> IO(Result<&1, &1, U32 & String, String>):
  (secure, host, port, path) = u
  fetch.url.go(secure, host, port, path)

def fetch.r(url: String, parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{u}:
      fetch.url(u)

def fetch(url):
  +u = url
  fetch.r(u, read_url(u))

# Serve: single-shot with a caller handler, plus a hardcoded echo
# loop (the loop reuses only top-level defs, never an affine
# closure, so it typechecks).

def serve.shipped(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, r) = sent
  match r:
    case Fail{e}:
      Socket.close(s2)
    case Done{u}:
      Socket.close(s2)

def serve.ship(s: Socket, st: U32, hs: List<&1, String & String>, body: String) ->
  IO(Unit):
  do IO<Unit>:
    shown : String <- IO.pass(String, show_response(st, hs, body))
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, shown)
    serve.shipped(sent)

def serve.split(s: Socket, resp: U32 & List<&1, String & String> & String) ->
  IO(Unit):
  (st, hs, body) = resp
  serve.ship(s, st, hs, body)

def serve.answer(s: Socket, req: String & String & List<&1, String & String> & String, handler: String & String & List<&1, String & String> & String -> IO(U32 & List<&1, String & String> & String)) ->
  IO(Unit):
  do IO<Unit>:
    resp : U32 & List<&1, String & String> & String <- handler(req)
    serve.split(s, resp)

def serve.parsed(s: Socket, handler: String & String & List<&1, String & String> & String -> IO(U32 & List<&1, String & String> & String), parsed: Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>) ->
  IO(Unit):
  match parsed:
    case Fail{e}:
      Socket.close(s)
    case Done{req}:
      serve.answer(s, req, handler)

def serve.reply(m: Socket & Result<&1, &1, U32 & String, String>, handler: String & String & List<&1, String & String> & String -> IO(U32 & List<&1, String & String> & String)) ->
  IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{req}:
      serve.parsed(s, handler, read_request(req))

def serve_once(sock: Socket, handler: String & String & List<&1, String & String> & String -> IO(U32 & List<&1, String & String> & String)) ->
  IO(Unit):
  do IO<Unit>:
    read : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(sock, 8192)
    serve.reply(read, handler)

def echo.body(req: String & String & List<&1, String & String> & String) ->
  IO(U32 & List<&1, String & String> & String):
  (m, p, hs, body) = req
  IO.pure(U32 & List<&1, String & String> & String, (200, [], body))

def echo.sent(s: Socket, text: String) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, text)
    serve.shipped(sent)

def echo.shown(s: Socket, shown: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match shown:
    case Fail{e}:
      Socket.close(s)
    case Done{text}:
      echo.sent(s, text)

def echo.send(s: Socket, req: String & String & List<&1, String & String> & String) ->
  IO(Unit):
  (m, p, hs, body) = req
  echo.shown(s, show_response(200, [], body))

def echo.go(s: Socket, parsed: Result<&1, &1, U32 & String, String & String & List<&1, String & String> & String>) ->
  IO(Unit):
  match parsed:
    case Fail{e}:
      Socket.close(s)
    case Done{req}:
      echo.send(s, req)

def echo.reply(m: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      Socket.close(s)
    case Done{req}:
      echo.go(s, read_request(req))

def echo.talk(s: Socket) -> IO(Unit):
  do IO<Unit>:
    read : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
    echo.reply(read)

def echo.conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  do IO<Listener>:
    s : Socket <- IO.pass(Socket, r)
    IO.spawn(Unit, echo.talk(s))
    return l

@unsafe
def echo.serve(l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    l2 : Listener <- echo.conn(m)
    echo.serve(l2)

def ok(+body: String) -> U32 & List<&1, String & String> & String:
  (200, [("Content-Length", body_len.show(body))], body)
