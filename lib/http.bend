# HTTP: the core that every protocol module imports. It owns the byte
# leaves, the text codecs, the 25 Data types and the request validation
# both protocols call. Bend keeps one constructor namespace per file, so
# every constructor of the library lives here.
#
# No protocol state lives here: no frames, no slots, no sockets.
#
# Import as: import ./http.bend as HTTP (from lib) or
# import ../../lib/http.bend as HTTP (from tests/io).
import Base

# Bytes
# -----

def x_cat.go(+bs: List<&2, U32>, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      x_cat.go(t, h <> acc)

def x_cat(+bs: List<&2, U32>) -> List<&2, U32>:
  x_cat.go(bs, Nil{})

# Reversed body push (stack-safe accumulation for big bodies): one
# tail pass, no intermediate list and no append depth. x_cat.go with
# a non-empty seed is exactly reverse-then-prepend: walking frag
# while prepending onto rev yields reverse(frag) ++ rev.
# ---------------------------------------------------------------------

def x_rev_push(+frag: List<&2, U32>, +rev: List<&2, U32>) -> List<&2, U32>:
  x_cat.go(frag, rev)

# NOTE (Phase 13 P7): x_take/x_drop Nat deleted — zero callers (take32/
# drop32 cover all sites). x_len stays: x_huff_decode.fuel takes Nat bl.
def x_len.go(+bs: List<&2, U32>, acc: Nat) -> Nat:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      x_len.go(t, 1n+acc)

def x_len(bs: List<&2, U32>) -> Nat:
  x_len.go(bs, 0n)

# Bounded take for the flow sender, Nat counter inside (U32 would
# box one decrement per element): reversed build plus one x_cat,
# same tail discipline as length_got_th in test.bend. Full-list
# copies cost a rebuild like any got; live call sites take small
# slices (16 KiB flow chunks, 24 B preface, 9 B headers), bounded
# by n, not by the buffer.
def x_take32.go(+bs: List<&2, U32>, +n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      x_cat(acc)
    case h <> t:
      match n:
        case 0n:
          x_cat(acc)
        case 1n+p:
          x_take32.go(t, p, h <> acc)

def x_take32(n: U32, bs: List<&2, U32>) -> List<&2, U32>:
  x_take32.go(bs, U32.to_nat(n), Nil{})

def x_drop32.go(+bs: List<&2, U32>, +n: Nat) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case h <> t:
      match n:
        case 0n:
          h <> t
        case 1n+p:
          x_drop32.go(t, p)

def x_drop32(n: U32, bs: List<&2, U32>) -> List<&2, U32>:
  x_drop32.go(bs, U32.to_nat(n))

# Bounded walkers (TASK-026 Phase 2, from TASK-023 Phase 12 item 12.3):
# the question every frame and header path asks is "are there n bytes
# here?", never "how big is this buffer?". len_upto answers
# min(n, len(bs)) and has_at_least is that question, both stopping at n
# so the cost is bounded by n and not by whatever the buffer holds.
# Measured in TASK-023: has_at_least(9) 1,27 s against
# U32.is_le(9, x_len32(bs)) 34,22 s for 20000 calls (a full walk
# answering a 9-byte question), and x_len32(x_take32(n, bs)) 7,65 s
# against 2,50 s for the same answers. The counter is Nat for the reason
# above, and has_at_least reuses the walker so the boundary (a buffer
# that ends exactly at n) has one home.
def x_len_upto.go(+bs: List<&2, U32>, +n: Nat, +acc: Nat) -> U32:
  match bs:
    case Nil{}:
      U32.from_nat(acc)
    case _ <> t:
      match n:
        case 0n:
          U32.from_nat(acc)
        case 1n+p:
          x_len_upto.go(t, p, (1n + acc : Nat))

def x_len_upto(n: U32, bs: List<&2, U32>) -> U32:
  x_len_upto.go(bs, U32.to_nat(n), 0n)

def x_has_at_least(+n: U32, bs: List<&2, U32>) -> Bool:
  U32.is_eq(x_len_upto.go(bs, U32.to_nat(n), 0n), n)

def x_len32.go(+bs: List<&2, U32>, +acc: U32) -> U32:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      x_len32.go(t, (acc + 1 : U32))

def x_len32(bs: List<&2, U32>) -> U32:
  x_len32.go(bs, 0)

# U32-counted String ops (Phase 13 P1): String.length returns Nat and
# String.drop/take Nat in Base; these walk with U32 so the lib never
# needs to_nat/from_nat at the call site. Structural form mirrors
# x_len32.go (match String first) and x_drop32.go (U32 guard inside).
def x_str_len32.go(+s: String, +acc: U32) -> U32:
  match s:
    case SNil{}:
      acc
    case SCon{h, t}:
      x_str_len32.go(t, (acc + 1 : U32))

def x_str_len32(+s: String) -> U32:
  x_str_len32.go(s, 0)

def x_str_drop32.go(+s: String, +n: Nat) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{h, t}:
      match n:
        case 0n:
          SCon{h, t}
        case 1n+p:
          x_str_drop32.go(t, p)

def x_str_drop32(+s: String, +n: U32) -> String:
  x_str_drop32.go(s, U32.to_nat(n))

def x_eq.mul(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

# Structural equality, tail-recursive: the conjunction rides in acc,
# no frame held across the call, so 1M elements answer flat.
def x_eq.go(a: List<&2, U32>, b: List<&2, U32>, +acc: U32) -> U32:
  match a b:
    case Nil{} Nil{}:
      acc
    case h1 <> t1 h2 <> t2:
      x_eq.go(t1, t2, x_eq.mul(acc, U32.is_eq(h1, h2)))
    case _ _:
      0

def x_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  x_eq.go(a, b, 1)

# ASCII-only String to bytes, tail-recursive: one cons per char,
# reversed acc plus one x_cat, 1M chars safe. Same tail discipline
# as x_utf8_encode.go (input spine dropped, single acc).
def x_str_bytes.go(+s: String, acc: List<&2, U32>) -> List<&2, U32>:
  match s:
    case SNil{}:
      x_cat(acc)
    case SCon{h, t}:
      match h:
        case Chr{code}:
          x_str_bytes.go(t, code <> acc)

def x_str_bytes(+s: String) -> List<&2, U32>:
  x_str_bytes.go(s, Nil{})

# Chunk size for stack-safe bytes->String (below).
# 1024 is measured, not taste: at 1M bytes it decodes faster than
# 8192 (median 335ms vs 440ms over 5 runs) and it keeps a wide
# margin under effects -- reaching an effect deepens the
# interpreter's machine stack, so the per-chunk depth (one frame
# per code point) stays a small fraction of the ceiling. Both sizes
# survive 1M bodies with 200 held frames and effects in between.
def x_str_chunk() -> U32:
  1024

# Stack-safe bytes->String: a byte-per-frame loop is linear-recursive
# (1 frame per byte), so a ~1MB body overflows the interp machine stack.
# Split into 1KB chunks (each converted with bounded depth), collect the
# chunk Strings reversed via a tail-recursive loop, then reverse +
# String.concat (depth = chunk count, ~977 per MB). Same bytes out.
# ---------------------------------------------------------------------

# Converts one reversed chunk straight to String, no x_cat pass:
# walking [c3, c2, c1] while prepending yields c1 <> c2 <> c3 in
# order. Tail loop, depth bounded by the chunk size.
def x_chunk_str.go(+rev: List<&2, U32>, acc: String) -> String:
  match rev:
    case Nil{}:
      acc
    case b <> t:
      x_chunk_str.go(t, SCon{Chr{b}, acc})

# Chunk counter is Nat on the inside and U32 on the API: U32 is
# Data, so every decrement boxes, while Nat matches 1n+p without
# allocating. Same shape as x_take32.go (Nat inside, one conversion
# per chunk at flush time, not per element).
def x_str_chunks.go(+bs: List<&2, U32>, +n: Nat, acc: List<&2, String>, +ch: List<&2, U32>) -> List<&2, String>:
  match bs:
    case Nil{}:
      x_chunk_str.go(ch, SNil{}) <> acc
    case h <> t:
      match n:
        case 0n:
          x_str_chunks.go(t, U32.to_nat((x_str_chunk() - 1 : U32)), x_chunk_str.go(ch, SNil{}) <> acc, [h])
        case 1n+p:
          x_str_chunks.go(t, p, acc, h <> ch)

def x_str_chunks(+bs: List<&2, U32>) -> List<&2, String>:
  x_str_chunks.go(bs, U32.to_nat(x_str_chunk()), Nil{}, Nil{})

def x_bytes_str(bs: List<&2, U32>) -> String:
  String.concat(List.reverse(&2, String, x_str_chunks(bs)))

# UTF-8 (RFC 3629): the text lane for fetch/request bodies. The x_str_bytes
# / x_bytes_str pair above is ASCII-only (raw code points, one byte each)
# and stays for the wire renderers (headers, HPACK, request lines); real
# text rides here. Ported verbatim from lib/wsm.bend's wsm_utf8_* (TASK-036
# Phase 3) — range-dispatched, no literal tables — so the two share one
# machine: bad sequences decode leniently (U+FFFD or dropped, never Fail),
# exactly like the wsm message path today; the strict gate is x_utf8_ok.
# ---------------------------------------------------------------------

def x_utf8_encode.go2(+code: U32) -> List<&2, U32>:
  b1 = (192 + U32.shrn(code, 6n) : U32)
  b2 = (128 + U32.and(code, 63) : U32)
  [b1, b2]

def x_utf8_encode.go3(+code: U32) -> List<&2, U32>:
  b1 = (224 + U32.shrn(code, 12n) : U32)
  b2 = (128 + U32.and(U32.shrn(code, 6n), 63) : U32)
  b3 = (128 + U32.and(code, 63) : U32)
  [b1, b2, b3]

def x_utf8_encode.go4(+code: U32) -> List<&2, U32>:
  b1 = (240 + U32.shrn(code, 18n) : U32)
  b2 = (128 + U32.and(U32.shrn(code, 12n), 63) : U32)
  b3 = (128 + U32.and(U32.shrn(code, 6n), 63) : U32)
  b4 = (128 + U32.and(code, 63) : U32)
  [b1, b2, b3, b4]

def x_utf8_encode.big(code: U32, is2: Bool, is3: Bool) -> List<&2, U32>:
  match is2 is3:
    case True{} _:
      x_utf8_encode.go2(code)
    case False{} True{}:
      x_utf8_encode.go3(code)
    case False{} False{}:
      x_utf8_encode.go4(code)

def x_utf8_encode.small(code: U32, is1: Bool, is2: Bool, is3: Bool) -> List<&2, U32>:
  match is1:
    case True{}:
      [code]
    case False{}:
      x_utf8_encode.big(code, is2, is3)

def x_utf8_encode_char(+code: U32) -> List<&2, U32>:
  x_utf8_encode.small(code, U32.is_lt(code, 128), U32.is_lt(code, 2048), U32.is_lt(code, 65536))

def x_utf8_encode.one(c: Char) -> List<&2, U32>:
  match c:
    case Chr{code}:
      x_utf8_encode_char(code)

# ASCII fast push: one cons, no per-char dispatch or append.
# Same tail discipline as length_th in test.bend: the input spine is
# dropped as it is consumed and the single acc carries the answer.
# Multibyte chars keep the bounded rev_push path (2-4 byte frags).
def x_utf8_encode.push(+code: U32, acc: List<&2, U32>, is_ascii: Bool) -> List<&2, U32>:
  match is_ascii:
    case True{}:
      code <> acc
    case False{}:
      x_rev_push(x_utf8_encode_char(code), acc)

# Tail encode: counts nothing, rebuilds reversed in acc.
# Every arm passes the extended accumulator as an argument, so no
# frame is held across the call, and x_cat un-reverses once at the end.
def x_utf8_encode.go(+s: String, acc: List<&2, U32>) -> List<&2, U32>:
  match s:
    case SNil{}:
      x_cat(acc)
    case SCon{h, t}:
      match h:
        case Chr{code}:
          x_utf8_encode.go(t, x_utf8_encode.push(code, acc, U32.is_lt(code, 128)))

# Encodes text to UTF-8 bytes, tail-recursive, 1M chars safe.
def x_utf8_encode(s: String) -> List<&2, U32>:
  x_utf8_encode.go(s, Nil{})

def x_utf8_is_cont(+b: U32) -> Bool:
  Bool.and(U32.is_ge(b, 128), U32.is_le(b, 191))

def x_utf8_need(+b: U32) -> U32:
  Bool.pick(U32, U32.is_lt(b, 128), 0, Bool.pick(U32, U32.is_lt(b, 194), 9, Bool.pick(U32, U32.is_lt(b, 224), 1, Bool.pick(U32, U32.is_lt(b, 240), 2, Bool.pick(U32, U32.is_le(b, 244), 3, 9)))))

def x_utf8_min(+need: U32) -> U32:
  match need:
    case 1:
      128
    case 2:
      2048
    case 3:
      65536
    case _:
      0

def x_utf8_mask(+need: U32) -> U32:
  match need:
    case 1:
      31
    case 2:
      15
    case 3:
      7
    case _:
      0

def x_utf8_code_ok(+code: U32, +min: U32) -> Bool:
  Bool.and(U32.is_ge(code, min), Bool.and(Bool.not(Bool.and(U32.is_ge(code, 55296), U32.is_le(code, 57343))), U32.is_le(code, 1114111)))

def x_utf8_fin2(+code2: U32, +min: U32) -> U32:
  Bool.pick(U32, x_utf8_code_ok(code2, min), 0, 9)

def x_utf8_fin(+code: U32, +min: U32, +b: U32) -> U32:
  Bool.pick(U32, x_utf8_is_cont(b), x_utf8_fin2((code * 64 + U32.and(b, 63) : U32), min), 9)

def x_utf8_go(+bs: List<&2, U32>, +need: U32, +min: U32, +code: U32) -> Bool:
  match bs:
    case Nil{}:
      U32.is_zero(need)
    case b <> t:
      match need:
        case 0:
          +nb = x_utf8_need(b)
          x_utf8_go(t, nb, x_utf8_min(nb), U32.and(b, x_utf8_mask(nb)))
        case 1:
          x_utf8_go(t, x_utf8_fin(code, min, b), 0, 0)
        case 2:
          x_utf8_go(t, Bool.pick(U32, x_utf8_is_cont(b), 1, 9), min, (code * 64 + U32.and(b, 63) : U32))
        case 3:
          x_utf8_go(t, Bool.pick(U32, x_utf8_is_cont(b), 2, 9), min, (code * 64 + U32.and(b, 63) : U32))
        case _:
          False{}

def x_utf8_ok(bs: List<&2, U32>) -> Bool:
  x_utf8_go(bs, 0, 0, 0)

# Keeps the accumulator when the sequence is still valid, and adds one
# U+FFFD in front of it when the sequence aborts.
def x_utf8_fffd(is_ok: Bool, acc: List<&2, U32>) -> List<&2, U32>:
  match is_ok:
    case True{}:
      acc
    case False{}:
      65533 <> acc

# Stack-safe utf-8 decode. The old one-frame-per-byte machine held one
# (SCon{Chr{...}, <self>}), which is fine for a header and fatal for a
# body: 16384 bytes decode, 32768 die with "memory fault (machine stack
# overflow?)" -- measured, and it is what every String body over ~32 KB
# hit (cloudflare.com, api.binance.com exchangeInfo). fetch_bytes answers
# the same hosts fine: its lane is the byte lane, and this decode is the
# only step that differs.
#
# Two changes, both about the stack, and neither about the bytes:
#
#   1. the decode itself becomes a tail-recursive loop that accumulates
#      code points into a reversed list -- every arm passes the extended
#      accumulator as an ARGUMENT, so no frame is held across the call and
#      the walk is constant-stack whatever the body is;
#   2. the code points become a String through the chunked converter
#      already used for byte bodies (x_str_chunks/x_bytes_str), whose
#      depth is one frame per code point INSIDE a chunk of x_str_chunk().
#
# No chunk boundary can split a sequence here: the state machine carries
# (need, min, code) across the whole body, so the only "boundary" is
# between two already-decoded code points. Every continuation byte is
# checked with the rules x_utf8_ok uses: a non-continuation byte, or a
# code point out of range, aborts the sequence and the pair answers one
# U+FFFD. That is what the invalid-lead arm (need 9) already did.
def x_utf8_decode.go(+bs: List<&2, U32>, +need: U32, +min: U32, +code: U32,
  acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      match need:
        case 8:
          code <> acc
        case _:
          acc
    case b <> t:
      match need:
        case 0:
          +is0 = U32.is_lt(b, 128)
          +nb0 = Bool.pick(U32, is0, 8, x_utf8_need(b))
          x_utf8_decode.go(t, nb0, x_utf8_min(nb0),
            Bool.pick(U32, is0, b, U32.and(b, x_utf8_mask(nb0))),
            acc)
        case 1:
          +is_c = x_utf8_is_cont(b)
          +code1 = (code * 64 + U32.and(b, 63) : U32)
          +ok1 = Bool.and(is_c, x_utf8_code_ok(code1, min))
          x_utf8_decode.go(t, 0, 0, 0,
            Bool.pick(U32, ok1, code1, 65533) <> acc)
        case 2:
          +is_c2 = x_utf8_is_cont(b)
          x_utf8_decode.go(t, Bool.pick(U32, is_c2, 1, 0),
            Bool.pick(U32, is_c2, min, 0),
            Bool.pick(U32, is_c2, (code * 64 + U32.and(b, 63) : U32), 0),
            x_utf8_fffd(is_c2, acc))
        case 3:
          +is_c3 = x_utf8_is_cont(b)
          x_utf8_decode.go(t, Bool.pick(U32, is_c3, 2, 0),
            Bool.pick(U32, is_c3, min, 0),
            Bool.pick(U32, is_c3, (code * 64 + U32.and(b, 63) : U32), 0),
            x_utf8_fffd(is_c3, acc))
        case 8:
          +nb8 = Bool.pick(U32, U32.is_lt(b, 128), 8, x_utf8_need(b))
          x_utf8_decode.go(t, nb8, x_utf8_min(nb8),
            Bool.pick(U32, U32.is_lt(b, 128), b, U32.and(b, x_utf8_mask(nb8))),
            code <> acc)
        case _:
          x_utf8_decode.go(t, 0, 0, 0, 65533 <> acc)

def x_utf8_decode.codes(+bs: List<&2, U32>) -> List<&2, U32>:
  x_utf8_decode.go(bs, 0, 0, 0, Nil{})

# Decodes UTF-8 bytes to text, tail-recursive, 1M bytes safe.
# Same bytes as the legacy one-frame-per-byte machine above, constant
# stack: code points accumulate reversed, then convert chunked.
def x_utf8_decode(+bs: List<&2, U32>) -> String:
  String.concat(List.reverse(&2, String,
    x_str_chunks(x_cat(x_utf8_decode.codes(bs)))))

# Small string helpers (reuse Base String.* everywhere else)

def has_crlf(+s: String) -> Bool:
  Bool.or(String.contains(s, "\r"), String.contains(s, "\n"))

def has_crlf3(a: String, b: String, c: String) -> Bool:
  Bool.or(has_crlf(a), Bool.or(has_crlf(b), has_crlf(c)))

def nul1() -> String:
  String.from_list([Chr{0}])

def has_nul(s: String) -> Bool:
  String.contains(s, nul1())

# Every char is an ASCII digit. Two callers: the A-record quad check
# (dns.bend) and the Content-Length check (http1.bend). Not tail-recursive,
# and it does not need to be: a dotted-quad octet is 1-3 chars and a header
# value stays under the 16 KB H1 head cap. test.bend measured the stack
# limit at 500000 elements, so the depth never gets close.
def all_digits.put(is_dig: Bool, rest: Bool) -> Bool:
  match is_dig:
    case True{}:
      rest
    case False{}:
      False{}

def all_digits(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+h, +t}:
      all_digits.put(Char.is_digit(h), all_digits(t))

def x_be32(+v: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(v, 24n), 255), U32.and(U32.shrn(v, 16n), 255), U32.and(U32.shrn(v, 8n), 255), U32.and(v, 255)]

# Types
# -----

type Hdr is Data:
  Hdr{name: String, value: String}

type ReqHead is Data:
  ReqHead{method: String, path: String, headers: List<&2, Hdr>}

# The parsed H1 request head plus the version flag the Host rule keys on
# (RFC 9112 section 3.2 asks for 400 on a missing Host for HTTP/1.1
# requests only, and the request-line parse is where the version is known).
# A Data type, not a pair: the value travels inside a Result inside another
# pair in the streaming lane, and bend 2.0.36 cannot infer a Sigma whose
# second half is a Bool in that position.
type H1Head is Data:
  H1Head{head: ReqHead, is_11: Bool}

type Request is Data:
  Request{method: String, path: String, headers: List<&2, Hdr>, body: List<&2, U32>}

type Response is Data:
  Response{status: U32, headers: List<&2, Hdr>, body: List<&2, U32>}

type Head is Data:
  Head{status: U32, headers: List<&2, Hdr>}

# Framing decision for one H1 message (TASK-036 Phase 3): the
# length-delimited / chunked / absent answer the lanes derive from the
# head, carried as one value so Phase 6 handlers never re-derive it.
# Field-for-field identical to lib/core/type.bend's CT.BodyFrame.
type BodyFrame is Data:
  BodyFrame{cl: U32, chunked: Bool, no_body: Bool}

# One stream slot, shared by the server and the client engines
# (TASK-055 phase 4a). The head rides a tag: the server stores a ReqHead
# and the client stores a Head, and Bend has no generics.
type SlotHead is Data:
  SlotReq{rh: ReqHead}
  SlotResp{h: Head}

type St is Data:
  St{head: Maybe<&2, SlotHead>, body: List<&2, U32>, sid: U32}

# One frame: the type, the flags, the stream id, the declared length of the
# payload (the length field of the 9-byte header, RFC 9113 section 4.1) and
# the payload. A DATA frame keeps its padding, so len is its payload size;
# a padded HEADERS frame loses the padding here, so len is the count before
# the strip. The receive path credits len, so it never walks the payload
# (TASK-063 phase 5).
type Frame is Data:
  Frame{typ: U32, flags: U32, sid: U32, len: U32, payload: List<&2, U32>}

# One step of the frame decoder: a unit came out, the bytes are not all
# here yet, the message ended, or the bytes are invalid (TASK-026 Phase 3,
# from TASK-023 Phases 9/11). The unit is RAW BYTES — x_frame_of(unit)
# builds the Frame record — and NeedMore carries the buffer back because a
# decoder that consumed bytes has to hand them over. End has no producer
# in this lane (a frame stream has no terminator), and it exists because
# the shape mirrors lib/core/type.bend's CT.UnitOut one for one: the day
# the lanes share a contract it is a requalification, not a redesign, and
# a match over four variants names all four.
type UnitOut is Data:
  Got{unit: List<&2, U32>, fin: Bool, rest: List<&2, U32>}
  NeedMore{missing: U32, rest: List<&2, U32>}
  End{rest: List<&2, U32>}
  Bad{code: U32, msg: String}

type Got is Data:
  GotOk{frame: Frame, buf: List<&2, U32>}
  GotErr{code: U32, msg: String}

# Dynamic table, newest entry at the head; size sums entry sizes
# (len(name) + len(value) + 32); max is the protocol limit 4096.
# Per-connection state threaded through the decode loop (never in slots).
type Tab is Data:
  Tab{ents: List<&2, Hdr>, size: U32, max: U32}

type HdrGot is Data:
  HdrGot{name: String, value: String, rest: List<&2, U32>, tab: Tab}

type Taken is Data:
  Taken{slots: List<&2, St>, st: St}

type FendTaken is Data:
  FendTaken{fends: List<&2, U32>, flag: U32}

type Cont is Data:
  Cont{block: List<&2, U32>, rest: List<&2, U32>, end: U32}

# sid, the HPACK table, the H2 flag and cw: the connection send window
# the client has left (task-063 phase 7a). cw starts at x_init_window()
# and the send pump seeds from it, so two bodies on one connection never
# pass the credit the peer granted.
type CliSt is Data:
  CliSt{sid: U32, tab: Tab, is_h2: Bool, cw: U32}

type StreamEv is Data:
  StreamHead{head: Head}
  StreamData{chunk: List<&2, U32>, fin: Bool}

type StreamOut is Data:
  StreamContinue{}
  StreamCancel{}

type SrvEv is Data:
  SrvReqHead{slot: U32, head: ReqHead}
  SrvReqData{slot: U32, chunk: List<&2, U32>, fin: Bool}

type SrvOut is Data:
  Continue{}
  RespondEarly{resp: Response}
  Cancel{}

# State of the H1 chunked decoder. The design note lives with the step
# that resumes from it (x_h1.chunk_* in the H1 module).
type ChunkSt is Data:
  ChunkSt{st: U32, rem: Nat, size: U32, acc: List<&2, List<&2, U32>>}

# The constructor names carry the C- prefix: Bend keeps one constructor
# namespace for each file, so StreamHead/StreamData/StreamContinue/
# StreamCancel belong to StreamEv/StreamOut above (probe measured on
# 2026-10-16: two constructors with one name in one file fail to
# compile).
type CStreamEv is Data:
  CStreamHead{slot: U32, head: Head}
  CStreamData{slot: U32, chunk: List<&2, U32>, fin: Bool}

type CStreamOut is Data:
  CStreamContinue{slot: U32}
  CStreamCancel{slot: U32}

# Request-head validation shared by both protocols. The client lanes call
# it before any byte goes on the wire, and a False answer becomes Fail 400.
def client.on.has_host_bad(+h: String) -> Bool:
  Bool.or(String.contains(h, "/"),
    Bool.or(String.contains(h, "?"),
      Bool.or(String.contains(h, "#"), String.contains(h, "@"))))

# Last stage of the host and path validators: a bad flag fails, and the
# space flag is negated. Two 6-line copies lived here (TASK-055 phase 3b).
def client.on.valid_last(bad: Bool, sp: Bool) -> Bool:
  match bad:
    case True{}:
      False{}
    case False{}:
      Bool.not(sp)

def client.on.valid_host.put2(crlf: Bool, bad: Bool, sp: Bool) -> Bool:
  match crlf:
    case True{}:
      False{}
    case False{}:
      client.on.valid_last(bad, sp)

def client.on.valid_host.put(empty: Bool, crlf: Bool, bad: Bool, sp: Bool) -> Bool:
  match empty:
    case True{}:
      False{}
    case False{}:
      client.on.valid_host.put2(crlf, bad, sp)

def client.on.valid_host(+h: String) -> Bool:
  client.on.valid_host.put(String.is_empty(h), Bool.or(has_crlf(h), has_nul(h)), client.on.has_host_bad(h), String.contains(h, " "))

def client.on.valid_port(+p: U32) -> Bool:
  Bool.and(U32.is_ge(p, 1), U32.is_le(p, 65535))

def client.on.valid_path.put(slash: Bool, crlf: Bool, sp: Bool) -> Bool:
  match slash:
    case True{}:
      client.on.valid_last(crlf, sp)
    case False{}:
      False{}

def client.on.valid_path(+p: String) -> Bool:
  client.on.valid_path.put(String.starts_with(p, "/"), Bool.or(has_crlf(p), has_nul(p)), String.contains(p, " "))

def client.on.valid.go(+host: String, +port: U32, +path: String) -> Bool:
  Bool.and(client.on.valid_host(host), Bool.and(client.on.valid_port(port), client.on.valid_path(path)))

# Upload cap removed (item 2): the flow sender slices DATA to peer windows
# (server gives WU per DATA). Bodies any size go through; the H1 lane keeps
# its own fail-closed 16KB server cap (subset decision, untouched).
def client.on.body_ok(+body: List<&2, U32>) -> Bool:
  True{}

def client_conc.count_go(reqs: List<&2, Request>, +acc: U32) -> U32:
  match reqs:
    case Nil{}:
      acc
    case _ <> t:
      client_conc.count_go(t, (acc + 1 : U32))

def client_conc.count(reqs: List<&2, Request>) -> U32:
  client_conc.count_go(reqs, 0)

def client_conc.valid_go(reqs: List<&2, Request>, +host: String, +port: U32, ok: Bool) -> Bool:
  match reqs:
    case Nil{}:
      ok
    case Request{method, path, headers, body} <> t:
      client_conc.valid_go(t, host, port, Bool.and(ok, Bool.and(client.on.valid.go(host, port, path), client.on.body_ok(body))))

def client_conc.valid_all(reqs: List<&2, Request>, +host: String, +port: U32) -> Bool:
  client_conc.valid_go(reqs, host, port, True{})
