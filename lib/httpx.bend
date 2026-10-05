# Httpx standalone server with a mini H2 codec inside (no http2 import).
#
# Isolation build: the full codec (lib/http2.bend, 4384 lines: Huffman
# tables rebuilt per probe, dynamic HPACK table, flow credit, client
# drain machinery) dominated httpx runtime/memory. This file serves
# interleaved H2 streams with the smallest codec that stays wire-faithful
# to literal (unindexed) peers:
# - frames: 9-byte header parse (split-safe), preface magic, SETTINGS
#   (fresh ack), PING (ack), GOAWAY (close), RST_STREAM (drop slot),
#   WINDOW_UPDATE (skip when valid), CONTINUATION fragments, unknown skip.
# - HPACK: literal without/with indexing (new, static or dynamic name)
#   plus full-indexed static 1-7 and dynamic refs, raw or Huffman
#   strings, minimal dynamic table (insert + evict + resize, cap 4096).
#   Huffman tables and dyn ops cost pay-per-use (only Huffman/indexing
#   peers enter them; raw literal peers never do).
# - responses: literal-only :status + headers, one DATA frame (cap 16KB).
# No flow-credit sends, no padding/priority parsing, no client.
#
# Stack: TLS (accept) -> mini-H2 below -> httpx slots. Allowed imports:
# Base + ./tls.bend + ./tcp.bend + ./dns.bend (the byte lanes; dns is needed
# by the plaintext dial, which resolves the name the TLS lane resolves for
# it). No https/http/https_http1/ws/wss/http2.
#
# Discipline (same as lib/https.bend): callee above caller; match
# scrutinees are params or pattern-bound vars; self-recursion only
# (@unsafe for fuel-bounded decode, frame read, accept/stream loops);
# + binders only for Data.
#
# Import as: import ./httpx.bend as HTTPX (from lib) or
# import ../../lib/httpx.bend as HTTPX (from tests/io).
import Base
import ./tls.bend as TLS
import ./tcp.bend as TCPB
import ./dns.bend as DNS

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

# Reversed body push (stack-safe accumulation for big bodies):
# List.append is linear-recursive (depth = len of the first list), so
# appending each DATA onto a growing body overflows the interp machine
# stack past ~1MB (cloudflare fetch: 1326902 bytes). Keep in-flight
# bodies REVERSED — per-DATA work stays bounded by chunk size (reverse
# the 16KB frag tail-recursively, append in front) — and un-reverse
# once with x_cat (tail-recursive loop) at the finish site. All
# drain/slot bodies below are rev-bodies; finish sites x_cat them.
# ---------------------------------------------------------------------

def x_rev_push(+frag: List<&2, U32>, +rev: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, x_cat(frag), rev)

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

# U32-counted list ops for the flow sender (Phase 12 item 2): the Nat
# versions above force to_nat/from_nat conversions at every chunk step;
# these keep the whole send path in U32 (RFC windows are U32).
#
# The counter is Nat on the inside and the API is U32 (TASK-026 Phase 2,
# from TASK-023 Phases 12/13): U32 is Data U32{data: Word(32n)}, so every
# decrement boxes and every guard is a match over Data, while Nat matches
# 1n+p without allocating. Same shape (reversed build + x_cat), 16 KiB
# buffer, measured in TASK-023: take 9,52 s -> 3,61 s and drop 12,92 s ->
# 2,81 s for 200/400 calls. The conversion is O(1) and happens once per
# call, not once per element.
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

def x_str_drop32.go(+s: String, +n: U32) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{h, t}:
      match n:
        case 0:
          SCon{h, t}
        case _:
          x_str_drop32.go(t, (n - 1 : U32))

def x_str_drop32(+s: String, +n: U32) -> String:
  x_str_drop32.go(s, n)

def x_eq.mul(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def x_eq.go(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      x_eq.mul(x_eq.go(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

def x_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  x_eq.go(a, b)

def x_str_bytes.go(+s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{Chr{c}, t}:
      List.append(&2, U32, [c], x_str_bytes.go(t))

def x_str_bytes(+s: String) -> List<&2, U32>:
  x_str_bytes.go(s)

def x_bytes_str.go(+bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case +b <> t:
      SCon{Chr{b}, x_bytes_str.go(t)}

# Chunk size for stack-safe bytes->String (below).
def x_str_chunk() -> U32:
  8192

# Stack-safe bytes->String: x_bytes_str.go is linear-recursive (1 frame
# per byte), so a ~1MB body overflows the interp machine stack. Split
# into 8KB chunks (each converted with bounded depth), collect the
# chunk Strings reversed via a tail-recursive loop, then reverse +
# String.concat (depth = chunk count, ~166 per MB). Same bytes out.
# ---------------------------------------------------------------------

def x_str_chunks.go(+bs: List<&2, U32>, +n: U32, acc: List<&2, String>, +ch: List<&2, U32>) -> List<&2, String>:
  match bs:
    case Nil{}:
      x_bytes_str.go(x_cat(ch)) <> acc
    case h <> t:
      match n:
        case 0:
          x_str_chunks.go(t, (x_str_chunk() - 1 : U32), x_bytes_str.go(x_cat(ch)) <> acc, [h])
        case _:
          x_str_chunks.go(t, (n - 1 : U32), acc, h <> ch)

def x_str_chunks(+bs: List<&2, U32>) -> List<&2, String>:
  x_str_chunks.go(bs, x_str_chunk(), Nil{}, Nil{})

def x_bytes_str(bs: List<&2, U32>) -> String:
  String.concat(List.reverse(&2, String, x_str_chunks(bs)))

# Consts
# ------

def x_f_ack() -> U32:
  1

def x_f_end_stream() -> U32:
  1

def x_f_end_headers() -> U32:
  4

def x_t_data() -> U32:
  0

def x_t_headers() -> U32:
  1

def x_t_rst() -> U32:
  3

def x_t_settings() -> U32:
  4

def x_t_ping() -> U32:
  6

def x_t_goaway() -> U32:
  7

def x_t_wu() -> U32:
  8

def x_t_cont() -> U32:
  9

def x_max_frame() -> U32:
  65535

def x_max_send() -> U32:
  16384

# RFC 9113 section 6.9.2 default: both connection and per-stream send
# windows start here; the peer SETTINGS INITIAL_WINDOW_SIZE picked up
# mid-send only ever raises the stream window from this base.
def x_init_window() -> U32:
  65535

def x_max_str() -> U32:
  65535

def x_b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" as bytes (no String compare needed).
def x_preface() -> List<&2, U32>:
  [80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10]

def x_be32(+v: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(v, 24n), 255), U32.and(U32.shrn(v, 16n), 255), U32.and(U32.shrn(v, 8n), 255), U32.and(v, 255)]

# Initial SETTINGS we announce (RFC 9113 section 6.5): INITIAL_WINDOW_SIZE
# 65535 + MAX_FRAME_SIZE 65535 (dono decision; Chrome announces 6MB but
# 65535 is the RFC default and what node uses). Sent at all 4 preface
# points; ACKs stay empty (ack-with-payload would be a protocol error).
def x_be16(+v: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(v, 8n), 255), U32.and(v, 255)]

def x_settings_initial_pay() -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, x_be16(4), x_be32(65535)), List.append(&2, U32, x_be16(5), x_be32(65535)))

# Types
# -----

type Hdr is Data:
  Hdr{name: String, value: String}

type ReqHead is Data:
  ReqHead{method: String, path: String, headers: List<&2, Hdr>}

type Request is Data:
  Request{method: String, path: String, headers: List<&2, Hdr>, body: List<&2, U32>}

type Response is Data:
  Response{status: U32, headers: List<&2, Hdr>, body: List<&2, U32>}

type Head is Data:
  Head{status: U32, headers: List<&2, Hdr>}

type St is Data:
  St{head: Maybe<&2, ReqHead>, body: List<&2, U32>, sid: U32}

type Frame is Data:
  Frame{typ: U32, flags: U32, sid: U32, payload: List<&2, U32>}

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

# Frame write
# -----------

def x_frame_write.cat(h: List<&2, U32>, t: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, h, t)

def x_frame_write.hdr(+len: U32, +typ: U32, +flags: U32, +sid: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(len, 16n), 255), U32.and(U32.shrn(len, 8n), 255), U32.and(len, 255),
   U32.and(typ, 255), U32.and(flags, 255),
   U32.and(U32.shrn(sid, 24n), 255), U32.and(U32.shrn(sid, 16n), 255),
   U32.and(U32.shrn(sid, 8n), 255), U32.and(sid, 255)]

def x_frame_write(+typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> List<&2, U32>:
  +len = x_len32(pay)
  x_frame_write.cat(x_frame_write.hdr(len, typ, flags, sid), pay)

def x_send_frame(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, x_frame_write(typ, flags, sid, pay))

def x_send_goaway.pay(+last: U32, +code: U32) -> List<&2, U32>:
  List.append(&2, U32, x_be32(last), x_be32(code))

def x_send_goaway(sock: Socket, +last: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_goaway(), 0, 0, x_send_goaway.pay(last, code))

# Frame parse (split-safe: NeedMore carries the missing count)
# ------------------------------------------------------------

def x_strip_pad.go(+pay: List<&2, U32>, +n: U32, +m: U32) -> List<&2, U32>:
  x_take32(n, x_drop32(m, pay))

def x_strip_pad_ok(+dist: U32, +len: U32) -> Bool:
  U32.is_gt(len, dist)

def x_strip_pad.last(+pay: List<&2, U32>, +len: U32, +p0: U32, ok: Bool) -> List<&2, U32>:
  match ok:
    case True{}:
      # RFC 9113 section 6.1: the pad-length byte is the FIRST byte (x_strip_pad.first
      # already dropped it into `pay`) and the padding octets are the LAST p0 bytes,
      # so the length drops by p0 + 1 and nothing else comes off the front. (The HTTPX
      # golden only measured the length of a p0 = 1 frame, where dropping p0 more
      # bytes gave the same count with the wrong content.)
      x_strip_pad.go(pay, (len - (p0 + 1 : U32) : U32), 0)
    case False{}:
      Nil{}

def x_strip_pad.first(pay: List<&2, U32>, +len: U32) -> List<&2, U32>:
  match pay:
    case Nil{}:
      Nil{}
    case +p0 <> pret:
      x_strip_pad.last(pret, len, p0, x_strip_pad_ok(p0, len))

def x_strip_pad.dec(+pay: List<&2, U32>, +len: U32, has_pad: Bool) -> List<&2, U32>:
  match has_pad:
    case False{}:
      pay
    case True{}:
      x_strip_pad.first(pay, len)

def x_strip_pad(+pay: List<&2, U32>, has_pad: Bool, +len: U32) -> List<&2, U32>:
  x_strip_pad.dec(pay, len, has_pad)

def x_strip_prio(+pay: List<&2, U32>, has_prio: Bool) -> List<&2, U32>:
  match has_prio:
    case False{}:
      pay
    case True{}:
      x_drop32(5, pay)

def x_frame_payload(+pay: List<&2, U32>, +typ: U32, +flags: U32, +len: U32) -> List<&2, U32>:
  x_strip_prio(x_strip_pad(pay, U32.is_eq(U32.and(flags, 8), 8), len), U32.is_eq(U32.and(flags, 32), 32))

# END_STREAM is flag bit 0, and it is the protocol-neutral fin of the
# shared outcome.
def x_frame.end_of(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, x_f_end_stream()), 1)

# The 3 length bytes and the 4 stream id bytes of the frame header
# (RFC 9113 section 4.1), as arithmetic. They are here, and not written
# twice, because this lane has two readers of the header: the walk below,
# which peels the bytes off a shrinking buffer one at a time, and
# x_frame_of, which reads them by position out of a whole frame. Same two
# numbers, one code each.
def x_frame.len3(+l0: U32, +l1: U32, +l2: U32) -> U32:
  (l0 * 65536 + l1 * 256 + l2 : U32)

def x_frame.sid4(+s0: U32, +s1: U32, +s2: U32, +s3: U32) -> U32:
  (s0 * 16777216 + s1 * 65536 + s2 * 256 + U32.and(s3, 127) : U32)

# The record one frame's raw bytes decode to — the price this lane pays
# for the shared outcome (TASK-026 Phase 3). UnitOut's unit is RAW BYTES
# (TASK-023 Phase 9 item 2.2), so the Frame the walk used to build in
# place is built here, from the 9 header bytes the unit starts with. Only
# the reading differs from the walk's; the arithmetic above is shared and
# the strip is the same x_frame_payload.
#
# at answers the i-th header byte, 0 past the end. That arm is
# unreachable from the codec — a Got's unit is 9 + len bytes by
# construction — and it exists so this stays one def instead of a
# nine-deep cascade of Nil arms.
@unsafe
def x_frame_of.at.go(+hd: List<&2, U32>, i: U32) -> U32:
  match hd:
    case Nil{}:
      0
    case b <> t:
      match i:
        case 0:
          b
        case _:
          x_frame_of.at.go(t, (i - 1 : U32))

def x_frame_of.at_i(hd: List<&2, U32>, i: U32) -> U32:
  x_frame_of.at.go(hd, i)

def x_frame_of(+unit: List<&2, U32>) -> Frame:
  +hd = List.take(&2, U32, unit, 9n)
  +len = x_frame.len3(x_frame_of.at_i(hd, 0), x_frame_of.at_i(hd, 1), x_frame_of.at_i(hd, 2))
  +typ = x_frame_of.at_i(hd, 3)
  +flags = x_frame_of.at_i(hd, 4)
  +sid = x_frame.sid4(x_frame_of.at_i(hd, 5), x_frame_of.at_i(hd, 6), x_frame_of.at_i(hd, 7), x_frame_of.at_i(hd, 8))
  Frame{typ, flags, sid, x_frame_payload(x_drop32(9, unit), typ, flags, len)}

# Frame walk
# ----------
# The walk answers UnitOut, so it is Got / NeedMore / End / Bad — three
# outcomes plus the one this lane cannot produce. What each means here:
# - Got{unit = the WHOLE FRAME, fin = END_STREAM, rest = the tail}: the
#   header is complete and the payload is there. The unit is raw bytes and
#   it starts at the frame header, because that is the slice x_frame_of
#   reads the record out of (it takes the first 9 bytes as the header and
#   strips pad/prio from the rest). The walk carries the buffer it started
#   with — `orig` on every def below — precisely so the slice is taken
#   once, at x_frame.fin3, from the whole buffer: the bytes are otherwise
#   unrecoverable, since the walk has already eaten the nine header bytes
#   off its own copy;
# - NeedMore{missing, rest}: fewer than 9 header bytes, or fewer payload
#   bytes than the length declares. missing counts what is still owed,
#   which is the split-safe path (a 9-byte header across two reads);
# - Bad{code, msg}: a protocol error — 413 above the max frame size, 400
#   on the eof that closed a half-frame, or whatever the socket reported.
#   The eof answer is deliberately Bad and not End: a truncated frame is
#   an error;
# - End: nothing in this lane produces it. A frame stream has no
#   terminator, so "the message is complete" has no H2 meaning; x_read_loop
#   carries the arm because the type has four and a match needs all of
#   them, and it answers the only thing that can be true if it ever
#   arrives (the connection is done).
def x_frame.fin3(+orig: List<&2, U32>, +flags: U32, +len: U32) -> UnitOut:
  +whole = (9 + len : U32)
  Got{x_take32(whole, orig), x_frame.end_of(flags), x_drop32(whole, orig)}

# Pad/prio strip (RFC 9113 6.1/6.2): PADDED rides flag 8 with a pad
# length prefix (must be < payload, else protocol error), PRIORITY
# rides flag 32 with a 5-byte fixed field. Frames without the flags come
# through untouched (passthrough gate in x_strip_pad.dec).
def x_frame.fin2(orig: List<&2, U32>, typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32, ok: Bool) ->
  UnitOut:
  match ok:
    case True{}:
      x_frame.fin3(orig, flags, len)
    case False{}:
      NeedMore{(len - x_len_upto(len, rest) : U32), rest}

# "Did the payload arrive?" is asked with has_at_least and answered with
# len_upto — both stop at len — instead of materializing the slice with
# take to measure it and then materializing it again to hand it over
# (TASK-023 Phase 12 item 12.3). x_frame.fin3 is where the frame IS
# materialized, once, from the buffer the walk started with.
def x_frame.fin(orig: List<&2, U32>, typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32) ->
  UnitOut:
  x_frame.fin2(orig, typ, flags, sid, rest, len, x_has_at_least(len, rest))

def x_frame.len_ok(orig: List<&2, U32>, +len24: U32, +typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>, ok_len: Bool) ->
  UnitOut:
  match ok_len:
    case False{}:
      Bad{413, "frame too large"}
    case True{}:
      x_frame.fin(orig, typ, flags, sid, rest, len24)

def x_frame.hd9.go(orig: List<&2, U32>, +len24: U32, +typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>) ->
  UnitOut:
  x_frame.len_ok(orig, len24, typ, flags, sid, rest, U32.is_le(len24, x_max_frame()))

def x_frame.hd9.b8(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +s2: U32, +rest8: List<&2, U32>) -> UnitOut:
  match rest8:
    case +s3 <> rest:
      x_frame.hd9.go(orig, x_frame.len3(len_hi, b1, b2), typ, flags, x_frame.sid4(s0, s1, s2, s3), rest)
    case Nil{}:
      NeedMore{1, rest8}

def x_frame.hd9.b7(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +rest7: List<&2, U32>) -> UnitOut:
  match rest7:
    case +s2 <> rest8:
      x_frame.hd9.b8(orig, len_hi, b1, b2, typ, flags, s0, s1, s2, rest8)
    case Nil{}:
      NeedMore{2, rest7}

def x_frame.hd9.b6(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +rest6: List<&2, U32>) -> UnitOut:
  match rest6:
    case +s1 <> rest7:
      x_frame.hd9.b7(orig, len_hi, b1, b2, typ, flags, s0, s1, rest7)
    case Nil{}:
      NeedMore{3, rest6}

def x_frame.hd9.b5(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +rest5: List<&2, U32>) -> UnitOut:
  match rest5:
    case +s0 <> rest6:
      x_frame.hd9.b6(orig, len_hi, b1, b2, typ, flags, s0, rest6)
    case Nil{}:
      NeedMore{4, rest5}

def x_frame.hd9.b4(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +rest4: List<&2, U32>) -> UnitOut:
  match rest4:
    case +fl <> rest5:
      x_frame.hd9.b5(orig, len_hi, b1, b2, typ, fl, rest5)
    case Nil{}:
      NeedMore{5, rest4}

def x_frame.hd9.b3(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +rest3: List<&2, U32>) -> UnitOut:
  match rest3:
    case +typ <> rest4:
      x_frame.hd9.b4(orig, len_hi, b1, b2, typ, rest4)
    case Nil{}:
      NeedMore{6, rest3}

def x_frame.hd9.b2(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +rest2: List<&2, U32>) -> UnitOut:
  match rest2:
    case +b2 <> rest3:
      x_frame.hd9.b3(orig, len_hi, b1, b2, rest3)
    case Nil{}:
      NeedMore{7, rest2}

def x_frame.hd9.b1(orig: List<&2, U32>, +len_hi: U32, +rest: List<&2, U32>) -> UnitOut:
  match rest:
    case +b1 <> rest2:
      x_frame.hd9.b2(orig, len_hi, b1, rest2)
    case Nil{}:
      NeedMore{8, rest}

def x_frame.hd9.b0(orig: List<&2, U32>, +rest: List<&2, U32>) -> UnitOut:
  match rest:
    case +len_hi <> rest2:
      x_frame.hd9.b1(orig, len_hi, rest2)
    case Nil{}:
      NeedMore{9, rest}

def x_parse.short(orig: List<&2, U32>, +bs: List<&2, U32>, +have: U32, short: Bool) -> UnitOut:
  match short:
    case True{}:
      NeedMore{(9 - have : U32), bs}
    case False{}:
      x_frame.hd9.b0(orig, bs)

# The header's nine bytes are the only thing the walk has to count for
# itself: len_upto(9) answers "short or not" and the exact count when it
# is short, without walking the payload that follows (TASK-023 Phase 12
# item 12.3: the full len for a 9-byte question was the expensive shape).
def x_parse(+bs: List<&2, U32>) -> UnitOut:
  +have = x_len_upto(9, bs)
  x_parse.short(bs, bs, have, U32.is_lt(have, 9))

# Frame read loop (no flow-credit sends: responses stay small)
# ------------------------------------------------------------

def x_read.done(s: Socket, +chunk: List<&2, U32>, +buf: List<&2, U32>, is_eof: Bool) ->
  Socket & UnitOut & List<&2, U32>:
  match is_eof:
    case True{}:
      (s, Bad{400, "eof"}, buf)
    case False{}:
      +buf2 = List.append(&2, U32, buf, chunk)
      (s, x_parse(buf2), buf2)

def x_read.grow(r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>) ->
  Socket & UnitOut & List<&2, U32>:
  (s, res) = r
  match res:
    case Fail{(code, msg)}:
      (s, Bad{code, msg}, buf)
    case Done{+chunk}:
      x_read.done(s, chunk, buf, List.is_empty(&2, U32, chunk))

@unsafe
def x_read_loop(state: Socket & UnitOut & List<&2, U32>) -> IO(Socket & Got):
  (s0, out, buf) = state
  match out:
    case Got{+unit, fin, +rest}:
      IO.pure(Socket & Got, (s0, GotOk{x_frame_of(unit), rest}))
    case Bad{code, msg}:
      IO.pure(Socket & Got, (s0, GotErr{code, msg}))
    case NeedMore{missing, rest}:
      do IO<Socket & Got>:
        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s0, 16384)
        x_read_loop(x_read.grow(r1, buf))
    case End{rest}:
      # Nothing in this lane produces End (see the walk's note). If it ever
      # does, the only true reading is "the connection is done", which is
      # the answer the eof already gives.
      IO.pure(Socket & Got, (s0, GotErr{400, "eof"}))

def x_read_frame(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & Got):
  x_read_loop((sock, x_parse(buf), buf))

# HPACK ints (prefix + continuation, RFC 7541 section 5.1)
# --------------------------------------------------------

def x_int.enc.go(+fuel: Nat, +rest: U32, acc: List<&2, U32>, big: Bool) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      match big:
        case True{}:
          +b = U32.add(U32.and(rest, 127), 128)
          +next = U32.shrn(rest, 7n)
          x_int.enc.go(f, next, List.append(&2, U32, acc, [b]), U32.is_ge(next, 128))
        case False{}:
          +b = U32.and(rest, 127)
          List.append(&2, U32, acc, [b])

def x_int.enc.small(+first: U32, +rest: U32, small: Bool) -> List<&2, U32>:
  match small:
    case True{}:
      [U32.or(first, rest)]
    case False{}:
      acc = x_int.enc.go(6n, (rest - 127 : U32), Nil{}, U32.is_ge((rest - 127 : U32), 128))
      List.append(&2, U32, [U32.or(first, 127)], acc)

def x_int.enc(+first: U32, +rest: U32) -> List<&2, U32>:
  x_int.enc.small(first, rest, U32.is_lt(rest, 127))

def x_int.dec.go2c(+rest: List<&2, U32>, cont: Bool, acc: U32, +m: U32, wrapped: Bool) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match rest:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b <> rest2:
      match cont:
        case False{}:
          Done{(acc, b <> rest2)}
        case True{}:
          match wrapped:
            case True{}:
              Fail{(502, "hpack int too long")}
            case False{}:
              +acc2 = (acc + m * U32.and(b, 127) : U32)
              +nm = (m * 128 : U32)
              x_int.dec.go2c(rest2, U32.is_eq(U32.and(b, 128), 128), acc2, nm, U32.is_eq(nm, 0))

def x_int.dec.go2(+rest: List<&2, U32>, acc: U32, +m: U32) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  x_int.dec.go2c(rest, True{}, acc, m, False{})

def x_int.dec.go4(+first: U32, +mask: U32, +rest: List<&2, U32>, short: Bool) ->
  Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match short:
    case True{}:
      Done{(U32.and(first, mask), rest)}
    case False{}:
      x_int.dec.go2(rest, mask, 1)

def x_int.dec.go(+first: U32, +mask: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  x_int.dec.go4(first, mask, rest, U32.is_lt(U32.and(first, mask), mask))

# Huffman strings (RFC 7541 Appendix B, canonical code). Same tables as
# the full codec: lengths/counts/firsts/starts/order. Cost is pay-per-use
# (list walks per bit, only on Huffman peers; raw peers never enter).
# ----------------------------------------------------------------------

def x_huff_lens() -> List<&2, U32>:
  [13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
   28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
   6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
   5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
   13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
   7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
   15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
   6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
   20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
   24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
   22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
   21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
   26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
   19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
   20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
   26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
   30]

def x_huff_counts() -> List<&2, U32>:
  [10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0,
   0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4]

def x_huff_firsts() -> List<&2, U32>:
  [0, 20, 92, 248,
   0, 1016, 2042, 4090,
   8184, 16380, 32764, 0,
   0, 0, 524272, 1048550,
   2097116, 4194258, 8388568, 16777194,
   33554412, 67108832, 134217694, 268435426,
   0, 1073741820]

def x_huff_starts() -> List<&2, U32>:
  [0, 10, 36, 68, 74, 74, 79, 82, 84, 90, 92, 95, 95,
   95, 95, 98, 106, 119, 145, 174, 186, 190, 205, 224, 253, 253]

def x_huff_order() -> List<&2, U32>:
  [48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51,
   52, 53, 54, 55, 56, 57, 61, 65, 95, 98, 100, 102, 103, 104, 108, 109,
   110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
   77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118,
   119, 120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39,
   43, 124, 35, 62, 0, 36, 64, 91, 93, 126, 94, 125, 60, 96, 123, 92,
   195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161, 167, 172, 176, 177,
   179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156, 160,
   163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232,
   233, 1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157,
   158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142,
   144, 145, 148, 159, 171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193,
   200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211,
   212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254,
   2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20,
   21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127, 220, 249, 10, 13, 22,
   256]

def x_huff_nth.go(+xs: List<&2, U32>, +n: U32) -> U32:
  match xs:
    case Nil{}:
      0
    case h <> t:
      match n:
        case 0:
          h
        case _:
          x_huff_nth.go(t, (n - 1 : U32))

def x_huff_nth(+xs: List<&2, U32>, +n: U32) -> U32:
  x_huff_nth.go(xs, n)

def x_huff_bits.go(+b: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(b, 7n), 1), U32.and(U32.shrn(b, 6n), 1),
   U32.and(U32.shrn(b, 5n), 1), U32.and(U32.shrn(b, 4n), 1),
   U32.and(U32.shrn(b, 3n), 1), U32.and(U32.shrn(b, 2n), 1),
   U32.and(U32.shrn(b, 1n), 1), U32.and(b, 1)]

def x_huff_bits(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case h <> t:
      List.append(&2, U32, x_huff_bits.go(h), x_huff_bits(t))

def x_huff_hit(+code: U32, +len: U32) -> Bool:
  +i = (len - 5 : U32)
  +cnt = x_huff_nth(x_huff_counts(), i)
  +fst = x_huff_nth(x_huff_firsts(), i)
  Bool.and(U32.is_ge(code, fst), U32.is_lt((code - fst : U32), cnt))

def x_huff_at(+code: U32, +len: U32) -> U32:
  +i = (len - 5 : U32)
  +fst = x_huff_nth(x_huff_firsts(), i)
  x_huff_nth(x_huff_order(), (x_huff_nth(x_huff_starts(), i) + (code - fst : U32) : U32))

def x_huff_ones(+bits: List<&2, U32>) -> Bool:
  match bits:
    case Nil{}:
      True{}
    case b <> t:
      Bool.and(U32.is_eq(b, 1), x_huff_ones(t))

def x_huff_pad(+bits: List<&2, U32>) -> Bool:
  Bool.and(Bool.not(x_has_at_least(8, bits)), x_huff_ones(bits))

def x_huff_empty(+bits: List<&2, U32>) -> Bool:
  match bits:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

def x_huff_emit.big(big: Bool) -> U32:
  match big:
    case True{}:
      31
    case False{}:
      0

def x_huff_emit.go(eos: Bool, big: Bool) -> U32:
  match eos:
    case True{}:
      30
    case False{}:
      x_huff_emit.big(big)

def x_huff_emit_phase(+sym: U32, +n: U32) -> U32:
  x_huff_emit.go(U32.is_eq(sym, 256), U32.is_gt(n, x_max_str()))

def x_huff_entry.padd(pad: Bool) -> U32:
  match pad:
    case True{}:
      2
    case False{}:
      10

def x_huff_entry.empty(+bits: List<&2, U32>, empty: Bool, pad: Bool) -> U32:
  match empty:
    case True{}:
      1
    case False{}:
      x_huff_entry.padd(pad)

def x_huff_entry(+bits: List<&2, U32>) -> U32:
  x_huff_entry.empty(bits, x_huff_empty(bits), x_huff_pad(bits))

def x_huff_sym_phase.go(hit: Bool) -> U32:
  match hit:
    case True{}:
      21
    case False{}:
      22

def x_huff_sym_phase.hit(+code: U32, +len: U32, hit: Bool, over: Bool) -> U32:
  match over:
    case True{}:
      20
    case False{}:
      x_huff_sym_phase.go(hit)

def x_huff_sym_phase(+code: U32, +len: U32) -> U32:
  x_huff_sym_phase.hit(code, len, x_huff_hit(code, len), U32.is_gt(len, 30))

def x_huff_dec.go(+fuel: Nat, +phase: U32, +bits: List<&2, U32>, +acc: List<&2, U32>, +n: U32, +code: U32, +len: U32) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  match fuel:
    case 0n:
      Fail{(502, "huffman fuel")}
    case 1n+f:
      match phase:
        case 0:
          x_huff_dec.go(f, x_huff_entry(bits), bits, acc, n, code, len)
        case 1:
          Done{x_cat(acc)}
        case 2:
          Done{x_cat(acc)}
        case 10:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              x_huff_dec.go(f, 11, t, acc, n, b, len)
        case 11:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              x_huff_dec.go(f, 12, t, acc, n, ((code * 2 : U32) + b : U32), len)
        case 12:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              x_huff_dec.go(f, 13, t, acc, n, ((code * 2 : U32) + b : U32), len)
        case 13:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              x_huff_dec.go(f, 14, t, acc, n, ((code * 2 : U32) + b : U32), len)
        case 14:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              +cc = ((code * 2 : U32) + b : U32)
              x_huff_dec.go(f, x_huff_sym_phase(cc, 5), t, acc, n, cc, 5)
        case 20:
          Fail{(502, "huffman code")}
        case 21:
          +sym = x_huff_at(code, len)
          +nn = (n + 1 : U32)
          x_huff_dec.go(f, x_huff_emit_phase(sym, nn), bits, sym <> acc, nn, code, len)
        case 22:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              +ln = (len + 1 : U32)
              +cc = ((code * 2 : U32) + b : U32)
              x_huff_dec.go(f, x_huff_sym_phase(cc, ln), t, acc, n, cc, ln)
        case 30:
          Fail{(502, "huffman eos")}
        case 31:
          Fail{(413, "huffman too large")}
        case _:
          Fail{(502, "huffman phase")}

def x_huff_decode.fuel(+bl: Nat) -> Nat:
  Nat.add(bl, Nat.add(bl, Nat.add(bl, 1n)))

def x_huff_decode(+bs: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +bits = x_huff_bits(bs)
  x_huff_dec.go(x_huff_decode.fuel(x_len(bits)), 0, bits, Nil{}, 0, 0, 0)

# HPACK strings (raw or Huffman; cap 65535)
# -----------------------------------------

def x_str.whole(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>, whole: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match whole:
    case True{}:
      Done{(x_bytes_str(taken), x_drop32(n, rest))}
    case False{}:
      Fail{(400, "hpack eof str")}

def x_str.fin(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  x_str.whole(n, rest, taken, x_has_at_least(n, rest))

def x_str.capped(+n: U32, +rest: List<&2, U32>, capped: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match capped:
    case False{}:
      Fail{(413, "hpack str too large")}
    case True{}:
      x_str.fin(n, rest, x_take32(n, rest))

def x_str.of_len(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+n, +rest)}:
      x_str.capped(n, rest, U32.is_le(n, x_max_str()))

def x_str.huffin(+bs: List<&2, U32>, +rest: List<&2, U32>, whole: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match whole:
    case True{}:
      Done{(x_bytes_str(bs), rest)}
    case False{}:
      Fail{(400, "hpack eof str")}

def x_str.huffed(+n: U32, +rest: List<&2, U32>, r: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{bs}:
      x_str.huffin(bs, x_drop32(n, rest), x_has_at_least(n, rest))

def x_str.huf2(+n: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  x_str.huffed(n, rest, x_huff_decode(x_take32(n, rest)))

def x_str.hufcap(+n: U32, +rest: List<&2, U32>, capped: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match capped:
    case False{}:
      Fail{(413, "hpack str too large")}
    case True{}:
      x_str.huf2(n, rest)

def x_str.hufin(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+n, +rest)}:
      x_str.hufcap(n, rest, U32.is_le(n, x_max_str()))

def x_str.after_huf(+b0: U32, +rest2: List<&2, U32>, huf: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match huf:
    case True{}:
      x_str.hufin(x_int.dec.go(b0, 127, rest2))
    case False{}:
      x_str.of_len(x_int.dec.go(b0, 127, rest2))

def x_str.dec.go(+rest: List<&2, U32>) -> Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match rest:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest2:
      x_str.after_huf(b0, rest2, U32.is_eq(U32.and(b0, 128), 128))

def x_str.enc(+s: String) -> List<&2, U32>:
  List.append(&2, U32, x_int.enc(0, x_str_len32(s)), x_str_bytes(s))

# Static table 1-61 (RFC 7541 Appendix A; indexed names + full pairs;
# >61 -> dyn table via x_tab.addr; 0 -> Fail in x_hdr.full)
# ---------------------------------------------------------------------

def x_static.go(+idx: U32) -> String & String:
  match idx:
    case 1:
      (":authority", "")
    case 2:
      (":method", "GET")
    case 3:
      (":method", "POST")
    case 4:
      (":path", "/")
    case 5:
      (":path", "/index.html")
    case 6:
      (":scheme", "http")
    case 7:
      (":scheme", "https")
    case 8:
      (":status", "200")
    case 9:
      (":status", "204")
    case 10:
      (":status", "206")
    case 11:
      (":status", "304")
    case 12:
      (":status", "400")
    case 13:
      (":status", "404")
    case 14:
      (":status", "500")
    case 15:
      ("accept-charset", "")
    case 16:
      ("accept-encoding", "gzip, deflate")
    case 17:
      ("accept-language", "")
    case 18:
      ("accept-ranges", "")
    case 19:
      ("accept", "")
    case 20:
      ("access-control-allow-origin", "")
    case 21:
      ("age", "")
    case 22:
      ("allow", "")
    case 23:
      ("authorization", "")
    case 24:
      ("cache-control", "")
    case 25:
      ("content-disposition", "")
    case 26:
      ("content-encoding", "")
    case 27:
      ("content-language", "")
    case 28:
      ("content-length", "")
    case 29:
      ("content-location", "")
    case 30:
      ("content-range", "")
    case 31:
      ("content-type", "")
    case 32:
      ("cookie", "")
    case 33:
      ("date", "")
    case 34:
      ("etag", "")
    case 35:
      ("expect", "")
    case 36:
      ("expires", "")
    case 37:
      ("from", "")
    case 38:
      ("host", "")
    case 39:
      ("if-match", "")
    case 40:
      ("if-modified-since", "")
    case 41:
      ("if-none-match", "")
    case 42:
      ("if-range", "")
    case 43:
      ("if-unmodified-since", "")
    case 44:
      ("last-modified", "")
    case 45:
      ("link", "")
    case 46:
      ("location", "")
    case 47:
      ("max-forwards", "")
    case 48:
      ("proxy-authenticate", "")
    case 49:
      ("proxy-authorization", "")
    case 50:
      ("range", "")
    case 51:
      ("referer", "")
    case 52:
      ("refresh", "")
    case 53:
      ("retry-after", "")
    case 54:
      ("server", "")
    case 55:
      ("set-cookie", "")
    case 56:
      ("strict-transport-security", "")
    case 57:
      ("transfer-encoding", "")
    case 58:
      ("user-agent", "")
    case 59:
      ("vary", "")
    case 60:
      ("via", "")
    case 61:
      ("www-authenticate", "")
    case _:
      ("", "")

def x_static.name(sp: String & String) -> String:
  (n, v) = sp
  n

def x_static.value(sp: String & String) -> String:
  (n, v) = sp
  v

def x_static_name(+idx: U32) -> String:
  x_static.name(x_static.go(idx))

# Dynamic table ops (insert + evict + lookup; newest at head)
# -----------------------------------------------------------

def x_tab.empty() -> Tab:
  Tab{Nil{}, 0, 4096}

def x_tab.entry_size(+name: String, +value: String) -> U32:
  (x_str_len32(name) + x_str_len32(value) + 32 : U32)

def x_tab.len.go(+ents: List<&2, Hdr>, +n: U32) -> U32:
  match ents:
    case Nil{}:
      n
    case _ <> t:
      x_tab.len.go(t, (n + 1 : U32))

def x_tab.len(+ents: List<&2, Hdr>) -> U32:
  x_tab.len.go(ents, 0)

# Structural eviction (no fuel: recurses on the tail, like x_tab.rev.go;
# the Nil arm returns (Nil,0) — trim only calls with empty ents at size 0).
def x_tab.fit.go(+ents: List<&2, Hdr>, fit: Bool, +size: U32, +max: U32) ->
  List<&2, Hdr> & U32:
  match ents:
    case Nil{}:
      (Nil{}, 0)
    case Hdr{n, v} <> t:
      match fit:
        case True{}:
          (Hdr{n, v} <> t, size)
        case False{}:
          +ns = U32.sub(size, x_tab.entry_size(n, v))
          x_tab.fit.go(t, U32.is_le(ns, max), ns, max)

def x_tab.rev.go(+ents: List<&2, Hdr>, acc: List<&2, Hdr>) -> List<&2, Hdr>:
  match ents:
    case Nil{}:
      acc
    case h <> t:
      x_tab.rev.go(t, h <> acc)

def x_tab.rev(+ents: List<&2, Hdr>) -> List<&2, Hdr>:
  x_tab.rev.go(ents, Nil{})

def x_tab.done(p: List<&2, Hdr> & U32, +max: U32) -> Tab:
  (kept, sz) = p
  Tab{x_tab.rev(kept), sz, max}

def x_tab.trim(+ents: List<&2, Hdr>, +size: U32, +max: U32) -> Tab:
  +rev = x_tab.rev(ents)
  x_tab.done(x_tab.fit.go(rev, U32.is_le(size, max), size, max), max)

def x_tab.do(+ents: List<&2, Hdr>, +size: U32, +max: U32, +name: String, +value: String, +es: U32) -> Tab:
  +ns = (size + es : U32)
  x_tab.trim(Hdr{name, value} <> ents, ns, max)

def x_tab.ins_fit(+ents: List<&2, Hdr>, +size: U32, +max: U32, +name: String, +value: String, fits: Bool, +es: U32) -> Tab:
  match fits:
    case False{}:
      Tab{Nil{}, 0, max}
    case True{}:
      x_tab.do(ents, size, max, name, value, es)

def x_tab.ins_go(+tab: Tab, +name: String, +value: String) -> Tab:
  match tab:
    case Tab{+ents, +size, +max}:
      +es = x_tab.entry_size(name, value)
      x_tab.ins_fit(ents, size, max, name, value, U32.is_le(es, max), es)

def x_tab.insert(+tab: Tab, +name: String, +value: String) -> Tab:
  x_tab.ins_go(tab, name, value)

def x_tab.resize.go(+tab: Tab, +max: U32) -> Tab:
  match tab:
    case Tab{+ents, +size, +old}:
      x_tab.trim(ents, size, max)

def x_tab.resize(+tab: Tab, +max: U32) -> Tab:
  x_tab.resize.go(tab, max)

# got: bounds-check + fetch in one walk (was lookup.go len-full + at-partial).
def x_tab.lookup.got(+ents: List<&2, Hdr>, +k: U32) -> Result<&1, &1, U32 & String, Hdr>:
  match ents:
    case Nil{}:
      Fail{(502, "hpack dyn bounds")}
    case Hdr{n, v} <> t:
      match k:
        case 0:
          Done{Hdr{n, v}}
        case _:
          x_tab.lookup.got(t, (k - 1 : U32))

def x_tab.lookup(+tab: Tab, +idx: U32) -> Result<&1, &1, U32 & String, Hdr>:
  match tab:
    case Tab{+ents, +size, +max}:
      x_tab.lookup.got(ents, idx)

def x_tab.static_hdr(sp: String & String) -> Hdr:
  (n, v) = sp
  Hdr{n, v}

def x_tab.addr.go(+tab: Tab, +idx: U32, is_static: Bool) ->
  Result<&1, &1, U32 & String, Hdr>:
  match is_static:
    case True{}:
      Done{x_tab.static_hdr(x_static.go(idx))}
    case False{}:
      x_tab.lookup(tab, (idx - 62 : U32))

def x_tab.addr(+tab: Tab, +idx: U32) -> Result<&1, &1, U32 & String, Hdr>:
  x_tab.addr.go(tab, idx, U32.is_le(idx, 61))

# One header field (incremental entries update the table)
# -------------------------------------------------------

def x_hdr.full(+idx: U32, +rest: List<&2, U32>, +tab: Tab) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match idx:
    case 1:
      Done{HdrGot{":authority", "", rest, tab}}
    case 2:
      Done{HdrGot{":method", "GET", rest, tab}}
    case 3:
      Done{HdrGot{":method", "POST", rest, tab}}
    case 4:
      Done{HdrGot{":path", "/", rest, tab}}
    case 5:
      Done{HdrGot{":path", "/index.html", rest, tab}}
    case 6:
      Done{HdrGot{":scheme", "http", rest, tab}}
    case 7:
      Done{HdrGot{":scheme", "https", rest, tab}}
    case 8:
      Done{HdrGot{":status", "200", rest, tab}}
    case 9:
      Done{HdrGot{":status", "204", rest, tab}}
    case 10:
      Done{HdrGot{":status", "206", rest, tab}}
    case 11:
      Done{HdrGot{":status", "304", rest, tab}}
    case 12:
      Done{HdrGot{":status", "400", rest, tab}}
    case 13:
      Done{HdrGot{":status", "404", rest, tab}}
    case 14:
      Done{HdrGot{":status", "500", rest, tab}}
    case 15:
      Done{HdrGot{"accept-charset", "", rest, tab}}
    case 16:
      Done{HdrGot{"accept-encoding", "gzip, deflate", rest, tab}}
    case 17:
      Done{HdrGot{"accept-language", "", rest, tab}}
    case 18:
      Done{HdrGot{"accept-ranges", "", rest, tab}}
    case 19:
      Done{HdrGot{"accept", "", rest, tab}}
    case 20:
      Done{HdrGot{"access-control-allow-origin", "", rest, tab}}
    case 21:
      Done{HdrGot{"age", "", rest, tab}}
    case 22:
      Done{HdrGot{"allow", "", rest, tab}}
    case 23:
      Done{HdrGot{"authorization", "", rest, tab}}
    case 24:
      Done{HdrGot{"cache-control", "", rest, tab}}
    case 25:
      Done{HdrGot{"content-disposition", "", rest, tab}}
    case 26:
      Done{HdrGot{"content-encoding", "", rest, tab}}
    case 27:
      Done{HdrGot{"content-language", "", rest, tab}}
    case 28:
      Done{HdrGot{"content-length", "", rest, tab}}
    case 29:
      Done{HdrGot{"content-location", "", rest, tab}}
    case 30:
      Done{HdrGot{"content-range", "", rest, tab}}
    case 31:
      Done{HdrGot{"content-type", "", rest, tab}}
    case 32:
      Done{HdrGot{"cookie", "", rest, tab}}
    case 33:
      Done{HdrGot{"date", "", rest, tab}}
    case 34:
      Done{HdrGot{"etag", "", rest, tab}}
    case 35:
      Done{HdrGot{"expect", "", rest, tab}}
    case 36:
      Done{HdrGot{"expires", "", rest, tab}}
    case 37:
      Done{HdrGot{"from", "", rest, tab}}
    case 38:
      Done{HdrGot{"host", "", rest, tab}}
    case 39:
      Done{HdrGot{"if-match", "", rest, tab}}
    case 40:
      Done{HdrGot{"if-modified-since", "", rest, tab}}
    case 41:
      Done{HdrGot{"if-none-match", "", rest, tab}}
    case 42:
      Done{HdrGot{"if-range", "", rest, tab}}
    case 43:
      Done{HdrGot{"if-unmodified-since", "", rest, tab}}
    case 44:
      Done{HdrGot{"last-modified", "", rest, tab}}
    case 45:
      Done{HdrGot{"link", "", rest, tab}}
    case 46:
      Done{HdrGot{"location", "", rest, tab}}
    case 47:
      Done{HdrGot{"max-forwards", "", rest, tab}}
    case 48:
      Done{HdrGot{"proxy-authenticate", "", rest, tab}}
    case 49:
      Done{HdrGot{"proxy-authorization", "", rest, tab}}
    case 50:
      Done{HdrGot{"range", "", rest, tab}}
    case 51:
      Done{HdrGot{"referer", "", rest, tab}}
    case 52:
      Done{HdrGot{"refresh", "", rest, tab}}
    case 53:
      Done{HdrGot{"retry-after", "", rest, tab}}
    case 54:
      Done{HdrGot{"server", "", rest, tab}}
    case 55:
      Done{HdrGot{"set-cookie", "", rest, tab}}
    case 56:
      Done{HdrGot{"strict-transport-security", "", rest, tab}}
    case 57:
      Done{HdrGot{"transfer-encoding", "", rest, tab}}
    case 58:
      Done{HdrGot{"user-agent", "", rest, tab}}
    case 59:
      Done{HdrGot{"vary", "", rest, tab}}
    case 60:
      Done{HdrGot{"via", "", rest, tab}}
    case 61:
      Done{HdrGot{"www-authenticate", "", rest, tab}}
    case _:
      Fail{(502, "hpack dyn")}

def x_hdr.indexed.go(+idx: U32, +rest: List<&2, U32>, +tab: Tab, ok: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack bad index")}
    case True{}:
      x_hdr.full(idx, rest, tab)

def x_hdr.indexed.num(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, +tab: Tab) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest)}:
      x_hdr.indexed.go(idx, rest, tab, U32.is_ge(idx, 1))

def x_hdr.indexed.go2(+b0: U32, +rest: List<&2, U32>, +tab: Tab) ->
  Result<&1, &1, U32 & String, HdrGot>:
  x_hdr.indexed.num(x_int.dec.go(b0, 127, rest), tab)

def x_hdr.dyn.at(+rest: List<&2, U32>, +tab: Tab, r: Result<&1, &1, U32 & String, Hdr>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      match h:
        case Hdr{+n, +v}:
          Done{HdrGot{n, v, rest, tab}}

def x_hdr.dyn.go(+idx: U32, +rest: List<&2, U32>, +tab: Tab, static: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match static:
    case True{}:
      x_hdr.full(idx, rest, tab)
    case False{}:
      x_hdr.dyn.at(rest, tab, x_tab.addr(tab, idx))

def x_hdr.dyn.num(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, +tab: Tab) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest)}:
      x_hdr.dyn.go(idx, rest, tab, U32.is_le(idx, 61))

def x_hdr.lit.put(+name: String, +value: String, +rest: List<&2, U32>, +tab: Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case False{}:
      Done{HdrGot{name, value, rest, tab}}
    case True{}:
      Done{HdrGot{name, value, rest, x_tab.insert(tab, name, value)}}

def x_hdr.lit.val(+name: String, +tab: Tab, is_incr: Bool, r: Result<&1, &1, U32 & String, String & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(value, rest)}:
      x_hdr.lit.put(name, value, rest, tab, is_incr)

def x_hdr.lit.name(r: Result<&1, &1, U32 & String, String & List<&2, U32>>, +tab: Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(name, rest2)}:
      x_hdr.lit.val(name, tab, is_incr, x_str.dec.go(rest2))

def x_hdr.lit.named(+rest: List<&2, U32>, +tab: Tab, is_incr: Bool, r: Result<&1, &1, U32 & String, Hdr>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      match h:
        case Hdr{+n, +v}:
          x_hdr.lit.val(n, tab, is_incr, x_str.dec.go(rest))

def x_hdr.lit.nameat(+idx: U32, +rest: List<&2, U32>, +tab: Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  x_hdr.lit.named(rest, tab, is_incr, x_tab.addr(tab, idx))

def x_hdr.lit.zero(+rest: List<&2, U32>, +tab: Tab, is_incr: Bool, +idx: U32, is_new: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_new:
    case True{}:
      x_hdr.lit.name(x_str.dec.go(rest), tab, is_incr)
    case False{}:
      x_hdr.lit.nameat(idx, rest, tab, is_incr)

def x_hdr.lit.go(+b0: U32, +rest: List<&2, U32>, +tab: Tab, r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest2)}:
      x_hdr.lit.zero(rest2, tab, is_incr, idx, U32.is_eq(idx, 0))

def x_hdr.lit.mask(is_incr: Bool) -> U32:
  match is_incr:
    case True{}:
      63
    case False{}:
      15

def x_hdr.lit(+b0: U32, +rest: List<&2, U32>, is_incr: Bool, +tab: Tab) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case True{}:
      x_hdr.lit.go(b0, rest, tab, x_int.dec.go(b0, 63, rest), True{})
    case False{}:
      x_hdr.lit.go(b0, rest, tab, x_int.dec.go(b0, 15, rest), False{})

def x_hdr.table.sized(+rest: List<&2, U32>, +tab: Tab, +ns: U32, ok: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack table too big")}
    case True{}:
      Done{HdrGot{"", "", rest, x_tab.resize(tab, ns)}}

def x_hdr.table.go(+tab: Tab, r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+ns, +rest)}:
      x_hdr.table.sized(rest, tab, ns, U32.is_le(ns, 4096))

def x_hdr.after_table(+b0: U32, +rest: List<&2, U32>, +tab: Tab, is_table: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_table:
    case True{}:
      x_hdr.table.go(tab, x_int.dec.go(b0, 31, rest))
    case False{}:
      x_hdr.lit(b0, rest, False{}, tab)

def x_hdr.after_incr(+b0: U32, +rest: List<&2, U32>, +tab: Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case True{}:
      x_hdr.lit(b0, rest, True{}, tab)
    case False{}:
      x_hdr.after_table(b0, rest, tab, U32.is_ge(b0, 32))

def x_hdr.after_idx(+b0: U32, +rest: List<&2, U32>, +tab: Tab, is_idx: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_idx:
    case True{}:
      x_hdr.dyn.num(x_int.dec.go(b0, 127, rest), tab)
    case False{}:
      x_hdr.after_incr(b0, rest, tab, U32.is_ge(b0, 64))

def x_hdr.dec(+bs: List<&2, U32>, +tab: Tab) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match bs:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest:
      x_hdr.after_idx(b0, rest, tab, U32.is_ge(b0, 128))

# Header block -> request head (phased loop, fuel-bounded)
# --------------------------------------------------------

def x_req.pick2(+method: String, +path: String, +headers: List<&2, Hdr>, +name: String, +value: String, +is_path: Bool) -> ReqHead:
  match is_path:
    case True{}:
      ReqHead{method, value, headers}
    case False{}:
      ReqHead{method, path, headers}

def x_req.pick(+method: String, +path: String, +headers: List<&2, Hdr>, +name: String, +value: String, +is_meth: Bool, +is_path: Bool) -> ReqHead:
  match is_meth:
    case True{}:
      ReqHead{value, path, headers}
    case False{}:
      x_req.pick2(method, path, headers, name, value, is_path)

def x_req.apply3(+method: String, +path: String, +headers: List<&2, Hdr>, +name: String, +value: String, is_meth: Bool, is_path: Bool, pseudo: Bool) -> ReqHead:
  match pseudo:
    case True{}:
      x_req.pick(method, path, headers, name, value, is_meth, is_path)
    case False{}:
      ReqHead{method, path, List.append(&2, Hdr, headers, [Hdr{name, value}])}

def x_req.apply2(+method: String, +path: String, +headers: List<&2, Hdr>, +name: String, +value: String, +is_meth: Bool, +is_path: Bool) -> ReqHead:
  x_req.apply3(method, path, headers, name, value, is_meth, is_path, Bool.or(is_meth, is_path))

def x_req.apply(+st: ReqHead, +name: String, +value: String, is_meth: Bool, is_path: Bool) -> ReqHead:
  match st:
    case ReqHead{+method, +path, +headers}:
      x_req.apply2(method, path, headers, name, value, is_meth, is_path)

def x_req.phase(emit: Bool) -> U32:
  match emit:
    case True{}:
      2
    case False{}:
      3

@unsafe
def x_req.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: ReqHead, +tab: Tab) ->
  Result<&1, &1, U32 & String, ReqHead & Tab>:
  match fuel:
    case 0n:
      Fail{(502, "too many headers")}
    case 1n+f:
      match phase:
        case 0:
          match bs:
            case Nil{}:
              Done{(st, tab)}
            case _:
              x_req.go(f, 1, bs, x_hdr.dec(bs, tab), "", "", st, tab)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HdrGot{+n, +v, +rrest, +tab2}}:
              x_req.go(f, 2, rrest, Fail{(0, "")}, n, v, st, tab2)
        case 2:
          +st2 = x_req.apply(st, name, value, String.eq(name, ":method"), String.eq(name, ":path"))
          x_req.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          x_req.go(f, 0, bs, r, "", "", st, tab)

def x_req.decode(+bs: List<&2, U32>, +tab: Tab) ->
  Result<&1, &1, U32 & String, ReqHead & Tab>:
  x_req.go(512n, 0, bs, Fail{(0, "")}, "", "", ReqHead{"", "", Nil{}}, tab)

def x_req.rh(r: Result<&1, &1, U32 & String, ReqHead & Tab>) -> ReqHead:
  match r:
    case Fail{e}:
      ReqHead{"", "", Nil{}}
    case Done{(+h, t)}:
      h

def x_req.ok(r: Result<&1, &1, U32 & String, ReqHead & Tab>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{(h, t)}:
      True{}

def x_req.tab(r: Result<&1, &1, U32 & String, ReqHead & Tab>) -> Tab:
  match r:
    case Fail{e}:
      Tab{Nil{}, 0, 4096}
    case Done{(h, +t)}:
      t

# got (Phase 14 A-cirurgia, piloto httpx_stream): 1 match responde a tripla;
# o caller nunca desdobra — a fase 7 do loop casa o param e ventila.
def x_req.got(dr: Result<&1, &1, U32 & String, ReqHead & Tab>) -> ReqHead & Bool & Tab:
  match dr:
    case Fail{e}:
      (ReqHead{"", "", Nil{}}, False{}, Tab{Nil{}, 0, 4096})
    case Done{(+h, +t)}:
      (h, True{}, t)

def x_req.no_got() -> ReqHead & Bool & Tab:
  (ReqHead{"", "", Nil{}}, False{}, Tab{Nil{}, 0, 4096})

# Response head decode (mirror of x_req.go, apply on :status)
# ------------------------------------------------------------

def x_resp.apply2(+status: U32, +headers: List<&2, Hdr>, +name: String, +value: String, is_status: Bool) -> Head:
  match is_status:
    case True{}:
      Head{Maybe.default(&2, U32, U32.read(value), 0), headers}
    case False{}:
      Head{status, List.append(&2, Hdr, headers, [Hdr{name, value}])}

def x_resp.apply(+st: Head, +name: String, +value: String, is_status: Bool) -> Head:
  match st:
    case Head{+status, +headers}:
      x_resp.apply2(status, headers, name, value, is_status)

@unsafe
def x_resp.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: Head, +tab: Tab) ->
  Result<&1, &1, U32 & String, Head & Tab>:
  match fuel:
    case 0n:
      Fail{(502, "too many headers")}
    case 1n+f:
      match phase:
        case 0:
          match bs:
            case Nil{}:
              Done{(st, tab)}
            case _:
              x_resp.go(f, 1, bs, x_hdr.dec(bs, tab), "", "", st, tab)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HdrGot{+n, +v, +rrest, +tab2}}:
              x_resp.go(f, 2, rrest, Fail{(0, "")}, n, v, st, tab2)
        case 2:
          +st2 = x_resp.apply(st, name, value, String.eq(name, ":status"))
          x_resp.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          x_resp.go(f, 0, bs, r, "", "", st, tab)

def x_resp.decode(+bs: List<&2, U32>, +tab: Tab) ->
  Result<&1, &1, U32 & String, Head & Tab>:
  x_resp.go(512n, 0, bs, Fail{(0, "")}, "", "", Head{0, Nil{}}, tab)

def x_resp.rh(r: Result<&1, &1, U32 & String, Head & Tab>) -> Head:
  match r:
    case Fail{e}:
      Head{0, Nil{}}
    case Done{(+h, t)}:
      h

def x_resp.ok(r: Result<&1, &1, U32 & String, Head & Tab>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{(h, t)}:
      True{}

def x_resp.tab(r: Result<&1, &1, U32 & String, Head & Tab>) -> Tab:
  match r:
    case Fail{e}:
      Tab{Nil{}, 0, 4096}
    case Done{(h, +t)}:
      t

# Header block encode (literal-only)
# ----------------------------------

def x_lit.enc(+name: String, +value: String) -> List<&2, U32>:
  List.append(&2, U32, [0], List.append(&2, U32, x_str.enc(name), x_str.enc(value)))

def x_block.go(hs: List<&2, Hdr>, acc: List<&2, U32>) -> List<&2, U32>:
  match hs:
    case Nil{}:
      acc
    case Hdr{n, v} <> t:
      x_block.go(t, List.append(&2, U32, acc, x_lit.enc(n, v)))

def x_block(hs: List<&2, Hdr>) -> List<&2, U32>:
  x_block.go(hs, Nil{})

# Classify / preface / responses
# ------------------------------

def x_preface_ok(+buf: List<&2, U32>) -> U32:
  x_eq(x_take32(24, buf), x_preface())

def x_needs_cont(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, x_t_headers()), U32.is_eq(U32.and(flags, x_f_end_headers()), 0))

def x_wu.val(+v: U32) -> Bool:
  Bool.and(U32.is_gt(v, 0), U32.is_lt(v, 2147483648))

def x_wu_ok.go(+b0: U32, +b1: U32, +b2: U32, +b3: U32) -> Bool:
  x_wu.val((((b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 : U32))))

# RFC 9113 section 6.9: the increment field is exactly 4 bytes, so a
# WINDOW_UPDATE with any other length is a connection error. The old
# x_wu_ok stopped after 4 bytes and ignored the tail, which let a 5+ byte
# frame through as a valid credit (found porting h2_rst.bend to httpx_rst).
def x_wu_ok.empty(+rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

def x_wu_ok.go4(+b0: U32, +b1: U32, +b2: U32, +b3: U32, +rest: List<&2, U32>) -> Bool:
  Bool.and(x_wu_ok.go(b0, b1, b2, b3), x_wu_ok.empty(rest))

def x_wu_ok.r3(+b0: U32, +b1: U32, +b2: U32, +rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      False{}
    case +b3 <> r3:
      x_wu_ok.go4(b0, b1, b2, b3, r3)

def x_wu_ok.r2(+b0: U32, +b1: U32, +rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      False{}
    case +b2 <> r2:
      x_wu_ok.r3(b0, b1, b2, r2)

def x_wu_ok.r1(+b0: U32, +rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      False{}
    case +b1 <> r1:
      x_wu_ok.r2(b0, b1, r1)

def x_wu_ok(+pay: List<&2, U32>) -> Bool:
  match pay:
    case Nil{}:
      False{}
    case +b0 <> r0:
      x_wu_ok.r1(b0, r0)

def x_cls.set_ack(fresh: Bool) -> U32:
  match fresh:
    case True{}:
      1
    case False{}:
      0

def x_cls.ping_ack(fresh: Bool) -> U32:
  match fresh:
    case True{}:
      4
    case False{}:
      0

def x_cls3(+typ: U32) -> U32:
  match typ:
    case 4:
      1
    case 1:
      6
    case 0:
      6
    case 7:
      5
    case _:
      0

def x_cls_rst(+typ: U32) -> U32:
  match typ:
    case 3:
      2
    case 9:
      8
    case _:
      x_cls3(typ)

def x_cls_wu_ok(ok: Bool) -> U32:
  match ok:
    case False{}:
      9
    case True{}:
      7

def x_cls_wu(+typ: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      x_cls_wu_ok(x_wu_ok(payload))
    case _:
      x_cls_rst(typ)

def x_conn_cls(+typ: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 4:
      x_cls.set_ack(U32.is_eq(U32.and(flags, x_f_ack()), 0))
    case 6:
      x_cls.ping_ack(U32.is_eq(U32.and(flags, x_f_ack()), 0))
    case 7:
      5
    case 8:
      x_cls_wu_ok(x_wu_ok(payload))
    case _:
      0

def x_cls2(+typ: U32, +odd: U32, +flags: U32, +payload: List<&2, U32>, is_odd: Bool) -> U32:
  match is_odd:
    case True{}:
      x_cls_wu(typ, payload)
    case False{}:
      x_conn_cls(typ, flags, payload)

def x_cls_odd(+typ: U32, +odd: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  x_cls2(typ, odd, flags, payload, U32.is_eq(odd, 1))

def x_cls(+typ: U32, +sid: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  x_cls_odd(typ, U32.and(sid, 1), flags, payload)

def x_classify(+frame: Frame) -> U32:
  match frame:
    case Frame{+typ, +flags, +sid, +payload}:
      x_cls(typ, sid, flags, payload)

def x_send_raw_frame(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, x_frame_write(typ, flags, sid, pay))

def x_send_data_frame(sock: Socket, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_raw_frame(sock, x_t_data(), x_f_end_stream(), sid, body)

# Flow pump v2 (item 2, nghttp2 mold): one @unsafe phased def + small
# leafs; got destructures at arm tops, fresh re-created pairs hop to hop.
# Phases: 0 pump, 4 slice (chunk = x_chunk_of), 5 send|park, 6 continue/
# END_STREAM, 9 parked read, 12 service (WU credit / SETTINGS ack+IW /
# PING ack / consume / RST-GOAWAY-CONT fail-closed).
# Credit math is U32 throughout (x_len32/take32/drop32); the chunk is
# the whole available credit capped at 16KB (nghttp2 #1722 note).
def x_flow_min.pick(+a: U32, +b: U32, pick_a: Bool) -> U32:
  match pick_a:
    case True{}:
      a
    case False{}:
      b

def x_flow_min(+a: U32, +b: U32) -> U32:
  x_flow_min.pick(a, b, U32.is_le(a, b))

def x_flow_wu_inc(+pay: List<&2, U32>) -> U32:
  match pay:
    case Nil{}:
      0
    case +b0 <> r0:
      match r0:
        case Nil{}:
          0
        case +b1 <> r1:
          match r1:
            case Nil{}:
              0
            case +b2 <> r2:
              match r2:
                case Nil{}:
                  0
                case +b3 <> r3:
                  (((b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 : U32)))

def x_flow_credit.mine(+cw: U32, +sw: U32, +inc: U32, is_mine: Bool) -> U32 & U32:
  match is_mine:
    case True{}:
      (cw, (sw + inc : U32))
    case False{}:
      (cw, sw)

def x_flow_credit.conn(+cw: U32, +sw: U32, +inc: U32, is_conn: Bool, is_mine: Bool) -> U32 & U32:
  match is_conn:
    case True{}:
      ((cw + inc : U32), sw)
    case False{}:
      x_flow_credit.mine(cw, sw, inc, is_mine)

def x_flow_credit.add(+cw: U32, +sw: U32, +sid: U32, +sid2: U32, +inc: U32) -> U32 & U32:
  x_flow_credit.conn(cw, sw, inc, U32.is_eq(sid2, 0), U32.is_eq(sid2, sid))

def x_flow_credit.go(+cw: U32, +sw: U32, +sid: U32, +sid2: U32, +inc: U32, valid: Bool) -> U32 & U32:
  match valid:
    case False{}:
      (cw, sw)
    case True{}:
      x_flow_credit.add(cw, sw, sid, sid2, inc)

def x_flow_cw(p: U32 & U32) -> U32:
  (a, b) = p
  a

def x_flow_sw(p: U32 & U32) -> U32:
  (a, b) = p
  b

def x_flow_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, GotErr{code, msg})
    case Done{u}:
      (s, GotErr{0, "next"})

def x_chunk_of(+cw: U32, +sw: U32, +blen: U32) -> U32:
  x_flow_min(x_flow_min(x_flow_min(cw, sw), x_max_send()), blen)

def x_chunk_pos(+chunk: U32) -> Bool:
  U32.is_gt(chunk, 0)

# Peer SETTINGS ledger (mold h2_settings.iw_of): current INITIAL_WINDOW_SIZE
# (id 4) or the running default when the peer never announces it.
def x_settings.iw_find(+cur: U32, +val: U32, is_four: Bool) -> U32:
  match is_four:
    case True{}:
      val
    case False{}:
      cur

def x_settings.iw_of(+pay: List<&2, U32>, +cur: U32) -> U32:
  match pay:
    case Nil{}:
      cur
    case +b0 <> r0:
      match r0:
        case Nil{}:
          cur
        case +b1 <> r1:
          match r1:
            case Nil{}:
              cur
            case +b2 <> r2:
              match r2:
                case Nil{}:
                  cur
                case +b3 <> r3:
                  match r3:
                    case Nil{}:
                      cur
                    case +b4 <> r4:
                      match r4:
                        case Nil{}:
                          cur
                        case +b5 <> rest:
                          x_settings.iw_of(rest, x_settings.iw_find(cur, (((b2 * 16777216 + b3 * 65536 + b4 * 256 + b5 : U32))), U32.is_eq((b0 * 256 + b1 : U32), 4)))

def x_flow.acked(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) -> Socket & Got:
  (s2, r2) = sent
  match r2:
    case Fail{(code, msg)}:
      (s2, GotErr{code, msg})
    case Done{u}:
      (s2, GotOk{Frame{0, 0, 0, Nil{}}, buf})

def x_flow.ack(got: Socket & Got, buf: List<&2, U32>) -> IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_settings(), x_f_ack(), 0, Nil{})
    IO.pure(Socket & Got, x_flow.acked(sent, buf))

def x_flow_wu_bad(got: Socket & Got) -> Socket & Result<&1, &1, U32 & String, Unit>:
  (s, g) = got
  (s, Fail{(502, "bad window_update")})

def x_flow.pair(got: Socket & Got) -> Socket & Got:
  (s, g) = got
  (s, GotErr{0, "next"})

@unsafe
def x_send_data_flow(+phase: U32, got: Socket & Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, +ok: Bool, +sid2p: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match phase:
    case 0:
      (s0, g0) = got
      match g0:
        case GotErr{code0, msg0}:
          match code0:
            case 0:
              match body:
                case Nil{}:
                  x_send_frame(s0, x_t_data(), x_f_end_stream(), sid, Nil{})
                case +b <> r:
                  x_send_data_flow(4, (s0, GotErr{0, "next"}), sid, b <> r, cw, sw, buf, cl, ful, pay2, ok, sid2p)
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s0, Fail{(code0, msg0)}))
        case GotOk{+frame0, +buf0}:
          x_send_data_flow(0, (s0, GotErr{0, "next"}), sid, body, cw, sw, buf0, 0, 0, Nil{}, True{}, sid2p)
    case 4:
      (s4, g4) = got
      x_send_data_flow(5, (s4, GotErr{0, "next"}), sid, body, cw, sw, buf, cl, x_chunk_of(cw, sw, x_len32(body)), Nil{}, x_chunk_pos(x_chunk_of(cw, sw, x_len32(body))), sid2p)
    case 5:
      (s5, g5) = got
      x_flow.chunker(got, sid, body, cw, sw, buf, cl, ful, pay2, ok, sid2p)
    case 6:
      (s6, g6) = got
      x_flow.reste(got, sid, body, cw, sw, buf, cl, ful, pay2, ok, sid2p)
    case 9:
      (s9, g9) = got
      match g9:
        case GotErr{code9, msg9}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s9, Fail{(code9, msg9)}))
        case GotOk{+frame9, +buf9}:
          match frame9:
            case Frame{+typ9, +flags9, +sid29, +payload9}:
              x_send_data_flow(12, got, sid, body, cw, sw, buf9, x_flow.cls(typ9), ful, payload9, x_wu_ok(payload9), sid29)
    case 12:
      (s12, g12) = got
      x_flow.do_act(got, sid, body, cw, sw, buf, cl, sid2p, pay2)
    case _:
      (s13, g13) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s13, Fail{(502, "flow bad phase")}))

def x_flow.cls(+typ: U32) -> U32:
  match typ:
    case 8:
      2
    case 4:
      4
    case 6:
      6
    case 3:
      3
    case 7:
      7
    case 9:
      9
    case _:
      0

def x_flow.chunker(got: Socket & Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, ok: Bool, +sid2p: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s5, g5) = got
  match ok:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s5, x_t_data(), 0, sid, x_take32(ful, body))
        x_send_data_flow(6, x_flow_sent(sent), sid, x_drop32(ful, body), (cw - ful : U32), (sw - ful : U32), buf, 0, 0, Nil{}, True{}, sid2p)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        got2 : Socket & Got <- x_read_frame(s5, buf)
        x_send_data_flow(9, got2, sid, body, cw, sw, buf, cl, ful, pay2, ok, sid2p)

def x_flow.reste(got: Socket & Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, +ok: Bool, +sid2p: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s6, g6) = got
  match body:
    case Nil{}:
      x_send_frame(s6, x_t_data(), x_f_end_stream(), sid, Nil{})
    case +b <> r:
      x_send_data_flow(0, (s6, GotErr{0, "next"}), sid, b <> r, cw, sw, buf, 0, 0, Nil{}, True{}, sid2p)

@unsafe
def x_flow.do_act(got: Socket & Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +sid2p: U32, +pay2: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, g) = got
  match cl:
    case 2:
      x_flow.wu(got, sid, body, cw, sw, buf, sid2p, x_flow_wu_inc(pay2), x_wu_ok(pay2))
    case 4:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        got2 : Socket & Got <- x_flow.ack(got, buf)
        x_send_data_flow(4, got2, sid, body, cw, x_settings.iw_of(pay2, sw), buf, 0, 0, Nil{}, True{}, sid2p)
    case 6:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_ping(), x_f_ack(), 0, pay2)
        x_send_data_flow(4, x_flow_sent(sent), sid, body, cw, sw, buf, 0, 0, Nil{}, True{}, sid2p)
    case 3:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{(502, "rst_stream")}))
    case 7:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{(502, "goaway")}))
    case 9:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{(502, "continuation")}))
    case _:
      x_send_data_flow(4, (s, GotErr{0, "next"}), sid, body, cw, sw, buf, 0, 0, Nil{}, True{}, sid2p)

@unsafe
def x_flow.wu(got: Socket & Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +sid2p: U32, +inc: U32, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match ok:
    case True{}:
      +cream = x_flow_credit.go(cw, sw, sid, sid2p, inc, True{})
      x_send_data_flow(4, x_flow.pair(got), sid, body, x_flow_cw(cream), x_flow_sw(cream), buf, 0, 0, Nil{}, True{}, sid2p)
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, x_flow_wu_bad(got))

def x_send_data_start.go(sock: Socket, +sid: U32, +body: List<&2, U32>, single: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match single:
    case True{}:
      x_send_data_frame(sock, sid, body)
    case False{}:
      x_send_data_flow(0, (sock, GotErr{0, "next"}), sid, body, x_init_window(), x_init_window(), Nil{}, 0, 0, Nil{}, True{}, 0)

def x_send_data_start(sock: Socket, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_data_start.go(sock, sid, body, U32.is_le(x_len32(body), x_max_send()))

def x_send_resp_body(sock: Socket, +sid: U32, +body: List<&2, U32>, too_big: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match too_big:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(413, "resp too large")}))
    case False{}:
      x_send_data_frame(sock, sid, body)

def x_send_resp_body2(sock: Socket, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_data_start(sock, sid, body)

def x_send_resp_head(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +body: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{u}:
      match is_empty:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
        case False{}:
          x_send_resp_body2(sock, sid, body)

def x_send_resp.go(sock: Socket, +sid: U32, +status: U32, +headers: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  hs = List.append(&2, Hdr, [Hdr{":status", U32.show(status)}], headers)
  blk = x_block(hs)
  +empty = List.is_empty(&2, U32, body)
  flags = (x_f_end_headers() + x_b2u(empty) : U32)
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_raw_frame(sock, x_t_headers(), flags, sid, blk)
    x_send_resp_head(sent, sid, body, empty)

def x_send_resp(sock: Socket, +sid: U32, +resp: Response) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match resp:
    case Response{+status, +headers, +body}:
      x_send_resp.go(sock, sid, status, headers, body)

# Httpx slots (unbounded List<St>; single-traversal take in Data wrapper)
# -----------------------------------------------------------------------

def httpx.sid_of(st: St) -> U32:
  match st:
    case St{head, body, +sid}:
      sid

# Ack only a fresh (non-ACK) SETTINGS: acking an ACK back would ping-pong
# the two unbounded read loops forever.
def httpx.cls_fix(base: U32, +flags: U32) -> U32:
  match base flags:
    case 1 1:
      0
    case _ _:
      base

# Parking value: the loop reads on every turn, so the carrier only has to
# carry the socket while no frame is in hand.
def httpx.again(s: Socket) -> Socket & Got:
  (s, GotOk{Frame{0, 0, 0, Nil{}}, Nil{}})

def httpx.close_got(got: Socket & Got) -> IO(Unit):
  (s, g) = got
  TLS.tls_close(s)

# Housekeeping sends keep the connection alive even if the write fails:
# the next read answers the dead socket and closes the connection.
def httpx.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & Got:
  (s2, r) = sent
  httpx.again(s2)

def httpx.ack(got: Socket & Got) -> IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_settings(), x_f_ack(), 0, Nil{})
    IO.pure(Socket & Got, httpx.sent(sent))

def httpx.ack_ping(got: Socket & Got, +payload: List<&2, U32>) -> IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_ping(), x_f_ack(), 0, payload)
    IO.pure(Socket & Got, httpx.sent(sent))

def httpx.body_of(st: St) -> List<&2, U32>:
  match st:
    case St{head, +body, sid}:
      body

def httpx.req_of(+rh: ReqHead, +body: List<&2, U32>) -> Request:
  match rh:
    case ReqHead{+method, +path, +headers}:
      Request{method, path, headers, body}

# Request straight from the slot, no +rh/+body. Thin projection style:
# the caller holds one reusable Taken bind.
def httpx.req_of_st(st: St, +payload: List<&2, U32>) -> Request:
  match st:
    case St{head, +body, +sid}:
      match head:
        case None{}:
          Request{"", "", Nil{}, x_cat(x_rev_push(payload, body))}
        case Some{+rh}:
          match rh:
            case ReqHead{+method, +path, +headers}:
              Request{method, path, headers, x_cat(x_rev_push(payload, body))}

def httpxn.no_slots() -> List<&2, St>:
  Nil{}

def httpxn.no_fends() -> List<&2, U32>:
  Nil{}

def httpxn.has(slots: List<&2, St>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      Bool.or(U32.is_eq(httpx.sid_of(st), sid), httpxn.has(t, sid))

# Single-traversal fragment probe: slot with sid exists AND head is None.
# 2 traversals + S clones -> 1 traversal, S incs (sids unique via put).
def httpxn.has_some_go(eq: Bool, st: St, rec: Bool) -> Bool:
  match eq:
    case True{}:
      match st:
        case St{head, body, sid}:
          match head:
            case None{}:
              True{}
            case Some{rh}:
              False{}
    case False{}:
      rec

def httpxn.has_some(slots: List<&2, St>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      httpxn.has_some_go(U32.is_eq(httpx.sid_of(st), sid), st, httpxn.has_some(t, sid))

def httpxn.del_go(eq: Bool, +st: St, rest: List<&2, St>) -> List<&2, St>:
  match eq:
    case True{}:
      rest
    case False{}:
      st <> rest

def httpxn.del(slots: List<&2, St>, +sid: U32) -> List<&2, St>:
  match slots:
    case Nil{}:
      Nil{}
    case +st <> t:
      httpxn.del_go(U32.is_eq(httpx.sid_of(st), sid), st, httpxn.del(t, sid))

# Single-traversal take in a Data wrapper (a top-level A & B pair is not
# Data and admits no + reuse). 1x O(S) always: strict args run the tail
# even on early match; sids unique via put so the tail found nothing.
def httpxn.take_go(eq: Bool, +st: St, p: Taken) -> Taken:
  match eq:
    case True{}:
      match p:
        case Taken{+slots, st2}:
          Taken{slots, st}
    case False{}:
      match p:
        case Taken{+slots2, +found2}:
          Taken{(st <> slots2), found2}

def httpxn.take_del(slots: List<&2, St>, +sid: U32) -> Taken:
  match slots:
    case Nil{}:
      Taken{Nil{}, St{None{}, Nil{}, 0}}
    case +st <> t:
      httpxn.take_go(U32.is_eq(httpx.sid_of(st), sid), st, httpxn.take_del(t, sid))

def httpxn.taken_slots(p: Taken) -> List<&2, St>:
  match p:
    case Taken{+slots, st}:
      slots

def httpxn.taken_st(p: Taken) -> St:
  match p:
    case Taken{slots, +st}:
      st

# DATA continue: keep the slot with the pushed rev-body, hp-less.
def httpxn.data_cont_slots(p: Taken, +payload: List<&2, U32>) -> List<&2, St>:
  match p:
    case Taken{+rest, st}:
      match st:
        case St{head, +body, +sid}:
          match head:
            case None{}:
              ((St{Some{ReqHead{"", "", Nil{}}}, x_rev_push(payload, body), sid} <> rest))
            case Some{+rh}:
              ((St{Some{rh}, x_rev_push(payload, body), sid} <> rest))

# CONTINUATION fragment: head stays None, rev-body grows.
def httpxn.frag_cont_slots(p: Taken, +payload: List<&2, U32>) -> List<&2, St>:
  match p:
    case Taken{+rest, st}:
      match st:
        case St{head, +body, +sid}:
          ((St{None{}, x_rev_push(payload, body), sid} <> rest))

def httpxn.put(slots: List<&2, St>, +st: St) -> List<&2, St>:
  st <> httpxn.del(slots, httpx.sid_of(st))

def httpxn.fdel_go(eq: Bool, +x: U32, rest: List<&2, U32>) -> List<&2, U32>:
  match eq:
    case True{}:
      rest
    case False{}:
      x <> rest

def httpxn.fdel(fends: List<&2, U32>, +sid: U32) -> List<&2, U32>:
  match fends:
    case Nil{}:
      Nil{}
    case +x <> t:
      httpxn.fdel_go(U32.is_eq(x, sid), x, httpxn.fdel(t, sid))

# Fused fends take: find + remove + flag in one traversal (2 -> 1).
def httpxn.fdel_flag_go(eq: Bool, +x: U32, p: FendTaken) -> FendTaken:
  match eq:
    case True{}:
      match p:
        case FendTaken{+rest, flag}:
          FendTaken{rest, 1}
    case False{}:
      match p:
        case FendTaken{+rest2, +flag2}:
          FendTaken{(x <> rest2), flag2}

def httpxn.fdel_flag(fends: List<&2, U32>, +sid: U32) -> FendTaken:
  match fends:
    case Nil{}:
      FendTaken{Nil{}, 0}
    case +x <> t:
      httpxn.fdel_flag_go(U32.is_eq(x, sid), x, httpxn.fdel_flag(t, sid))

def httpxn.ftaken_fends(p: FendTaken) -> List<&2, U32>:
  match p:
    case FendTaken{+fends, flag}:
      fends

def httpxn.ftaken_flag(p: FendTaken) -> U32:
  match p:
    case FendTaken{fends, +flag}:
      flag

def httpxn.fput(fends: List<&2, U32>, +sid: U32) -> List<&2, U32>:
  sid <> httpxn.fdel(fends, sid)

def httpxn.fend_up(fends: List<&2, U32>, +sid: U32, is_end: Bool) -> List<&2, U32>:
  match is_end:
    case True{}:
      httpxn.fput(fends, sid)
    case False{}:
      httpxn.fdel(fends, sid)

def httpxn.frag_has(+slots: List<&2, St>, +sid: U32) -> Bool:
  httpxn.has_some(slots, sid)

# HEADERS action codes: 0 claim slot, 1 answer now, 5 decode fail,
# 6 park header fragment (HEADERS without END_HEADERS).
def httpxn.head_act(need: U32, ok: Bool, +end: U32) -> U32:
  match need ok end:
    case 1 _ _:
      6
    case 0 False{} _:
      5
    case 0 True{} 1:
      1
    case _ _ _:
      0

# DATA action codes: 0 append, 1 answer, 4 stray skip-or-close.
def httpxn.decide_data(has: Bool, +end: U32) -> U32:
  match has end:
    case False{} _:
      4
    case True{} 1:
      1
    case _ _:
      0

# CONTINUATION action codes: 0 append fragment, 1 finish block,
# 4 connection error (no open fragment for this sid).
def httpxn.decide_cont(has_frag: Bool, +endh: U32) -> U32:
  match has_frag endh:
    case False{} _:
      4
    case True{} 0:
      0
    case True{} 4:
      1
    case _ _:
      4

def httpxn.need_go(needs: Bool) -> U32:
  match needs:
    case True{}:
      1
    case False{}:
      0

def httpxn.need_u(+typ: U32, +flags: U32) -> U32:
  httpxn.need_go(x_needs_cont(typ, flags))

# Both arms close the socket: no match needed (same shape as httpx.sent).
def httpxn.cont_failed(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = sent
  TLS.tls_close(s)

def x_send_wu(sock: Socket, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_wu(), 0, sid, x_be32(inc))

def x_send_wu2.next(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{e}))
    case Done{u}:
      x_send_wu(s2, sid, inc)

def x_send_wu_len.go(sock: Socket, +sid: U32, +inc: U32, empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match empty:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_wu(sock, 0, inc)
        x_send_wu2.next(sent, sid, inc)

def x_send_wu_len(sock: Socket, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_wu_len.go(sock, sid, inc, U32.is_eq(inc, 0))

def x_send_rst(sock: Socket, +sid: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_rst(), 0, sid, x_be32(code))

# Receive-side credit leaf for the server loops (mold client.on.wu_best,
# buf carried): best-effort double WINDOW_UPDATE (conn 0 + stream sid);
# a failed credit still delivers the frame, the dead socket fails next read.
def httpx.wo(got: Socket & Got) -> Socket:
  (sx, gx) = got
  sx

def httpx.wu_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) ->
  Socket & Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, GotErr{code, msg})
    case Done{u}:
      (s, GotOk{Frame{0, 0, 0, Nil{}}, buf})

def httpx.wu_er(got: Socket & Got, buf: List<&2, U32>, +sid: U32, +payload: List<&2, U32>) ->
  IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_wu_len(s, sid, x_len32(payload))
    IO.pure(Socket & Got, httpx.wu_kept(sent, buf))

# Main interleave loop (single @unsafe self-recursive def; phase-0 reset
# spelled out at each site). Single Socket carrier threaded whole, slot
# decisions as Bool/U32 params computed in caller arg position, open
# streams as List<St> + fragment END_STREAM ledger fends.
# Phases: 0 read, 1 decompose, 2 connection dispatch (cls),
# 3 stream dispatch (typ), 4 HEADERS-complete, 5 DATA, 6 CONTINUATION.
# 13 params + handler (was 14 + handler with the HpDyn tab).

@unsafe
def httpx(~H: Request -> IO(Response), phase: U32, got: Socket & Got, +slots: List<&2, St>, +fends: List<&2, U32>, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +rh: ReqHead, act: U32, +tab: Tab) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & Got <- x_read_frame(s0, buf)
        httpx(~H, 1, got2, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
    case 1:
      (s1, g1) = got
      match g1:
        case GotErr{code1, msg1}:
          TLS.tls_close(s1)
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ2, +flags2, +sid22, +payload2}:
              httpx(~H, 2, (s1, GotOk{frame, buf2}), slots, fends, buf2, typ2, flags2, sid22, payload2, httpx.cls_fix(x_classify(frame), flags2), U32.and(flags2, x_f_end_stream()), ReqHead{"", "", Nil{}}, 4, tab)
    case 2:
      match cls:
        case 1:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.ack(got)
            httpx(~H, 0, got2, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 4:
          do IO<Unit>:
            gotp : Socket & Got <- httpx.ack_ping(got, payload)
            httpx(~H, 0, gotp, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 5:
          httpx.close_got(got)
        case 2:
          httpx(~H, 0, got, httpxn.del(slots, sid2), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 7:
          httpx(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 9:
          httpx.close_got(got)
        case 8:
          httpx(~H, 6, got, slots, fends, buf, typ, flags, sid2, payload, cls, U32.and(flags, x_f_end_headers()), ReqHead{"", "", Nil{}}, httpxn.decide_cont(httpxn.frag_has(slots, sid2), U32.and(flags, x_f_end_headers())), tab)
        case 6:
          httpx(~H, 3, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, ReqHead{"", "", Nil{}}, 4, tab)
        case 0:
          httpx(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case _:
          httpx(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
    case 3:
      match typ:
        case 1:
          +dr : Result<&1, &1, U32 & String, ReqHead & Tab> = x_req.decode(payload, tab)
          httpx(~H, 4, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, x_req.rh(dr), httpxn.head_act(httpxn.need_u(typ, flags), x_req.ok(dr), end), x_req.tab(dr))
        case 0:
          httpx(~H, 5, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, ReqHead{"", "", Nil{}}, httpxn.decide_data(httpxn.has(slots, sid2), end), tab)
        case _:
          httpx(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
    case 4:
      (s4, g4) = got
      match act:
        case 0:
          httpx(~H, 0, got, httpxn.put(slots, St{Some{rh}, Nil{}, sid2}), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 1:
          do IO<Unit>:
            req : Request = httpx.req_of(rh, Nil{})
            resp : Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_resp(s4, sid2, resp)
            httpx(~H, 0, httpx.sent(sent), httpxn.del(slots, sid2), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 6:
          httpx(~H, 0, got, httpxn.put(slots, St{None{}, x_cat(payload), sid2}), httpxn.fend_up(fends, sid2, U32.is_eq(end, 1)), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 5:
          TLS.tls_close(s4)
        case _:
          TLS.tls_close(s4)
    case 5:
      (sb, gb) = got
      match act:
        case 0:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.wu_er((sb, gb), buf, sid2, payload)
            httpx(~H, 0, got2, httpxn.data_cont_slots(httpxn.take_del(slots, sid2), payload), fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 1:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.wu_er((sb, gb), buf, sid2, payload)
            +tp : Taken = httpxn.take_del(slots, sid2)
            req : Request = httpx.req_of_st(httpxn.taken_st(tp), payload)
            resp : Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_resp(httpx.wo(got2), sid2, resp)
            httpx(~H, 0, httpx.sent(sent), httpxn.taken_slots(tp), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 4:
          httpx.close_got(got)
        case _:
          httpx.close_got(got)
    case 6:
      (s6, g6) = got
      match act:
        case 0:
          httpx(~H, 0, got, httpxn.frag_cont_slots(httpxn.take_del(slots, sid2), payload), fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)
        case 1:
          +tp2 : Taken = httpxn.take_del(slots, sid2)
          +full : List<&2, U32> = x_cat(x_rev_push(payload, httpx.body_of(httpxn.taken_st(tp2))))
          +dr6 : Result<&1, &1, U32 & String, ReqHead & Tab> = x_req.decode(full, tab)
          +fp : FendTaken = httpxn.fdel_flag(fends, sid2)
          +ff : U32 = httpxn.ftaken_flag(fp)
          httpx(~H, 4, got, httpxn.taken_slots(tp2), httpxn.ftaken_fends(fp), buf, typ, flags, sid2, Nil{}, cls, ff, x_req.rh(dr6), httpxn.head_act(0, x_req.ok(dr6), ff), x_req.tab(dr6))
        case _:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s6, 0, 1)
            httpxn.cont_failed(sent)
    case _:
      httpx(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, tab)

# Preface entry (owns the byte buffer end-to-end, so pipelined frames are
# never dropped between streams). Below httpx: calls upward.

@unsafe
def httpx_pre(~H: Request -> IO(Response), phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          httpx_pre(~H, 1, (s0, Done{chunk}), acc2, x_preface_ok(acc2), Bool.not(x_has_at_least(24, acc2)))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            httpx_pre(~H, 0, r2, acc, 0, False{})
        case False{}:
          httpx_pre(~H, 2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s2, x_t_settings(), 0, 0, x_settings_initial_pay())
            httpx(~H, 0, httpx.sent(sent), httpxn.no_slots(), httpxn.no_fends(), x_drop32(24, acc), 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, x_tab.empty())
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def httpx_start(~H: Request -> IO(Response), sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    httpx_pre(~H, 0, r1, Nil{}, 0, False{})

# Accept plumbing (httpx-only, H2-only): every connection runs httpx_start.
# No H1 split — ALPN non-H2 closes fail-closed.

def httpx_spawn.go(~H: Request -> IO(Response), sock: Socket) -> IO(Unit):
  httpx_start(~H, sock)

def httpx_spawn(~H: Request -> IO(Response), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, httpx_spawn.go(~H, sock))
    return l

def httpx_conn(~H: Request -> IO(Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      httpx_spawn(~H, sock, l)

def httpx_alpn_close(sock: Socket, l: Listener) -> IO(Listener):
  do IO<Listener>:
    x : Unit <- TLS.tls_close(sock)
    return l

def httpx_alpn_go(~H: Request -> IO(Response), is_h2: Bool, listener: Listener, sock: Socket) -> IO(Listener):
  match is_h2:
    case True{}:
      httpx_spawn(~H, sock, listener)
    case False{}:
      httpx_alpn_close(sock, listener)

def httpx_alpn_conn(~H: Request -> IO(Response), accepted: Listener & Result<&1, &1, U32 & String, Socket & String>) -> IO(Listener):
  (listener, result) = accepted
  match result:
    case Fail{e}:
      IO.pure(Listener, listener)
    case Done{value}:
      (sock, protocol) = value
      httpx_alpn_go(~H, TLS.tls_alpn_is_h2(protocol), listener, sock)

# Public servers. Strict pair requires H2 ALPN; _alpn pair accepts the
# handshake with h2/http1.1 offer but serves H2 only (non-H2 closes).

@unsafe
def server.concurrent(~H: Request -> IO(Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- httpx_conn(~H, m)
    z : Unit <- server.concurrent(~H, l2, cert, key)
    return z

@unsafe
def server.concurrent_alpn(~H: Request -> IO(Response), listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_accept_alpn(listener, cert, key)
    next : Listener <- httpx_alpn_conn(~H, accepted)
    z : Unit <- server.concurrent_alpn(~H, next, cert, key)
    return z

# Client H2 (Phase 8: A x_resp above; B once; E stream; C keep-alive;
# D concurrent; F server stream). Only Base+tls imports are kept: all
# codec pieces reuse x_* above, validation is local (same Fail 400).
# ---------------------------------------------------------------------

type Cont is Data:
  Cont{block: List<&2, U32>, rest: List<&2, U32>}

type CliSt is Data:
  CliSt{sid: U32, tab: Tab, is_h2: Bool}

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

# Local validation (same Fail 400 as https valid.go; no http import)
# ------------------------------------------------------------------

def client.on.has_crlf(+s: String) -> Bool:
  Bool.or(String.contains(s, "\r"), String.contains(s, "\n"))

def client.on.nul1() -> String:
  String.from_list([Chr{0}])

def client.on.has_nul(s: String) -> Bool:
  String.contains(s, client.on.nul1())

def client.on.has_host_bad(+h: String) -> Bool:
  Bool.or(String.contains(h, "/"),
    Bool.or(String.contains(h, "?"),
      Bool.or(String.contains(h, "#"), String.contains(h, "@"))))

def client.on.valid_host.put4(sp: Bool) -> Bool:
  match sp:
    case True{}:
      False{}
    case False{}:
      True{}

def client.on.valid_host.put3(bad: Bool, sp: Bool) -> Bool:
  match bad:
    case True{}:
      False{}
    case False{}:
      client.on.valid_host.put4(sp)

def client.on.valid_host.put2(crlf: Bool, bad: Bool, sp: Bool) -> Bool:
  match crlf:
    case True{}:
      False{}
    case False{}:
      client.on.valid_host.put3(bad, sp)

def client.on.valid_host.put(empty: Bool, crlf: Bool, bad: Bool, sp: Bool) -> Bool:
  match empty:
    case True{}:
      False{}
    case False{}:
      client.on.valid_host.put2(crlf, bad, sp)

def client.on.valid_host(+h: String) -> Bool:
  client.on.valid_host.put(String.is_empty(h), Bool.or(client.on.has_crlf(h), client.on.has_nul(h)), client.on.has_host_bad(h), String.contains(h, " "))

def client.on.valid_port(+p: U32) -> Bool:
  Bool.and(U32.is_ge(p, 1), U32.is_le(p, 65535))

def client.on.valid_path.put3(sp: Bool) -> Bool:
  match sp:
    case True{}:
      False{}
    case False{}:
      True{}

def client.on.valid_path.put2(crlf: Bool, sp: Bool) -> Bool:
  match crlf:
    case True{}:
      False{}
    case False{}:
      client.on.valid_path.put3(sp)

def client.on.valid_path.put(slash: Bool, crlf: Bool, sp: Bool) -> Bool:
  match slash:
    case True{}:
      client.on.valid_path.put2(crlf, sp)
    case False{}:
      False{}

def client.on.valid_path(+p: String) -> Bool:
  client.on.valid_path.put(String.starts_with(p, "/"), Bool.or(client.on.has_crlf(p), client.on.has_nul(p)), String.contains(p, " "))

def client.on.valid.go(+host: String, +port: U32, +path: String) -> Bool:
  Bool.and(client.on.valid_host(host), Bool.and(client.on.valid_port(port), client.on.valid_path(path)))

# Authority + request block (mirror https with_authority, Hdr)
# ---------------------------------------------------------------

def client.on.drop_authority.go(+n: String, +v: String, rec: List<&2, Hdr>, is_auth: Bool) ->
  List<&2, Hdr>:
  match is_auth:
    case True{}:
      rec
    case False{}:
      Hdr{n, v} <> rec

def client.on.drop_authority(hs: List<&2, Hdr>) -> List<&2, Hdr>:
  match hs:
    case Nil{}:
      Nil{}
    case Hdr{n, v} <> t:
      +nn = n
      +vv = v
      client.on.drop_authority.go(nn, vv, client.on.drop_authority(t), String.eq(nn, ":authority"))

def client.on.with_authority(+host: String, +port: U32, hs: List<&2, Hdr>) ->
  List<&2, Hdr>:
  Hdr{":authority", host ++ ":" ++ U32.show(port)} <> client.on.drop_authority(hs)

def client.on.req_hdrs(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>) ->
  List<&2, Hdr>:
  List.append(&2, Hdr, [Hdr{":method", method}, Hdr{":path", path}, Hdr{":scheme", "https"}], client.on.with_authority(host, port, hs))

def client.on.req_block(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>) ->
  List<&2, U32>:
  x_block(client.on.req_hdrs(host, port, method, path, hs))

# Window-update + RST sends (best-effort credit, mold h2_send_wu_len)
# -------------------------------------------------------------------


# CONTINUATION finish for client HEADERS without END_HEADERS
# (mirror h2_cont_read; narrow single-@unsafe loop)
# ----------------------------------------------------------

def client.on.cont_end(last: Bool) -> U32:
  match last:
    case True{}:
      0
    case False{}:
      1

def client.on.cont_ok(+typ: U32, +sid: U32, +exp: U32) -> Bool:
  Bool.and(U32.is_eq(typ, x_t_cont()), Bool.and(U32.is_eq(sid, exp), U32.is_gt(sid, 0)))

def client.on.cont_last(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, x_f_end_headers()), x_f_end_headers())

def client.on.cont_cls(+typ: U32, +sid2: U32, +sid: U32, +flags: U32, ok: Bool) -> U32:
  match ok:
    case True{}:
      client.on.cont_end(client.on.cont_last(flags))
    case False{}:
      2

def client.on.cont_cls_of(+typ: U32, +sid2: U32, +sid: U32, +flags: U32) -> U32:
  client.on.cont_cls(typ, sid2, sid, flags, client.on.cont_ok(typ, sid2, sid))

def client.on.cont_failed(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, Cont>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Cont>, (s, Fail{e}))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Cont>, (s, Fail{(502, "continuation")}))

@unsafe
def client.on.cont_read(+phase: U32, +sid: U32, +acc: List<&2, U32>, +buf: List<&2, U32>, prev: Socket & Got, +cls: U32, +frag: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Cont>):
  match phase:
    case 0:
      (s0, g0) = prev
      match g0:
        case GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, Cont>>:
                got2 : Socket & Got <- x_read_frame(s0, buf)
                client.on.cont_read(0, sid, acc, buf, got2, 0, Nil{})
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, Cont>, (s0, Fail{(code, msg)}))
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ, +flags, +sid2, +payload}:
              client.on.cont_read(1, sid, acc, buf2, (s0, GotErr{0, "next"}), client.on.cont_cls_of(typ, sid2, sid, flags), payload)
    case 1:
      (s1, g1) = prev
      match cls:
        case 0:
          IO.pure(Socket & Result<&1, &1, U32 & String, Cont>, (s1, Done{Cont{List.append(&2, U32, acc, frag), buf}}))
        case 1:
          client.on.cont_read(0, sid, List.append(&2, U32, acc, frag), buf, (s1, GotErr{0, "next"}), 0, Nil{})
        case _:
          do IO<Socket & Result<&1, &1, U32 & String, Cont>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s1, 0, 1)
            client.on.cont_failed(sent)
    case _:
      (sx, gx) = prev
      IO.pure(Socket & Result<&1, &1, U32 & String, Cont>, (sx, Fail{(502, "bad phase")}))

def client.on.cont_start(sock: Socket, +sid: U32, +acc: List<&2, U32>, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Cont>):
  client.on.cont_read(0, sid, acc, buf, (sock, GotErr{0, "next"}), 0, Nil{})

# Single-stream drain leafs (once/keep-alive share; streaming adds WU)
# ---------------------------------------------------------------------

def client.on.again(s: Socket) -> Socket & Got:
  (s, GotOk{Frame{0, 0, 0, Nil{}}, Nil{}})

def client.on.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & Got:
  (s2, r) = sent
  client.on.again(s2)

def client.on.ack(got: Socket & Got) -> IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_settings(), x_f_ack(), 0, Nil{})
    IO.pure(Socket & Got, client.on.sent(sent))

def client.on.ack_ping(got: Socket & Got, +payload: List<&2, U32>) -> IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_ping(), x_f_ack(), 0, payload)
    IO.pure(Socket & Got, client.on.sent(sent))

def client.on.resp_of(+head: Head, +body: List<&2, U32>) -> Response:
  match head:
    case Head{+status, +headers}:
      Response{status, headers, body}

def client.on.head_status(+head: Head) -> U32:
  match head:
    case Head{+status, headers}:
      status

def client.on.has_head(+head: Head) -> Bool:
  U32.is_ne(client.on.head_status(head), 0)

def client.on.mine_go(+cls: U32, is_stream: Bool, is_mine: Bool) -> U32:
  match is_stream is_mine:
    case True{} False{}:
      0
    case _ _:
      cls

def client.on.mine_cls(+cls: U32, +sid2: U32, +exp: U32) -> U32:
  client.on.mine_go(cls, U32.is_eq(cls, 6), U32.is_eq(sid2, exp))

# Upload cap removed (item 2): the flow sender slices DATA to peer windows
# (server gives WU per DATA). Bodies any size go through; the H1 lane keeps
# its own fail-closed 16KB server cap (subset decision, untouched).
def client.on.body_ok(+body: List<&2, U32>) -> Bool:
  True{}

def client.on.head_flags(is_empty: Bool) -> U32:
  match is_empty:
    case True{}:
      (x_f_end_headers() + x_f_end_stream() : U32)
    case False{}:
      x_f_end_headers()

def client.on.fail(got: Socket & Got, +tab: Tab, +code: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & Tab):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, Response> & Tab, (s, Fail{(code, msg)}, tab))

def client.on.done(got: Socket & Got, +tab: Tab, +head: Head, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & Tab):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, Response> & Tab, (s, Done{client.on.resp_of(head, x_cat(body))}, tab))

def client.on.done_data(got: Socket & Got, +tab: Tab, +head: Head, +body: List<&2, U32>, +payload: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & Tab):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, Response> & Tab, (s, Done{client.on.resp_of(head, x_cat(x_rev_push(payload, body)))}, tab))

# Single-stream response drain (once shape; keep-alive threads tab/sid
# outside). Phases: 0 read, 1 decompose, 2 conn dispatch, 3 stream
# dispatch (HEADERS decodes here, DATA decides here), 4 HEADERS act,
# 5 DATA act. Fragmented HEADERS (need==1) fails 502 — peers here send
# one HEADERS (node echo does); CONT accumulation lives in cont_read
# for later streaming phases.
# ---------------------------------------------------------------------

@unsafe
def client.on.drain(phase: U32, got: Socket & Got, +buf: List<&2, U32>, +tab: Tab, +head: Head, +body: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +exp: U32, act: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & Tab):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Socket & Result<&1, &1, U32 & String, Response> & Tab>:
        got2 : Socket & Got <- x_read_frame(s0, buf)
        client.on.drain(1, got2, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case GotErr{code1, msg1}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response> & Tab, (s1, Fail{(code1, msg1)}, tab))
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ2, +flags2, +sid22, +payload2}:
              client.on.drain(2, (s1, GotOk{frame, buf2}), buf2, tab, head, body, typ2, flags2, sid22, payload2, client.on.mine_cls(httpx.cls_fix(x_classify(frame), flags2), sid22, exp), U32.and(flags2, x_f_end_stream()), exp, 4)
    case 2:
      match cls:
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Response> & Tab>:
            got2 : Socket & Got <- client.on.ack(got)
            client.on.drain(0, got2, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Response> & Tab>:
            gotp : Socket & Got <- client.on.ack_ping(got, payload)
            client.on.drain(0, gotp, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 5:
          client.on.fail(got, tab, 502, "goaway")
        case 7:
          client.on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 9:
          client.on.fail(got, tab, 502, "bad window_update")
        case 8:
          client.on.fail(got, tab, 502, "continuation")
        case 2:
          client.on.fail(got, tab, 502, "rst_stream")
        case 6:
          client.on.drain(3, got, buf, tab, head, body, typ, flags, sid2, payload, cls, end, exp, 4)
        case 0:
          client.on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case _:
          client.on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 3:
      match typ:
        case 1:
          +dr : Result<&1, &1, U32 & String, Head & Tab> = x_resp.decode(payload, tab)
          client.on.drain(4, got, buf, x_resp.tab(dr), x_resp.rh(dr), body, typ, flags, sid2, payload, cls, end, exp, httpxn.head_act(httpxn.need_u(typ, flags), x_resp.ok(dr), end))
        case 0:
          client.on.drain(5, got, buf, tab, head, body, typ, flags, sid2, payload, cls, end, exp, httpxn.decide_data(client.on.has_head(head), end))
        case _:
          client.on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 4:
      match act:
        case 0:
          client.on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 1:
          client.on.done(got, tab, head, body)
        case 6:
          do IO<Socket & Result<&1, &1, U32 & String, Response> & Tab>:
            cres : Socket & Result<&1, &1, U32 & String, Cont> <- client.on.cont_start(httpx.wo(got), exp, payload, buf)
            client.on.drain_conted(cres, tab, body, end, exp)
        case 5:
          client.on.fail(got, tab, 502, "head decode")
        case _:
          client.on.fail(got, tab, 502, "head")
    case 5:
      match act:
        case 0:
          do IO<Socket & Result<&1, &1, U32 & String, Response> & Tab>:
            got2 : Socket & Got <- client.on.wu_blest(got, buf, sid2, x_len32(payload))
            client.on.drain(0, got2, buf, tab, head, x_rev_push(payload, body), 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Response> & Tab>:
            got2 : Socket & Got <- client.on.wu_blest(got, buf, sid2, x_len32(payload))
            client.on.done_data(got2, tab, head, body, payload)
        case 4:
          client.on.fail(got, tab, 502, "stray data")
        case _:
          client.on.fail(got, tab, 502, "data")
    case _:
      client.on.fail(got, tab, 502, "bad phase")

# CONTINUATION finish for drain (Phase 15 item 1): cont_start (above)
# reassembles the header block inline-blocking (RFC 9113 section 6.10:
# no interleave allowed mid-sequence, so no per-stream ledger); here the
# full block decodes with need=0 and rejoins phase 4. Fail closes like
# the old fragmented path. Below drain (forward from @unsafe), calls
# drain above (backward) — probe3 pattern.
# ---------------------------------------------------------------------

@unsafe
def client.on.drain_conted(cres: Socket & Result<&1, &1, U32 & String, Cont>, +tab: Tab, +body: List<&2, U32>, +end: U32, +exp: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & Tab):
  (cs, cr) = cres
  match cr:
    case Fail{(fc, fm)}:
      client.on.fail(client.on.again(cs), tab, fc, fm)
    case Done{+mc}:
      match mc:
        case Cont{+block, +rest}:
          +dr2 : Result<&1, &1, U32 & String, Head & Tab> = x_resp.decode(block, tab)
          client.on.drain(4, client.on.again(cs), rest, x_resp.tab(dr2), x_resp.rh(dr2), body, 1, 4, exp, Nil{}, 0, end, exp, httpxn.head_act(0, x_resp.ok(dr2), end))

# Dial + preface (ALPN h2 required; non-H2 closes fail-closed 615)
# ---------------------------------------------------------------

def client.on.preface_bytes() -> List<&2, U32>:
  List.append(&2, U32, x_preface(), x_frame_write(x_t_settings(), 0, 0, x_settings_initial_pay()))

def client.on.send_preface(sock: Socket) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, client.on.preface_bytes())

def client.on.prefaced(pre: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  (sock, r) = pre
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, Socket>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{u}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Done{sock})

def client.on.alpn_go(sock: Socket, is_h2: Bool) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match is_h2:
    case True{}:
      do IO<Result<&1, &1, U32 & String, Socket>>:
        pre : Socket & Result<&1, &1, U32 & String, Unit> <- client.on.send_preface(sock)
        client.on.prefaced(pre)
    case False{}:
      # H1 connection: no preface, the socket goes straight to the H1 lane.
      # client.on (batch), client.request and client.once all dispatch on
      # the CliSt's is_h2 now, so the socket is handed over as it is.
      IO.pure(Result<&1, &1, U32 & String, Socket>, Done{sock})

def client.on.alpn_conn(conn: Result<&1, &1, U32 & String, Socket & String>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{value}:
      (sock, protocol) = value
      client.on.alpn_go(sock, TLS.tls_alpn_is_h2(protocol))

def client.on.connected(pre: Result<&1, &1, U32 & String, Socket>, is_h2: Bool) ->
  IO(Result<&1, &1, U32 & String, Socket & CliSt>):
  match pre:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & CliSt>, Fail{e})
    case Done{sock2}:
      IO.pure(Result<&1, &1, U32 & String, Socket & CliSt>, Done{(sock2, CliSt{1, x_tab.empty(), is_h2})})

def client.on.connected_go(conn: Result<&1, &1, U32 & String, Socket & String>) ->
  IO(Result<&1, &1, U32 & String, Socket & CliSt>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & CliSt>, Fail{e})
    case Done{value}:
      (sock, protocol) = value
      +is_h2 = TLS.tls_alpn_is_h2(protocol)
      do IO<Result<&1, &1, U32 & String, Socket & CliSt>>:
        pre : Result<&1, &1, U32 & String, Socket> <- client.on.alpn_go(sock, is_h2)
        client.on.connected(pre, is_h2)

# The streaming and concurrent lanes are H2-only: they need the H2 slot
# machinery, so an H1 connection is closed with 615 — the answer the old
# H2-strict connect gave — instead of being handed to a lane that cannot
# speak it. client.on, client.request and client.once dispatch to H1.
def client.on.h2_only(conn: Result<&1, &1, U32 & String, Socket & CliSt>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{value}:
      (sock, st) = value
      match st:
        case CliSt{sid, tab, is_h2}:
          match is_h2:
            case True{}:
              IO.pure(Result<&1, &1, U32 & String, Socket>, Done{sock})
            case False{}:
              do IO<Result<&1, &1, U32 & String, Socket>>:
                x : Unit <- TLS.tls_close(sock)
                IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{(615, "alpn mismatch")})

def client.on.connect_secure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & CliSt>):
  do IO<Result<&1, &1, U32 & String, Socket & CliSt>>:
    conn : Result<&1, &1, U32 & String, Socket & String> <- TLS.tls_connect_any(host, port)
    client.on.connected_go(conn)

def client.on.connect_insecure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & CliSt>):
  do IO<Result<&1, &1, U32 & String, Socket & CliSt>>:
    conn : Result<&1, &1, U32 & String, Socket & String> <- TLS.tls_connect_any_insecure(host, port)
    client.on.connected_go(conn)

# Request send (HEADERS + one DATA; upload cap 16KB checked by caller)
# --------------------------------------------------------------------

def client.on.send_req_head(sock: Socket, +sid: U32, +block: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_headers(), client.on.head_flags(is_empty), sid, block)

def client.on.send_req_body(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +body: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{u}:
      match is_empty:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
        case False{}:
          x_send_data_start(sock, sid, body)

def client.on.send_req(sock: Socket, +sid: U32, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  +empty = List.is_empty(&2, U32, body)
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- client.on.send_req_head(sock, sid, client.on.req_block(host, port, method, path, hs), empty)
    client.on.send_req_body(sent, sid, body, empty)

# H1 lane, ported patterns (Phase 11): http.bend is the base that works,
# so its shapes come over verbatim (window scan, recurse-in-args with
# match-result-as-param, fuel loops) — but speaking Request/Response/Hdr
# natively, so no pairs converters and no encode/decode layer are needed.
# Subset, fail-closed: no chunked (→502), client requires Content-Length
# (missing →502, never hangs on keep-alive), server treats missing CL as
# empty body. Keep-alive on both ends since TASK-027: the server answers
# and loops back to read (x_h1.srv.head phase 3), the client reuses the
# socket for N requests in order (x_h1.cli.exch / client_seq.h1.keep).
# Closing is by "connection: close", EOF, or a terminal 413/502; no
# Connection header is ever emitted, so the one-shot bytes are unchanged.
# ---------------------------------------------------------------------

def x_h1.eq_ci(a: String, b: String) -> Bool:
  String.eq(String.to_lower(a), String.to_lower(b))

def x_h1.bad_char(+s: String) -> Bool:
  Bool.or(client.on.has_crlf(s), client.on.has_nul(s))

# Render safety of a header FIELD (TASK-030): render_hs.go writes
# "name: value\r\n" verbatim, so a CR/LF/NUL inside either half ends the
# field early and the rest is read as headers the caller never asked for —
# request splitting on the client render, response splitting on the server
# render, one predicate for both. bad_char is the same check the request
# line already applied to method/path/host. Note the parser cannot be the
# source: it cuts the head on CRLF, so a parsed value never carries one —
# the source is text the app built itself (a decoded query/path echoed
# into a response header is the classic case).
def x_h1.bad_hdr(+h: Hdr) -> Bool:
  match h:
    case Hdr{+n, +v}:
      Bool.or(x_h1.bad_char(n), x_h1.bad_char(v))

def x_h1.bad_hdrs.go(+hs: List<&2, Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case h <> t:
      x_h1.bad_hdrs.go(t, Bool.or(acc, x_h1.bad_hdr(h)))

def x_h1.bad_hdrs(hs: List<&2, Hdr>) -> Bool:
  x_h1.bad_hdrs.go(hs, False{})

# Everything the request line and the header block render, in one place:
# the same expression was copied inline in x_h1.render_req and
# x_h1.cli.exch.open.fit, and neither copy looked at hs.
def x_h1.bad_req(+method: String, +path: String, +host: String, hs: List<&2, Hdr>) ->
  Bool:
  Bool.or(x_h1.bad_char(method),
    Bool.or(x_h1.bad_char(path),
      Bool.or(x_h1.bad_char(host), x_h1.bad_hdrs(hs))))

def x_h1.forbidden(+name: String) -> Bool:
  Bool.or(String.starts_with(name, ":"),
    Bool.or(x_h1.eq_ci(name, "host"),
      Bool.or(x_h1.eq_ci(name, "connection"),
        Bool.or(x_h1.eq_ci(name, "content-length"),
          Bool.or(x_h1.eq_ci(name, "transfer-encoding"),
            Bool.or(x_h1.eq_ci(name, "upgrade"), x_h1.eq_ci(name, "keep-alive")))))))

# Keep-alive policy: the H1 server closes only when the request says so.
# "connection: close" is the one signal — HTTP/1.1 keeps the connection
# alive by default, and the client codec never renders the header
# (x_h1.forbidden skips it), so a peer that sends it means it.
def x_h1.conn_close.go(hs: List<&2, Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case Hdr{+n, +v} <> t:
      x_h1.conn_close.go(t, Bool.or(acc, Bool.and(x_h1.eq_ci(n, "connection"), x_h1.eq_ci(v, "close"))))

def x_h1.conn_close(hs: List<&2, Hdr>) -> Bool:
  x_h1.conn_close.go(hs, False{})

def x_h1.render_hs.skip(+n: String, +v: String, acc: List<&2, U32>, skip: Bool) -> List<&2, U32>:
  match skip:
    case True{}:
      acc
    case False{}:
      List.append(&2, U32, acc, x_str_bytes(n ++ ": " ++ v ++ "\r\n"))

# Upgrade renders keep `connection`/`upgrade` (the handshake's own headers):
# forbidden() still drops the rest. Case-insensitive like the parse side.
def x_h1.render_hs.keep(upgrade: Bool, +n: String) -> Bool:
  match upgrade:
    case True{}:
      Bool.or(x_h1.eq_ci(n, "connection"), x_h1.eq_ci(n, "upgrade"))
    case False{}:
      False{}

def x_h1.render_hs.go(hs: List<&2, Hdr>, acc: List<&2, U32>, +upgrade: Bool) -> List<&2, U32>:
  match hs:
    case Nil{}:
      acc
    case Hdr{+n, +v} <> t:
      x_h1.render_hs.go(t, x_h1.render_hs.skip(n, v, acc, Bool.and(x_h1.forbidden(n), Bool.not(x_h1.render_hs.keep(upgrade, n)))), upgrade)

# An upgrade handshake carries no body framing: with upgrade=True an empty
# body renders no Content-Length at all (a 101 must not claim one); any
# non-empty body still counts exactly as before.
def x_h1.render_cl.empty(upgrade: Bool) -> String:
  match upgrade:
    case True{}:
      ""
    case False{}:
      "Content-Length: 0\r\n"

def x_h1.render_cl(+body: List<&2, U32>, upgrade: Bool) -> String:
  match body:
    case Nil{}:
      x_h1.render_cl.empty(upgrade)
    case _ <> _:
      "Content-Length: " ++ U32.show(x_len32(body)) ++ "\r\n"

def x_h1.render_req.go(+upgrade: Bool, bad: Bool, +method: String, +path: String, +host: String, +port: U32, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      Done{List.append(&2, U32, List.append(&2, U32, x_h1.render_hs.go(hs, x_str_bytes(method ++ " " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ ":" ++ U32.show(port) ++ "\r\n" ++ x_h1.render_cl(body, upgrade)), upgrade), x_str_bytes("\r\n")), body)}

# hs is + here (and only here): the header block is read twice, once by
# bad_req and once by the render below.
def x_h1.render_req(+method: String, +path: String, +host: String, +port: U32, +hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  x_h1.render_req.go(False{}, x_h1.bad_req(method, path, host, hs), method, path, host, port, hs, body)

def x_h1.reason(st: U32) -> String:
  match st:
    case 101:
      "Switching Protocols"
    case 200:
      "OK"
    case 204:
      "No Content"
    case 304:
      "Not Modified"
    case 400:
      "Bad Request"
    case 404:
      "Not Found"
    case 411:
      "Length Required"
    case 413:
      "Content Too Large"
    case 500:
      "Internal Error"
    case 502:
      "Bad Gateway"
    case _:
      SNil{}

# Responses render with upgrade=False today: no handler emits Upgrade yet.
# Phase 3 (answer_open/show_resp_head) revisits this for the 101 path.
def x_h1.show_resp(+status: U32, hs: List<&2, Hdr>, +body: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, x_h1.render_hs.go(hs, x_str_bytes("HTTP/1.1 " ++ U32.show(status) ++ " " ++ x_h1.reason(status) ++ "\r\nContent-Length: " ++ U32.show(x_len32(body)) ++ "\r\n"), False{}), x_str_bytes("\r\n")), body)

# The 101 head: status line + the handler's headers (Upgrade/Connection
# kept via upgrade=True) + blank line. No Content-Length, no body — a 101
# carries neither by definition, and show_resp would inject Length: 0.
def x_h1.show_resp_head(+status: U32, hs: List<&2, Hdr>) -> List<&2, U32>:
  List.append(&2, U32, x_h1.render_hs.go(hs, x_str_bytes("HTTP/1.1 " ++ U32.show(status) ++ " " ++ x_h1.reason(status) ++ "\r\n"), True{}), x_str_bytes("\r\n"))

# Blank-line cut over bytes (window 218762506 = \r\n\r\n, same as
# http.bend bs_head; the discriminant rides a param, never a match on
# computed). Triple (head, rest, found) with thin projections.
# ---------------------------------------------------------------------

def x_h1.split.go(+bs: List<&2, U32>, found: Bool, +w: U32, acc: List<&2, U32>) -> List<&2, U32> & List<&2, U32> & Bool:
  match bs:
    case Nil{}:
      # found is carried out of the Nil arm: the boundary can land exactly
      # at the end of the buffer (a GET with no body, a bodyless response),
      # and dropping the flag here made the H1 head loop read forever
      # (TASK-026 Phase 7b, found by tests/io/httpx_plain_h1).
      (List.reverse(&2, U32, acc), Nil{}, found)
    case +b <> t:
      match found:
        case True{}:
          (List.reverse(&2, U32, acc), b <> t, True{})
        case False{}:
          +w2 = (w * 256 + b : U32)
          x_h1.split.go(t, U32.is_eq(w2, 218762506), w2, b <> acc)

def x_h1.split(+bs: List<&2, U32>) -> List<&2, U32> & List<&2, U32> & Bool:
  x_h1.split.go(bs, False{}, 0, Nil{})

def x_h1.split_head(p: List<&2, U32> & List<&2, U32> & Bool) -> List<&2, U32>:
  match p:
    case (h, r, f):
      h

def x_h1.split_rest(p: List<&2, U32> & List<&2, U32> & Bool) -> List<&2, U32>:
  match p:
    case (h, r, f):
      r

def x_h1.split_found(p: List<&2, U32> & List<&2, U32> & Bool) -> Bool:
  match p:
    case (h, r, f):
      f

def x_h1.head_lines(+head: List<&2, U32>) -> List<&2, String>:
  String.lines(x_bytes_str(head))

def x_h1.first_line(lines: List<&2, String>) -> String:
  match lines:
    case Nil{}:
      SNil{}
    case h <> t:
      h

def x_h1.rest_lines(lines: List<&2, String>) -> List<&2, String>:
  match lines:
    case Nil{}:
      Nil{}
    case h <> t:
      t

# Request line: exactly 3 tokens; validity folds version + target +
# bad chars into one Bool carried as param (head_act discipline).
# ---------------------------------------------------------------------

def x_h1.req_valid(+m: String, +p: String, +v: String) -> Bool:
  Bool.and(String.starts_with(v, "HTTP/1."),
    Bool.and(String.starts_with(p, "/"),
      Bool.and(Bool.not(x_h1.bad_char(m)), Bool.not(x_h1.bad_char(p)))))

def x_h1.req_tok(parts: List<&2, String>) -> Result<&1, &1, U32 & String, String & String & String & Bool>:
  match parts:
    case +m <> r1:
      match r1:
        case +p <> r2:
          match r2:
            case +v <> Nil{}:
              Done{(m, p, v, x_h1.req_valid(m, p, v))}
            case Nil{}:
              Fail{(400, "bad request line")}
            case +v <> r3:
              Fail{(400, "bad request line")}
        case Nil{}:
          Fail{(400, "bad request line")}
    case Nil{}:
      Fail{(400, "bad request line")}

def x_h1.req_head(r: Result<&1, &1, U32 & String, String & String & String & Bool>) -> Result<&1, &1, U32 & String, ReqHead>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{q}:
      match q:
        case (m, p, v, ok):
          match ok:
            case True{}:
              Done{ReqHead{m, p, Nil{}}}
            case False{}:
              Fail{(400, "bad request")}

def x_h1.req_join.hs(+m: String, +p: String, hs: Result<&1, &1, U32 & String, List<&2, Hdr>>) ->
  Result<&1, &1, U32 & String, ReqHead>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{+headers}:
      Done{ReqHead{m, p, headers}}

def x_h1.req_join(tok: Result<&1, &1, U32 & String, ReqHead>, hs: Result<&1, &1, U32 & String, List<&2, Hdr>>) ->
  Result<&1, &1, U32 & String, ReqHead>:
  match tok:
    case Fail{e}:
      Fail{e}
    case Done{+rh}:
      match rh:
        case ReqHead{+m, +p, +hs0}:
          x_h1.req_join.hs(m, p, hs)

# Status line: version + numeric code (Maybe.default like http.bend:976).
# ---------------------------------------------------------------------

def x_h1.res_valid(+v: String, +c: String) -> Bool:
  Bool.and(String.starts_with(v, "HTTP/1."),
    Bool.not(U32.is_eq(Maybe.default(&2, U32, U32.read(c), 0), 0)))

def x_h1.res_tok(parts: List<&2, String>) -> Result<&1, &1, U32 & String, U32 & Bool>:
  match parts:
    case v <> r1:
      match r1:
        case +c <> r2:
          Done{(Maybe.default(&2, U32, U32.read(c), 0), x_h1.res_valid(v, c))}
        case Nil{}:
          Fail{(400, "bad status")}
    case Nil{}:
      Fail{(400, "bad status")}

def x_h1.res_head(q: U32 & Bool) -> Result<&1, &1, U32 & String, U32>:
  match q:
    case (code, ok):
      match ok:
        case True{}:
          Done{code}
        case False{}:
          Fail{(400, "bad status")}

def x_h1.res_lift(r: Result<&1, &1, U32 & String, U32 & Bool>) -> Result<&1, &1, U32 & String, U32>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{q}:
      x_h1.res_head(q)

# Header lines: blank (\r, post-lines-split) ends; colon-less fails.
# Recursion rides args with match-result-as-param (parse_headers shape).
# ---------------------------------------------------------------------

def x_h1.is_blank(+l: String) -> Bool:
  Bool.or(String.is_empty(l), String.eq(l, "\r"))

def x_h1.strip_cr.go(h: Char, t: String, is_cr: Bool) -> String:
  match is_cr:
    case True{}:
      t
    case False{}:
      SCon{h, t}

def x_h1.strip_cr(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      x_h1.strip_cr.go(h, t, Char.is_eq(h, Chr{13}))

def x_h1.hdr_val(+line: String, +nlen: Nat) -> String:
  String.trim(String.drop(line, (nlen + 1n : Nat)))

def x_h1.parse_hdr(done: Bool, parts: List<&2, String>, +line: String, rec: Result<&1, &1, U32 & String, List<&2, Hdr>>) ->
  Result<&1, &1, U32 & String, List<&2, Hdr>>:
  match done:
    case True{}:
      Done{Nil{}}
    case False{}:
      match parts:
        case Nil{}:
          Fail{(400, "bad header")}
        case +n <> vs:
          match vs:
            case Nil{}:
              Fail{(400, "bad header")}
            case +v <> vvs:
              match rec:
                case Fail{e}:
                  Fail{e}
                case Done{+tl}:
                  Done{Hdr{n, x_h1.hdr_val(line, String.length(n))} <> tl}

def x_h1.parse_hs(lines: List<&2, String>) ->
  Result<&1, &1, U32 & String, List<&2, Hdr>>:
  match lines:
    case Nil{}:
      Done{Nil{}}
    case +h <> t:
      +l1 = String.trim(x_h1.strip_cr(h))
      x_h1.parse_hdr(x_h1.is_blank(h), String.split(l1, ':'), l1, x_h1.parse_hs(t))

# Framing queries (folds with combiner, fdel_go shape) + no_body.
# ---------------------------------------------------------------------

def x_h1.cl_at(is_cl: Bool, +v: String, +acc: U32) -> U32:
  match is_cl:
    case True{}:
      Maybe.default(&2, U32, U32.read(v), 0)
    case False{}:
      acc

def x_h1.cl_of.go(hs: List<&2, Hdr>, +acc: U32) -> U32:
  match hs:
    case Nil{}:
      acc
    case Hdr{n, v} <> t:
      x_h1.cl_of.go(t, x_h1.cl_at(x_h1.eq_ci(n, "content-length"), v, acc))

def x_h1.cl_of(hs: List<&2, Hdr>) -> U32:
  x_h1.cl_of.go(hs, 0)

def x_h1.te_at(is_te: Bool, +v: String, acc: Bool) -> Bool:
  match is_te:
    case True{}:
      Bool.or(acc, String.contains(String.to_lower(v), "chunked"))
    case False{}:
      acc

def x_h1.te_go(hs: List<&2, Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case Hdr{n, v} <> t:
      x_h1.te_go(t, x_h1.te_at(x_h1.eq_ci(n, "transfer-encoding"), v, acc))

def x_h1.is_chunked(hs: List<&2, Hdr>) -> Bool:
  x_h1.te_go(hs, False{})

def x_h1.no_body.go(head: Bool, +status: U32) -> Bool:
  match head:
    case True{}:
      True{}
    case False{}:
      match status:
        case 204:
          True{}
        case 304:
          True{}
        case _:
          U32.is_lt(status, 200)

def x_h1.no_body(+method: String, +status: U32) -> Bool:
  x_h1.no_body.go(String.eq(method, "HEAD"), status)

# H1 client exchange (fallback lane): render, send, head/body fuel loops,
# close. Matches go forward in param order per branch (checker rule).
# Transport is three templates (~recv/~send/~close), instantiated per
# lane at the public entries: TLS (tls_recv/send_bytes + tls_close) or
# TCP (TCPB.recv/send_bytes + Socket.close). The grammar is identical —
# that is what let the x_h1p.* mirror die in Phase 1.
# ---------------------------------------------------------------------

@unsafe
def x_h1.cli.bd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, fuel: Nat, enough: Bool, +code: U32, +hs: List<&2, Hdr>, +rest: List<&2, U32>, +cl: U32) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          match enough:
            case True{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s0, Done{Response{code, hs, x_take32(cl, rest)}}))
            case False{}:
              do IO<Socket & Result<&1, &1, U32 & String, Response>>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
                x_h1.cli.bd(~recv, ~send, ~close, 1, r, f, False{}, code, hs, rest, cl)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s1, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s1, Fail{(400, "eof")}))
            case h <> t:
              +rest2 = List.append(&2, U32, rest, part)
              x_h1.cli.bd(~recv, ~send, ~close, 0, (s1, Done{Nil{}}), fuel, x_has_at_least(cl, rest2), code, hs, rest2, cl)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s9, Fail{(502, "bad phase")}))

def x_h1.cli.hd2(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, +hs: List<&2, Hdr>, nbody: Bool, chunked: Bool) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  match nbody:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (sock, Done{Response{code, hs, Nil{}}}))
    case False{}:
      match chunked:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (sock, Fail{(502, "chunked refused")}))
        case False{}:
          +clc = x_h1.cl_of(hs)
          x_h1.cli.bd(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), fuel, x_has_at_least(clc, rest), code, hs, rest, clc)

def x_h1.cli.hd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, hsres: Result<&1, &1, U32 & String, List<&2, Hdr>>, nbody: Bool) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  match hsres:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (sock, Fail{e}))
    case Done{+hs}:
      x_h1.cli.hd2(~recv, ~send, ~close, sock, rest, fuel, code, hs, nbody, x_h1.is_chunked(hs))

def x_h1.cli.coded(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +method: String, +rest: List<&2, U32>, fuel: Nat, coderes: Result<&1, &1, U32 & String, U32>, hsres: Result<&1, &1, U32 & String, List<&2, Hdr>>) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  match coderes:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (sock, Fail{e}))
    case Done{+code}:
      x_h1.cli.hd(~recv, ~send, ~close, sock, rest, fuel, code, hsres, x_h1.no_body(method, code))

def x_h1.cli.parsed(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s1: Socket, +acc2: List<&2, U32>, fuel: Nat, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  +hl = x_h1.head_lines(x_h1.split_head(x_h1.split(acc2)))
  +rest = x_h1.split_rest(x_h1.split(acc2))
  x_h1.cli.coded(~recv, ~send, ~close, s1, method, rest, fuel, x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl)))

@unsafe
def x_h1.cli.head(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, +method: String, found: Bool) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          do IO<Socket & Result<&1, &1, U32 & String, Response>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.cli.head(~recv, ~send, ~close, 1, r, acc, f, method, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s1, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s1, Fail{(400, "eof")}))
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              x_h1.cli.head(~recv, ~send, ~close, 2, (s1, Done{Nil{}}), acc2, fuel, method, x_h1.split_found(x_h1.split(acc2)))
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          x_h1.cli.head(~recv, ~send, ~close, 0, (s2, Done{Nil{}}), acc, fuel, method, False{})
        case True{}:
          x_h1.cli.parsed(~recv, ~send, ~close, s2, acc, fuel, method)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (s9, Fail{(502, "bad phase")}))

def x_h1.exch.sent(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (sock, Fail{e}))
    case Done{u}:
      x_h1.cli.head(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), Nil{}, 64n, method, False{})

def x_h1.exch.send(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, Response>):
  match rendered:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>, (sock, Fail{e}))
    case Done{+bytes}:
      do IO<Socket & Result<&1, &1, U32 & String, Response>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        x_h1.exch.sent(~recv, ~send, ~close, sent, method)

def x_h1.exch.done(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), out: Socket & Result<&1, &1, U32 & String, Response>) -> IO(Result<&1, &1, U32 & String, Response>):
  (s, r) = out
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, Response>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, Response>, Fail{e})
    case Done{+resp}:
      do IO<Result<&1, &1, U32 & String, Response>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, Response>, Done{resp})

def x_h1.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Response>):
  do IO<Result<&1, &1, U32 & String, Response>>:
    out : Socket & Result<&1, &1, U32 & String, Response> <- x_h1.exch.send(~recv, ~send, ~close, sock, x_h1.render_req(method, path, host, port, hs, body), method)
    x_h1.exch.done(~recv, ~send, ~close, out)

# The exchange that does NOT close: one request out, one response read
# back, socket handed over. x_h1.exch.send already behaves that way
# (x_h1.exch is the one-shot wrapper that closes at the end); this is the
# named entry for the sequential batch lane, and it validates like the
# H2 keep-alive path (client.on.fit_keep) so both lanes fail with the
# same 400/413 before any byte leaves.
def x_h1.cli.exch.fit(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Response>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          x_h1.exch.send(~recv, ~send, ~close, sock, x_h1.render_req(method, path, host, port, hs, body), method)
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response>,
            (sock, Fail{(413, "req too large")}))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response>,
        (sock, Fail{(400, "bad request")}))

def x_h1.cli.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Response>):
  x_h1.cli.exch.fit(~recv, ~send, ~close, sock, host, port, method, path, hs, body, client.on.valid.go(host, port, path), client.on.body_ok(body))

# H1 upgrade chain (101): the head half of the exchange, stopping at the
# head. Like the plain chain above, but the nbody=True arm hands the triple
# (socket, response, rest) over instead of dropping the rest — those bytes
# past the head are the first frame bytes, and head_open never reads a
# body: nbody=False is Fail 502 "upgrade without 101", fail-closed.
# No chunked consult here: a 101 carries no body by definition.
# ---------------------------------------------------------------------

def x_h1.cli.hd2_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, +hs: List<&2, Hdr>, nbody: Bool) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  match nbody:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (sock, Done{(Response{code, hs, Nil{}}, rest)}))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (sock, Fail{(502, "upgrade without 101")}))

def x_h1.cli.hd_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, hsres: Result<&1, &1, U32 & String, List<&2, Hdr>>, nbody: Bool) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  match hsres:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+hs}:
      x_h1.cli.hd2_open(~recv, ~send, ~close, sock, rest, fuel, code, hs, nbody)

def x_h1.cli.coded_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +method: String, +rest: List<&2, U32>, fuel: Nat, coderes: Result<&1, &1, U32 & String, U32>, hsres: Result<&1, &1, U32 & String, List<&2, Hdr>>) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  match coderes:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+code}:
      x_h1.cli.hd_open(~recv, ~send, ~close, sock, rest, fuel, code, hsres, x_h1.no_body(method, code))

def x_h1.cli.parsed_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s1: Socket, +acc2: List<&2, U32>, fuel: Nat, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  +hl = x_h1.head_lines(x_h1.split_head(x_h1.split(acc2)))
  +rest = x_h1.split_rest(x_h1.split(acc2))
  x_h1.cli.coded_open(~recv, ~send, ~close, s1, method, rest, fuel, x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl)))

@unsafe
def x_h1.cli.head_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, +method: String, found: Bool) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          do IO<Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.cli.head_open(~recv, ~send, ~close, 1, r, acc, f, method, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (s1, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (s1, Fail{(400, "eof")}))
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              x_h1.cli.head_open(~recv, ~send, ~close, 2, (s1, Done{Nil{}}), acc2, fuel, method, x_h1.split_found(x_h1.split(acc2)))
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          x_h1.cli.head_open(~recv, ~send, ~close, 0, (s2, Done{Nil{}}), acc, fuel, method, False{})
        case True{}:
          x_h1.cli.parsed_open(~recv, ~send, ~close, s2, acc, fuel, method)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

def x_h1.exch.sent_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{u}:
      x_h1.cli.head_open(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), Nil{}, 64n, method, False{})

def x_h1.exch.send_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  match rendered:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+bytes}:
      do IO<Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        x_h1.exch.sent_open(~recv, ~send, ~close, sent, method)

# The handshake exchange: like x_h1.cli.exch (same 400/413 before any byte
# leaves) but rendered with upgrade=True and answered by the _open chain,
# so the socket comes back live with the bytes past the head. Not closing
# is the caller's job — that is the whole point of the triple.
# hs is + for the same reason as x_h1.render_req: bad_req and the render
# both read the header block.
def x_h1.cli.exch.open.fit(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, +hs: List<&2, Hdr>, +body: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          x_h1.exch.send_open(~recv, ~send, ~close, sock, x_h1.render_req.go(True{}, x_h1.bad_req(method, path, host, hs), method, path, host, port, hs, body), method)
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>,
            (sock, Fail{(413, "req too large")}))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>,
        (sock, Fail{(400, "bad request")}))

def x_h1.cli.exch.open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>):
  x_h1.cli.exch.open.fit(~recv, ~send, ~close, sock, host, port, method, path, hs, body, client.on.valid.go(host, port, path), client.on.body_ok(body))

# Post-dial runner for the upgrade handshake, the _open pair of h1_once.conn:
# the dial differs per lane, the grammar after it is one.
def h1_open.rewrap(~close: Socket -> IO(Unit), out: Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>):
  (s, r) = out
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>, Fail{e})
    case Done{pr}:
      (resp, rest) = pr
      IO.pure(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>, Done{(s, resp, rest)})

def h1_open.sock(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +req: Request) ->
  IO(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>):
  match req:
    case Request{method, path, headers, body}:
      do IO<Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>>:
        out : Socket & Result<&1, &1, U32 & String, Response & List<&2, U32>> <- x_h1.cli.exch.open(~recv, ~send, ~close, sock, host, port, method, path, headers, body)
        h1_open.rewrap(~close, out)

def h1_open.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, +req: Request) ->
  IO(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>, Fail{e})
    case Done{sock}:
      h1_open.sock(~recv, ~send, ~close, sock, host, port, req)

# H1 once (no-ALPN dial, WSS-style): single-shot over the H1 lane.
# ---------------------------------------------------------------------

def h1_once.dial(+host: String, +port: U32, insecure: Bool) -> IO(Result<&1, &1, U32 & String, Socket>):
  match insecure:
    case True{}:
      TLS.tls_connect_noalpn_insecure(host, port)
    case False{}:
      TLS.tls_connect_noalpn(host, port)

# Post-dial runner shared by both dials: the TLS one-shot (h1_once.dial)
# and the plaintext one (TCP.connect in fetch.plain). The triple picks
# the lane; the grammar after the dial is one.
def h1_once.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Response>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Response>, Fail{e})
    case Done{sock}:
      x_h1.exch(~recv, ~send, ~close, sock, host, port, method, path, hs, body)

def h1_once.fit(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>, insecure: Bool, fit: Bool, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, Response>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          do IO<Result<&1, &1, U32 & String, Response>>:
            conn : Result<&1, &1, U32 & String, Socket> <- h1_once.dial(host, port, insecure)
            h1_once.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, method, path, hs, body)
        case False{}:
          IO.pure(Result<&1, &1, U32 & String, Response>, Fail{(413, "req too large")})
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, Response>, Fail{(400, "bad request")})

def h1_once(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Response>):
  h1_once.fit(host, port, method, path, hs, body, False{}, client.on.valid.go(host, port, path), client.on.body_ok(body))

def h1_once_insecure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Response>):
  h1_once.fit(host, port, method, path, hs, body, True{}, client.on.valid.go(host, port, path), client.on.body_ok(body))

def h1_open.go(+host: String, +port: U32, +req: Request, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- h1_once.dial(host, port, insecure)
    h1_open.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, req)

def h1_open(+host: String, +port: U32, +req: Request) ->
  IO(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>):
  h1_open.go(host, port, req, False{})

def h1_open_insecure(+host: String, +port: U32, +req: Request) ->
  IO(Result<&1, &1, U32 & String, Socket & Response & List<&2, U32>>):
  h1_open.go(host, port, req, True{})

# Dual-dial dispatch for once/fetch: h2 → preface+exchange (existing
# path, byte-identical); http/1.1 → H1 lane on the same socket (this
# replaces the 615 close; keep_connect stays H2-strict).
# ---------------------------------------------------------------------

# Streaming download (Phase E): HEADERS/DATA to a pure handler, O(1)
# per chunk (counts only, no body accumulation). WU per non-fin DATA
# (best-effort, mold h2_send_wu_len); Cancel sends RST_STREAM (8) + Fail.
# ---------------------------------------------------------------------

def client.on.is_cont(+out: StreamOut) -> Bool:
  match out:
    case StreamContinue{}:
      True{}
    case StreamCancel{}:
      False{}

def client.on.stream_act(is_cont: Bool, +need: U32, ok: Bool, +end: U32) -> U32:
  match is_cont need ok end:
    case False{} _ _ _:
      7
    case True{} 1 _ _:
      6
    case True{} 0 False{} _:
      5
    case True{} 0 True{} 1:
      1
    case _ _ _ _:
      0

def client.on.sdata_act(is_cont: Bool, has: Bool, +end: U32) -> U32:
  match is_cont has end:
    case False{} _ _:
      7
    case True{} False{} _:
      4
    case True{} True{} 1:
      1
    case _ _ _:
      0

def client.on.sfail(got: Socket & Got, +code: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32>):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s, Fail{(code, msg)}))

def client.on.sdone(got: Socket & Got, +total: U32, +fins: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32>):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s, Done{(total, fins)}))

def client.on.cancel_done(rst: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32>):
  (s2, r2) = rst
  IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s2, Fail{(8, "cancelled")}))

def client.on.cancelled(got: Socket & Got, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32>):
  (s, g) = got
  do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
    rst : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(s, sid, 8)
    client.on.cancel_done(rst)

def client.on.wu_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) ->
  Socket & Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, GotErr{code, msg})
    case Done{u}:
      (s, GotOk{Frame{0, 0, 0, Nil{}}, buf})

def client.on.wu_blest(got: Socket & Got, buf: List<&2, U32>, +sid: U32, +inc: U32) -> IO(Socket & Got):
  (s, g) = got
  do IO<Socket & Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_wu_len(s, sid, inc)
    IO.pure(Socket & Got, client.on.wu_kept(sent, buf))

# CONTINUATION inline leaves for sdrop (Phase 15 item 2): fresh Err-next
# pair to (re)enter the cont-read phase, and GOAWAY-fail mapping for a
# bad CONT frame (mirror client.on.cont_failed, sdrop result shape).
# Pure leaves above the loop (callee-above-caller, no ~H inside).
# ---------------------------------------------------------------------

def client.on.sdrop_next(s: Socket) -> Socket & Got:
  (s, GotErr{0, "next"})

def client.on.sdrop_sendfail(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s, Fail{e}))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s, Fail{(502, "continuation")}))

@unsafe
def client.on.sdrop(~H: StreamEv -> StreamOut, phase: U32, got: Socket & Got, +buf: List<&2, U32>, +tab: Tab, +head: Head, +total: U32, +fins: U32, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +exp: U32, act: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32>):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
        got2 : Socket & Got <- x_read_frame(s0, buf)
        client.on.sdrop(~H, 1, got2, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case GotErr{code1, msg1}:
          IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s1, Fail{(code1, msg1)}))
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ2, +flags2, +sid22, +payload2}:
              client.on.sdrop(~H, 2, (s1, GotOk{frame, buf2}), buf2, tab, head, total, fins, typ2, flags2, sid22, payload2, client.on.mine_cls(httpx.cls_fix(x_classify(frame), flags2), sid22, exp), U32.and(flags2, x_f_end_stream()), exp, 4)
    case 2:
      match cls:
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
            got2 : Socket & Got <- client.on.ack(got)
            client.on.sdrop(~H, 0, got2, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
            gotp : Socket & Got <- client.on.ack_ping(got, payload)
            client.on.sdrop(~H, 0, gotp, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 5:
          client.on.sfail(got, 502, "goaway")
        case 7:
          client.on.sdrop(~H, 0, got, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 9:
          client.on.sfail(got, 502, "bad window_update")
        case 8:
          client.on.sfail(got, 502, "continuation")
        case 2:
          client.on.sfail(got, 502, "rst_stream")
        case 6:
          client.on.sdrop(~H, 3, got, buf, tab, head, total, fins, typ, flags, sid2, payload, cls, end, exp, 4)
        case 0:
          client.on.sdrop(~H, 0, got, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case _:
          client.on.sdrop(~H, 0, got, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 3:
      match typ:
        case 1:
          +dr : Result<&1, &1, U32 & String, Head & Tab> = x_resp.decode(payload, tab)
          +nh : Head = x_resp.rh(dr)
          +nt : Tab = x_resp.tab(dr)
          +ok : Bool = x_resp.ok(dr)
          +need : U32 = httpxn.need_u(typ, flags)
          +out : StreamOut = H(StreamHead{nh})
          client.on.sdrop(~H, 4, got, buf, nt, nh, total, fins, typ, flags, sid2, payload, cls, end, exp, client.on.stream_act(client.on.is_cont(out), need, ok, end))
        case 0:
          +fin : Bool = U32.is_eq(end, 1)
          +out0 : StreamOut = H(StreamData{payload, fin})
          client.on.sdrop(~H, 5, got, buf, tab, head, total, fins, typ, flags, sid2, payload, cls, end, exp, client.on.sdata_act(client.on.is_cont(out0), client.on.has_head(head), end))
        case _:
          client.on.sdrop(~H, 0, got, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 4:
      match act:
        case 0:
          client.on.sdrop(~H, 0, got, buf, tab, head, total, fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 1:
          client.on.sdone(got, total, (fins + 1 : U32))
        case 6:
          client.on.sdrop(~H, 6, client.on.sdrop_next(httpx.wo(got)), buf, tab, head, total, fins, 0, 0, 0, payload, 0, end, exp, 0)
        case 5:
          client.on.sfail(got, 502, "head decode")
        case 7:
          client.on.cancelled(got, sid2)
        case _:
          client.on.sfail(got, 502, "head")
    case 5:
      match act:
        case 0:
          do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
            got2 : Socket & Got <- client.on.wu_blest(got, buf, sid2, x_len32(payload))
            client.on.sdrop(~H, 0, got2, buf, tab, head, (total + x_len32(payload) : U32), fins, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
            got2 : Socket & Got <- client.on.wu_blest(got, buf, sid2, x_len32(payload))
            client.on.sdone(got2, (total + x_len32(payload) : U32), (fins + 1 : U32))
        case 4:
          client.on.sfail(got, 502, "stray data")
        case 7:
          client.on.cancelled(got, sid2)
        case _:
          client.on.sfail(got, 502, "data")
    case 6:
      (s6, g6) = got
      match g6:
        case GotErr{code6, msg6}:
          match code6:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
                got6 : Socket & Got <- x_read_frame(s6, buf)
                client.on.sdrop(~H, 6, got6, buf, tab, head, total, fins, 0, 0, 0, payload, 0, end, exp, 0)
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32>, (s6, Fail{(code6, msg6)}))
        case GotOk{+frame6, +buf6}:
          match frame6:
            case Frame{+typ6, +flags6, +sid6, +pay6}:
              client.on.sdrop(~H, 7, (s6, GotOk{frame6, buf6}), buf6, tab, head, total, fins, typ6, flags6, sid6, List.append(&2, U32, payload, pay6), client.on.cont_cls_of(typ6, sid6, exp, flags6), end, exp, 0)
    case 7:
      (s7, g7) = got
      match cls:
        case 0:
          +dr7 : Result<&1, &1, U32 & String, Head & Tab> = x_resp.decode(payload, tab)
          client.on.sdrop(~H, 4, client.on.again(s7), buf, x_resp.tab(dr7), x_resp.rh(dr7), total, fins, typ, flags, sid2, Nil{}, cls, end, exp, httpxn.head_act(0, x_resp.ok(dr7), end))
        case 1:
          client.on.sdrop(~H, 6, client.on.sdrop_next(s7), buf, tab, head, total, fins, 0, 0, 0, payload, 0, end, exp, 0)
        case _:
          do IO<Socket & Result<&1, &1, U32 & String, U32 & U32>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s7, 0, 1)
            client.on.sdrop_sendfail(sent)
    case _:
      client.on.sfail(got, 502, "bad phase")

# Streaming public (dial, one request sid 1, handler counts, close)
# ------------------------------------------------------------------

def client_stream.drained(drained: Socket & Result<&1, &1, U32 & String, U32 & U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, r) = drained
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{counts}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Done{counts})

def client_stream.sent(~H: StreamEv -> StreamOut, sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        drained : Socket & Result<&1, &1, U32 & String, U32 & U32> <- client.on.sdrop(~H, 0, (sock, GotErr{0, "next"}), Nil{}, x_tab.empty(), Head{0, Nil{}}, 0, 0, 0, 0, 0, Nil{}, 0, 0, 1, 4)
        client_stream.drained(drained)

def client_stream.exch(~H: StreamEv -> StreamOut, sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- client.on.send_req(sock, 1, host, port, method, path, hs, body)
    client_stream.sent(~H, sent)

def client_stream.conn(~H: StreamEv -> StreamOut, conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{sock}:
      client_stream.exch(~H, sock, host, port, method, path, hs, body)

def client_stream.go(~H: StreamEv -> StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match insecure:
    case True{}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        c : Result<&1, &1, U32 & String, Socket & CliSt> <- client.on.connect_insecure(host, port)
        conn : Result<&1, &1, U32 & String, Socket> <- client.on.h2_only(c)
        client_stream.conn(~H, conn, host, port, method, path, hs, body)
    case False{}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        c : Result<&1, &1, U32 & String, Socket & CliSt> <- client.on.connect_secure(host, port)
        conn : Result<&1, &1, U32 & String, Socket> <- client.on.h2_only(c)
        client_stream.conn(~H, conn, host, port, method, path, hs, body)

def client_stream.fit(~H: StreamEv -> StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>, insecure: Bool, fit: Bool, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          client_stream.go(~H, host, port, method, path, hs, body, insecure)
        case False{}:
          IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{(413, "req too large")})
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{(400, "bad request")})

def client.stream(~H: StreamEv -> StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  client_stream.fit(~H, host, port, method, path, hs, body, False{}, client.on.valid.go(host, port, path), client.on.body_ok(body))

def client.stream_insecure(~H: StreamEv -> StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  client_stream.fit(~H, host, port, method, path, hs, body, True{}, client.on.valid.go(host, port, path), client.on.body_ok(body))

# Keep-alive (Phase C): one dial, sequential sids 1,3,5…, caller threads
# Socket + CliSt{sid,tab} (tab persists for dyn reuse). Request never
# closes (caller closes after last); validation fails keep sid/tab.
# ---------------------------------------------------------------------

def client.on.st_sid(+st: CliSt) -> U32:
  match st:
    case CliSt{+sid, tab, h2}:
      sid

def client.on.st_tab(+st: CliSt) -> Tab:
  match st:
    case CliSt{sid, +tab, h2}:
      tab

# is_h2 is the ALPN answer, kept on the connection record so the entries
# above can dispatch: client.on/once are H2 for an H2 connection and the
# H1 one-shot (x_h1.exch) for an H1 one (TASK-026 Phase 5, the
# "unificar num ponto só" that the old client_once.by_proto did).
def client.on.st_h2(+st: CliSt) -> Bool:
  match st:
    case CliSt{sid, tab, +h2}:
      h2

def client.on.next_sid(+sid: U32) -> U32:
  (sid + 2 : U32)

def client.on.next_st(+st: CliSt, +tab: Tab) -> CliSt:
  match st:
    case CliSt{+sid, old, +h2}:
      CliSt{client.on.next_sid(sid), tab, h2}

def client.connect(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & CliSt>):
  client.on.connect_secure(host, port)

def client.connect_insecure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & CliSt>):
  client.on.connect_insecure(host, port)

def client.on.drained_keep(drained: Socket & Result<&1, &1, U32 & String, Response> & Tab, +st: CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  (s, r, t) = drained
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response> & CliSt, (s, Fail{e}, client.on.next_st(st, t)))
    case Done{+resp}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response> & CliSt, (s, Done{resp}, client.on.next_st(st, t)))

def client.on.sent_keep(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response> & CliSt, (sock, Fail{e}, st))
    case Done{u}:
      do IO<Socket & Result<&1, &1, U32 & String, Response> & CliSt>:
        drained : Socket & Result<&1, &1, U32 & String, Response> & Tab <- client.on.drain(0, (sock, GotErr{0, "next"}), Nil{}, client.on.st_tab(st), Head{0, Nil{}}, Nil{}, 0, 0, 0, Nil{}, 0, 0, client.on.st_sid(st), 4)
        client.on.drained_keep(drained, st)

def client.on.exch_keep(sock: Socket, +st: CliSt, +host: String, +port: U32, req: Request) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  match req:
    case Request{method, path, headers, body}:
      do IO<Socket & Result<&1, &1, U32 & String, Response> & CliSt>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- client.on.send_req(sock, client.on.st_sid(st), host, port, method, path, headers, body)
        client.on.sent_keep(sent, st)

def client.on.fit_keep(sock: Socket, +st: CliSt, +host: String, +port: U32, req: Request, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  match fit:
    case True{}:
      match ok:
        case True{}:
          client.on.exch_keep(sock, st, host, port, req)
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Response> & CliSt, (sock, Fail{(413, "req too large")}, st))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Response> & CliSt, (sock, Fail{(400, "bad request")}, st))

# H1 leg of the keep-alive single request: the exchange that never closes,
# with the CliSt threaded back unchanged so the caller loop is the same
# shape as the H2 one. H1 has no sids and no HPACK table, so sid/tab just
# ride along.
def client.on.h1_keep_st(out: Socket & Result<&1, &1, U32 & String, Response>, +st: CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  (s, r) = out
  IO.pure(Socket & Result<&1, &1, U32 & String, Response> & CliSt,
    (s, r, st))

def client.on.h1_keep(sock: Socket, +st: CliSt, +host: String, +port: U32, req: Request) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  match req:
    case Request{method, path, headers, body}:
      do IO<Socket & Result<&1, &1, U32 & String, Response> & CliSt>:
        out : Socket & Result<&1, &1, U32 & String, Response> <- x_h1.cli.exch(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, sock, host, port, method, path, headers, body)
        client.on.h1_keep_st(out, st)

# H2 arm of the client exchange: the request is destructured here (once)
# because the gate needs :path, and req itself rides on to fit_keep.
def client.on.h2_keep(sock: Socket, +st: CliSt, +host: String, +port: U32, +req: Request) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  match req:
    case Request{method, path, headers, body}:
      client.on.fit_keep(sock, st, host, port, req, client.on.valid.go(host, port, path), client.on.body_ok(body))

# The client exchange, both ALPN answers (TASK-031): ONE request on the
# connection the caller already owns, and it never closes -- the caller closes
# (client.on / client.once do) or calls again for the next request, threading
# the socket and the state. N requests are that loop at the call site; the
# returned CliSt carries the advanced sid and the HPACK table the next response
# decodes against.
def client.request(sock: Socket, +st: CliSt, +host: String, +port: U32, +req: Request) ->
  IO(Socket & Result<&1, &1, U32 & String, Response> & CliSt):
  match st:
    case CliSt{sid, tab, is_h2}:
      match is_h2:
        case True{}:
          client.on.h2_keep(sock, CliSt{sid, tab, is_h2}, host, port, req)
        case False{}:
          client.on.h1_keep(sock, st, host, port, req)

def client_seq.rev.go(+xs: List<&2, Response>, acc: List<&2, Response>) -> List<&2, Response>:
  match xs:
    case Nil{}:
      acc
    case +h <> t:
      client_seq.rev.go(t, h <> acc)

def client_seq.rev(+xs: List<&2, Response>) -> List<&2, Response>:
  client_seq.rev.go(xs, Nil{})

# Sequential batch over a connection the caller already owns: N requests, one
# client.request each, answers in request order, socket and state handed back.
# Nothing closes here -- client.on / client.once close what they dialed. The
# first Fail aborts with the socket still handed back, so the caller can always
# close it. One loop serves both ALPN answers, because client.request
# dispatches; H1 has no sid or HPACK table, so the CliSt just rides along.
def client_seq.keep.go(rest: List<&2, Request>, +acc: List<&2, Response>, got: Socket & Result<&1, &1, U32 & String, Response> & CliSt, +host: String, +port: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt):
  match rest:
    case Nil{}:
      (s0, r0, st0) = got
      match r0:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt, (s0, Fail{e}, st0))
        case Done{+resp}:
          IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt, (s0, Done{client_seq.rev(resp <> acc)}, st0))
    case req <> t:
      (s2, r2, st2) = got
      match r2:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt, (s2, Fail{e}, st2))
        case Done{+resp}:
          do IO<Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt>:
            got3 : Socket & Result<&1, &1, U32 & String, Response> & CliSt <- client.request(s2, st2, host, port, req)
            client_seq.keep.go(t, resp <> acc, got3, host, port)

def client_seq.keep(sock: Socket, +st: CliSt, +host: String, +port: U32, reqs: List<&2, Request>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt):
  match reqs:
    case Nil{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt, (sock, Done{Nil{}}, st))
    case req <> t:
      do IO<Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt>:
        got : Socket & Result<&1, &1, U32 & String, Response> & CliSt <- client.request(sock, st, host, port, req)
        client_seq.keep.go(t, Nil{}, got, host, port)

# Close the socket and drop the state: what the dialing entries end with,
# because they own the connection they opened.
def client.on.closed(out: Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt) ->
  IO(Result<&1, &1, U32 & String, List<&2, Response>>):
  (s, r, st) = out
  do IO<Result<&1, &1, U32 & String, List<&2, Response>>>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(Result<&1, &1, U32 & String, List<&2, Response>>, r)

def client.on.conn(conn: Result<&1, &1, U32 & String, Socket & CliSt>, +host: String, +port: U32, +reqs: List<&2, Request>) ->
  IO(Result<&1, &1, U32 & String, List<&2, Response>>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, Response>>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, List<&2, Response>>>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, Response>> & CliSt <- client_seq.keep(sock, st, host, port, reqs)
        client.on.closed(out)

def client.on(+host: String, +port: U32, +reqs: List<&2, Request>) ->
  IO(Result<&1, &1, U32 & String, List<&2, Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, Response>>>:
    conn : Result<&1, &1, U32 & String, Socket & CliSt> <- client.connect(host, port)
    client.on.conn(conn, host, port, reqs)

def client.on_insecure(+host: String, +port: U32, +reqs: List<&2, Request>) ->
  IO(Result<&1, &1, U32 & String, List<&2, Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, Response>>>:
    conn : Result<&1, &1, U32 & String, Socket & CliSt> <- client.connect_insecure(host, port)
    client.on.conn(conn, host, port, reqs)

# One-shot entries: dial, one client.request, close. No list to unwrap -- the
# exchange answers a single Response, and client.request dispatches both ALPN
# answers, so the H1 leg needs nothing of its own.
# ---------------------------------------------------------------------

def client.once.closed(out: Socket & Result<&1, &1, U32 & String, Response> & CliSt) ->
  IO(Result<&1, &1, U32 & String, Response>):
  (s, r, st) = out
  do IO<Result<&1, &1, U32 & String, Response>>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(Result<&1, &1, U32 & String, Response>, r)

def client.once.dialed(conn: Result<&1, &1, U32 & String, Socket & CliSt>, +host: String, +port: U32, req: Request) ->
  IO(Result<&1, &1, U32 & String, Response>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Response>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, Response>>:
        out : Socket & Result<&1, &1, U32 & String, Response> & CliSt <- client.request(sock, st, host, port, req)
        client.once.closed(out)

def client.once(+host: String, +port: U32, req: Request) ->
  IO(Result<&1, &1, U32 & String, Response>):
  do IO<Result<&1, &1, U32 & String, Response>>:
    conn : Result<&1, &1, U32 & String, Socket & CliSt> <- client.connect(host, port)
    client.once.dialed(conn, host, port, req)

def client.once_insecure(+host: String, +port: U32, req: Request) ->
  IO(Result<&1, &1, U32 & String, Response>):
  do IO<Result<&1, &1, U32 & String, Response>>:
    conn : Result<&1, &1, U32 & String, Socket & CliSt> <- client.connect_insecure(host, port)
    client.once.dialed(conn, host, port, req)

def client.echo(+host: String, +port: U32, +path: String) ->
  IO(Result<&1, &1, U32 & String, Response>):
  client.once(host, port, Request{"GET", path, Nil{}, Nil{}})

def client.echo_insecure(+host: String, +port: U32, +path: String) ->
  IO(Result<&1, &1, U32 & String, Response>):
  client.once_insecure(host, port, Request{"GET", path, Nil{}, Nil{}})

# URL + fetch (Phase 9): read_url ported verbatim from http.bend:653-840
# with a httpx_url prefix and no import — the chain only needs Base plus
# the client.on.valid_host/port/path copies already living above.
# fetch* mirrors https.bend:286-396 over client_once.dialgo (GET, Nil body);
# http:// refuses with 400 (TLS-only, same contract as https.fetch).
# No laws: the httpx keeps no publish surface (dono decision).
# ---------------------------------------------------------------------

def httpx_url.default_port(secure: Bool) -> U32:
  match secure:
    case True{}:
      443
    case False{}:
      80

def httpx_url.strip_host(h: String) -> String:
  String.trim(h)

def httpx_url.split_host_port.put(h: Char, t: String, host: String, port: String, rec: String & String, is_colon: Bool) -> String & String:
  match is_colon:
    case True{}:
      (host, t)
    case False{}:
      rec

def httpx_url.split_host_port.go(s: String, +host: String, +port: String) -> String & String:
  match s:
    case SNil{}:
      (host, port)
    case SCon{+h, +t}:
      httpx_url.split_host_port.put(h, t, host, port, httpx_url.split_host_port.go(t, host ++ Char.show(h), port), Char.is_eq(h, ':'))

def httpx_url.split_host_port(s: String) -> String & String:
  httpx_url.split_host_port.go(s, SNil{}, SNil{})

def httpx_url.split_host_path.put(h: Char, t: String, acc: String, rec: String & String, is_slash: Bool) -> String & String:
  match is_slash:
    case True{}:
      (acc, SCon{h, t})
    case False{}:
      rec

def httpx_url.split_host_path.go(s: String, +acc: String) -> String & String:
  match s:
    case SNil{}:
      (acc, SNil{})
    case SCon{+h, +t}:
      httpx_url.split_host_path.put(h, t, acc, httpx_url.split_host_path.go(t, acc ++ Char.show(h)), Char.is_eq(h, '/'))

def httpx_url.split_host_path(s: String) -> String & String:
  httpx_url.split_host_path.go(s, SNil{})

def httpx_url.norm_path(p: String) -> String:
  match p:
    case SNil{}:
      "/"
    case SCon{h, t}:
      p

def httpx_url.done(secure: Bool, host: String, port: U32, path: String, ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match ok:
    case True{}:
      Done{(secure, host, port, path)}
    case False{}:
      Fail{(400, "bad url")}

def httpx_url.explicit.put(secure: Bool, host: String, +path: String, port: Maybe<&2, U32>) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match port:
    case None{}:
      Fail{(400, "bad port")}
    case Some{p}:
      +c = p
      httpx_url.done(secure, host, c, path, Bool.and(client.on.valid_port(c), client.on.valid_path(path)))

def httpx_url.explicit(secure: Bool, host: String, portstr: String, path: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  httpx_url.explicit.put(secure, host, path, U32.read(portstr))

def httpx_url.port.go(+secure: Bool, host: String, portstr: String, +path: String, no_port: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match no_port:
    case True{}:
      httpx_url.done(secure, host, httpx_url.default_port(secure), path, client.on.valid_path(path))
    case False{}:
      httpx_url.explicit(secure, host, portstr, path)

def httpx_url.port(secure: Bool, host: String, +portstr: String, path: String, host_ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match host_ok:
    case False{}:
      Fail{(400, "bad host")}
    case True{}:
      httpx_url.port.go(secure, host, portstr, path, String.is_empty(portstr))

def httpx_url.host.go(secure: Bool, path: String, hp: String & String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  (host, portstr) = hp
  +h1 = httpx_url.strip_host(host)
  httpx_url.port(secure, h1, portstr, path, client.on.valid_host(h1))

def httpx_url.host(secure: Bool, +hostport: String, path: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  httpx_url.host.go(secure, path, httpx_url.split_host_port(hostport))

def httpx_url.split(hp: String & String, secure: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  (hostport, path0) = hp
  httpx_url.host(secure, hostport, httpx_url.norm_path(path0))

def httpx_url.rest(+rest: String, secure: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  httpx_url.split(httpx_url.split_host_path(rest), secure)

def httpx_url.http(url: String, is_http: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match is_http:
    case True{}:
      httpx_url.rest(x_str_drop32(url, 7), False{})
    case False{}:
      Fail{(400, "bad scheme")}

def httpx_url.scheme(url: String, is_https: Bool, is_http: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match is_https:
    case True{}:
      httpx_url.rest(x_str_drop32(url, 8), True{})
    case False{}:
      httpx_url.http(url, is_http)

def httpx_url.read_url(+url: String) -> Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  httpx_url.scheme(url, String.starts_with(url, "https://"), String.starts_with(url, "http://"))

# fetch: GET by URL (mirror https.fetch, https only). Answers the body
# as String; fetch_bytes answers raw bytes. insecure=False{} verifies.
# ---------------------------------------------------------------------

def fetch.text(r: Result<&1, &1, U32 & String, Response>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+resp}:
      match resp:
        case Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, String>, Done{x_bytes_str(body)})

def fetch.raw(r: Result<&1, &1, U32 & String, Response>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{+resp}:
      match resp:
        case Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Done{body})

def fetch.once(+host: String, port: U32, path: String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, Response>):
  match insecure:
    case True{}:
      client.once_insecure(host, port, Request{"GET", path, Nil{}, Nil{}})
    case False{}:
      client.once(host, port, Request{"GET", path, Nil{}, Nil{}})

def fetch.get(+host: String, port: U32, path: String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    r : Result<&1, &1, U32 & String, Response> <- fetch.once(host, port, path, insecure)
    fetch.text(r)

def fetch_bytes.get(+host: String, port: U32, path: String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    r : Result<&1, &1, U32 & String, Response> <- fetch.once(host, port, path, insecure)
    fetch.raw(r)

def fetch.host(host: String, +port: U32, path: String, insecure: Bool, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      fetch.get(host, port, path, insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad host")})

def fetch_bytes.host(host: String, +port: U32, path: String, insecure: Bool, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match ok:
    case True{}:
      fetch_bytes.get(host, port, path, insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad host")})

# Plaintext dial: resolve first, then connect to the IPv4. TCP.connect wants
# the dotted quad -- handing it the NAME is EINVAL 22 -- while the name still
# rides the Host header (h1_once.conn takes host and socket separately). A
# resolve failure fails with the DNS code (601-605) before any socket exists,
# so no handle can leak. Mirror of http.bend's fetch.dial, lost when this lane
# was inlined here.
def plain.dial.asked(port: U32, r: Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{ip}:
      TCP.connect(ip, port)

def plain.dial(+host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  do IO<Result<&1, &1, U32 & String, Socket>>:
    r : Result<&1, &1, U32 & String, String> <- DNS.resolve(host)
    plain.dial.asked(port, r)

def fetch.plain(+host: String, +port: U32, path: String, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        conn : Result<&1, &1, U32 & String, Socket> <- plain.dial(host, port)
        r : Result<&1, &1, U32 & String, Response> <- h1_once.conn(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, conn, host, port, "GET", path, Nil{}, Nil{})
        fetch.text(r)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad host")})

def fetch_bytes.plain(+host: String, +port: U32, path: String, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match ok:
    case True{}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        conn : Result<&1, &1, U32 & String, Socket> <- plain.dial(host, port)
        r : Result<&1, &1, U32 & String, Response> <- h1_once.conn(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, conn, host, port, "GET", path, Nil{}, Nil{})
        fetch.raw(r)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad host")})

def fetch.url.go(secure: Bool, +host: String, port: U32, path: String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match secure:
    case True{}:
      fetch.host(host, port, path, insecure, client.on.valid_host(host))
    case False{}:
      # http:// is only served when the caller said insecure: the plaintext
      # H1 lane is the insecure dial, so http:// + verify stays 400.
      match insecure:
        case True{}:
          fetch.plain(host, port, path, client.on.valid_host(host))
        case False{}:
          IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad scheme")})

def fetch_bytes.url.go(secure: Bool, +host: String, port: U32, path: String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match secure:
    case True{}:
      fetch_bytes.host(host, port, path, insecure, client.on.valid_host(host))
    case False{}:
      match insecure:
        case True{}:
          fetch_bytes.plain(host, port, path, client.on.valid_host(host))
        case False{}:
          IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad scheme")})

def fetch.url(u: Bool & String & U32 & String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  (secure, host, port, path) = u
  fetch.url.go(secure, host, port, path, insecure)

def fetch_bytes.url(u: Bool & String & U32 & String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  (secure, host, port, path) = u
  fetch_bytes.url.go(secure, host, port, path, insecure)

def fetch.r(url: String, parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{u}:
      fetch.url(u, insecure)

def fetch_bytes.r(url: String, parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{u}:
      fetch_bytes.url(u, insecure)

def fetch(+url: String) -> IO(Result<&1, &1, U32 & String, String>):
  fetch.r(url, httpx_url.read_url(url), False{})

def fetch_insecure(+url: String) -> IO(Result<&1, &1, U32 & String, String>):
  fetch.r(url, httpx_url.read_url(url), True{})

def fetch_bytes(+url: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  fetch_bytes.r(url, httpx_url.read_url(url), False{})

def fetch_bytes_insecure(+url: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  fetch_bytes.r(url, httpx_url.read_url(url), True{})

# request: any method with headers and a String body; answers the
# response body as String via fetch.text. request_bytes takes raw bytes
# in and answers raw bytes via fetch.raw. Both are thin aliases over
# client.once(_insecure) — the one-shot dial/exchange/close lives there
# (TASK-026 Phase 6; send_request* is gone, not aliased).
# insecure=False{} verifies.
# ---------------------------------------------------------------------

def request.once(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, Response>):
  match insecure:
    case True{}:
      client.once_insecure(host, port, Request{method, path, hs, body})
    case False{}:
      client.once(host, port, Request{method, path, hs, body})

# request.plain: any method with headers and a raw body over the PLAINTEXT H1
# lane (no TLS at all) -- the sibling of request.once, which always speaks TLS.
# fetch(_bytes)_insecure("http://...") is the GET-only route into this lane;
# this is the route for every other method, and the public entries are
# request_plain / request_bytes_plain. Dial, one exchange and close, all here.
def request.plain(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Response>):
  do IO<Result<&1, &1, U32 & String, Response>>:
    conn : Result<&1, &1, U32 & String, Socket> <- plain.dial(host, port)
    h1_once.conn(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, conn, host, port, method, path, hs, body)

def request_bytes.go(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: List<&2, U32>, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    r : Result<&1, &1, U32 & String, Response> <- request.once(host, port, method, path, hs, body, insecure)
    fetch.raw(r)

def request_bytes.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: List<&2, U32>, insecure: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match fit:
    case True{}:
      request_bytes.go(host, port, path, method, hs, body, insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad request")})

def request_bytes(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  request_bytes.fit(host, port, path, method, hs, body, False{}, client.on.valid.go(host, port, path))

def request_bytes_insecure(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  request_bytes.fit(host, port, path, method, hs, body, True{}, client.on.valid.go(host, port, path))

# The plaintext twins of request_bytes / request: same contract, no TLS, so
# there is no insecure flag to thread (which is why there is no .go split --
# the .fit def gates and does the work).
def request_bytes_plain.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: List<&2, U32>, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match fit:
    case True{}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        r : Result<&1, &1, U32 & String, Response> <- request.plain(host, port, method, path, hs, body)
        fetch.raw(r)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad request")})

def request_bytes_plain(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  request_bytes_plain.fit(host, port, path, method, hs, body, client.on.valid.go(host, port, path))

def request_plain.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: String, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match fit:
    case True{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        r : Result<&1, &1, U32 & String, Response> <- request.plain(host, port, method, path, hs, x_str_bytes(body))
        fetch.text(r)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad request")})

def request_plain(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  request_plain.fit(host, port, path, method, hs, body, client.on.valid.go(host, port, path))

def request.go(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: String, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    r : Result<&1, &1, U32 & String, Response> <- request.once(host, port, method, path, hs, x_str_bytes(body), insecure)
    fetch.text(r)

def request.fit(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: String, insecure: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match fit:
    case True{}:
      request.go(host, port, path, method, hs, body, insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad request")})

def request(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  request.fit(host, port, path, method, hs, body, False{}, client.on.valid.go(host, port, path))

def request_insecure(+host: String, +port: U32, +path: String, +method: String, hs: List<&2, Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  request.fit(host, port, path, method, hs, body, True{}, client.on.valid.go(host, port, path))

# Concurrent slots (Phase D): response assembly per sid. New ClSt type
# (head is Head, not ReqHead, so St ops cannot reuse without
# copy); ops mirror httpxn.* single-traversal, clone-free (S incs, no
# clones). fends/CONT stays Fail 502 (single-HEADERS peers); fdel_flag
# remains for later CONT if a peer fragments.
# ---------------------------------------------------------------------

type ClSt is Data:
  ClSt{head: Maybe<&2, Head>, body: List<&2, U32>, sid: U32}

type ClTaken is Data:
  ClTaken{slots: List<&2, ClSt>, st: ClSt}

def httpxc.sid_of(st: ClSt) -> U32:
  match st:
    case ClSt{head, body, +sid}:
      sid

def httpxc.has(slots: List<&2, ClSt>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      Bool.or(U32.is_eq(httpxc.sid_of(st), sid), httpxc.has(t, sid))

def httpxc.has_some_go(eq: Bool, st: ClSt, rec: Bool) -> Bool:
  match eq:
    case True{}:
      match st:
        case ClSt{head, body, sid}:
          match head:
            case None{}:
              True{}
            case Some{rh}:
              False{}
    case False{}:
      rec

def httpxc.has_some(slots: List<&2, ClSt>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      httpxc.has_some_go(U32.is_eq(httpxc.sid_of(st), sid), st, httpxc.has_some(t, sid))

def httpxc.del_go(eq: Bool, +st: ClSt, rest: List<&2, ClSt>) -> List<&2, ClSt>:
  match eq:
    case True{}:
      rest
    case False{}:
      st <> rest

def httpxc.del(slots: List<&2, ClSt>, +sid: U32) -> List<&2, ClSt>:
  match slots:
    case Nil{}:
      Nil{}
    case +st <> t:
      httpxc.del_go(U32.is_eq(httpxc.sid_of(st), sid), st, httpxc.del(t, sid))

def httpxc.take_go(eq: Bool, +st: ClSt, p: ClTaken) -> ClTaken:
  match eq:
    case True{}:
      match p:
        case ClTaken{+slots, st2}:
          ClTaken{slots, st}
    case False{}:
      match p:
        case ClTaken{+slots2, +found2}:
          ClTaken{(st <> slots2), found2}

def httpxc.take_del(slots: List<&2, ClSt>, +sid: U32) -> ClTaken:
  match slots:
    case Nil{}:
      ClTaken{Nil{}, ClSt{None{}, Nil{}, 0}}
    case +st <> t:
      httpxc.take_go(U32.is_eq(httpxc.sid_of(st), sid), st, httpxc.take_del(t, sid))

def httpxc.taken_slots(p: ClTaken) -> List<&2, ClSt>:
  match p:
    case ClTaken{+slots, st}:
      slots

def httpxc.taken_st(p: ClTaken) -> ClSt:
  match p:
    case ClTaken{slots, +st}:
      st

def httpxc.put(slots: List<&2, ClSt>, +st: ClSt) -> List<&2, ClSt>:
  st <> httpxc.del(slots, httpxc.sid_of(st))

def httpxc.body_of(st: ClSt) -> List<&2, U32>:
  match st:
    case ClSt{head, +body, sid}:
      body

def httpxc.head_of(st: ClSt) -> Head:
  match st:
    case ClSt{head, body, sid}:
      match head:
        case None{}:
          Head{0, Nil{}}
        case Some{+h}:
          h

def httpxc.resp_of(+head: Head, +body: List<&2, U32>) -> Response:
  match head:
    case Head{+status, +headers}:
      Response{status, headers, body}

def httpxc.req_of_st(st: ClSt, +payload: List<&2, U32>) -> Response:
  match st:
    case ClSt{head, +body, +sid}:
      match head:
        case None{}:
          Response{0, Nil{}, x_cat(x_rev_push(payload, body))}
        case Some{+rh}:
          match rh:
            case Head{+status, +headers}:
              Response{status, headers, x_cat(x_rev_push(payload, body))}

def httpxc.data_cont_slots(p: ClTaken, +payload: List<&2, U32>) -> List<&2, ClSt>:
  match p:
    case ClTaken{+rest, st}:
      match st:
        case ClSt{head, +body, +sid}:
          match head:
            case None{}:
              ((ClSt{Some{Head{0, Nil{}}}, x_rev_push(payload, body), sid} <> rest))
            case Some{+rh}:
              ((ClSt{Some{rh}, x_rev_push(payload, body), sid} <> rest))

# Concurrent send-all (pipelined HEADERS+DATA, sids 1,3,5…; aborts on
# first send Fail; caller validates bodies/paths upfront)
# ---------------------------------------------------------------------

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

def client_conc.send_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = sent
  s

@unsafe
def client_conc.send_all(sock: Socket, +sid: U32, +host: String, +port: U32, reqs: List<&2, Request>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match reqs:
    case Nil{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case Request{+method, +path, +headers, +body} <> t:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- client.on.send_req(sock, sid, host, port, method, path, headers, body)
        client_conc.send_all(client_conc.send_kept(sent), (sid + 2 : U32), host, port, t)

# Concurrent drain leafs (sum, no tab return; connection closes after)
# --------------------------------------------------------------------

def client_conc.fail(got: Socket & Got, +code: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, U32>):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, U32>, (s, Fail{(code, msg)}))

def client_conc.done(got: Socket & Got, +total: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, U32>):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, U32>, (s, Done{total}))

def client_conc.finish_next(+pending: U32) -> U32:
  match pending:
    case 1:
      7
    case _:
      0

# CONTINUATION inline leaves for conc drain (Phase 15 item 3): same shape
# as the sdrop pair — fresh Err-next pair plus GOAWAY-fail mapping with
# the conc result type. No ~H inside (leaves above the loop).
# ---------------------------------------------------------------------

def client_conc.next(s: Socket) -> Socket & Got:
  (s, GotErr{0, "next"})

def client_conc.sendfail(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, U32>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, U32>, (s, Fail{e}))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, U32>, (s, Fail{(502, "continuation")}))

@unsafe
def client_conc.drain(~H: Response -> U32, phase: U32, got: Socket & Got, +buf: List<&2, U32>, +tab: Tab, +slots: List<&2, ClSt>, +pending: U32, +total: U32, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +nh: Head, act: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, U32>):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Socket & Result<&1, &1, U32 & String, U32>>:
        got2 : Socket & Got <- x_read_frame(s0, buf)
        client_conc.drain(~H, 1, got2, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case GotErr{code1, msg1}:
          IO.pure(Socket & Result<&1, &1, U32 & String, U32>, (s1, Fail{(code1, msg1)}))
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ2, +flags2, +sid22, +payload2}:
              client_conc.drain(~H, 2, (s1, GotOk{frame, buf2}), buf2, tab, slots, pending, total, typ2, flags2, sid22, payload2, httpx.cls_fix(x_classify(frame), flags2), U32.and(flags2, x_f_end_stream()), Head{0, Nil{}}, 4)
    case 2:
      match cls:
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, U32>>:
            got2 : Socket & Got <- client.on.ack(got)
            client_conc.drain(~H, 0, got2, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, U32>>:
            gotp : Socket & Got <- client.on.ack_ping(got, payload)
            client_conc.drain(~H, 0, gotp, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 5:
          client_conc.fail(got, 502, "goaway")
        case 7:
          client_conc.drain(~H, 0, got, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 9:
          client_conc.fail(got, 502, "bad window_update")
        case 8:
          client_conc.fail(got, 502, "continuation")
        case 2:
          client_conc.drain(~H, client_conc.finish_next(pending), got, buf, tab, httpxc.del(slots, sid2), (pending - 1 : U32), total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 6:
          client_conc.drain(~H, 3, got, buf, tab, slots, pending, total, typ, flags, sid2, payload, cls, end, Head{0, Nil{}}, 4)
        case 0:
          client_conc.drain(~H, 0, got, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case _:
          client_conc.drain(~H, 0, got, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
    case 3:
      match typ:
        case 1:
          +dr : Result<&1, &1, U32 & String, Head & Tab> = x_resp.decode(payload, tab)
          client_conc.drain(~H, 4, got, buf, x_resp.tab(dr), slots, pending, total, typ, flags, sid2, payload, cls, end, x_resp.rh(dr), httpxn.head_act(httpxn.need_u(typ, flags), x_resp.ok(dr), end))
        case 0:
          client_conc.drain(~H, 5, got, buf, tab, slots, pending, total, typ, flags, sid2, payload, cls, end, Head{0, Nil{}}, httpxn.decide_data(httpxc.has(slots, sid2), end))
        case _:
          client_conc.drain(~H, 0, got, buf, tab, slots, pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
    case 4:
      match act:
        case 0:
          client_conc.drain(~H, 0, got, buf, tab, httpxc.put(slots, ClSt{Some{nh}, Nil{}, sid2}), pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 1:
          +sc1 : U32 = H(httpxc.resp_of(nh, Nil{}))
          client_conc.drain(~H, client_conc.finish_next(pending), got, buf, tab, slots, (pending - 1 : U32), (total + sc1 : U32), 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 6:
          client_conc.drain(~H, 6, client_conc.next(httpx.wo(got)), buf, tab, slots, pending, total, 0, 0, sid2, payload, 0, end, Head{0, Nil{}}, 0)
        case 5:
          client_conc.fail(got, 502, "head decode")
        case _:
          client_conc.fail(got, 502, "head")
    case 5:
      match act:
        case 0:
          client_conc.drain(~H, 0, got, buf, tab, httpxc.data_cont_slots(httpxc.take_del(slots, sid2), payload), pending, total, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 1:
          +tp1 : ClTaken = httpxc.take_del(slots, sid2)
          +resp1 : Response = httpxc.req_of_st(httpxc.taken_st(tp1), payload)
          +sc5 : U32 = H(resp1)
          client_conc.drain(~H, client_conc.finish_next(pending), got, buf, tab, httpxc.taken_slots(tp1), (pending - 1 : U32), (total + sc5 : U32), 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        case 4:
          client_conc.fail(got, 502, "stray data")
        case _:
          client_conc.fail(got, 502, "data")
    case 7:
      client_conc.done(got, total)
    case 6:
      (s6, g6) = got
      match g6:
        case GotErr{code6, msg6}:
          match code6:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, U32>>:
                got6 : Socket & Got <- x_read_frame(s6, buf)
                client_conc.drain(~H, 6, got6, buf, tab, slots, pending, total, 0, 0, sid2, payload, 0, end, Head{0, Nil{}}, 0)
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, U32>, (s6, Fail{(code6, msg6)}))
        case GotOk{+frame6, +buf6}:
          match frame6:
            case Frame{+typ6, +flags6, +sid6, +pay6}:
              client_conc.drain(~H, 8, (s6, GotOk{frame6, buf6}), buf6, tab, slots, pending, total, typ6, flags6, sid2, List.append(&2, U32, payload, pay6), client.on.cont_cls_of(typ6, sid6, sid2, flags6), end, Head{0, Nil{}}, 0)
    case 8:
      (s8, g8) = got
      match cls:
        case 0:
          +dr8 : Result<&1, &1, U32 & String, Head & Tab> = x_resp.decode(payload, tab)
          client_conc.drain(~H, 4, client_conc.next(s8), buf, x_resp.tab(dr8), slots, pending, total, typ, flags, sid2, Nil{}, cls, end, x_resp.rh(dr8), httpxn.head_act(0, x_resp.ok(dr8), end))
        case 1:
          client_conc.drain(~H, 6, client_conc.next(s8), buf, tab, slots, pending, total, 0, 0, sid2, payload, 0, end, Head{0, Nil{}}, 0)
        case _:
          do IO<Socket & Result<&1, &1, U32 & String, U32>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s8, 0, 1)
            client_conc.sendfail(sent)
    case _:
      client_conc.fail(got, 502, "bad phase")

# Concurrent public (dial once, pipeline N, drain to sum, close)
# ---------------------------------------------------------------

def client_conc.drained(drained: Socket & Result<&1, &1, U32 & String, U32>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  (s, r) = drained
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(Result<&1, &1, U32 & String, U32>, Fail{e})
    case Done{+total}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(Result<&1, &1, U32 & String, U32>, Done{total})

def client_conc.after_send(~H: Response -> U32, sent: Socket & Result<&1, &1, U32 & String, Unit>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, U32>, Fail{e})
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        drained : Socket & Result<&1, &1, U32 & String, U32> <- client_conc.drain(~H, 0, (sock, GotErr{0, "next"}), Nil{}, x_tab.empty(), Nil{}, pending, 0, 0, 0, 0, Nil{}, 0, 0, Head{0, Nil{}}, 4)
        client_conc.drained(drained)

def client_conc.exch(~H: Response -> U32, sock: Socket, +host: String, +port: U32, reqs: List<&2, Request>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32>):
  do IO<Result<&1, &1, U32 & String, U32>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- client_conc.send_all(sock, 1, host, port, reqs)
    client_conc.after_send(~H, sent, pending)

def client_conc.conn(~H: Response -> U32, conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, reqs: List<&2, Request>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32>, Fail{e})
    case Done{sock}:
      client_conc.exch(~H, sock, host, port, reqs, pending)

def client_conc.go(~H: Response -> U32, +host: String, +port: U32, reqs: List<&2, Request>, +pending: U32, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, U32>):
  match insecure:
    case True{}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        c : Result<&1, &1, U32 & String, Socket & CliSt> <- client.on.connect_insecure(host, port)
        conn : Result<&1, &1, U32 & String, Socket> <- client.on.h2_only(c)
        client_conc.conn(~H, conn, host, port, reqs, pending)
    case False{}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        c : Result<&1, &1, U32 & String, Socket & CliSt> <- client.on.connect_secure(host, port)
        conn : Result<&1, &1, U32 & String, Socket> <- client.on.h2_only(c)
        client_conc.conn(~H, conn, host, port, reqs, pending)

def client_conc.fit_n(~H: Response -> U32, +host: String, +port: U32, reqs: List<&2, Request>, +pending: U32, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, U32>):
  match pending:
    case 0:
      IO.pure(Result<&1, &1, U32 & String, U32>, Done{0})
    case _:
      client_conc.go(~H, host, port, reqs, pending, insecure)

def client_conc.fit(~H: Response -> U32, +host: String, +port: U32, +reqs: List<&2, Request>, insecure: Bool, valid: Bool) ->
  IO(Result<&1, &1, U32 & String, U32>):
  match valid:
    case True{}:
      client_conc.fit_n(~H, host, port, reqs, client_conc.count(reqs), insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, U32>, Fail{(400, "bad request")})

def client.concurrent(~H: Response -> U32, +host: String, +port: U32, +reqs: List<&2, Request>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  client_conc.fit(~H, host, port, reqs, False{}, client_conc.valid_all(reqs, host, port))

def client.concurrent_insecure(~H: Response -> U32, +host: String, +port: U32, +reqs: List<&2, Request>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  client_conc.fit(~H, host, port, reqs, True{}, client_conc.valid_all(reqs, host, port))

# Server streaming (Phase F): sibling httpx_stream loop with pure handler
# ~H: SrvEv -> SrvOut (Continue buffers like today, RespondEarly
# sends + frees + skips rest via stray-skip). Shares take_del/has/
# put/classify/preface/plumbing (no copy); self-recursive own loop (no
# mutual with httpx). No WU sends (backpressure via withheld WU, like httpx).
# Stray DATA skips (not closes) to allow early-rest skipping.
# ---------------------------------------------------------------------

def httpxs.is_more(+out: SrvOut) -> Bool:
  match out:
    case Continue{}:
      True{}
    case RespondEarly{resp}:
      False{}

def httpxs.out_resp(+out: SrvOut) -> Response:
  match out:
    case Continue{}:
      Response{0, Nil{}, Nil{}}
    case RespondEarly{+resp}:
      resp

def httpxs.head_act(is_more: Bool, +need: U32, ok: Bool, +end: U32) -> U32:
  match is_more need ok end:
    case False{} _ _ _:
      1
    case True{} 1 _ _:
      6
    case True{} 0 False{} _:
      5
    case True{} 0 True{} 1:
      7
    case _ _ _ _:
      0

def httpxs.data_act(is_more: Bool, has: Bool, +end: U32) -> U32:
  match is_more has end:
    case False{} _ _:
      1
    case True{} False{} _:
      8
    case True{} True{} 1:
      7
    case _ _ _:
      0

def httpxs.head_out(+out: SrvOut, +end: U32) -> U32 & Response:
  match out:
    case Continue{}:
      match end:
        case 1:
          (7, Response{0, Nil{}, Nil{}})
        case _:
          (0, Response{0, Nil{}, Nil{}})
    case RespondEarly{+resp}:
      (1, resp)

def httpxs.data_out(+out: SrvOut, fin: Bool) -> U32 & Response:
  match out:
    case Continue{}:
      match fin:
        case True{}:
          (7, Response{0, Nil{}, Nil{}})
        case False{}:
          (0, Response{0, Nil{}, Nil{}})
    case RespondEarly{+resp}:
      (1, resp)

def httpxs.head_act_from_out(+out: SrvOut, +end: U32) -> U32:
  match out:
    case Continue{}:
      match end:
        case 1:
          7
        case _:
          0
    case RespondEarly{resp}:
      1

def httpxs.head_resp_from_out(+out: SrvOut) -> Response:
  match out:
    case Continue{}:
      Response{0, Nil{}, Nil{}}
    case RespondEarly{+resp}:
      resp

def httpxs.data_act_from_out(+out: SrvOut, fin: Bool) -> U32:
  match out:
    case Continue{}:
      match fin:
        case True{}:
          7
        case False{}:
          0
    case RespondEarly{resp}:
      1

def httpxs.data_resp_from_out(+out: SrvOut) -> Response:
  match out:
    case Continue{}:
      Response{0, Nil{}, Nil{}}
    case RespondEarly{+resp}:
      resp

def httpxs.head_act_of(~H: SrvEv -> SrvOut, ok: Bool, +need: U32, +end: U32, +nh: ReqHead, +nt: Tab, +sid: U32) -> U32:
  match ok need:
    case _ 1:
      6
    case False{} 0:
      5
    case True{} 0:
      httpxs.head_act_from_out(H(SrvReqHead{sid, nh}), end)
    case _ _:
      5

def httpxs.head_resp_of(~H: SrvEv -> SrvOut, ok: Bool, +need: U32, +end: U32, +nh: ReqHead, +nt: Tab, +sid: U32) -> Response:
  match ok need:
    case _ 1:
      Response{0, Nil{}, Nil{}}
    case False{} 0:
      Response{0, Nil{}, Nil{}}
    case True{} 0:
      httpxs.head_resp_from_out(H(SrvReqHead{sid, nh}))
    case _ _:
      Response{0, Nil{}, Nil{}}

def httpxs.data_act_of(~H: SrvEv -> SrvOut, has: Bool, +payload: List<&2, U32>, +fin: Bool, +sid: U32) -> U32:
  match has:
    case False{}:
      8
    case True{}:
      httpxs.data_act_from_out(H(SrvReqData{sid, payload, fin}), fin)

def httpxs.data_resp_of(~H: SrvEv -> SrvOut, has: Bool, +payload: List<&2, U32>, +fin: Bool, +sid: U32) -> Response:
  match has:
    case False{}:
      Response{0, Nil{}, Nil{}}
    case True{}:
      httpxs.data_resp_from_out(H(SrvReqData{sid, payload, fin}))

def httpxs.goaway_close(got: Socket & Got) -> IO(Unit):
  (s, g) = got
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s, 0, 1)
    httpxn.cont_failed(sent)

# Sibling interleave loop (own @unsafe self-recursion, no mutual with
# httpx; shares take_del/has/put/classify/preface/plumbing, no copy).
# Delivers SrvReqHead on HEADERS-complete and SrvReqData per DATA
# END_STREAM; Continue buffers like today, RespondEarly sends + frees +
# skips rest (stray-skip, not close). No WU sends (backpressure held).
# ---------------------------------------------------------------------

@unsafe
def httpx_stream(~H: SrvEv -> SrvOut, phase: U32, got: Socket & Got, +slots: List<&2, St>, +fends: List<&2, U32>, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +rh: ReqHead, act: U32, +resp: Response, +tab: Tab, +drt: ReqHead & Bool & Tab) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & Got <- x_read_frame(s0, buf)
        httpx_stream(~H, 1, got2, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 1:
      (s1, g1) = got
      match g1:
        case GotErr{code1, msg1}:
          TLS.tls_close(s1)
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ2, +flags2, +sid22, +payload2}:
              httpx_stream(~H, 2, (s1, GotOk{frame, buf2}), slots, fends, buf2, typ2, flags2, sid22, payload2, httpx.cls_fix(x_classify(frame), flags2), U32.and(flags2, x_f_end_stream()), ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 2:
      match cls:
        case 1:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.ack(got)
            httpx_stream(~H, 0, got2, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 4:
          do IO<Unit>:
            gotp : Socket & Got <- httpx.ack_ping(got, payload)
            httpx_stream(~H, 0, gotp, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 5:
          httpx.close_got(got)
        case 2:
          httpx_stream(~H, 0, got, httpxn.del(slots, sid2), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 7:
          httpx_stream(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 9:
          httpx.close_got(got)
        case 8:
          httpx_stream(~H, 6, got, slots, fends, buf, typ, flags, sid2, payload, cls, U32.and(flags, x_f_end_headers()), ReqHead{"", "", Nil{}}, httpxn.decide_cont(httpxn.frag_has(slots, sid2), U32.and(flags, x_f_end_headers())), Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 6:
          httpx_stream(~H, 3, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 0:
          httpx_stream(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case _:
          httpx_stream(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 3:
      match typ:
        case 1:
          httpx_stream(~H, 7, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.got(x_req.decode(payload, tab)))
        case 0:
          httpx_stream(~H, 5, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, ReqHead{"", "", Nil{}}, httpxs.data_act_of(~H, httpxn.has(slots, sid2), payload, U32.is_eq(end, 1), sid2), httpxs.data_resp_of(~H, httpxn.has(slots, sid2), payload, U32.is_eq(end, 1), sid2), tab, x_req.no_got())
        case _:
          httpx_stream(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 4:
      (s4, g4) = got
      match act:
        case 0:
          httpx_stream(~H, 0, got, httpxn.put(slots, St{Some{rh}, Nil{}, sid2}), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_resp(s4, sid2, resp)
            httpx_stream(~H, 0, httpx.sent(sent), httpxn.del(slots, sid2), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 6:
          httpx_stream(~H, 0, got, httpxn.put(slots, St{None{}, x_cat(payload), sid2}), httpxn.fend_up(fends, sid2, U32.is_eq(end, 1)), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 5:
          TLS.tls_close(s4)
        case 7:
          TLS.tls_close(s4)
        case _:
          TLS.tls_close(s4)
    case 5:
      (sb2, gb2) = got
      match act:
        case 0:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.wu_er((sb2, gb2), buf, sid2, payload)
            httpx_stream(~H, 0, got2, httpxn.data_cont_slots(httpxn.take_del(slots, sid2), payload), fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 1:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.wu_er((sb2, gb2), buf, sid2, payload)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_resp(httpx.wo(got2), sid2, resp)
            httpx_stream(~H, 0, httpx.sent(sent), httpxn.taken_slots(httpxn.take_del(slots, sid2)), httpxn.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 8:
          httpx_stream(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 7:
          TLS.tls_close(sb2)
        case _:
          httpx.close_got((sb2, gb2))
    case 6:
      (s6, g6) = got
      match act:
        case 0:
          httpx_stream(~H, 0, got, httpxn.frag_cont_slots(httpxn.take_del(slots, sid2), payload), fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 1:
          +tp2 : Taken = httpxn.take_del(slots, sid2)
          +full : List<&2, U32> = x_cat(x_rev_push(payload, httpx.body_of(httpxn.taken_st(tp2))))
          +dr6 : Result<&1, &1, U32 & String, ReqHead & Tab> = x_req.decode(full, tab)
          +fp : FendTaken = httpxn.fdel_flag(fends, sid2)
          +ff : U32 = httpxn.ftaken_flag(fp)
          httpx_stream(~H, 7, got, httpxn.taken_slots(tp2), httpxn.ftaken_fends(fp), buf, typ, flags, sid2, Nil{}, cls, ff, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, x_req.tab(dr6), x_req.got(dr6))
        case _:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s6, 0, 1)
            httpxn.cont_failed(sent)
    case 7:
      match drt:
        case (+h, +ot):
          match ot:
            case (+ok, +t):
              +nu = httpxn.need_u(typ, flags)
              httpx_stream(~H, 4, got, slots, fends, buf, typ, flags, sid2, payload, cls, end, h, httpxs.head_act_of(~H, ok, nu, end, h, t, sid2), httpxs.head_resp_of(~H, ok, nu, end, h, t, sid2), t, x_req.no_got())
    case _:
      httpx_stream(~H, 0, got, slots, fends, buf, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, tab, x_req.no_got())

# Streaming accept plumbing (H2-only, no H1 split; non-H2 fail-closed)
# ---------------------------------------------------------------------

@unsafe
def httpxs_pre(~H: SrvEv -> SrvOut, phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          httpxs_pre(~H, 1, (s0, Done{chunk}), acc2, x_preface_ok(acc2), Bool.not(x_has_at_least(24, acc2)))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            httpxs_pre(~H, 0, r2, acc, 0, False{})
        case False{}:
          httpxs_pre(~H, 2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s2, x_t_settings(), 0, 0, x_settings_initial_pay())
            httpx_stream(~H, 0, httpx.sent(sent), httpxn.no_slots(), httpxn.no_fends(), x_drop32(24, acc), 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 4, Response{0, Nil{}, Nil{}}, x_tab.empty(), x_req.no_got())
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def httpxs_start(~H: SrvEv -> SrvOut, sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    httpxs_pre(~H, 0, r1, Nil{}, 0, False{})

def httpxs_spawn.go(~H: SrvEv -> SrvOut, sock: Socket) -> IO(Unit):
  httpxs_start(~H, sock)

def httpxs_spawn(~H: SrvEv -> SrvOut, sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, httpxs_spawn.go(~H, sock))
    return l

def httpxs_conn(~H: SrvEv -> SrvOut, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      httpxs_spawn(~H, sock, l)

def httpxs_alpn_close(sock: Socket, l: Listener) -> IO(Listener):
  do IO<Listener>:
    x : Unit <- TLS.tls_close(sock)
    return l

def httpxs_alpn_go(~H: SrvEv -> SrvOut, is_h2: Bool, listener: Listener, sock: Socket) -> IO(Listener):
  match is_h2:
    case True{}:
      httpxs_spawn(~H, sock, listener)
    case False{}:
      httpxs_alpn_close(sock, listener)

def httpxs_alpn_conn(~H: SrvEv -> SrvOut, accepted: Listener & Result<&1, &1, U32 & String, Socket & String>) -> IO(Listener):
  (listener, result) = accepted
  match result:
    case Fail{e}:
      IO.pure(Listener, listener)
    case Done{value}:
      (sock, protocol) = value
      httpxs_alpn_go(~H, TLS.tls_alpn_is_h2(protocol), listener, sock)

@unsafe
def server.stream(~H: SrvEv -> SrvOut, l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- httpxs_conn(~H, m)
    z : Unit <- server.stream(~H, l2, cert, key)
    return z

@unsafe
def server.stream_alpn(~H: SrvEv -> SrvOut, listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_accept_alpn(listener, cert, key)
    next : Listener <- httpxs_alpn_conn(~H, accepted)
    z : Unit <- server.stream_alpn(~H, next, cert, key)
    return z

# Sequential server (Phase 10): one stream at a time per connection, same
# wire contract as the httpx (literal-only 1-DATA 16KB responses, same Fail
# codes) so sequential traffic answers byte-identical. Pipelined HEADERS
# while a stream is open gets RST_STREAM 7 (refused) and the connection
# lives on; stray DATA closes; stray CONT gets GOAWAY+close. Single
# @unsafe self-recursive def (no mutual, D10); matches only on params
# and pattern-bound vars (D9: after a tuple destructure only the pieces
# are scrutinized — probed in /tmp/opencode/seqprobe/p6); computed codes
# ride arg position (need/act/endh pattern from drain).
# ---------------------------------------------------------------------

def httpx.seq_open(is_zero: Bool) -> Bool:
  match is_zero:
    case True{}:
      False{}
    case False{}:
      True{}

def httpx.seq_tphase(+typ: U32, busy: Bool) -> U32:
  match typ:
    case 1:
      match busy:
        case True{}:
          7
        case False{}:
          3
    case 0:
      4
    case _:
      0

def httpx.seq_cnext(has_frag: Bool) -> U32:
  match has_frag:
    case True{}:
      5
    case False{}:
      8

@unsafe
def httpx_seq(~H: Request -> IO(Response), phase: U32, act: U32, +endh: U32, got: Socket & Got, +buf: List<&2, U32>, +tab: Tab, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +rh: ReqHead, +sid_a: U32, +body: List<&2, U32>, +frag: List<&2, U32>, frag_end: U32, +need: U32) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & Got <- x_read_frame(s0, buf)
        httpx_seq(~H, 1, 4, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)
    case 1:
      (s1, g1) = got
      match g1:
        case GotErr{code1, msg1}:
          TLS.tls_close(s1)
        case GotOk{+frame, +buf2}:
          match frame:
            case Frame{+typ2, +flags2, +sid22, +payload2}:
              httpx_seq(~H, 2, 4, 0, (s1, GotOk{frame, buf2}), buf2, tab, typ2, flags2, sid22, payload2, httpx.cls_fix(x_classify(frame), flags2), U32.and(flags2, x_f_end_stream()), rh, sid_a, body, frag, frag_end, 0)
    case 2:
      match cls:
        case 1:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.ack(got)
            httpx_seq(~H, 0, 4, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)
        case 4:
          do IO<Unit>:
            gotp : Socket & Got <- httpx.ack_ping(got, payload)
            httpx_seq(~H, 0, 4, 0, gotp, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)
        case 5:
          httpx.close_got(got)
        case 2:
          httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 0, Nil{}, Nil{}, 0, 0)
        case 7:
          httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)
        case 9:
          httpx.close_got(got)
        case 8:
          httpx_seq(~H, httpx.seq_cnext(Bool.not(List.is_empty(&2, U32, frag))), 4, U32.and(flags, x_f_end_headers()), got, buf, tab, typ, flags, sid2, payload, cls, end, ReqHead{"", "", Nil{}}, sid_a, body, frag, frag_end, 0)
        case 6:
          httpx_seq(~H, httpx.seq_tphase(typ, Bool.or(httpx.seq_open(U32.is_eq(sid_a, 0)), Bool.not(List.is_empty(&2, U32, frag)))), httpxn.decide_data(Bool.and(httpx.seq_open(U32.is_eq(sid_a, 0)), U32.is_eq(sid2, sid_a)), end), 0, got, buf, tab, typ, flags, sid2, payload, cls, end, rh, sid_a, body, frag, frag_end, httpxn.need_u(typ, flags))
        case 0:
          httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)
        case _:
          httpx.close_got(got)
    case 3:
      +dr : Result<&1, &1, U32 & String, ReqHead & Tab> = x_req.decode(payload, tab)
      httpx_seq(~H, 9, httpxn.head_act(need, x_req.ok(dr), end), endh, got, buf, x_req.tab(dr), typ, flags, sid2, payload, cls, end, x_req.rh(dr), sid_a, body, frag, frag_end, need)
    case 9:
      match act:
        case 0:
          httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid2, Nil{}, Nil{}, 0, 0)
        case 1:
          (s3, g3) = got
          do IO<Unit>:
            req : Request = httpx.req_of(rh, Nil{})
            resp : Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_resp(s3, sid2, resp)
            httpx_seq(~H, 0, 4, 0, httpx.sent(sent), buf, tab, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 0, Nil{}, Nil{}, 0, 0)
        case 6:
          httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, sid_a, body, x_cat(payload), end, 0)
        case 5:
          httpx.close_got(got)
        case _:
          httpx.close_got(got)
    case 4:
      match act:
        case 0:
          do IO<Unit>:
            got2 : Socket & Got <- httpx.wu_er(got, buf, sid2, payload)
            httpx_seq(~H, 0, 4, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, x_rev_push(payload, body), frag, frag_end, 0)
        case 1:
          (s4, g4) = got
          do IO<Unit>:
            got2 : Socket & Got <- httpx.wu_er(got, buf, sid2, payload)
            req : Request = httpx.req_of(rh, x_cat(x_rev_push(payload, body)))
            resp : Response <- H(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_resp(httpx.wo(got2), sid2, resp)
            httpx_seq(~H, 0, 4, 0, httpx.sent(sent), buf, tab, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 0, Nil{}, Nil{}, 0, 0)
        case 4:
          httpx.close_got(got)
        case _:
          httpx.close_got(got)
    case 5:
      match endh:
        case 0:
          httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, sid_a, body, x_rev_push(payload, frag), frag_end, 0)
        case 4:
          +full : List<&2, U32> = x_cat(x_rev_push(payload, frag))
          httpx_seq(~H, 3, 4, 0, got, buf, tab, 1, flags, sid2, full, cls, frag_end, ReqHead{"", "", Nil{}}, sid_a, body, Nil{}, 0, 0)
        case _:
          (s5, g5) = got
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s5, 0, 1)
            httpxn.cont_failed(sent)
    case 7:
      (s7, g7) = got
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(s7, sid2, 7)
        httpx_seq(~H, 0, 4, 0, httpx.sent(sent), buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)
    case 8:
      (s8, g8) = got
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s8, 0, 1)
        httpxn.cont_failed(sent)
    case _:
      httpx_seq(~H, 0, 4, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, rh, sid_a, body, frag, frag_end, 0)

# Preface entry for the sequential loop (owns the byte buffer, same as
# httpx_pre; enters httpx_seq instead of httpx).
# ---------------------------------------------------------------------

def seq_pre.recv(rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s1, r1) = rs
  TLS.tls_recv_bytes(s1, 16384)

@unsafe
def seq_pre(~H: Request -> IO(Response), phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          seq_pre(~H, 1, (s0, Done{chunk}), acc2, x_preface_ok(acc2), Bool.not(x_has_at_least(24, acc2)))
    case 1:
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- seq_pre.recv(rs)
            seq_pre(~H, 0, r2, acc, 0, False{})
        case False{}:
          seq_pre(~H, 2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s2, x_t_settings(), 0, 0, x_settings_initial_pay())
            httpx_seq(~H, 0, 4, 0, httpx.sent(sent), x_drop32(24, acc), x_tab.empty(), 0, 0, 0, Nil{}, 0, 0, ReqHead{"", "", Nil{}}, 0, Nil{}, Nil{}, 0, 0)
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def seq_start(~H: Request -> IO(Response), sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    seq_pre(~H, 0, r1, Nil{}, 0, False{})

# Accept plumbing (sequential, H2-only): every connection runs seq_start.
# ---------------------------------------------------------------------

def seq_spawn.go(~H: Request -> IO(Response), sock: Socket) -> IO(Unit):
  seq_start(~H, sock)

def seq_spawn(~H: Request -> IO(Response), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, seq_spawn.go(~H, sock))
    return l

def seq_conn(~H: Request -> IO(Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      seq_spawn(~H, sock, l)

@unsafe
def server.on(~H: Request -> IO(Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- seq_conn(~H, m)
    z : Unit <- server.on(~H, l2, cert, key)
    return z

# server.on already speaks H2 only; the explicit name is the mono-protocol
# entry the ALPN-dispatching server.on_alpn complements.
def server.on_h2(~H: Request -> IO(Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  server.on(~H, l, cert, key)

# One connection and stop: the same accept and the same per-connection
# lane as server.on, without the recursion. This is the entry a test or a
# single-shot server wants, and it is why no acceptor has to recurse.
def server.once(~H: Request -> IO(Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- seq_conn(~H, m)
    return Unit{}

# The fixed echo handler: status 200, no headers, the request body back
# (mirror of http.bend echo.body:2290). server.echo is the whole server
# built on it, for the H2-only and the ALPN entries.
def echo_body(req: Request) -> IO(Response):
  match req:
    case Request{method, path, headers, body}:
      IO.pure(Response, Response{200, Nil{}, body})

def server.echo(l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  server.on(echo_body, l, cert, key)


# H1 serve (Phase 11), keep-alive since TASK-027: the connection lane is
# one state machine (x_h1.srv.head) whose phase 3 decides reuse vs close,
# fed back by the answer path as a (socket, outcome) pair — Bend has no
# forward references, so the loop cannot be a mutual recursion. Closing is
# by "connection: close" (x_h1.conn_close), EOF, or a terminal 413/502.
# Handlers speak Request / Response natively, so server.on_alpn takes ONE
# handler for both lanes.
# ---------------------------------------------------------------------

def x_h1.srv.needs_body(+m: String) -> Bool:
  Bool.not(Bool.or(String.eq(m, "GET"), String.eq(m, "HEAD")))

def x_h1.srv.sock_of(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> Socket:
  (s, r) = got
  s

# Renderability gate for a handler response (TASK-030). x_h1.show_resp and
# x_h1.show_resp_head render the handler's headers through the same
# x_h1.render_hs.go the client uses, verbatim, so a CR/LF/NUL in a name or
# value would end the field early and ship the rest as response headers
# nobody asked for — response splitting, and the classic way to get one is
# a decoded query/path echoed into Location or Set-Cookie.
#
# The whole response is replaced by a bare 500 rather than dropping the
# offending field: rendering it at all IS the injection, and silently
# shipping a narrower response than the handler asked for hides the bug
# that produced it. A 101 with bad headers falls into the same 500, so the
# upgrade is refused instead of half-negotiated.
def x_h1.srv.safe_resp.go(+status: U32, +headers: List<&2, Hdr>, +body: List<&2, U32>, bad: Bool) ->
  Response:
  match bad:
    case True{}:
      Response{500, Nil{}, Nil{}}
    case False{}:
      Response{status, headers, body}

def x_h1.srv.safe_resp(resp: Response) -> Response:
  match resp:
    case Response{+status, +headers, +body}:
      x_h1.srv.safe_resp.go(status, headers, body, x_h1.bad_hdrs(headers))

# The answer path never closes the socket: it hands it back to the head
# machine in the very pair type the read phases use, so phase 3 is the
# single place that decides reuse vs close.
#   read_next(s, rest) -> Done{rest}: the answer is out, read the next
#     request, seeded with the bytes already read past this one.
#   stop(s, e)         -> Fail{e}: this connection ends here. e is the
#     send/read error, or (413/502, ...) for a terminal answer, or
#     (0, "close") for a peer that asked for close.
# Fail already means "stop" in phases 1 and 3, so no second outcome type
# is invented. The loop cannot be a mutual recursion (respond -> head ->
# parsed -> ... -> respond): Bend only sees defs already defined, so the
# head machine is the one def allowed to loop and the answer path ends by
# returning to it.
def x_h1.srv.read_next(s: Socket, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
    (s, Done{rest}))

def x_h1.srv.stop(s: Socket, e: U32 & String) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (code, msg) = e
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
    (s, Fail{(code, msg)}))

def x_h1.srv.sent_keep(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s2, r2) = sent
  match r2:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
        (s2, Fail{e}))
    case Done{u}:
      match keep:
        case True{}:
          x_h1.srv.read_next(s2, rest)
        case False{}:
          x_h1.srv.stop(s2, (0, "close"))

def x_h1.srv.respond(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +resp: Response, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match resp:
    case Response{+status, +headers, +body}:
      do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, x_h1.show_resp(status, headers, body))
        x_h1.srv.sent_keep(~recv, ~send, ~close, sent, keep, rest)

def x_h1.srv.answer(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +req: Request, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s, r) = got
  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
    resp : Response <- H(req)
    x_h1.srv.respond(~recv, ~send, ~close, s, x_h1.srv.safe_resp(resp), keep, rest)

def x_h1.srv.recv(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s0, r0) = got
  recv(s0, 16384)

@unsafe
def x_h1.srv.bd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +m: String, +p: String, +hs: List<&2, Hdr>, +have: List<&2, U32>, fuel: Nat, +cl: U32, enough: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match phase:
    case 0:
      match fuel:
        case 0n:
          x_h1.srv.stop(x_h1.srv.sock_of(got), (413, "request too long"))
        case 1n+f:
          match enough:
            case True{}:
              x_h1.srv.answer(~recv, ~send, ~close, ~H, got, Request{m, p, hs, x_take32(cl, have)}, Bool.not(x_h1.conn_close(hs)), x_drop32(cl, have))
            case False{}:
              do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.recv(~recv, ~send, ~close, got)
                x_h1.srv.bd(~recv, ~send, ~close, ~H, 1, r, m, p, hs, have, f, cl, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          x_h1.srv.stop(s1, e)
        case Done{+part}:
          match part:
            case Nil{}:
              x_h1.srv.stop(s1, (400, "eof"))
            case h <> t:
              +have2 = List.append(&2, U32, have, part)
              x_h1.srv.bd(~recv, ~send, ~close, ~H, 0, (s1, Done{Nil{}}), m, p, hs, have2, fuel, cl, x_has_at_least(cl, have2))
    case _:
      (s9, r9) = got
      x_h1.srv.stop(s9, (502, "bad phase"))

def x_h1.srv.cl(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), s: Socket, +m: String, +p: String, +hs: List<&2, Hdr>, +rest: List<&2, U32>, fuel: Nat, +cl: U32, big: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match big:
    case True{}:
      x_h1.srv.respond(~recv, ~send, ~close, s, Response{413, Nil{}, Nil{}}, False{}, Nil{})
    case False{}:
      x_h1.srv.bd(~recv, ~send, ~close, ~H, 0, (s, Done{Nil{}}), m, p, hs, rest, fuel, cl, x_has_at_least(cl, rest))

def x_h1.srv.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), s: Socket, +m: String, +p: String, +hs: List<&2, Hdr>, +rest: List<&2, U32>, fuel: Nat, needs: Bool, +cl: U32, chunked: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match needs:
    case False{}:
      x_h1.srv.answer(~recv, ~send, ~close, ~H, (s, Done{Nil{}}), Request{m, p, hs, Nil{}}, Bool.not(x_h1.conn_close(hs)), rest)
    case True{}:
      match chunked:
        case True{}:
          x_h1.srv.respond(~recv, ~send, ~close, s, Response{502, Nil{}, Nil{}}, False{}, Nil{})
        case False{}:
          x_h1.srv.cl(~recv, ~send, ~close, ~H, s, m, p, hs, rest, fuel, cl, U32.is_gt(cl, 16384))

def x_h1.srv.ruled(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), s1: Socket, +rest: List<&2, U32>, fuel: Nat, joinres: Result<&1, &1, U32 & String, ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match joinres:
    case Fail{e}:
      x_h1.srv.stop(s1, e)
    case Done{+rh}:
      match rh:
        case ReqHead{+m, +p, +hs}:
          x_h1.srv.go(~recv, ~send, ~close, ~H, s1, m, p, hs, rest, fuel, x_h1.srv.needs_body(m), x_h1.cl_of(hs), x_h1.is_chunked(hs))

def x_h1.srv.parsed(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  +hl = x_h1.head_lines(x_h1.split_head(x_h1.split(acc)))
  +rest = x_h1.split_rest(x_h1.split(acc))
  x_h1.srv.ruled(~recv, ~send, ~close, ~H, x_h1.srv.sock_of(got), rest, fuel, x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))))

@unsafe
def x_h1.srv.head(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          close(s0)
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.srv.head(~recv, ~send, ~close, ~H, 1, r, acc, f, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          close(s1)
        case Done{+part}:
          match part:
            case Nil{}:
              close(s1)
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              x_h1.srv.head(~recv, ~send, ~close, ~H, 2, (s1, Done{Nil{}}), acc2, fuel, x_h1.split_found(x_h1.split(acc2)))
    case 2:
      match found:
        case False{}:
          x_h1.srv.head(~recv, ~send, ~close, ~H, 0, got, acc, fuel, False{})
        case True{}:
          # The answer path hands the socket back: Done{rest} keeps the
          # connection (phase 3 re-seeds from the leftover), Fail{e}
          # stops it (phase 3 closes). acc restarts empty — the bytes
          # just answered are not part of the next request — and the
          # head fuel budget restarts per request, or a long-lived
          # connection would starve after 64 of them.
          do IO<Unit>:
            out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.parsed(~recv, ~send, ~close, ~H, got, acc, fuel)
            x_h1.srv.head(~recv, ~send, ~close, ~H, 3, out, Nil{}, 64n, False{})
    case 3:
      # Keep-alive re-entry: never reads here, only decides. An empty
      # seed (nothing was buffered past the request) goes back to the
      # socket; a non-empty one is the next request's first bytes, so it
      # enters the accumulate phase exactly like a fresh recv would —
      # pipelined requests lose nothing.
      (s3, r3) = got
      match r3:
        case Fail{e}:
          close(s3)
        case Done{+seed}:
          match seed:
            case Nil{}:
              x_h1.srv.head(~recv, ~send, ~close, ~H, 0, (s3, Done{Nil{}}), acc, fuel, False{})
            case h <> t:
              x_h1.srv.head(~recv, ~send, ~close, ~H, 1, (s3, Done{seed}), acc, fuel, False{})
    case _:
      (s9, r9) = got
      close(s9)

def x_h1.serve_start(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), sock: Socket) -> IO(Unit):
  x_h1.srv.head(~recv, ~send, ~close, ~H, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def h1_spawn.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), sock: Socket) -> IO(Unit):
  x_h1.serve_start(~recv, ~send, ~close, ~H, sock)

def h1_spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, h1_spawn.go(~recv, ~send, ~close, ~H, sock))
    return l

def h1_conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      h1_spawn(~recv, ~send, ~close, ~H, sock, l)

# H1 upgrade lane (101): the answer path that lends the socket out. Unlike
# x_h1.srv.answer (which hands the socket BACK to the head machine's phase
# 3 as read_next/stop), answer_open never returns the socket to the
# machine: on 101 it sends the head and calls ~K(sock, rest), and the
# socket stays with ~K until the WS loop closes it. Anything else answers
# through the normal respond and REJOINS the machine (rejoin = phase 3
# with the leftover seed), so a ~H that refuses the upgrade reuses or
# closes exactly like the keep-alive lane. The keep-alive machine itself
# is untouched — no signature churn on the hot path, no wire change.
# A 101 body is dropped (a 101 carries none); only status and headers
# ride show_resp_head.
# ---------------------------------------------------------------------

def x_h1.srv.sent_open(~close: Socket -> IO(Unit), ~K: Socket -> List<&2, U32> -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +rest: List<&2, U32>) -> IO(Unit):
  (s2, r2) = sent
  match r2:
    case Fail{e}:
      close(s2)
    case Done{u}:
      K(s2, rest)

def x_h1.srv.rejoin(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), out: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = out
  match r:
    case Fail{e}:
      close(s)
    case Done{+seed}:
      x_h1.srv.head(~recv, ~send, ~close, ~H, 3, (s, Done{seed}), Nil{}, 64n, False{})

def x_h1.srv.status_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, +status: U32, +headers: List<&2, Hdr>, +body: List<&2, U32>, keep: Bool, +rest: List<&2, U32>, is101: Bool) -> IO(Unit):
  match is101:
    case True{}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, x_h1.show_resp_head(status, headers))
        x_h1.srv.sent_open(~close, ~K, sent, rest)
    case False{}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, sock, Response{status, headers, body}, keep, rest)
        x_h1.srv.rejoin(~recv, ~send, ~close, ~H, out)

def x_h1.srv.reply_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, +resp: Response, keep: Bool, +rest: List<&2, U32>) -> IO(Unit):
  match resp:
    case Response{+status, +headers, +body}:
      x_h1.srv.status_open(~recv, ~send, ~close, ~H, ~K, sock, status, headers, body, keep, rest, U32.is_eq(status, 101))

def x_h1.srv.answer_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +req: Request, keep: Bool, +rest: List<&2, U32>) -> IO(Unit):
  (s, r) = got
  do IO<Unit>:
    resp : Response <- H(req)
    x_h1.srv.reply_open(~recv, ~send, ~close, ~H, ~K, s, x_h1.srv.safe_resp(resp), keep, rest)

@unsafe
def x_h1.srv.bd_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +m: String, +p: String, +hs: List<&2, Hdr>, +have: List<&2, U32>, fuel: Nat, +cl: U32, enough: Bool) -> IO(Unit):
  match phase:
    case 0:
      match fuel:
        case 0n:
          close(x_h1.srv.sock_of(got))
        case 1n+f:
          match enough:
            case True{}:
              x_h1.srv.answer_open(~recv, ~send, ~close, ~H, ~K, got, Request{m, p, hs, x_take32(cl, have)}, Bool.not(x_h1.conn_close(hs)), x_drop32(cl, have))
            case False{}:
              do IO<Unit>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.recv(~recv, ~send, ~close, got)
                x_h1.srv.bd_open(~recv, ~send, ~close, ~H, ~K, 1, r, m, p, hs, have, f, cl, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          close(s1)
        case Done{+part}:
          match part:
            case Nil{}:
              close(s1)
            case h <> t:
              +have2 = List.append(&2, U32, have, part)
              x_h1.srv.bd_open(~recv, ~send, ~close, ~H, ~K, 0, (s1, Done{Nil{}}), m, p, hs, have2, fuel, cl, x_has_at_least(cl, have2))
    case _:
      (s9, r9) = got
      close(s9)

def x_h1.srv.cl_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s: Socket, +m: String, +p: String, +hs: List<&2, Hdr>, +rest: List<&2, U32>, fuel: Nat, +cl: U32, big: Bool) -> IO(Unit):
  match big:
    case True{}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, s, Response{413, Nil{}, Nil{}}, False{}, Nil{})
        x_h1.srv.rejoin(~recv, ~send, ~close, ~H, out)
    case False{}:
      x_h1.srv.bd_open(~recv, ~send, ~close, ~H, ~K, 0, (s, Done{Nil{}}), m, p, hs, rest, fuel, cl, x_has_at_least(cl, rest))

def x_h1.srv.go_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s: Socket, +m: String, +p: String, +hs: List<&2, Hdr>, +rest: List<&2, U32>, fuel: Nat, needs: Bool, +cl: U32, chunked: Bool) -> IO(Unit):
  match needs:
    case False{}:
      x_h1.srv.answer_open(~recv, ~send, ~close, ~H, ~K, (s, Done{Nil{}}), Request{m, p, hs, Nil{}}, Bool.not(x_h1.conn_close(hs)), rest)
    case True{}:
      match chunked:
        case True{}:
          do IO<Unit>:
            out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, s, Response{502, Nil{}, Nil{}}, False{}, Nil{})
            x_h1.srv.rejoin(~recv, ~send, ~close, ~H, out)
        case False{}:
          x_h1.srv.cl_open(~recv, ~send, ~close, ~H, ~K, s, m, p, hs, rest, fuel, cl, U32.is_gt(cl, 16384))

def x_h1.srv.ruled_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s1: Socket, +rest: List<&2, U32>, fuel: Nat, joinres: Result<&1, &1, U32 & String, ReqHead>) -> IO(Unit):
  match joinres:
    case Fail{e}:
      close(s1)
    case Done{+rh}:
      match rh:
        case ReqHead{+m, +p, +hs}:
          x_h1.srv.go_open(~recv, ~send, ~close, ~H, ~K, s1, m, p, hs, rest, fuel, x_h1.srv.needs_body(m), x_h1.cl_of(hs), x_h1.is_chunked(hs))

def x_h1.srv.parsed_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat) -> IO(Unit):
  +hl = x_h1.head_lines(x_h1.split_head(x_h1.split(acc)))
  +rest = x_h1.split_rest(x_h1.split(acc))
  x_h1.srv.ruled_open(~recv, ~send, ~close, ~H, ~K, x_h1.srv.sock_of(got), rest, fuel, x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))))

@unsafe
def x_h1.srv.head_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          close(s0)
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 1, r, acc, f, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          close(s1)
        case Done{+part}:
          match part:
            case Nil{}:
              close(s1)
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 2, (s1, Done{Nil{}}), acc2, fuel, x_h1.split_found(x_h1.split(acc2)))
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 0, (s2, Done{Nil{}}), acc, fuel, False{})
        case True{}:
          x_h1.srv.parsed_open(~recv, ~send, ~close, ~H, ~K, (s2, Done{Nil{}}), acc, fuel)
    case _:
      (s9, r9) = got
      close(s9)

def h1_open_spawn.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket) -> IO(Unit):
  x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def h1_open_spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, h1_open_spawn.go(~recv, ~send, ~close, ~H, ~K, sock))
    return l

def h1_open_conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      h1_open_spawn(~recv, ~send, ~close, ~H, ~K, sock, l)

# Plaintext H1 server (http://): no cert/key, TCP.listen owns the listener,
# and the accept comes from Base's TCP.accept. One connection at a time,
# each serving N requests over keep-alive like server.on_h1.
@unsafe
def server.on_h1_plain(~H: Request -> IO(Response), listener: Listener) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(listener)
    next : Listener <- h1_conn(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~H, m)
    z : Unit <- server.on_h1_plain(~H, next)
    return z

def server.echo_h1_plain(listener: Listener) -> IO(Unit):
  server.on_h1_plain(echo_body, listener)

def httpxa_alpn_go(~H: Request -> IO(Response), is_h2: Bool, listener: Listener, sock: Socket) -> IO(Listener):
  match is_h2:
    case True{}:
      seq_spawn(~H, sock, listener)
    case False{}:
      h1_spawn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, sock, listener)

def httpxa_alpn_conn(~H: Request -> IO(Response), accepted: Listener & Result<&1, &1, U32 & String, Socket & String>) -> IO(Listener):
  (listener, result) = accepted
  match result:
    case Fail{e}:
      IO.pure(Listener, listener)
    case Done{value}:
      (sock, protocol) = value
      httpxa_alpn_go(~H, TLS.tls_alpn_is_h2(protocol), listener, sock)

@unsafe
def server.on_alpn(~H: Request -> IO(Response), listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      TLS.tls_accept_alpn(listener, cert, key)
    next : Listener <- httpxa_alpn_conn(~H, accepted)
    z : Unit <- server.on_alpn(~H, next, cert, key)
    return z

def server.echo_alpn(l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  server.on_alpn(echo_body, l, cert, key)

@unsafe
def server.on_h1(~H: Request -> IO(Response), listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_accept_http1(listener, cert, key)
    next : Listener <- h1_conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, accepted)
    z : Unit <- server.on_h1(~H, next, cert, key)
    return z

# The H1 pair of server.once: one accept (http/1.1 only) and the connection
# lane, without the recursion. With a single accept, a client batch can only
# close its golden if every request came over the same connection — which is
# what tests/io/httpx_h1_keepalive uses to prove the reuse.
def server.once_h1(~H: Request -> IO(Response), listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_accept_http1(listener, cert, key)
    next : Listener <- h1_conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, accepted)
    return Unit{}

# Upgrade servers: the accept loop lives here, the frame loop lives in ~K.
# ~H answers the handshake (101 lends the socket out); ~K owns it from
# there until the WS close. Anything else follows the keep-alive machine.
@unsafe
def server.on_h1_open(~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_accept_http1(listener, cert, key)
    next : Listener <- h1_open_conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, ~K, accepted)
    z : Unit <- server.on_h1_open(~H, ~K, next, cert, key)
    return z

@unsafe
def server.on_h1_open_plain(~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), listener: Listener) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(listener)
    next : Listener <- h1_open_conn(~TCPB.recv_bytes, ~TCPB.send_bytes, ~Socket.close, ~H, ~K, m)
    z : Unit <- server.on_h1_open_plain(~H, ~K, next)
    return z

# The upgrade pair of server.once_h1: one accept, no recursion. With a
# single accept, a 101 that came back to the keep-alive machine instead
# of ~K would hang or close — which is what tests/io/httpx_h1_upgrade
# uses to prove the socket left the machine.
def server.once_h1_open(~H: Request -> IO(Response), ~K: Socket -> List<&2, U32> -> IO(Unit), listener: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_accept_http1(listener, cert, key)
    next : Listener <- h1_open_conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, ~K, accepted)
    return Unit{}
