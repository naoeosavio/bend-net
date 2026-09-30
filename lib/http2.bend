# HTTP/2 (RFC 9113/7541) over the TLS lane: native codec in Bend, no
# nghttp2/node:http2. The frame layer and HPACK ride the byte lane like
# lib/ws.bend does; the only IO is TLS.tls_send_bytes / tls_recv_bytes.
#
# The codec below is the one from lib/httpx.bend, inlined (dono, 2026-09-29:
# copiar, nao importar) as the transitive slice this file uses -- 263 defs
# whose names are unchanged (m_*, mux*, muxn*, m_tab.*, ...), so the two
# copies can be diffed def by def. Nothing here imports ./httpx.bend.
#
# One type family, not two: the codec's records (frame, head, req head,
# request, response, header, dynamic table, got) are the SAME shapes the
# 22 consumers name, so the codec runs straight on H2Frame / H2Hdr /
# H2Request / H2Response / HpDyn / H2Got and the file has no converter
# layer at all. The single exception is the frame result: the public
# H2FrameOut counts the missing bytes in Nat (its signature is frozen) and
# the codec counts in U32, so H2FrameOut + h2_frame_read.go are the one
# mapping left (3 arms).
#
# On top of the codec sits the public HTTP/2 surface (h2_frame_read,
# h2_serve_once, ...) that the 22 files importing `http2.bend as H2` name:
# 17 type variants plus 53 entry points, with the signatures they have
# always had. What stays local here and why:
# - H2Settings + h2_settings_default/one/apply: the peer SETTINGS ledger.
#   The codec slice keeps only INITIAL_WINDOW_SIZE for its own flow math,
#   and the announce below is the 6 MB window this codec has always sent,
#   not the RFC default 65535.
# - h2_resp.classify family: the client-side class numbering is
#   per-consumer (1 SETTINGS, 2 HEADERS, 3 DATA, 4 PING, 5 GOAWAY, 6 WU
#   ok, 7 RST, 8 CONT, 9 WU bad) and the codec slice unified it with the
#   server's. h2_srv.classify reuses the slice's; the client side stays.
# - h2_srv.loop: the codec slice's server loops take a H2Request ->
#   IO(H2Response) handler and Bend has no closures (a function value is a
#   def name, and function types are nominal), so an H2Request handler
#   cannot be handed to them. This is the same sequential loop with H2
#   types in the state, answering through the caller's handler.
# - h2_srv.st_hp / rst_reset, h2_resp.st_hp: HPACK ledger projections
#   over the H2 state records.
# - h2_cont_ok / h2_cont_start: CONTINUATION pairing, no pair in the
#   slice.
#
# Fail codes: 400 eof, 413 too large, 502 protocol error, 503 bad
# preface; TLS/DNS codes (601-616) surface unchanged from lib/tls.bend.
#
# Discipline (same as lib/httpx.bend): callee above caller; match
# scrutinees are params or pattern-bound vars, never computed; + binds
# only for Data; self-recursion only.

import Base
import ./tls.bend as TLS

type H2Hdr is Data:
  H2Hdr{name: String, value: String}

type H2Head is Data:
  H2Head{status: U32, headers: List<&2, H2Hdr>}

type H2ReqHead is Data:
  H2ReqHead{method: String, path: String, headers: List<&2, H2Hdr>}

type H2RespSt is Data:
  H2RespSt{head: Maybe<&2, H2Head>, body: List<&2, U32>, hp: HpDyn}

type H2Response is Data:
  H2Response{status: U32, headers: List<&2, H2Hdr>, body: List<&2, U32>}

type H2Settings is Data:
  H2Settings{max_frame: U32, init_window: U32, max_headers: U32, max_streams: U32, table_size: U32}

type H2Request is Data:
  H2Request{method: String, path: String, headers: List<&2, H2Hdr>, body: List<&2, U32>}

# Dynamic table, newest entry at the head; size sums entry sizes
# (len(name) + len(value) + 32); max is the protocol limit 4096.
# Per-connection state threaded through the decode loop (never in slots).
type HpDyn is Data:
  HpDyn{ents: List<&2, H2Hdr>, size: U32, max: U32}

type H2SrvSt is Data:
  H2SrvSt{head: Maybe<&2, H2ReqHead>, body: List<&2, U32>, sid: U32, hp: HpDyn}

type H2Frame is Data:
  H2Frame{typ: U32, flags: U32, sid: U32, payload: List<&2, U32>}

# The public frame result keeps its Nat count (H2FrameOut is what the 22
# consumers name); the codec counts in U32, so this is the one pair the
# file does NOT collapse.
type H2FrameOut is Data:
  H2FrameOk{frame: H2Frame, rest: List<&2, U32>}
  H2NeedMore{missing: U32}
  H2FrameBad{code: U32, msg: String}

type HdrGot is Data:
  HdrGot{name: String, value: String, rest: List<&2, U32>, tab: HpDyn}

type H2Got is Data:
  H2GotOk{frame: H2Frame, buf: List<&2, U32>}
  H2GotErr{code: U32, msg: String}

# Finished CONTINUATION block plus the leftover read buffer.
type H2Cont is Data:
  H2Cont{block: List<&2, U32>, rest: List<&2, U32>}


# Bytes
# -----

def b_cat.go(+bs: List<&2, U32>, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      b_cat.go(t, h <> acc)

def b_cat(+bs: List<&2, U32>) -> List<&2, U32>:
  b_cat.go(bs, Nil{})

# NOTE (Phase 13 P7): b_take/b_drop Nat deleted — zero callers (take/
# drop cover all sites).
# U32-counted list ops for the flow sender (Phase 12 item 2): the Nat
# versions above force to_nat/from_nat conversions at every chunk step;
# these keep the whole send path in U32 (RFC windows are U32).
def b_take.go(+bs: List<&2, U32>, +n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      b_cat(acc)
    case h <> t:
      match n:
        case 0:
          b_cat(acc)
        case _:
          b_take.go(t, (n - 1 : U32), h <> acc)

def b_take32(+n: U32, bs: List<&2, U32>) -> List<&2, U32>:
  b_take.go(bs, n, Nil{})

# b_take/b_drop/b_len keep the Nat counts the 22 consumers call them with
# (H2.b_take(4n, ...)); the U32 core above is the one the codec uses.
def b_take(+n: Nat, bs: List<&2, U32>) -> List<&2, U32>:
  b_take32(U32.from_nat(n), bs)

def b_drop.go(+bs: List<&2, U32>, +n: U32) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case h <> t:
      match n:
        case 0:
          h <> t
        case _:
          b_drop.go(t, (n - 1 : U32))

def b_drop32(+n: U32, bs: List<&2, U32>) -> List<&2, U32>:
  b_drop.go(bs, n)

def b_drop(+n: Nat, bs: List<&2, U32>) -> List<&2, U32>:
  b_drop32(U32.from_nat(n), bs)

def b_len.go(+bs: List<&2, U32>, acc: Nat) -> Nat:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      b_len.go(t, 1n+acc)

def b_len(bs: List<&2, U32>) -> Nat:
  b_len.go(bs, 0n)

def b_append(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, a, b)

def m_rev_push(+frag: List<&2, U32>, +rev: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, b_cat(frag), rev)

def b_len32.go(+bs: List<&2, U32>, +acc: U32) -> U32:
  match bs:
    case Nil{}:
      acc
    case h <> t:
      b_len32.go(t, (acc + 1 : U32))

def b_len32(bs: List<&2, U32>) -> U32:
  b_len32.go(bs, 0)

# U32-counted String ops (Phase 13 P1): String.length returns Nat and
# String.drop/take Nat in Base; these walk with U32 so the lib never
# needs to_nat/from_nat at the call site. Structural form mirrors
# b_len32.go (match String first) and b_drop.go (U32 guard inside).
def str_len32.go(+s: String, +acc: U32) -> U32:
  match s:
    case SNil{}:
      acc
    case SCon{h, t}:
      str_len32.go(t, (acc + 1 : U32))

def str_len32(+s: String) -> U32:
  str_len32.go(s, 0)

def b_eq.mul(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def b_eq.go(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      b_eq.mul(b_eq.go(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

def b_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  b_eq.go(a, b)

def str_bytes.go(+s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{Chr{c}, t}:
      List.append(&2, U32, [c], str_bytes.go(t))

def str_bytes(+s: String) -> List<&2, U32>:
  str_bytes.go(s)

def bytes_str.go(+bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case +b <> t:
      SCon{Chr{b}, bytes_str.go(t)}

# Chunk size for stack-safe bytes->String (below).
def str_chunk() -> U32:
  8192

def str_chunks.go(+bs: List<&2, U32>, +n: U32, acc: List<&2, String>, +ch: List<&2, U32>) -> List<&2, String>:
  match bs:
    case Nil{}:
      bytes_str.go(b_cat(ch)) <> acc
    case h <> t:
      match n:
        case 0:
          str_chunks.go(t, (str_chunk() - 1 : U32), bytes_str.go(b_cat(ch)) <> acc, [h])
        case _:
          str_chunks.go(t, (n - 1 : U32), acc, h <> ch)

def str_chunks(+bs: List<&2, U32>) -> List<&2, String>:
  str_chunks.go(bs, str_chunk(), Nil{}, Nil{})

def bytes_str(bs: List<&2, U32>) -> String:
  String.concat(List.reverse(&2, String, str_chunks(bs)))

def h2_t_data() -> U32:
  0

def h2_t_headers() -> U32:
  1

def h2_t_rst_stream() -> U32:
  3

def h2_t_settings() -> U32:
  4

def h2_t_ping() -> U32:
  6

def h2_t_goaway() -> U32:
  7

def h2_t_window_update() -> U32:
  8

def h2_t_continuation() -> U32:
  9

def h2_f_ack() -> U32:
  1

def h2_f_end_stream() -> U32:
  1

def h2_f_end_headers() -> U32:
  4

def h2_max_send() -> U32:
  16384

# RFC 9113 section 6.9.2 default: both connection and per-stream send
# windows start here; the peer SETTINGS INITIAL_WINDOW_SIZE picked up
# mid-send only ever raises the stream window from this base.
def h2_init_window() -> U32:
  6291456

def h2_max_hpack() -> U32:
  65535

def m_max_frame() -> U32:
  65535

def h2_be16.go(+v: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(v, 8n), 255), U32.and(v, 255)]

def h2_be16(+v: U32) -> List<&2, U32>:
  h2_be16.go(v)

def h2_be32.go(+v: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(v, 24n), 255), U32.and(U32.shrn(v, 16n), 255), U32.and(U32.shrn(v, 8n), 255), U32.and(v, 255)]

def h2_be32(+v: U32) -> List<&2, U32>:
  h2_be32.go(v)

def h2_settings_initial_pay() -> List<&2, U32>:
  b_append(b_append(h2_be16(4), h2_be32(h2_init_window())), b_append(h2_be16(5), h2_be32(65535)))

def h2_strip_pad.go(+pay: List<&2, U32>, +n: U32, +m: U32) -> List<&2, U32>:
  b_take32(n, b_drop32(m, pay))

def h2_strip_pad_ok(+dist: U32, +len: U32) -> Bool:
  U32.is_gt(len, dist)

def h2_strip_pad.last(+pay: List<&2, U32>, +len: U32, +p0: U32, ok: Bool) -> List<&2, U32>:
  match ok:
    case True{}:
      # RFC 9113 section 6.1: the pad-length byte is the FIRST byte (h2_strip_pad.first
      # already dropped it into `pay`) and the padding octets are the LAST p0 bytes,
      # so the length drops by p0 + 1 and nothing else comes off the front. (mux_frame_read
      # only measured the length of a p0 = 1 frame, where dropping p0 more bytes
      # gave the same count with the wrong content; h2_flow's p0 = 2 vector is what
      # caught it.)
      h2_strip_pad.go(pay, (len - (p0 + 1 : U32) : U32), 0)
    case False{}:
      Nil{}

def h2_strip_pad.first(pay: List<&2, U32>, +len: U32) -> List<&2, U32>:
  match pay:
    case Nil{}:
      Nil{}
    case +p0 <> pret:
      h2_strip_pad.last(pret, len, p0, h2_strip_pad_ok(p0, len))

def h2_strip_pad.dec(+pay: List<&2, U32>, +len: U32, has_pad: Bool) -> List<&2, U32>:
  match has_pad:
    case False{}:
      pay
    case True{}:
      h2_strip_pad.first(pay, len)

def h2_strip_pad(+pay: List<&2, U32>, has_pad: Bool, +len: U32) -> List<&2, U32>:
  h2_strip_pad.dec(pay, len, has_pad)

def h2_strip_prio(+pay: List<&2, U32>, has_prio: Bool) -> List<&2, U32>:
  match has_prio:
    case False{}:
      pay
    case True{}:
      b_drop32(5, pay)

# PADDED/PRIORITY strip before HPACK decode (RFC 9113 6.1/6.2). The len
# is the frame length the pad bound is checked against; the public entry
# below derives it from the payload it was handed (same bytes).
def h2_frame_payload.go(+pay: List<&2, U32>, +typ: U32, +flags: U32, +len: U32) -> List<&2, U32>:
  h2_strip_prio(h2_strip_pad(pay, U32.is_eq(U32.and(flags, 8), 8), len), U32.is_eq(U32.and(flags, 32), 32))

def h2_frame_payload(+pay: List<&2, U32>, +flags: U32, +typ: U32) -> List<&2, U32>:
  h2_frame_payload.go(pay, typ, flags, b_len32(pay))

def u32_of4(b3: U32, b2: U32, b1: U32, b0: U32) -> U32:
  (b3 * 16777216 + b2 * 65536 + b1 * 256 + b0 : U32)


def h2_frame.fin3(+typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>, +len: U32) ->
  H2FrameOut:
  H2FrameOk{H2Frame{typ, flags, sid, h2_frame_payload.go(b_take32(len, rest), typ, flags, len)}, b_drop32(len, rest)}

# Pad/prio strip (RFC 9113 6.1/6.2): PADDED rides flag 8 with a pad
# length prefix (must be < payload, else protocol error), PRIORITY
# rides flag 32 with a 5-byte fixed field. Frames without the flags come
# through untouched (passthrough gate in h2_strip_pad.dec).
def h2_frame.fin2(typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32, ok: Bool) ->
  H2FrameOut:
  match ok:
    case True{}:
      h2_frame.fin3(typ, flags, sid, rest, len)
    case False{}:
      H2NeedMore{(len - b_len32(b_take32(len, rest)) : U32)}

def h2_frame.fin(typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32) ->
  H2FrameOut:
  h2_frame.fin2(typ, flags, sid, rest, len, U32.is_eq(len, b_len32(b_take32(len, rest))))

def h2_frame.len_ok(+len24: U32, +typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>, ok_len: Bool) ->
  H2FrameOut:
  match ok_len:
    case False{}:
      H2FrameBad{413, "frame too large"}
    case True{}:
      h2_frame.fin(typ, flags, sid, rest, len24)

def h2_frame.mid6(+len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +s2: U32, +rest8: List<&2, U32>) -> H2FrameOut:
  match rest8:
    case +s3 <> rest:
      +sid   = u32_of4(s0, s1, s2, U32.and(s3, 127))
      +len24 = (len_hi * 65536 + b1 * 256 + b2 : U32)
    h2_frame.len_ok(len24, typ, flags, sid, rest, U32.is_le(len24, m_max_frame()))
    case Nil{}:
      H2NeedMore{1}

def h2_frame.mid5(+len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +rest7: List<&2, U32>) -> H2FrameOut:
  match rest7:
    case +s2 <> rest8:
      h2_frame.mid6(len_hi, b1, b2, typ, flags, s0, s1, s2, rest8)
    case Nil{}:
      H2NeedMore{2}

def h2_frame.mid4(+len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +rest6: List<&2, U32>) -> H2FrameOut:
  match rest6:
    case +s1 <> rest7:
      h2_frame.mid5(len_hi, b1, b2, typ, flags, s0, s1, rest7)
    case Nil{}:
      H2NeedMore{3}

def h2_frame.mid3(+len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +rest5: List<&2, U32>) -> H2FrameOut:
  match rest5:
    case +s0 <> rest6:
      h2_frame.mid4(len_hi, b1, b2, typ, flags, s0, rest6)
    case Nil{}:
      H2NeedMore{4}

def h2_frame.mid2(+len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +rest4: List<&2, U32>) -> H2FrameOut:
  match rest4:
    case +flags <> rest5:
      h2_frame.mid3(len_hi, b1, b2, typ, flags, rest5)
    case Nil{}:
      H2NeedMore{5}

def h2_frame.mid(+len_hi: U32, +b1: U32, +b2: U32, +rest: List<&2, U32>) -> H2FrameOut:
  match rest:
    case +typ <> rest4:
      h2_frame.mid2(len_hi, b1, b2, typ, rest4)
    case Nil{}:
      H2NeedMore{6}

def h2_frame.hi4(+len_hi: U32, +b1: U32, +rest2: List<&2, U32>) -> H2FrameOut:
  match rest2:
    case +b2 <> rest3:
      h2_frame.mid(len_hi, b1, b2, rest3)
    case Nil{}:
      H2NeedMore{7}

def h2_frame.hi3(+len_hi: U32, +rest: List<&2, U32>) -> H2FrameOut:
  match rest:
    case +b1 <> rest2:
      h2_frame.hi4(len_hi, b1, rest2)
    case Nil{}:
      H2NeedMore{8}

def h2_frame.hi2b(+rest: List<&2, U32>) -> H2FrameOut:
  match rest:
    case +len_hi <> rest2:
      h2_frame.hi3(len_hi, rest2)
    case Nil{}:
      H2NeedMore{9}

def h2_frame.hi2(+bs: List<&2, U32>, +have: U32, short: Bool) -> H2FrameOut:
  match short:
    case True{}:
      H2NeedMore{(9 - have : U32)}
    case False{}:
      h2_frame.hi2b(bs)

def h2_frame_read.go(+bs: List<&2, U32>) -> H2FrameOut:
  h2_frame.hi2(bs, b_len32(bs), U32.is_lt(b_len32(bs), 9))

def h2_frame_read(bs: List<&2, U32>) -> H2FrameOut:
  h2_frame_read.go(bs)

def h2_frame_write.cat(h: List<&2, U32>, t: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, h, t)

def h2_frame_write.hdr(+len: U32, +typ: U32, +flags: U32, +sid: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(len, 16n), 255), U32.and(U32.shrn(len, 8n), 255), U32.and(len, 255),
   U32.and(typ, 255), U32.and(flags, 255),
   U32.and(U32.shrn(sid, 24n), 255), U32.and(U32.shrn(sid, 16n), 255),
   U32.and(U32.shrn(sid, 8n), 255), U32.and(sid, 255)]

def h2_frame_write(+typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> List<&2, U32>:
  +len = b_len32(pay)
  h2_frame_write.cat(h2_frame_write.hdr(len, typ, flags, sid), pay)

# Preface plus the H2 SETTINGS announce (6 MB window, not the codec 65535).
def h2_settings_initial() -> List<&2, U32>:
  h2_frame_write(h2_t_settings(), 0, 0, h2_settings_initial_pay())

# Peer SETTINGS ledger (RFC 9113 section 6.5): unknown ids are
# ignored; 0 means unlimited for max_headers / max_streams.
def h2_settings_default() -> H2Settings:
  H2Settings{16384, 65535, 0, 0, 4096}

def h2_settings_one.done(+mf: U32, +iw: U32, +mhl: U32, +mcc: U32, +hts: U32, +id: U32, +val: U32) -> H2Settings:
  match id:
    case 1:
      H2Settings{mf, iw, mhl, mcc, val}
    case 3:
      H2Settings{mf, iw, mhl, val, hts}
    case 4:
      H2Settings{mf, val, mhl, mcc, hts}
    case 5:
      H2Settings{val, iw, mhl, mcc, hts}
    case 6:
      H2Settings{mf, iw, val, mcc, hts}
    case _:
      H2Settings{mf, iw, mhl, mcc, hts}

def h2_settings_one.go(+st: H2Settings, +id: U32, +val: U32) -> H2Settings:
  match st:
    case H2Settings{+mf, +iw, +mhl, +mcc, +hts}:
      h2_settings_one.done(mf, iw, mhl, mcc, hts, id, val)

def h2_settings_one(+st: H2Settings, +id: U32, +val: U32) -> H2Settings:
  h2_settings_one.go(st, id, val)

# Phase 10.3: defueled. The fuel was b_len(pay) read left to right, but every
# arm already passes `rest` (6 bytes shorter than `pay`), so the structural
# recursion is the termination proof and the Nat counter is gone. Same walk,
# one pass, no b_len pre-traversal.
def h2_settings_apply_go(+pay: List<&2, U32>, +st: H2Settings) -> H2Settings:
  match pay:
    case Nil{}:
      st
    case +b0 <> r0:
      match r0:
        case Nil{}:
          st
        case +b1 <> r1:
          match r1:
            case Nil{}:
              st
            case +b2 <> r2:
              match r2:
                case Nil{}:
                  st
                case +b3 <> r3:
                  match r3:
                    case Nil{}:
                      st
                    case +b4 <> r4:
                      match r4:
                        case Nil{}:
                          st
                        case +b5 <> rest:
                          h2_settings_apply_go(rest, h2_settings_one(st, (b0 * 256 + b1 : U32), u32_of4(b2, b3, b4, b5)))

def h2_settings_apply(+pay: List<&2, U32>, +st: H2Settings) -> H2Settings:
  h2_settings_apply_go(pay, st)

# HPACK ints (prefix + continuation, RFC 7541 section 5.1)
# --------------------------------------------------------
def h2_window_update_val(+v: U32) -> Bool:
  Bool.and(U32.is_gt(v, 0), U32.is_lt(v, 2147483648))

def h2_window_update_ok.go(+b0: U32, +b1: U32, +b2: U32, +b3: U32) -> Bool:
  h2_window_update_val((((b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 : U32))))

# RFC 9113 section 6.9: the increment field is exactly 4 bytes, so a
# WINDOW_UPDATE with any other length is a connection error. The old
# h2_window_update_ok stopped after 4 bytes and ignored the tail, which let a 5+ byte
# frame through as a valid credit (found porting h2_rst.bend to mux_rst).
def h2_window_update_ok.empty(+rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

def h2_window_update_ok.go4(+b0: U32, +b1: U32, +b2: U32, +b3: U32, +rest: List<&2, U32>) -> Bool:
  Bool.and(h2_window_update_ok.go(b0, b1, b2, b3), h2_window_update_ok.empty(rest))

def h2_window_update_ok.r3(+b0: U32, +b1: U32, +b2: U32, +rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      False{}
    case +b3 <> r3:
      h2_window_update_ok.go4(b0, b1, b2, b3, r3)

def h2_window_update_ok.r2(+b0: U32, +b1: U32, +rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      False{}
    case +b2 <> r2:
      h2_window_update_ok.r3(b0, b1, b2, r2)

def h2_window_update_ok.r1(+b0: U32, +rest: List<&2, U32>) -> Bool:
  match rest:
    case Nil{}:
      False{}
    case +b1 <> r1:
      h2_window_update_ok.r2(b0, b1, r1)

def h2_window_update_ok(+pay: List<&2, U32>) -> Bool:
  match pay:
    case Nil{}:
      False{}
    case +b0 <> r0:
      h2_window_update_ok.r1(b0, r0)

def hpack_int.enc.go(+fuel: Nat, +rest: U32, acc: List<&2, U32>, big: Bool) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      match big:
        case True{}:
          +b = U32.add(U32.and(rest, 127), 128)
          +next = U32.shrn(rest, 7n)
          hpack_int.enc.go(f, next, b_append(acc, [b]), U32.is_ge(next, 128))
        case False{}:
          +b = U32.and(rest, 127)
          b_append(acc, [b])

def hpack_int.enc.small(+first: U32, +rest: U32, small: Bool) -> List<&2, U32>:
  match small:
    case True{}:
      [U32.or(first, rest)]
    case False{}:
      acc = hpack_int.enc.go(6n, (rest - 127 : U32), Nil{}, U32.is_ge((rest - 127 : U32), 128))
      b_append([U32.or(first, 127)], acc)

def hpack_int.enc(+first: U32, +rest: U32) -> List<&2, U32>:
  hpack_int.enc.small(first, rest, U32.is_lt(rest, 127))

def hpack_int.dec.go2c(+rest: List<&2, U32>, cont: Bool, acc: U32, +m: U32, wrapped: Bool) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
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
              hpack_int.dec.go2c(rest2, U32.is_eq(U32.and(b, 128), 128), acc2, nm, U32.is_eq(nm, 0))

def hpack_int.dec.go2(+rest: List<&2, U32>, acc: U32, +m: U32) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  hpack_int.dec.go2c(rest, True{}, acc, m, False{})

def hpack_int.dec.go4(+first: U32, +mask: U32, +rest: List<&2, U32>, short: Bool) ->
  Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match short:
    case True{}:
      Done{(U32.and(first, mask), rest)}
    case False{}:
      hpack_int.dec.go2(rest, mask, 1)

def hpack_int.dec.go(+first: U32, +mask: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  hpack_int.dec.go4(first, mask, rest, U32.is_lt(U32.and(first, mask), mask))

# Huffman strings (RFC 7541 Appendix B, canonical code)
# -----------------------------------------------------

def huff_counts() -> List<&2, U32>:
  [10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0,
   0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4]

def huff_firsts() -> List<&2, U32>:
  [0, 20, 92, 248,
   0, 1016, 2042, 4090,
   8184, 16380, 32764, 0,
   0, 0, 524272, 1048550,
   2097116, 4194258, 8388568, 16777194,
   33554412, 67108832, 134217694, 268435426,
   0, 1073741820]

def huff_starts() -> List<&2, U32>:
  [0, 10, 36, 68, 74, 74, 79, 82, 84, 90, 92, 95, 95,
   95, 95, 98, 106, 119, 145, 174, 186, 190, 205, 224, 253, 253]

def huff_order() -> List<&2, U32>:
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

def huff_nth.go(+xs: List<&2, U32>, +n: U32) -> U32:
  match xs:
    case Nil{}:
      0
    case h <> t:
      match n:
        case 0:
          h
        case _:
          huff_nth.go(t, (n - 1 : U32))

def huff_nth(+xs: List<&2, U32>, +n: U32) -> U32:
  huff_nth.go(xs, n)

def huff_bits.go(+b: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(b, 7n), 1), U32.and(U32.shrn(b, 6n), 1),
   U32.and(U32.shrn(b, 5n), 1), U32.and(U32.shrn(b, 4n), 1),
   U32.and(U32.shrn(b, 3n), 1), U32.and(U32.shrn(b, 2n), 1),
   U32.and(U32.shrn(b, 1n), 1), U32.and(b, 1)]

def huff_bits(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case h <> t:
      List.append(&2, U32, huff_bits.go(h), huff_bits(t))

def huff_hit(+code: U32, +len: U32) -> Bool:
  +i = (len - 5 : U32)
  +cnt = huff_nth(huff_counts(), i)
  +fst = huff_nth(huff_firsts(), i)
  Bool.and(U32.is_ge(code, fst), U32.is_lt((code - fst : U32), cnt))

def huff_at(+code: U32, +len: U32) -> U32:
  +i = (len - 5 : U32)
  +fst = huff_nth(huff_firsts(), i)
  huff_nth(huff_order(), (huff_nth(huff_starts(), i) + (code - fst : U32) : U32))

def huff_ones(+bits: List<&2, U32>) -> Bool:
  match bits:
    case Nil{}:
      True{}
    case b <> t:
      Bool.and(U32.is_eq(b, 1), huff_ones(t))

def huff_pad(+bits: List<&2, U32>) -> Bool:
  Bool.and(U32.is_lt(b_len32(bits), 8), huff_ones(bits))

def huff_empty(+bits: List<&2, U32>) -> Bool:
  match bits:
    case Nil{}:
      True{}
    case _ <> _:
      False{}

def huff_emit.big(big: Bool) -> U32:
  match big:
    case True{}:
      31
    case False{}:
      0

def huff_emit.go(eos: Bool, big: Bool) -> U32:
  match eos:
    case True{}:
      30
    case False{}:
      huff_emit.big(big)

def huff_emit_phase(+sym: U32, +n: U32) -> U32:
  huff_emit.go(U32.is_eq(sym, 256), U32.is_gt(n, h2_max_hpack()))

def huff_entry.pad(pad: Bool) -> U32:
  match pad:
    case True{}:
      2
    case False{}:
      10

def huff_entry.empty(+bits: List<&2, U32>, empty: Bool, pad: Bool) -> U32:
  match empty:
    case True{}:
      1
    case False{}:
      huff_entry.pad(pad)

def huff_entry(+bits: List<&2, U32>) -> U32:
  huff_entry.empty(bits, huff_empty(bits), huff_pad(bits))

# Main huffman loop: one self-recursive phased def (fuel, phase,
# bits, acc, n, code, len). Phase 0 dispatches (empty/pad/prime),
# 1/2 finish, 10-14 prime five bits, 20 over-long, 21 emit, 22
# consume one more bit, 30 EOS, 31 oversize. Fuel bounds total calls
# (each symbol costs prime 5 + consume 25 at most + emit/dispatch).

def huff_sym_phase.go(hit: Bool) -> U32:
  match hit:
    case True{}:
      21
    case False{}:
      22

def huff_sym_phase.hit(+code: U32, +len: U32, hit: Bool, over: Bool) -> U32:
  match over:
    case True{}:
      20
    case False{}:
      huff_sym_phase.go(hit)

def huff_sym_phase(+code: U32, +len: U32) -> U32:
  huff_sym_phase.hit(code, len, huff_hit(code, len), U32.is_gt(len, 30))

def huff_dec.go(+fuel: Nat, +phase: U32, +bits: List<&2, U32>, +acc: List<&2, U32>, +n: U32, +code: U32, +len: U32) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  match fuel:
    case 0n:
      Fail{(502, "huffman fuel")}
    case 1n+f:
      match phase:
        case 0:
          huff_dec.go(f, huff_entry(bits), bits, acc, n, code, len)
        case 1:
          Done{b_cat(acc)}
        case 2:
          Done{b_cat(acc)}
        case 10:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              huff_dec.go(f, 11, t, acc, n, b, len)
        case 11:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              huff_dec.go(f, 12, t, acc, n, ((code * 2 : U32) + b : U32), len)
        case 12:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              huff_dec.go(f, 13, t, acc, n, ((code * 2 : U32) + b : U32), len)
        case 13:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              huff_dec.go(f, 14, t, acc, n, ((code * 2 : U32) + b : U32), len)
        case 14:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              +cc = ((code * 2 : U32) + b : U32)
              huff_dec.go(f, huff_sym_phase(cc, 5), t, acc, n, cc, 5)
        case 20:
          Fail{(502, "huffman code")}
        case 21:
          +sym = huff_at(code, len)
          +nn = (n + 1 : U32)
          huff_dec.go(f, huff_emit_phase(sym, nn), bits, sym <> acc, nn, code, len)
        case 22:
          match bits:
            case Nil{}:
              Fail{(502, "huffman truncated")}
            case b <> t:
              +ln = (len + 1 : U32)
              +cc = ((code * 2 : U32) + b : U32)
              huff_dec.go(f, huff_sym_phase(cc, ln), t, acc, n, cc, ln)
        case 30:
          Fail{(502, "huffman eos")}
        case 31:
          Fail{(413, "huffman too large")}
        case _:
          Fail{(502, "huffman phase")}

def huff_decode.fuel(+bl: Nat) -> Nat:
  Nat.add(bl, Nat.add(bl, Nat.add(bl, 1n)))

def huff_decode(+bs: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  +bits = huff_bits(bs)
  huff_dec.go(huff_decode.fuel(b_len(bits)), 0, bits, Nil{}, 0, 0, 0)

# HPACK strings (raw or Huffman; cap 65535)
# -----------------------------------------

def hpack_str.dec.huffin(+bs: List<&2, U32>, +rest: List<&2, U32>, whole: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match whole:
    case True{}:
      Done{(bytes_str(bs), rest)}
    case False{}:
      Fail{(400, "hpack eof str")}

def hpack_str.dec.huffed(+n: U32, +rest: List<&2, U32>, r: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{bs}:
      hpack_str.dec.huffin(bs, b_drop32(n, rest), U32.is_eq(n, b_len32(b_take32(n, rest))))

def hpack_str.dec.huf2(+n: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  hpack_str.dec.huffed(n, rest, huff_decode(b_take32(n, rest)))

def hpack_str.dec.hufcap(+n: U32, +rest: List<&2, U32>, capped: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match capped:
    case False{}:
      Fail{(413, "hpack str too large")}
    case True{}:
      hpack_str.dec.huf2(n, rest)

def hpack_str.dec.hufin(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+n, +rest)}:
      hpack_str.dec.hufcap(n, rest, U32.is_le(n, h2_max_hpack()))

def hpack_str.enc(+s: String) -> List<&2, U32>:
  b_append(hpack_int.enc(0, str_len32(s)), str_bytes(s))

def hpack_str.dec.whole(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>, whole: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match whole:
    case True{}:
      Done{(bytes_str(taken), b_drop32(n, rest))}
    case False{}:
      Fail{(400, "hpack eof str")}

def hpack_str.dec.fin(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  hpack_str.dec.whole(n, rest, taken, U32.is_eq(n, b_len32(taken)))

def hpack_str.dec.len(+n: U32, +rest: List<&2, U32>, capped: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match capped:
    case False{}:
      Fail{(413, "hpack str too large")}
    case True{}:
      hpack_str.dec.fin(n, rest, b_take32(n, rest))

def hpack_str.dec.str(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+n, +rest)}:
      hpack_str.dec.len(n, rest, U32.is_le(n, h2_max_hpack()))

def hpack_str.dec.huf(+b0: U32, +rest2: List<&2, U32>, huf: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match huf:
    case True{}:
      hpack_str.dec.hufin(hpack_int.dec.go(b0, 127, rest2))
    case False{}:
      hpack_str.dec.str(hpack_int.dec.go(b0, 127, rest2))

def hpack_str.dec.go(+rest: List<&2, U32>) -> Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match rest:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest2:
      hpack_str.dec.huf(b0, rest2, U32.is_eq(U32.and(b0, 128), 128))

# Static table 1-61 (RFC 7541 Appendix A)
# ------------------------------------------------

def hp_static.go(+idx: U32) -> String & String:
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

# Dynamic table (RFC 7541 section 2.3.2, section 4)
# ------------------------------------------------
# Newest entry at the head; size is the sum of entry sizes
# (len(name) + len(value) + 32); max is the protocol limit 4096.
# The decoder owns one table per connection, threaded through the
# header-block loops (Phase 3 wires it; here are the pure ops).

def hp_empty() -> HpDyn:
  HpDyn{Nil{}, 0, 4096}

def hp_entry_size(+name: String, +value: String) -> U32:
  (str_len32(name) + str_len32(value) + 32 : U32)

# Structural eviction (no fuel: recurses on the tail, like hp_rev.go;
# the Nil arm returns (Nil,0) — trim only calls with empty ents at size 0).
def hp_fit.go(+ents: List<&2, H2Hdr>, fit: Bool, +size: U32, +max: U32) ->
  List<&2, H2Hdr> & U32:
  match ents:
    case Nil{}:
      (Nil{}, 0)
    case H2Hdr{n, v} <> t:
      match fit:
        case True{}:
          (H2Hdr{n, v} <> t, size)
        case False{}:
          +ns = U32.sub(size, hp_entry_size(n, v))
          hp_fit.go(t, U32.is_le(ns, max), ns, max)

def hp_rev.go(+ents: List<&2, H2Hdr>, acc: List<&2, H2Hdr>) -> List<&2, H2Hdr>:
  match ents:
    case Nil{}:
      acc
    case h <> t:
      hp_rev.go(t, h <> acc)

def hp_rev(+ents: List<&2, H2Hdr>) -> List<&2, H2Hdr>:
  hp_rev.go(ents, Nil{})

def hp_done(p: List<&2, H2Hdr> & U32, +max: U32) -> HpDyn:
  (kept, sz) = p
  HpDyn{hp_rev(kept), sz, max}

def hp_insert.trim(+ents: List<&2, H2Hdr>, +size: U32, +max: U32) -> HpDyn:
  hp_done(hp_fit.go(hp_rev(ents), U32.is_le(size, max), size, max), max)

def hp_insert.do(+ents: List<&2, H2Hdr>, +size: U32, +max: U32, +name: String, +value: String, +es: U32) -> HpDyn:
  +ns = (size + es : U32)
  hp_insert.trim(H2Hdr{name, value} <> ents, ns, max)

def hp_insert.fit.go(+ents: List<&2, H2Hdr>, +size: U32, +max: U32, +name: String, +value: String, fits: Bool, +es: U32) -> HpDyn:
  match fits:
    case False{}:
      HpDyn{Nil{}, 0, max}
    case True{}:
      hp_insert.do(ents, size, max, name, value, es)

# The public fit takes 6 args and sizes the entry itself (hpack_dyntab.bend
# names it); the 7-arg form above is what the codec's insert path uses.
def hp_insert.fit(+ents: List<&2, H2Hdr>, +size: U32, +max: U32, +name: String, +value: String, fits: Bool) -> HpDyn:
  hp_insert.fit.go(ents, size, max, name, value, fits, hp_entry_size(name, value))

def hp_insert.go(+tab: HpDyn, +name: String, +value: String) -> HpDyn:
  match tab:
    case HpDyn{+ents, +size, +max}:
      +es = hp_entry_size(name, value)
      hp_insert.fit.go(ents, size, max, name, value, U32.is_le(es, max), es)

def hp_insert(+tab: HpDyn, +name: String, +value: String) -> HpDyn:
  hp_insert.go(tab, name, value)

def hp_resize.go(+tab: HpDyn, +max: U32) -> HpDyn:
  match tab:
    case HpDyn{+ents, +size, +old}:
      hp_insert.trim(ents, size, max)

def hp_resize(+tab: HpDyn, +max: U32) -> HpDyn:
  hp_resize.go(tab, max)

# got: bounds-check + fetch in one walk (was lookup.go len-full + at-partial).
def hp_lookup.got(+ents: List<&2, H2Hdr>, +k: U32) -> Result<&1, &1, U32 & String, H2Hdr>:
  match ents:
    case Nil{}:
      Fail{(502, "hpack dyn bounds")}
    case H2Hdr{n, v} <> t:
      match k:
        case 0:
          Done{H2Hdr{n, v}}
        case _:
          hp_lookup.got(t, (k - 1 : U32))

def hp_lookup(+tab: HpDyn, +idx: U32) -> Result<&1, &1, U32 & String, H2Hdr>:
  match tab:
    case HpDyn{+ents, +size, +max}:
      hp_lookup.got(ents, idx)

def hp_addr.static(sp: String & String) -> H2Hdr:
  (n, v) = sp
  H2Hdr{n, v}

def hp_addr.go(+tab: HpDyn, +idx: U32, is_static: Bool) ->
  Result<&1, &1, U32 & String, H2Hdr>:
  match is_static:
    case True{}:
      Done{hp_addr.static(hp_static.go(idx))}
    case False{}:
      hp_lookup(tab, (idx - 62 : U32))

def hp_addr(+tab: HpDyn, +idx: U32) -> Result<&1, &1, U32 & String, H2Hdr>:
  hp_addr.go(tab, idx, U32.is_le(idx, 61))


# One header field (incremental entries update the table)
# -------------------------------------------------------

def hpack_hdr.full(+idx: U32, +rest: List<&2, U32>, +tab: HpDyn) ->
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


def hpack_hdr.lit.put(+name: String, +value: String, +rest: List<&2, U32>, +tab: HpDyn, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case False{}:
      Done{HdrGot{name, value, rest, tab}}
    case True{}:
      Done{HdrGot{name, value, rest, hp_insert(tab, name, value)}}

def hpack_hdr.lit.val(+name: String, +tab: HpDyn, is_incr: Bool, r: Result<&1, &1, U32 & String, String & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(value, rest)}:
      hpack_hdr.lit.put(name, value, rest, tab, is_incr)

def hpack_hdr.lit.name(r: Result<&1, &1, U32 & String, String & List<&2, U32>>, +tab: HpDyn, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(name, rest2)}:
      hpack_hdr.lit.val(name, tab, is_incr, hpack_str.dec.go(rest2))

def hpack_hdr.lit.named(+rest: List<&2, U32>, +tab: HpDyn, is_incr: Bool, r: Result<&1, &1, U32 & String, H2Hdr>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      match h:
        case H2Hdr{+n, +v}:
          hpack_hdr.lit.val(n, tab, is_incr, hpack_str.dec.go(rest))

def hpack_hdr.lit.nameat(+idx: U32, +rest: List<&2, U32>, +tab: HpDyn, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.lit.named(rest, tab, is_incr, hp_addr(tab, idx))

def hpack_hdr.lit.zero(+rest: List<&2, U32>, +tab: HpDyn, is_incr: Bool, +idx: U32, is_new: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_new:
    case True{}:
      hpack_hdr.lit.name(hpack_str.dec.go(rest), tab, is_incr)
    case False{}:
      hpack_hdr.lit.nameat(idx, rest, tab, is_incr)

def hpack_hdr.lit.go(+b0: U32, +rest: List<&2, U32>, +tab: HpDyn, r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest2)}:
      hpack_hdr.lit.zero(rest2, tab, is_incr, idx, U32.is_eq(idx, 0))

def hpack_hdr.lit(+b0: U32, +rest: List<&2, U32>, is_incr: Bool, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case True{}:
      hpack_hdr.lit.go(b0, rest, tab, hpack_int.dec.go(b0, 63, rest), True{})
    case False{}:
      hpack_hdr.lit.go(b0, rest, tab, hpack_int.dec.go(b0, 15, rest), False{})

def hpack_hdr.indexed.at(+rest: List<&2, U32>, +tab: HpDyn, r: Result<&1, &1, U32 & String, H2Hdr>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      match h:
        case H2Hdr{+n, +v}:
          Done{HdrGot{n, v, rest, tab}}

def hpack_hdr.indexed.go(+idx: U32, +rest: List<&2, U32>, +tab: HpDyn, static: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match static:
    case True{}:
      hpack_hdr.full(idx, rest, tab)
    case False{}:
      hpack_hdr.indexed.at(rest, tab, hp_addr(tab, idx))

def hpack_hdr.indexed.num(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest)}:
      hpack_hdr.indexed.go(idx, rest, tab, U32.is_le(idx, 61))

def hpack_hdr.table.sized(+rest: List<&2, U32>, +tab: HpDyn, +ns: U32, ok: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack table too big")}
    case True{}:
      Done{HdrGot{"", "", rest, hp_resize(tab, ns)}}

def hpack_hdr.table.go(+tab: HpDyn, r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+ns, +rest)}:
      hpack_hdr.table.sized(rest, tab, ns, U32.is_le(ns, 4096))

# RFC 7541 §6 first-byte patterns (top three bits), not (b0>>4)&15:
# 1xxxxxxx indexed, 01xxxxxx literal incremental, 001xxxxx table size
# update, 0000/0001 literal without/never indexing. Indexed (0x80-0xFF)
# used to fall through to lit and eat the next header as a value string
# (node's :status 200 = 0x88 → "hpack eof str").

def hpack_hdr.after_table(+b0: U32, +rest: List<&2, U32>, +tab: HpDyn, is_table: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_table:
    case True{}:
      hpack_hdr.table.go(tab, hpack_int.dec.go(b0, 31, rest))
    case False{}:
      hpack_hdr.lit(b0, rest, False{}, tab)

def hpack_hdr.after_incr(+b0: U32, +rest: List<&2, U32>, +tab: HpDyn, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case True{}:
      hpack_hdr.lit(b0, rest, True{}, tab)
    case False{}:
      hpack_hdr.after_table(b0, rest, tab, U32.is_ge(b0, 32))

def hpack_hdr.after_idx(+b0: U32, +rest: List<&2, U32>, +tab: HpDyn, is_idx: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_idx:
    case True{}:
      hpack_hdr.indexed.num(hpack_int.dec.go(b0, 127, rest), tab)
    case False{}:
      hpack_hdr.after_incr(b0, rest, tab, U32.is_ge(b0, 64))

def hpack_hdr.dec(+bs: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match bs:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest:
      hpack_hdr.after_idx(b0, rest, tab, U32.is_ge(b0, 128))

def hpack_lit.enc(+name: String, +value: String) -> List<&2, U32>:
  b_append([0], b_append(hpack_str.enc(name), hpack_str.enc(value)))

def hpack_block.go(hs: List<&2, H2Hdr>, acc: List<&2, U32>) -> List<&2, U32>:
  match hs:
    case Nil{}:
      acc
    case H2Hdr{n, v} <> t:
      hpack_block.go(t, b_append(acc, hpack_lit.enc(n, v)))

def hpack_block(hs: List<&2, H2Hdr>) -> List<&2, U32>:
  hpack_block.go(hs, Nil{})

# "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" as bytes (no String compare needed).
def h2_preface() -> List<&2, U32>:
  [80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10]


def h2_send_frame(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, h2_frame_write(typ, flags, sid, pay))

def h2_send_window_update(sock: Socket, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_frame(sock, h2_t_window_update(), 0, sid, h2_be32.go(inc))

def h2_send_wu2.next(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{e}))
    case Done{u}:
      h2_send_window_update(s2, sid, inc)

def h2_send_wu_len.go(sock: Socket, +sid: U32, +inc: U32, empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match empty:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_window_update(sock, 0, inc)
        h2_send_wu2.next(sent, sid, inc)

def h2_send_wu_len(sock: Socket, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_wu_len.go(sock, sid, inc, U32.is_eq(inc, 0))

# Frame reader: parse the buffer and, while the frame is still
# incomplete, read one more chunk. The read budget is unbounded on
# purpose — a peer may split a frame across any number of TLS records
# (Cloudflare delivers ~1.4KB per record, so its 3.6KB HEADERS block
# alone needs 3 reads and the 8KB DATA behind it 6 more) and a frame may
# carry up to 65535 bytes, which is more reads than any fixed budget
# allowed (the old 4-read chain turned a real response into `400 eof`).
# Only a real EOF (an empty chunk) ends the wait, and then only while the
# frame is still incomplete.
#
# The parse result rides the state tuple whole: Bend only takes a param
# or a pattern-bound var as a match scrutinee, and the buffer may not
# travel twice.

def h2_read.loop.done(s: Socket, +chunk: List<&2, U32>, +buf: List<&2, U32>, is_eof: Bool) ->
  Socket & H2FrameOut & List<&2, U32>:
  match is_eof:
    case True{}:
      (s, H2FrameBad{400, "eof"}, buf)
    case False{}:
      +buf2 = b_append(buf, chunk)
      (s, h2_frame_read(buf2), buf2)

def h2_read.loop.grow(r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>) ->
  Socket & H2FrameOut & List<&2, U32>:
  (s, res) = r
  match res:
    case Fail{(code, msg)}:
      (s, H2FrameBad{code, msg}, buf)
    case Done{+chunk}:
      h2_read.loop.done(s, chunk, buf, U32.is_eq(b_len32(chunk), 0))

@unsafe
def h2_read_loop(state: Socket & H2FrameOut & List<&2, U32>) -> IO(Socket & H2Got):
  (s0, out, buf) = state
  match out:
    case H2FrameOk{frame, rest}:
      IO.pure(Socket & H2Got, (s0, H2GotOk{frame, rest}))
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (s0, H2GotErr{code, msg}))
    case H2NeedMore{missing}:
      do IO<Socket & H2Got>:
        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s0, 16384)
        h2_read_loop(h2_read.loop.grow(r1, buf))

def h2_read_frame(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_read_loop((sock, h2_frame_read(buf), buf))

# Flow control, window updates and the IO leaves
# ------------------------------------------

# Flow pump v2 (item 2, nghttp2 mold): one @unsafe phased def + small
# leafs; got destructures at arm tops, fresh re-created pairs hop to hop.
# Phases: 0 pump, 4 slice (chunk = h2_chunk_of), 5 send|park, 6 continue/
# END_STREAM, 9 parked read, 12 service (WU credit / SETTINGS ack+IW /
# PING ack / consume / RST-GOAWAY-CONT fail-closed).
# Credit math is U32 throughout (b_len32/take/drop); the chunk is
# the whole available credit capped at 16KB (nghttp2 1722 note).
def h2_u32_min.pick(+a: U32, +b: U32, pick_a: Bool) -> U32:
  match pick_a:
    case True{}:
      a
    case False{}:
      b

def h2_u32_min(+a: U32, +b: U32) -> U32:
  h2_u32_min.pick(a, b, U32.is_le(a, b))

def h2_flow_wu_inc(+pay: List<&2, U32>) -> U32:
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
                  u32_of4(b0, b1, b2, b3)

def h2_flow_credit.mine(+cw: U32, +sw: U32, +inc: U32, is_mine: Bool) -> U32 & U32:
  match is_mine:
    case True{}:
      (cw, (sw + inc : U32))
    case False{}:
      (cw, sw)

def h2_flow_credit.conn(+cw: U32, +sw: U32, +inc: U32, is_conn: Bool, is_mine: Bool) -> U32 & U32:
  match is_conn:
    case True{}:
      ((cw + inc : U32), sw)
    case False{}:
      h2_flow_credit.mine(cw, sw, inc, is_mine)

def h2_flow_credit.add(+cw: U32, +sw: U32, +sid: U32, +sid2: U32, +inc: U32) -> U32 & U32:
  h2_flow_credit.conn(cw, sw, inc, U32.is_eq(sid2, 0), U32.is_eq(sid2, sid))

def h2_flow_credit.go(+cw: U32, +sw: U32, +sid: U32, +sid2: U32, +inc: U32, valid: Bool) -> U32 & U32:
  match valid:
    case False{}:
      (cw, sw)
    case True{}:
      h2_flow_credit.add(cw, sw, sid, sid2, inc)

def h2_flow_cw(p: U32 & U32) -> U32:
  (a, b) = p
  a

def h2_flow_sw(p: U32 & U32) -> U32:
  (a, b) = p
  b

def h2_flow_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, H2GotErr{code, msg})
    case Done{u}:
      (s, H2GotErr{0, "next"})

def h2_chunk_of(+cw: U32, +sw: U32, +blen: U32) -> U32:
  h2_u32_min(h2_u32_min(h2_u32_min(cw, sw), h2_max_send()), blen)

def h2_chunk_pos(+chunk: U32) -> Bool:
  U32.is_gt(chunk, 0)

def h2_settings.iw_find(+cur: U32, +val: U32, is_four: Bool) -> U32:
  match is_four:
    case True{}:
      val
    case False{}:
      cur

def h2_settings.iw_of(+pay: List<&2, U32>, +cur: U32) -> U32:
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
                          h2_settings.iw_of(rest, h2_settings.iw_find(cur, u32_of4(b2, b3, b4, b5), U32.is_eq((b0 * 256 + b1 : U32), 4)))

# Response head decode (mirror of h2_reqhead.go, apply on :status)
# ---------------------------------------------------------
@unsafe
def h2_send_data_flow(+phase: U32, got: Socket & H2Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, +ok: Bool, +sid2p: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match phase:
    case 0:
      (s0, g0) = got
      match g0:
        case H2GotErr{code0, msg0}:
          match code0:
            case 0:
              match body:
                case Nil{}:
                  h2_send_frame(s0, h2_t_data(), h2_f_end_stream(), sid, Nil{})
                case +b <> r:
                  h2_send_data_flow(4, (s0, H2GotErr{0, "next"}), sid, b <> r, cw, sw, buf, cl, ful, pay2, ok, sid2p)
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s0, Fail{(code0, msg0)}))
        case H2GotOk{+frame0, +buf0}:
          h2_send_data_flow(0, (s0, H2GotErr{0, "next"}), sid, body, cw, sw, buf0, 0, 0, Nil{}, True{}, sid2p)
    case 4:
      (s4, g4) = got
      h2_send_data_flow(5, (s4, H2GotErr{0, "next"}), sid, body, cw, sw, buf, cl, h2_chunk_of(cw, sw, b_len32(body)), Nil{}, h2_chunk_pos(h2_chunk_of(cw, sw, b_len32(body))), sid2p)
    case 5:
      (s5, g5) = got
      m_flow.chunker(got, sid, body, cw, sw, buf, cl, ful, pay2, ok, sid2p)
    case 6:
      (s6, g6) = got
      m_flow.reste(got, sid, body, cw, sw, buf, cl, ful, pay2, ok, sid2p)
    case 9:
      (s9, g9) = got
      match g9:
        case H2GotErr{code9, msg9}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s9, Fail{(code9, msg9)}))
        case H2GotOk{+frame9, +buf9}:
          match frame9:
            case H2Frame{+typ9, +flags9, +sid29, +payload9}:
              h2_send_data_flow(12, got, sid, body, cw, sw, buf9, m_flow.cls(typ9), ful, payload9, h2_window_update_ok(payload9), sid29)
    case 12:
      (s12, g12) = got
      m_flow.do_act(got, sid, body, cw, sw, buf, cl, sid2p, pay2)
    case _:
      (s13, g13) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s13, Fail{(502, "flow bad phase")}))

def m_flow.cls(+typ: U32) -> U32:
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

def m_flow.chunker(got: Socket & H2Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, ok: Bool, +sid2p: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s5, g5) = got
  match ok:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s5, h2_t_data(), 0, sid, b_take32(ful, body))
        h2_send_data_flow(6, h2_flow_sent(sent), sid, b_drop32(ful, body), (cw - ful : U32), (sw - ful : U32), buf, 0, 0, Nil{}, True{}, sid2p)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        got2 : Socket & H2Got <- h2_read_frame(s5, buf)
        h2_send_data_flow(9, got2, sid, body, cw, sw, buf, cl, ful, pay2, ok, sid2p)

def m_flow.reste(got: Socket & H2Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, +ok: Bool, +sid2p: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s6, g6) = got
  match body:
    case Nil{}:
      h2_send_frame(s6, h2_t_data(), h2_f_end_stream(), sid, Nil{})
    case +b <> r:
      h2_send_data_flow(0, (s6, H2GotErr{0, "next"}), sid, b <> r, cw, sw, buf, 0, 0, Nil{}, True{}, sid2p)

@unsafe
def m_flow.do_act(got: Socket & H2Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +cl: U32, +sid2p: U32, +pay2: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, g) = got
  match cl:
    case 2:
      m_flow.wu(got, sid, body, cw, sw, buf, sid2p, h2_flow_wu_inc(pay2), h2_window_update_ok(pay2))
    case 4:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        got2 : Socket & H2Got <- m_flow.ack(got, buf)
        h2_send_data_flow(4, got2, sid, body, cw, h2_settings.iw_of(pay2, sw), buf, 0, 0, Nil{}, True{}, sid2p)
    case 6:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s, h2_t_ping(), h2_f_ack(), 0, pay2)
        h2_send_data_flow(4, h2_flow_sent(sent), sid, body, cw, sw, buf, 0, 0, Nil{}, True{}, sid2p)
    case 3:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{(502, "rst_stream")}))
    case 7:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{(502, "goaway")}))
    case 9:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{(502, "continuation")}))
    case _:
      h2_send_data_flow(4, (s, H2GotErr{0, "next"}), sid, body, cw, sw, buf, 0, 0, Nil{}, True{}, sid2p)

@unsafe
def m_flow.wu(got: Socket & H2Got, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +buf: List<&2, U32>, +sid2p: U32, +inc: U32, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match ok:
    case True{}:
      +cream = h2_flow_credit.go(cw, sw, sid, sid2p, inc, True{})
      h2_send_data_flow(4, m_flow.pair(got), sid, body, h2_flow_cw(cream), h2_flow_sw(cream), buf, 0, 0, Nil{}, True{}, sid2p)
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, h2_flow_wu_bad(got))

def h2_send_data_start.go(sock: Socket, +sid: U32, +body: List<&2, U32>, single: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match single:
    case True{}:
      h2_send_frame(sock, h2_t_data(), h2_f_end_stream(), sid, body)
    case False{}:
      h2_send_data_flow(0, (sock, H2GotErr{0, "next"}), sid, body, h2_init_window(), h2_init_window(), Nil{}, 0, 0, Nil{}, True{}, 0)

def h2_send_data_start(sock: Socket, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_data_start.go(sock, sid, body, U32.is_le(b_len32(body), h2_max_send()))


def h2_head.apply2(+status: U32, +headers: List<&2, H2Hdr>, +name: String, +value: String, is_status: Bool) -> H2Head:
  match is_status:
    case True{}:
      H2Head{Maybe.default(&2, U32, U32.read(value), 0), headers}
    case False{}:
      H2Head{status, List.append(&2, H2Hdr, headers, [H2Hdr{name, value}])}

def h2_head.apply(+st: H2Head, +name: String, +value: String, is_status: Bool) -> H2Head:
  match st:
    case H2Head{+status, +headers}:
      h2_head.apply2(status, headers, name, value, is_status)

@unsafe
def h2_head.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: H2Head, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, H2Head & HpDyn>:
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
              h2_head.go(f, 1, bs, hpack_hdr.dec(bs, tab), "", "", st, tab)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HdrGot{+name, +value, +rrest, +tab2}}:
              h2_head.go(f, 2, rrest, Fail{(0, "")}, name, value, st, tab2)
        case 2:
          +st2 = h2_head.apply(st, name, value, String.eq(name, ":status"))
          h2_head.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          h2_head.go(f, 0, bs, r, "", "", st, tab)

def h2_head.decode(+bs: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, H2Head & HpDyn>:
  h2_head.go(512n, 0, bs, Fail{(0, "")}, "", "", H2Head{0, Nil{}}, tab)

def h2_head.rh(r: Result<&1, &1, U32 & String, H2Head & HpDyn>) -> H2Head:
  match r:
    case Fail{e}:
      H2Head{0, Nil{}}
    case Done{(+h, t)}:
      h

def h2_head.ok(r: Result<&1, &1, U32 & String, H2Head & HpDyn>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{(h, t)}:
      True{}

def h2_head.tab(r: Result<&1, &1, U32 & String, H2Head & HpDyn>) -> HpDyn:
  match r:
    case Fail{e}:
      HpDyn{Nil{}, 0, 4096}
    case Done{(h, +t)}:
      t

# The three projections the callers ask of one decode result: the head,
# whether it decoded, the table to keep encoding on. A Fail answers the
# empty head, False{} and the empty table.
def h2_head.of(r: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  Result<&1, &1, U32 & String, H2Head>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+head, +tab)}:
      Done{head}

# Header block -> request head
# ----------------------------------


def h2_reqhead.pick2(+method: String, +path: String, +headers: List<&2, H2Hdr>, +name: String, +value: String, +is_path: Bool) -> H2ReqHead:
  match is_path:
    case True{}:
      H2ReqHead{method, value, headers}
    case False{}:
      H2ReqHead{method, path, headers}

def h2_reqhead.pick(+method: String, +path: String, +headers: List<&2, H2Hdr>, +name: String, +value: String, +is_meth: Bool, +is_path: Bool) -> H2ReqHead:
  match is_meth:
    case True{}:
      H2ReqHead{value, path, headers}
    case False{}:
      h2_reqhead.pick2(method, path, headers, name, value, is_path)

def h2_reqhead.apply3(+method: String, +path: String, +headers: List<&2, H2Hdr>, +name: String, +value: String, is_meth: Bool, is_path: Bool, pseudo: Bool) -> H2ReqHead:
  match pseudo:
    case True{}:
      h2_reqhead.pick(method, path, headers, name, value, is_meth, is_path)
    case False{}:
      H2ReqHead{method, path, List.append(&2, H2Hdr, headers, [H2Hdr{name, value}])}

def h2_reqhead.apply2(+method: String, +path: String, +headers: List<&2, H2Hdr>, +name: String, +value: String, +is_meth: Bool, +is_path: Bool) -> H2ReqHead:
  h2_reqhead.apply3(method, path, headers, name, value, is_meth, is_path, Bool.or(is_meth, is_path))

def h2_reqhead.apply(+st: H2ReqHead, +name: String, +value: String, is_meth: Bool, is_path: Bool) -> H2ReqHead:
  match st:
    case H2ReqHead{+method, +path, +headers}:
      h2_reqhead.apply2(method, path, headers, name, value, is_meth, is_path)

@unsafe
def h2_reqhead.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: H2ReqHead, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, H2ReqHead & HpDyn>:
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
              h2_reqhead.go(f, 1, bs, hpack_hdr.dec(bs, tab), "", "", st, tab)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HdrGot{+name, +value, +rrest, +tab2}}:
              h2_reqhead.go(f, 2, rrest, Fail{(0, "")}, name, value, st, tab2)
        case 2:
          +st2 = h2_reqhead.apply(st, name, value, String.eq(name, ":method"), String.eq(name, ":path"))
          h2_reqhead.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          h2_reqhead.go(f, 0, bs, r, "", "", st, tab)

def h2_reqhead.decode(+bs: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, H2ReqHead & HpDyn>:
  h2_reqhead.go(512n, 0, bs, Fail{(0, "")}, "", "", H2ReqHead{"", "", Nil{}}, tab)

def h2_reqhead.rh(r: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  H2ReqHead:
  match r:
    case Fail{e}:
      H2ReqHead{"", "", Nil{}}
    case Done{(+head, +tab)}:
      head

def h2_reqhead.ok(r: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{(head, tab)}:
      True{}

def h2_reqhead.tab(r: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) -> HpDyn:
  match r:
    case Fail{e}:
      hp_empty()
    case Done{(head, +tab)}:
      tab

def h2_connect.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{u}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Done{sock})

def h2_connect.go(conn: Result<&1, &1, U32 & String, Socket>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, Socket>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, b_append(h2_preface(), h2_settings_initial()))
        h2_connect.sent(sent)

def h2_connect(host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  do IO<Result<&1, &1, U32 & String, Socket>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect(host, port)
    h2_connect.go(conn)

def h2_request.head(+method: String, +path: String, hs: List<&2, H2Hdr>) -> List<&2, U32>:
  hpack_block(List.append(&2, H2Hdr, [H2Hdr{":method", method}, H2Hdr{":path", path}, H2Hdr{":scheme", "https"}], hs))

def h2_resp.cls3(+typ: U32) -> U32:
  match typ:
    case 1:
      2
    case 0:
      3
    case 4:
      1
    case 6:
      4
    case 7:
      5
    case _:
      0

def h2_resp.cls_wu_ok(ok: Bool) -> U32:
  match ok:
    case False{}:
      9
    case True{}:
      6

# Phase 4: stream RST/CONTINUATION surface as 7/8 instead of skip.
def h2_resp.cls_rst(+typ: U32) -> U32:
  match typ:
    case 3:
      7
    case 9:
      8
    case _:
      h2_resp.cls3(typ)

def h2_resp.cls_wu(+typ: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      h2_resp.cls_wu_ok(h2_window_update_ok(payload))
    case _:
      h2_resp.cls_rst(typ)
      


# Connection-level frames (RFC 9113 section 6.1: everything but
# DATA and HEADERS) belong to the connection, not to a stream.
def h2_resp.mine_conn(+typ: U32, is_conn: Bool) -> Bool:
  match is_conn:
    case True{}:
      Bool.and(U32.is_ne(typ, 0), U32.is_ne(typ, 1))
    case False{}:
      False{}

# A frame is ours when it rides our stream, or when it is a
# connection-level frame that is NOT an ACK echo: RFC 9113 section 6.5
# says acking an ACK ping-pongs forever, so a stale SETTINGS/PING ack
# has to land in conn_cls (which answers 0), not in the stream table.
def h2_resp.mine_of(+typ: U32, +flags: U32, +sid2: U32, +sid: U32) -> Bool:
  Bool.or(Bool.and(U32.is_eq(sid2, sid), U32.is_gt(sid2, 0)),
    Bool.and(h2_resp.mine_conn(typ, U32.is_eq(sid2, 0)), U32.is_eq(U32.and(flags, h2_f_ack()), 0)))

def h2_resp.set_ack(fresh: Bool) -> U32:
  match fresh:
    case True{}:
      1
    case False{}:
      0

def h2_resp.ping_ack(fresh: Bool) -> U32:
  match fresh:
    case True{}:
      4
    case False{}:
      0

def h2_resp.conn_cls(+typ: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 4:
      h2_resp.set_ack(U32.is_eq(U32.and(flags, h2_f_ack()), 0))
    case 6:
      h2_resp.ping_ack(U32.is_eq(U32.and(flags, h2_f_ack()), 0))
    case 7:
      5
    case 8:
      h2_resp.cls_wu_ok(h2_window_update_ok(payload))
    case _:
      0

def h2_resp.cls_mine(+typ: U32, +flags: U32, +payload: List<&2, U32>, mine: Bool, +sid2: U32) -> U32:
  match mine:
    case True{}:
      h2_resp.cls_wu(typ, payload)
    case False{}:
      h2_resp.conn_cls(typ, flags, payload)


def h2_resp.classify(+frame: H2Frame, +sid: U32) -> U32:
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      h2_resp.cls_mine(typ, flags, payload, h2_resp.mine_of(typ, flags, sid2, sid), sid2)

# RFC 9113 section 6.9: the increment field is exactly 4 bytes, so any
# other length is a connection error. h2_window_update_ok checks the tail too (the old
# reader stopped after 4 bytes and let a 5-byte frame pass as credit).

def h2_resp.st_hp(+st: H2RespSt) -> HpDyn:
  match st:
    case H2RespSt{head, body, hp}:
      hp

def h2_needs_cont(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, h2_t_headers()), U32.is_eq(U32.and(flags, h2_f_end_headers()), 0))

# CONTINUATION pairing: same nonzero sid as the open block, and
# END_HEADERS closes it.
def h2_cont_last(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, h2_f_end_headers()), h2_f_end_headers())

def h2_cont_ok(+typ: U32, +sid: U32, +exp: U32) -> Bool:
  Bool.and(U32.is_eq(typ, h2_t_continuation()), Bool.and(U32.is_eq(sid, exp), U32.is_gt(sid, 0)))

def h2_rst_pay(+code: U32) -> List<&2, U32>:
  h2_be32(code)

def h2_goaway_pay(+last_sid: U32, +code: U32) -> List<&2, U32>:
  b_append(h2_be32(U32.and(last_sid, 2147483647)), h2_be32(code))

def h2_send_rst(sock: Socket, +sid: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_frame(sock, h2_t_rst_stream(), 0, sid, h2_rst_pay(code))


def h2_send_goaway.pay(+last_sid: U32, +code: U32) -> List<&2, U32>:
  List.append(&2, U32, h2_be32.go(last_sid), h2_be32.go(code))

def h2_send_goaway(sock: Socket, +last_sid: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_frame(sock, h2_t_goaway(), 0, 0, h2_send_goaway.pay(last_sid, code))

# Shared CONTINUATION reader: finishes a header block opened by a
# HEADERS without END_HEADERS. Accumulates CONTINUATION payloads of
# the same nonzero sid until END_HEADERS; any other frame inside the
# block is a connection error (RFC 9113 section 6.10) answered with
# GOAWAY PROTOCOL_ERROR before failing. Returns the full block plus
# the leftover read buffer. Narrow single-@unsafe loop (7 params):
# phase 0 reads or decomposes one frame, phase 1 dispatches on cls
# (0 done, 1 more, 2 connection error).
def h2_cont_end(last: Bool) -> U32:
  match last:
    case True{}:
      0
    case False{}:
      1

def h2_cont_cls(+typ: U32, +sid2: U32, +sid: U32, +flags: U32, ok: Bool) -> U32:
  match ok:
    case True{}:
      h2_cont_end(h2_cont_last(flags))
    case False{}:
      2

def h2_cont_cls_of(+typ: U32, +sid2: U32, +sid: U32, +flags: U32) -> U32:
  h2_cont_cls(typ, sid2, sid, flags, h2_cont_ok(typ, sid2, sid))

def h2_cont_failed(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Cont>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Cont>, (s, Fail{e}))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Cont>, (s, Fail{(502, "continuation")}))

@unsafe
def h2_cont_read(+phase: U32, +sid: U32, +acc: List<&2, U32>, +buf: List<&2, U32>, prev: Socket & H2Got, +cls: U32, +frag: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Cont>):
  match phase:
    case 0:
      (s0, g0) = prev
      match g0:
        case H2GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, H2Cont>>:
                got2 : Socket & H2Got <- h2_read_frame(s0, buf)
                h2_cont_read(0, sid, acc, buf, got2, 0, Nil{})
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, H2Cont>, (s0, Fail{(code, msg)}))
        case H2GotOk{+frame, +buf2}:
          match frame:
            case H2Frame{+typ, +flags, +sid2, +payload}:
              h2_cont_read(1, sid, acc, buf2, (s0, H2GotErr{0, "next"}), h2_cont_cls_of(typ, sid2, sid, flags), payload)
    case 1:
      (s1, g1) = prev
      match cls:
        case 0:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Cont>, (s1, Done{H2Cont{b_append(acc, frag), buf}}))
        case 1:
          h2_cont_read(0, sid, b_append(acc, frag), buf, (s1, H2GotErr{0, "next"}), 0, Nil{})
        case _:
          do IO<Socket & Result<&1, &1, U32 & String, H2Cont>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_goaway(s1, 0, 1)
            h2_cont_failed(sent)
    case _:
      (sx, gx) = prev
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Cont>, (sx, Fail{(502, "bad phase")}))

def h2_cont_start(sock: Socket, +sid: U32, +acc: List<&2, U32>, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Cont>):
  h2_cont_read(0, sid, acc, buf, (sock, H2GotErr{0, "next"}), 0, Nil{})

def h2_resp.cls(+typ: U32) -> U32:
  match typ:
    case 1:
      2
    case 0:
      3
    case 4:
      1
    case 6:
      4
    case 7:
      5
    case _:
      0

# The server numbering already is the codec's (1 SETTINGS, 2 RST, 4 PING,
# 5 GOAWAY, 6 stream, 7 WU ok, 8 CONT, 9 WU bad, 0 skip), so the family
# delegates and the frame crosses as a direct field copy
# Per-consumer numbering (1 SETTINGS, 2 HEADERS, 3 DATA, 4 PING,
# 5 GOAWAY, 6 WU ok, 7 RST, 8 CONT, 9 WU bad), kept as it was: the codec
# unified it with the server's and the consumers of this file read
# these numbers directly.



def m_flow.acked(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) -> Socket & H2Got:
  (s2, r2) = sent
  match r2:
    case Fail{(code, msg)}:
      (s2, H2GotErr{code, msg})
    case Done{u}:
      (s2, H2GotOk{H2Frame{0, 0, 0, Nil{}}, buf})

def m_flow.ack(got: Socket & H2Got, buf: List<&2, U32>) -> IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s, h2_t_settings(), h2_f_ack(), 0, Nil{})
    IO.pure(Socket & H2Got, m_flow.acked(sent, buf))

def h2_flow_wu_bad(got: Socket & H2Got) -> Socket & Result<&1, &1, U32 & String, Unit>:
  (s, g) = got
  (s, Fail{(502, "bad window_update")})

def m_flow.pair(got: Socket & H2Got) -> Socket & H2Got:
  (s, g) = got
  (s, H2GotErr{0, "next"})

# Ack only a fresh (non-ACK) SETTINGS: acking an ACK back would ping-pong
# the two unbounded read loops forever.
def mux.cls_fix(base: U32, +flags: U32) -> U32:
  match base flags:
    case 1 1:
      0
    case _ _:
      base

# Parking value: the loop reads on every turn, so the carrier only has to
# carry the socket while no frame is in hand.
def mux.again(s: Socket) -> Socket & H2Got:
  (s, H2GotOk{H2Frame{0, 0, 0, Nil{}}, Nil{}})

# Housekeeping sends keep the connection alive even if the write fails:
# the next read answers the dead socket and closes the connection.
def mux.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2Got:
  (s2, r) = sent
  mux.again(s2)

def mux.ack(got: Socket & H2Got) -> IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s, h2_t_settings(), h2_f_ack(), 0, Nil{})
    IO.pure(Socket & H2Got, mux.sent(sent))

def mux.ack_ping(got: Socket & H2Got, +payload: List<&2, U32>) -> IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s, h2_t_ping(), h2_f_ack(), 0, payload)
    IO.pure(Socket & H2Got, mux.sent(sent))

# HEADERS action codes: 0 claim slot, 1 answer now, 5 decode fail,
# 6 park header fragment (HEADERS without END_HEADERS).
def muxn.head_act(need: U32, ok: Bool, +end: U32) -> U32:
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
def muxn.decide_data(has: Bool, +end: U32) -> U32:
  match has end:
    case False{} _:
      4
    case True{} 1:
      1
    case _ _:
      0

def muxn.need_go(needs: Bool) -> U32:
  match needs:
    case True{}:
      1
    case False{}:
      0

def muxn.need_u(+typ: U32, +flags: U32) -> U32:
  muxn.need_go(h2_needs_cont(typ, flags))

# Receive-side credit leaf for the server loops (mold client_on.wu_best,
# buf carried): best-effort double WINDOW_UPDATE (conn 0 + stream sid);
# a failed credit still delivers the frame, the dead socket fails next read.
def mux.wo(got: Socket & H2Got) -> Socket:
  (sx, gx) = got
  sx

def mux.wu_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) ->
  Socket & H2Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, H2GotErr{code, msg})
    case Done{u}:
      (s, H2GotOk{H2Frame{0, 0, 0, Nil{}}, buf})

def mux.wu_er(got: Socket & H2Got, buf: List<&2, U32>, +sid: U32, +payload: List<&2, U32>) ->
  IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_wu_len(s, sid, b_len32(payload))
    IO.pure(Socket & H2Got, mux.wu_kept(sent, buf))

# Client
# ------

def client_on.again(s: Socket) -> Socket & H2Got:
  (s, H2GotOk{H2Frame{0, 0, 0, Nil{}}, Nil{}})

def client_on.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2Got:
  (s2, r) = sent
  client_on.again(s2)

def client_on.ack(got: Socket & H2Got) -> IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s, h2_t_settings(), h2_f_ack(), 0, Nil{})
    IO.pure(Socket & H2Got, client_on.sent(sent))

def client_on.ack_ping(got: Socket & H2Got, +payload: List<&2, U32>) -> IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s, h2_t_ping(), h2_f_ack(), 0, payload)
    IO.pure(Socket & H2Got, client_on.sent(sent))

def client_on.resp_of(+head: H2Head, +body: List<&2, U32>) -> H2Response:
  match head:
    case H2Head{+status, +headers}:
      H2Response{status, headers, body}
def client_on.head_status(+head: H2Head) -> U32:
  match head:
    case H2Head{+status, headers}:
      status

def client_on.has_head(+head: H2Head) -> Bool:
  U32.is_ne(client_on.head_status(head), 0)

def client_on.mine_go(+cls: U32, is_stream: Bool, is_mine: Bool) -> U32:
  match is_stream is_mine:
    case True{} False{}:
      0
    case _ _:
      cls

def client_on.mine_cls(+cls: U32, +sid2: U32, +exp: U32) -> U32:
  client_on.mine_go(cls, U32.is_eq(cls, 6), U32.is_eq(sid2, exp))

def client_on.fail(got: Socket & H2Got, +tab: HpDyn, +code: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn, (s, Fail{(code, msg)}, tab))

def client_on.done(got: Socket & H2Got, +tab: HpDyn, +head: H2Head, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn, (s, Done{client_on.resp_of(head, b_cat(body))}, tab))

def client_on.done_data(got: Socket & H2Got, +tab: HpDyn, +head: H2Head, +body: List<&2, U32>, +payload: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn):
  (s, g) = got
  IO.pure(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn, (s, Done{client_on.resp_of(head, b_cat(m_rev_push(payload, body)))}, tab))

@unsafe
def client_on.drain(phase: U32, got: Socket & H2Got, +buf: List<&2, U32>, +tab: HpDyn, +head: H2Head, +body: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +exp: U32, act: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn>:
        got2 : Socket & H2Got <- h2_read_frame(s0, buf)
        client_on.drain(1, got2, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case H2GotErr{code1, msg1}:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn, (s1, Fail{(code1, msg1)}, tab))
        case H2GotOk{+frame, +buf2}:
          match frame:
            case H2Frame{+typ2, +flags2, +sid22, +payload2}:
              client_on.drain(2, (s1, H2GotOk{frame, buf2}), buf2, tab, head, body, typ2, flags2, sid22, payload2, client_on.mine_cls(mux.cls_fix(h2_srv.classify(frame), flags2), sid22, exp), U32.and(flags2, h2_f_end_stream()), exp, 4)
    case 2:
      match cls:
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn>:
            got2 : Socket & H2Got <- client_on.ack(got)
            client_on.drain(0, got2, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn>:
            gotp : Socket & H2Got <- client_on.ack_ping(got, payload)
            client_on.drain(0, gotp, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 5:
          client_on.fail(got, tab, 502, "goaway")
        case 7:
          client_on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 9:
          client_on.fail(got, tab, 502, "bad window_update")
        case 8:
          client_on.fail(got, tab, 502, "continuation")
        case 2:
          client_on.fail(got, tab, 502, "rst_stream")
        case 6:
          client_on.drain(3, got, buf, tab, head, body, typ, flags, sid2, payload, cls, end, exp, 4)
        case 0:
          client_on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case _:
          client_on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 3:
      match typ:
        case 1:
          +dr : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, tab)
          client_on.drain(4, got, buf, h2_head.tab(dr), h2_head.rh(dr), body, typ, flags, sid2, payload, cls, end, exp, muxn.head_act(muxn.need_u(typ, flags), h2_head.ok(dr), end))
        case 0:
          client_on.drain(5, got, buf, tab, head, body, typ, flags, sid2, payload, cls, end, exp, muxn.decide_data(client_on.has_head(head), end))
        case _:
          client_on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
    case 4:
      match act:
        case 0:
          client_on.drain(0, got, buf, tab, head, body, 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 1:
          client_on.done(got, tab, head, body)
        case 6:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn>:
            cres : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(mux.wo(got), exp, payload, buf)
            client_on.drain_conted(cres, tab, body, end, exp)
        case 5:
          client_on.fail(got, tab, 502, "head decode")
        case _:
          client_on.fail(got, tab, 502, "head")
    case 5:
      match act:
        case 0:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn>:
            got2 : Socket & H2Got <- client_on.wu_blest(got, buf, sid2, b_len32(payload))
            client_on.drain(0, got2, buf, tab, head, m_rev_push(payload, body), 0, 0, 0, Nil{}, 0, 0, exp, 4)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn>:
            got2 : Socket & H2Got <- client_on.wu_blest(got, buf, sid2, b_len32(payload))
            client_on.done_data(got2, tab, head, body, payload)
        case 4:
          client_on.fail(got, tab, 502, "stray data")
        case _:
          client_on.fail(got, tab, 502, "data")
    case _:
      client_on.fail(got, tab, 502, "bad phase")

@unsafe
def client_on.drain_conted(cres: Socket & Result<&1, &1, U32 & String, H2Cont>, +tab: HpDyn, +body: List<&2, U32>, +end: U32, +exp: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn):
  (cs, cr) = cres
  match cr:
    case Fail{(fc, fm)}:
      client_on.fail(client_on.again(cs), tab, fc, fm)
    case Done{+mc}:
      match mc:
        case H2Cont{+block, +rest}:
          +dr2 : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(block, tab)
          client_on.drain(4, client_on.again(cs), rest, h2_head.tab(dr2), h2_head.rh(dr2), body, 1, 4, exp, Nil{}, 0, end, exp, muxn.head_act(0, h2_head.ok(dr2), end))

def client_on.wu_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) ->
  Socket & H2Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, H2GotErr{code, msg})
    case Done{u}:
      (s, H2GotOk{H2Frame{0, 0, 0, Nil{}}, buf})

def client_on.wu_blest(got: Socket & H2Got, buf: List<&2, U32>, +sid: U32, +inc: U32) -> IO(Socket & H2Got):
  (s, g) = got
  do IO<Socket & H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_wu_len(s, sid, inc)
    IO.pure(Socket & H2Got, client_on.wu_kept(sent, buf))


def h2_request.got(drained: Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r, tab) = drained
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{resp}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Done{resp}))

def h2_request.drain(sock: Socket, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    drained : Socket & Result<&1, &1, U32 & String, H2Response> & HpDyn <-
      client_on.drain(0, (sock, H2GotErr{0, "next"}), Nil{}, hp_empty(), H2Head{0, Nil{}}, Nil{}, 0, 0, 0, Nil{}, 0, 0, sid, 4)
    h2_request.got(drained)

def h2_request.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{u}:
      h2_request.drain(sock, sid)

# The DATA frame always goes out, empty body included: the HEADERS
# never carries END_STREAM, so a peer that reads a fixed frame count
# (the canned peers in the goldens) sees the same three frames as
# before -- SETTINGS, HEADERS, DATA.
def h2_request.data(sock: Socket, +sid: U32, +body: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_empty:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_data(), h2_f_end_stream(), sid, Nil{})
        h2_request.sent(sent, sid)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_data_start(sock, sid, body)
        h2_request.sent(sent, sid)

def h2_request.body(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{u}:
      h2_request.data(sock, sid, body, U32.is_eq(b_len32(body), 0))

def h2_request(sock: Socket, +sid: U32, +method: String, +path: String, hs: List<&2, H2Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      h2_send_frame(sock, h2_t_headers(), h2_f_end_headers(), sid, h2_request.head(method, path, hs))
    h2_request.body(sent, sid, body)

def h2_b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def h2_srv.preface_ok(+buf: List<&2, U32>) -> U32:
  b_eq(b_take32(24, buf), h2_preface())

# Literal :status block, then one flow-aware DATA; END_STREAM rides
# whichever of the two is empty.
# Literal :status block, then one flow-aware DATA; END_STREAM rides
# whichever of the two is empty. (The codec has the same shape as
# x_send_resp, which stayed out of this file's slice.)
def h2_srv.resp_data(sock: Socket, +sid: U32, +body: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_empty:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case False{}:
      h2_send_data_start(sock, sid, body)

def h2_srv.resp_body(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +body: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{u}:
      h2_srv.resp_data(sock, sid, body, is_empty)

def h2_srv.send_resp(sock: Socket, +sid: U32, +resp: H2Response) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match resp:
    case H2Response{+status, +headers, +body}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hs : List<&2, H2Hdr> = List.append(&2, H2Hdr, [H2Hdr{":status", U32.show(status)}], headers)
        flags : U32 = (h2_f_end_headers() + h2_b2u(U32.is_eq(b_len32(body), 0)) : U32)
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_headers(), flags, sid, hpack_block(hs))
        h2_srv.resp_body(sent, sid, body, U32.is_eq(b_len32(body), 0))

def h2_srv.st_hp(+st: H2SrvSt) -> HpDyn:
  match st:
    case H2SrvSt{head, body, sid, hp}:
      hp

# Aborting a stream keeps the connection alive: drop the pending head
# and body, keep the connection HPACK table.
def h2_srv.rst_reset(+st: H2SrvSt) -> H2SrvSt:
  match st:
    case H2SrvSt{head, body, sid, hp}:
      H2SrvSt{None{}, Nil{}, 0, hp}
def h2_srv.cls3(+typ: U32) -> U32:
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

def h2_srv.cls_wu_ok(ok: Bool) -> U32:
  match ok:
    case False{}:
      9
    case True{}:
      7

def h2_srv.cls_rst(+typ: U32) -> U32:
  match typ:
    case 3:
      2
    case 9:
      8
    case _:
      h2_srv.cls3(typ)

def h2_srv.cls_wu(+typ: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      h2_srv.cls_wu_ok(h2_window_update_ok(payload))
    case _:
      h2_srv.cls_rst(typ)

def h2_srv.conn_cls(+typ: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 4:
      h2_resp.set_ack(U32.is_eq(U32.and(flags, h2_f_ack()), 0))
    case 6:
      h2_resp.ping_ack(U32.is_eq(U32.and(flags, h2_f_ack()), 0))
    case 7:
      5
    case 8:
      h2_srv.cls_wu_ok(h2_window_update_ok(payload))
    case _:
      0

def h2_srv.cls2(+typ: U32, +odd: U32, +flags: U32, +payload: List<&2, U32>, is_odd: Bool) -> U32:
  match is_odd:
    case True{}:
      h2_srv.cls_wu(typ, payload)
    case False{}:
      h2_srv.conn_cls(typ, flags, payload)

def h2_srv.cls_odd(+typ: U32, +odd: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  h2_srv.cls2(typ, odd, flags, payload, U32.is_eq(odd, 1))

def h2_srv.cls(+typ: U32, +sid: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  h2_srv.cls_odd(typ, U32.and(sid, 1), flags, payload)

def h2_srv.classify(+frame: H2Frame) -> U32:
  match frame:
    case H2Frame{+typ, +flags, +sid, +payload}:
      h2_srv.cls(typ, sid, flags, payload)

# Server
# ------

# The codec's sequential loop with H2 types in the state: one request stream
# at a time, answered through the caller's handler, then the socket,
# the send receipt and the HPACK table go back so the caller can serve
# the next stream on the same connection.
#
# Phases: 0 read, 1 decompose, 2 dispatch, 3 decode HEADERS, 4 DATA,
# 5 CONTINUATION, 7 refuse a pipelined HEADERS, 9 act on the decoded
# head. Housekeeping (SETTINGS ack, PING ack, GOAWAY, WINDOW_UPDATE)
# rides the codec leaves; the carrier is H2Got so the frame never
# crosses back to H2 inside the loop.

# Loop exits: the triple every serve entry hands back.
def h2_srv.out(sock: Socket, r: Result<&1, &1, U32 & String, Unit>, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, r, tab))

def h2_srv.failed(sent: Socket & Result<&1, &1, U32 & String, Unit>, +code: U32, +msg: String, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  h2_srv.out(sock, Fail{(code, msg)}, tab)

# Protocol error: best-effort GOAWAY (PROTOCOL_ERROR 1, RFC 9113 7.1)
# so the peer sees a graceful close, then Fail with the code the
# caller reads. The socket travels back either way -- the caller owns
# it, exactly as before this facade existed.
def h2_srv.fail_on(got: Socket & H2Got, +code: U32, +msg: String, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, g) = got
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_goaway(sock, 0, 1)
    h2_srv.failed(sent, code, msg, tab)

# Peer GOAWAY (RFC 9113 7.1): no stream to finish, so the serve
# succeeds empty-handed and the caller closes.
def h2_srv.graceful(got: Socket & H2Got, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, g) = got
  h2_srv.out(sock, Done{Unit{}}, tab)

# After the response send: the receipt and the table travel back.
def h2_srv.answered(sent: Socket & Result<&1, &1, U32 & String, Unit>, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  h2_srv.out(sock, r, tab)

# Stream-frame routing: 3 decode HEADERS, 4 DATA on the open stream,
# 7 refuse a pipelined HEADERS, 8 close on stray DATA.
def h2_srv.act_stream(typ: U32, busy: Bool, same: Bool) -> U32:
  match typ busy same:
    case 1 False{} _:
      3
    case 1 True{} _:
      7
    case 0 _ True{}:
      4
    case _ _ _:
      8

# The request is complete: hand it to the caller's handler and answer.
def h2_srv.answer(handler: H2Request -> IO(H2Response), got: Socket & H2Got, +rh: H2ReqHead, +body: List<&2, U32>, +sid: U32, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, g) = got
  match rh:
    case H2ReqHead{+method, +path, +headers}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        req : H2Request = H2Request{method, path, headers, body}
        resp : H2Response <- handler(req)
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_srv.send_resp(sock, sid, resp)
        h2_srv.answered(sent, tab)

@unsafe
def h2_srv.loop(handler: H2Request -> IO(H2Response), phase: U32, +act: U32, got: Socket & H2Got,
  +buf: List<&2, U32>, +tab: HpDyn, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>,
  +cls: U32, +end: U32, +endh: U32, +rh: H2ReqHead, +sid_a: U32, +body: List<&2, U32>, +frag: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match phase:
    case 0:
      (s0, _g0) = got
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got2 : Socket & H2Got <- h2_read_frame(s0, buf)
        h2_srv.loop(handler, 1, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, frag)
    case 1:
      (s1, g1) = got
      match g1:
        case H2GotErr{code1, msg1}:
          h2_srv.out(s1, Fail{(code1, msg1)}, tab)
        case H2GotOk{+frame, +buf2}:
          match frame:
            case H2Frame{+typ2, +flags2, +sid22, +payload2}:
              h2_srv.loop(handler, 2, 0, (s1, H2GotOk{frame, buf2}), buf2, tab, typ2, flags2, sid22, payload2,
                mux.cls_fix(h2_srv.classify(frame), flags2), U32.and(flags2, h2_f_end_stream()),
                U32.and(flags2, h2_f_end_headers()), rh, sid_a, body, frag)
    case 2:
      match cls:
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            got2 : Socket & H2Got <- mux.ack(got)
            h2_srv.loop(handler, 0, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, frag)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            got2 : Socket & H2Got <- mux.ack_ping(got, payload)
            h2_srv.loop(handler, 0, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, frag)
        case 5:
          h2_srv.graceful(got, tab)
        case 2:
          h2_srv.loop(handler, 0, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, H2ReqHead{"", "", Nil{}}, 0, Nil{}, frag)
        case 7:
          h2_srv.loop(handler, 0, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, frag)
        case 8:
          h2_srv.loop(handler, 5, 0, got, buf, tab, typ, flags, sid2, payload, cls, end,
            U32.and(flags, h2_f_end_headers()), rh, sid_a, body, frag)
        case 6:
          h2_srv.loop(handler, h2_srv.act_stream(typ, Bool.or(U32.is_gt(sid_a, 0), U32.is_gt(b_len32(frag), 0)),
            U32.is_eq(sid2, sid_a)), muxn.decide_data(U32.is_eq(sid2, sid_a), end), got, buf, tab,
            typ, flags, sid2, payload, cls, end, endh, rh, sid_a, body, frag)
        case 0:
          h2_srv.loop(handler, 0, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, frag)
        case _:
          h2_srv.fail_on(got, 502, "bad frame", tab)
    case 3:
      +dr : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, tab)
      h2_srv.loop(handler, 9, muxn.head_act(muxn.need_u(typ, flags), h2_reqhead.ok(dr), end), got,
        buf, h2_reqhead.tab(dr), typ, flags, sid2, payload, cls, end, endh, h2_reqhead.rh(dr), sid2, Nil{}, Nil{})
    case 9:
      match act:
        case 0:
          h2_srv.loop(handler, 0, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, Nil{})
        case 1:
          h2_srv.answer(handler, got, rh, body, sid2, tab)
        case 6:
          h2_srv.loop(handler, 0, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, H2ReqHead{"", "", Nil{}}, sid2, Nil{}, payload)
        case _:
          h2_srv.fail_on(got, 502, "hpack decode", tab)
    case 4:
      match act:
        case 0:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            got2 : Socket & H2Got <- mux.wu_er(got, buf, sid_a, payload)
            h2_srv.loop(handler, 0, 0, got2, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, m_rev_push(payload, body), Nil{})
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            got2 : Socket & H2Got <- mux.wu_er(got, buf, sid_a, payload)
            h2_srv.answer(handler, got2, rh, b_cat(m_rev_push(payload, body)), sid_a, tab)
        case _:
          h2_srv.fail_on(got, 400, "stray data", tab)
    case 5:
      match endh:
        case 4:
          h2_srv.loop(handler, 3, 0, got, buf, tab, 1, flags, sid2, b_cat(m_rev_push(payload, frag)), cls, 0, 0,
            H2ReqHead{"", "", Nil{}}, sid_a, Nil{}, Nil{})
        case 0:
          h2_srv.loop(handler, 0, 0, got, buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, m_rev_push(payload, frag))
        case _:
          h2_srv.fail_on(got, 502, "continuation", tab)
    case 7:
      (s7, _g7) = got
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_rst(s7, sid2, 7)
        h2_srv.loop(handler, 0, 0, mux.sent(sent), buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, rh, sid_a, body, frag)
    case _:
      h2_srv.fail_on(got, 502, "bad frame", tab)

# One more stream on an established connection, keeping the caller's
# HPACK table (so dynamic indices from the previous block still read).
def h2_serve_next.go(handler: H2Request -> IO(H2Response), sock: Socket, +tab: HpDyn, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.loop(handler, 0, 0, (sock, H2GotErr{0, "next"}), buf, tab, 0, 0, 0, Nil{}, 0, 0, 0, H2ReqHead{"", "", Nil{}}, 0, Nil{}, Nil{})

# Preface entry: read the 24 magic bytes, send the H2 SETTINGS, then
# serve one stream on this connection.
def h2_srv.pre.recv(rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s1, _r1) = rs
  TLS.tls_recv_bytes(s1, 16384)

def h2_serve_once.ready(sent: Socket & Result<&1, &1, U32 & String, Unit>, +acc: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{e}:
      h2_srv.out(sock, Fail{e}, hp_empty())
    case Done{u}:
      h2_serve_next.go(handler, sock, hp_empty(), b_drop32(24, acc))

def h2_serve_once.magic(sock: Socket, +acc: List<&2, U32>, handler: H2Request -> IO(H2Response), magic: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match magic:
    case 1:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), 0, 0, h2_settings_initial_pay())
        h2_serve_once.ready(sent, acc, handler)
    case _:
      h2_srv.out(sock, Fail{(503, "bad preface")}, hp_empty())

def h2_serve_once.opened(sock: Socket, +acc: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_serve_once.magic(sock, acc, handler, h2_srv.preface_ok(acc))

@unsafe
def h2_serve_once.pre(handler: H2Request -> IO(H2Response), phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, short: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          h2_srv.out(s0, Fail{(400, "eof")}, hp_empty())
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          h2_serve_once.pre(handler, 1, (s0, Done{chunk}), acc2, U32.is_lt(b_len32(acc2), 24))
    case 1:
      (s1, _r1) = rs
      match short:
        case True{}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- h2_srv.pre.recv(rs)
            h2_serve_once.pre(handler, 0, r2, acc, False{})
        case False{}:
          h2_serve_once.opened(s1, acc, handler)
    case _:
      (s9, _r9) = rs
      h2_srv.out(s9, Fail{(400, "eof")}, hp_empty())

def h2_serve_once(sock: Socket, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    h2_serve_once.pre(handler, 0, r1, Nil{}, False{})
def h2_connect_insecure(host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  do IO<Result<&1, &1, U32 & String, Socket>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(host, port)
    h2_connect.go(conn)

def h2_serve_next(sock: Socket, handler: H2Request -> IO(H2Response), +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_serve_next.go(handler, sock, tab, Nil{})
