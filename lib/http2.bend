# HTTP/2 (RFC 7540/7541) over the TLS lane: native codec in Bend, no
# nghttp2/node:http2. The frame layer and HPACK ride the byte lane like
# lib/ws.bend does; the only IO is TLS.tls_send_bytes / tls_recv_bytes.
#
# Scope of this first cut (fail-closed):
# - one connection, streams served sequentially (sid 1, 3, 5, ... on the
#   client); true interleaved multiplexing is backlog — the affine
#   connection handle keeps all reads on one linear flow.
# - HPACK: literal (no index / never indexed / incremental, all without
#   dynamic table updates), static-table indexed (<= 61) and indexed
#   name fields. Huffman-coded strings and dynamic-table references are
#   refused (502) instead of misread. Bend peers here never huffmanize.
# - SETTINGS/PING/WINDOW_UPDATE/GOAWAY are answered or skipped; frames
#   of unknown types are skipped per RFC 7540 s5.5.
# - Bodies are byte-faithful List<&2, U32>; the payload cap is 64 KB
#   per frame read (Fail 413 past it).
#
# Fail codes: 400 eof, 413 too large, 502 protocol error, 503 bad
# preface; TLS/DNS codes (601-616) surface unchanged from lib/tls.bend.
#
# Discipline (same as lib/http.bend): every callee is defined ABOVE its
# caller; match scrutinees are params or pattern-bound vars, never
# computed; helpers above drivers are leaves; self-recursion only, with
# a structurally shrinking argument (Nat fuel or list tail).

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

type HpDyn is Data:
  HpDyn{ents: List<&2, H2Hdr>, size: U32, max: U32}

type H2SrvSt is Data:
  H2SrvSt{head: Maybe<&2, H2ReqHead>, body: List<&2, U32>, sid: U32, hp: HpDyn}

type H2Frame is Data:
  H2Frame{typ: U32, flags: U32, sid: U32, payload: List<&2, U32>}

type H2FrameOut is Data:
  H2FrameOk{frame: H2Frame, rest: List<&2, U32>}
  H2NeedMore{missing: Nat}
  H2FrameBad{code: U32, msg: String}

type HdrGot is Data:
  HdrGot{name: String, value: String, rest: List<&2, U32>, tab: HpDyn, emit: Bool}

type H2Buf is Data:
  H2BufOk{buf: List<&2, U32>}
  H2BufErr{code: U32, msg: String}

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

def b_take.go2(+n: Nat, +bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case h <> t:
      h <> b_take.go2(n, t)

def b_take.go(+n: Nat, +bs: List<&2, U32>, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      b_cat(acc)
    case 1n+m:
      match bs:
        case Nil{}:
          b_cat(acc)
        case h <> t:
          b_take.go(m, t, h <> acc)

def b_take(+n: Nat, bs: List<&2, U32>) -> List<&2, U32>:
  b_take.go(n, bs, Nil{})

def b_drop.go(+n: Nat, +bs: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      bs
    case 1n+m:
      match bs:
        case Nil{}:
          Nil{}
        case h <> t:
          b_drop.go(m, t)

def b_drop(+n: Nat, bs: List<&2, U32>) -> List<&2, U32>:
  b_drop.go(n, bs)

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

def bytes_str(bs: List<&2, U32>) -> String:
  bytes_str.go(bs)

def s_eq.mul(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def s_eq.go2(a: String, b: String) -> U32:
  b_eq(str_bytes(a), str_bytes(b))

def s_eq.go(+a: String, +b: String) -> U32:
  s_eq.mul(s_eq.go2(a, b), Nat.is_eq(String.length(a), String.length(b)))

def s_eq(a: String, b: String) -> U32:
  s_eq.go(a, b)

def h2_t_data() -> U32:
  0

def h2_t_headers() -> U32:
  1

def h2_t_priority() -> U32:
  2

def h2_t_rst_stream() -> U32:
  3

def h2_t_settings() -> U32:
  4

def h2_t_push_promise() -> U32:
  5

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

def h2_f_padded() -> U32:
  8

def h2_f_priority() -> U32:
  32

# Phase 3 flow/frame tuning: we always slice outbound DATA to 16384
# (safe under any peer: RFC 9113 section 6.5.2 minimum), announce a
# 6 MB inbound window plus 65535 max frame, and accept HPACK strings
# up to 65535 bytes.
def h2_max_send() -> U32:
  16384

def h2_init_window() -> U32:
  6291456

def h2_max_hpack() -> U32:
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

# Strip PADDED / PRIORITY framing before HPACK decode (RFC 9113
# sections 6.1/6.2): PADDED prefix is pad-length byte plus that many
# trailing pad bytes; PRIORITY adds a 5-byte exclusive+dependency
# field. Only HEADERS (1) and DATA (0) carry these flags here.
def h2_strip_pad_take(+rest: List<&2, U32>, +total: Nat, +pad: U32) -> List<&2, U32>:
  b_take((total - U32.to_nat(pad) : Nat), rest)

def h2_strip_pad_cut(+rest: List<&2, U32>, +pad: U32) -> List<&2, U32>:
  h2_strip_pad_take(rest, b_len(rest), pad)

def h2_strip_pad_dec(+rest: List<&2, U32>, +pad: U32, has_pad: Bool) -> List<&2, U32>:
  match has_pad:
    case False{}:
      pad <> rest
    case True{}:
      h2_strip_pad_cut(rest, pad)

def h2_strip_pad_go(+pay: List<&2, U32>, has_pad: Bool) -> List<&2, U32>:
  match pay:
    case Nil{}:
      Nil{}
    case +p0 <> rest:
      h2_strip_pad_dec(rest, p0, has_pad)

def h2_strip_prio_go(+pay: List<&2, U32>, has_prio: Bool) -> List<&2, U32>:
  match has_prio:
    case False{}:
      pay
    case True{}:
      b_drop(5n, pay)

def h2_frame_payload(+pay: List<&2, U32>, +flags: U32, +typ: U32) -> List<&2, U32>:
  match typ:
    case 0:
      h2_strip_prio_go(h2_strip_pad_go(pay, U32.is_eq(U32.and(flags, 8), 8)), U32.is_eq(U32.and(flags, 32), 32))
    case 1:
      h2_strip_prio_go(h2_strip_pad_go(pay, U32.is_eq(U32.and(flags, 8), 8)), U32.is_eq(U32.and(flags, 32), 32))
    case _:
      pay

def u32_of4.go(b3: U32, b2: U32, b1: U32, b0: U32) -> U32:
  (((b3 * 16777216 + b2 * 65536 + b1 * 256 + b0 : U32)))

def u32_of4(b3: U32, b2: U32, b1: U32, b0: U32) -> U32:
  u32_of4.go(b3, b2, b1, b0)

def h2_frame.fin4(typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, len: U32) -> H2FrameOut:
  +n = U32.to_nat(len)
  H2NeedMore{(n - b_len(b_take(n, rest)) : Nat)}

def h2_frame.fin3(+typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>, len: U32) -> H2FrameOut:
  +n = U32.to_nat(len)
  +taken = b_take(n, rest)
  H2FrameOk{H2Frame{typ, flags, sid, h2_frame_payload(taken, flags, typ)}, b_drop(n, rest)}

def h2_frame.fin2(typ: U32, flags: U32, sid: U32, rest: List<&2, U32>, len: U32, ok: Bool) ->
  H2FrameOut:
  match ok:
    case True{}:
      h2_frame.fin3(typ, flags, sid, rest, len)
    case False{}:
      h2_frame.fin4(typ, flags, sid, rest, len)

def h2_frame.fin(typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32) ->
  H2FrameOut:
  h2_frame.fin2(typ, flags, sid, rest, len, U32.is_eq(len, U32.from_nat(b_len(b_take(U32.to_nat(len), rest)))))

def h2_frame.go2(typ: U32, flags: U32, sid: U32, rest: List<&2, U32>, len: U32, ok_len: Bool) ->
  H2FrameOut:
  match ok_len:
    case False{}:
      H2FrameBad{413, "frame too large"}
    case True{}:
      h2_frame.fin(typ, flags, sid, rest, len)

def h2_frame.mid6(+len24: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +s2: U32, +rest6: List<&2, U32>) -> H2FrameOut:
  match rest6:
    case +s3 <> rest7:
      +sid = u32_of4(s0, s1, s2, U32.and(s3, 127))
      h2_frame.go2(typ, flags, sid, rest7, len24, U32.is_le(len24, 65535))
    case Nil{}:
      H2NeedMore{1n}

def h2_frame.mid5(+len24: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +rest5: List<&2, U32>) -> H2FrameOut:
  match rest5:
    case +s2 <> rest6:
      h2_frame.mid6(len24, typ, flags, s0, s1, s2, rest6)
    case Nil{}:
      H2NeedMore{2n}

def h2_frame.mid4(+len24: U32, +typ: U32, +flags: U32, +s0: U32, +rest4: List<&2, U32>) -> H2FrameOut:
  match rest4:
    case +s1 <> rest5:
      h2_frame.mid5(len24, typ, flags, s0, s1, rest5)
    case Nil{}:
      H2NeedMore{3n}

def h2_frame.mid3(+len24: U32, +typ: U32, +flags: U32, +rest3: List<&2, U32>) -> H2FrameOut:
  match rest3:
    case +s0 <> rest4:
      h2_frame.mid4(len24, typ, flags, s0, rest4)
    case Nil{}:
      H2NeedMore{4n}

def h2_frame.mid2(+len24: U32, +typ: U32, +rest2: List<&2, U32>) -> H2FrameOut:
  match rest2:
    case +flags <> rest3:
      h2_frame.mid3(len24, typ, flags, rest3)
    case Nil{}:
      H2NeedMore{5n}

def h2_frame.mid(+len24: U32, +rest: List<&2, U32>) -> H2FrameOut:
  match rest:
    case +typ <> rest2:
      h2_frame.mid2(len24, typ, rest2)
    case Nil{}:
      H2NeedMore{6n}

def h2_frame.hi4(+len_hi: U32, +b1: U32, +rest2: List<&2, U32>) -> H2FrameOut:
  match rest2:
    case +b2 <> rest3:
      h2_frame.mid((len_hi * 65536 + b1 * 256 + b2 : U32), rest3)
    case Nil{}:
      H2NeedMore{7n}

def h2_frame.hi3(+len_hi: U32, +rest: List<&2, U32>) -> H2FrameOut:
  match rest:
    case +b1 <> rest2:
      h2_frame.hi4(len_hi, b1, rest2)
    case Nil{}:
      H2NeedMore{8n}

def h2_frame.hi2b(+len_hi: U32, +rest: List<&2, U32>, +have: Nat, short: Bool) -> H2FrameOut:
  match short:
    case True{}:
      H2NeedMore{(9n - have : Nat)}
    case False{}:
      h2_frame.hi3(len_hi, rest)

def h2_frame.hi2(+len_hi: U32, +rest: List<&2, U32>, +have: Nat) -> H2FrameOut:
  h2_frame.hi2b(len_hi, rest, have, Nat.is_lt(have, 8n))

def h2_frame.hi(+len_hi: U32, +rest: List<&2, U32>) ->
  H2FrameOut:
  h2_frame.hi2(len_hi, rest, b_len(rest))

def h2_frame_read(bs: List<&2, U32>) -> H2FrameOut:
  match bs:
    case Nil{}:
      H2NeedMore{9n}
    case +b0 <> rest:
      h2_frame.hi(b0, rest)

def h2_frame_write.cat(h: List<&2, U32>, t: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, h, t)

def h2_frame_write.hdr(+len: U32, +typ: U32, +flags: U32, +sid: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(len, 16n), 255), U32.and(U32.shrn(len, 8n), 255), U32.and(len, 255),
   U32.and(typ, 255), U32.and(flags, 255),
   U32.and(U32.shrn(sid, 24n), 255), U32.and(U32.shrn(sid, 16n), 255),
   U32.and(U32.shrn(sid, 8n), 255), U32.and(sid, 255)]

def h2_frame_write(+typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> List<&2, U32>:
  +len = U32.from_nat(b_len(pay))
  h2_frame_write.cat(h2_frame_write.hdr(len, typ, flags, sid), pay)

def h2_settings_initial() -> List<&2, U32>:
  h2_frame_write(h2_t_settings(), 0, 0, h2_settings_initial_pay())

def h2_window_update_pay(+inc: U32) -> List<&2, U32>:
  h2_be32(U32.and(inc, 2147483647))

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

def h2_settings_apply_go(+fuel: Nat, +pay: List<&2, U32>, +st: H2Settings) -> H2Settings:
  match fuel:
    case 0n:
      st
    case 1n+f:
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
                              h2_settings_apply_go(f, rest, h2_settings_one(st, (b0 * 256 + b1 : U32), u32_of4(b2, b3, b4, b5)))

def h2_settings_apply(+pay: List<&2, U32>, +st: H2Settings) -> H2Settings:
  h2_settings_apply_go(b_len(pay), pay, st)

def h2_window_update_val(+v: U32) -> Bool:
  Bool.and(U32.is_gt(v, 0), U32.is_lt(v, 2147483648))

def h2_window_update_ok(+pay: List<&2, U32>) -> Bool:
  match pay:
    case Nil{}:
      False{}
    case +b0 <> r0:
      match r0:
        case Nil{}:
          False{}
        case +b1 <> r1:
          match r1:
            case Nil{}:
              False{}
            case +b2 <> r2:
              match r2:
                case Nil{}:
                  False{}
                case +b3 <> r3:
                  h2_window_update_val(u32_of4(b0, b1, b2, b3))

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

def hpack_int.dec.go2c(+rest: List<&2, U32>, cont: Bool, +fuel: Nat, acc: U32, +m: U32) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match rest:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b <> rest2:
      match cont:
        case False{}:
          Done{(acc, b <> rest2)}
        case True{}:
          match fuel:
            case 0n:
              Fail{(502, "hpack int too long")}
            case 1n+f:
              +acc2 = (acc + m * U32.and(b, 127) : U32)
              hpack_int.dec.go2c(rest2, U32.is_eq(U32.and(b, 128), 128), f, acc2, (m * 128 : U32))

def hpack_int.dec.go2(+rest: List<&2, U32>, +fuel: Nat, acc: U32, +m: U32) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  hpack_int.dec.go2c(rest, True{}, fuel, acc, m)

def hpack_int.dec.go4(+first: U32, +mask: U32, +rest: List<&2, U32>, short: Bool) ->
  Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match short:
    case True{}:
      Done{(U32.and(first, mask), rest)}
    case False{}:
      hpack_int.dec.go2(rest, 5n, mask, 1)

def hpack_int.dec.go(+first: U32, +mask: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  hpack_int.dec.go4(first, mask, rest, U32.is_lt(U32.and(first, mask), mask))

def hpack_int.dec6(first: U32, rest: List<&2, U32>) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  hpack_int.dec.go(first, 63, rest)

# Huffman strings (RFC 7541 Appendix B, canonical code)
# -----------------------------------------------------
# Lengths per symbol 0..256 plus per-length (5..30) counts, first
# codes and order offsets, generated from the RFC text (no manual
# transcription). The codes rebuild canonically from the lengths with
# zero mismatches (257/257), so decode derives everything here.
# Vectors live in tests/io/hpack_huffman.bend (RFC C.4.1/C.6.1).

def huff_lens() -> List<&2, U32>:
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

def huff_nth.go(+xs: List<&2, U32>, +n: Nat) -> U32:
  match xs:
    case Nil{}:
      0
    case h <> t:
      match n:
        case 0n:
          h
        case 1n+m:
          huff_nth.go(t, m)

def huff_nth(+xs: List<&2, U32>, +n: Nat) -> U32:
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
  +i = U32.to_nat((len - 5 : U32))
  +cnt = huff_nth(huff_counts(), i)
  +fst = huff_nth(huff_firsts(), i)
  Bool.and(U32.is_ge(code, fst), U32.is_lt((code - fst : U32), cnt))

def huff_at(+code: U32, +len: U32) -> U32:
  +i = U32.to_nat((len - 5 : U32))
  +cnt = huff_nth(huff_counts(), i)
  +fst = huff_nth(huff_firsts(), i)
  huff_nth(huff_order(), U32.to_nat((huff_nth(huff_starts(), i) + (code - fst : U32) : U32)))

def huff_ones(+bits: List<&2, U32>) -> Bool:
  match bits:
    case Nil{}:
      True{}
    case b <> t:
      Bool.and(U32.is_eq(b, 1), huff_ones(t))

def huff_pad(+bits: List<&2, U32>) -> Bool:
  Bool.and(Nat.is_lt(b_len(bits), 8n), huff_ones(bits))

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
  huff_dec.go(huff_decode.fuel(b_len(huff_bits(bs))), 0, huff_bits(bs), Nil{}, 0, 0, 0)

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
      hpack_str.dec.huffin(bs, b_drop(U32.to_nat(n), rest), U32.is_eq(n, U32.from_nat(b_len(b_take(U32.to_nat(n), rest)))))

def hpack_str.dec.huf2(+n: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  hpack_str.dec.huffed(n, rest, huff_decode(b_take(U32.to_nat(n), rest)))

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

def hpack_str.enc.cat(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, a, b)

def hpack_str.enc(+s: String) -> List<&2, U32>:
  hpack_str.enc.cat(hpack_int.enc(0, U32.from_nat(String.length(s))), str_bytes(s))

def hpack_str.dec.whole(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>, whole: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match whole:
    case True{}:
      Done{(bytes_str(taken), b_drop(U32.to_nat(n), rest))}
    case False{}:
      Fail{(400, "hpack eof str")}

def hpack_str.dec.fin(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  hpack_str.dec.whole(n, rest, taken, U32.is_eq(n, U32.from_nat(b_len(taken))))

def hpack_str.dec.len(+n: U32, +rest: List<&2, U32>, capped: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match capped:
    case False{}:
      Fail{(413, "hpack str too large")}
    case True{}:
      hpack_str.dec.fin(n, rest, b_take(U32.to_nat(n), rest))

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
      r = hpack_int.dec.go(b0, 127, rest2)
      hpack_str.dec.str(r)

def hpack_str.dec.go(+rest: List<&2, U32>) -> Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match rest:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest2:
      hpack_str.dec.huf(b0, rest2, U32.is_eq(U32.and(b0, 128), 128))

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

def hp_static.name(sp: String & String) -> String:
  (n, v) = sp
  n

def hp_static.value(sp: String & String) -> String:
  (n, v) = sp
  v

def hp_static_name(+idx: U32) -> String:
  hp_static.name(hp_static.go(idx))

def hp_static_pair(+idx: U32) -> String & String:
  hp_static.go(idx)

# Dynamic table (RFC 7541 section 2.3.2, section 4)
# ------------------------------------------------
# Newest entry at the head; size is the sum of entry sizes
# (len(name) + len(value) + 32); max is the protocol limit 4096.
# The decoder owns one table per connection, threaded through the
# header-block loops (Phase 3 wires it; here are the pure ops).

def hp_empty() -> HpDyn:
  HpDyn{Nil{}, 0, 4096}

def hp_entry_size(+name: String, +value: String) -> U32:
  (U32.from_nat(String.length(name)) + U32.from_nat(String.length(value)) + 32 : U32)

def hp_len.go(+ents: List<&2, H2Hdr>, +n: Nat) -> Nat:
  match ents:
    case Nil{}:
      n
    case _ <> t:
      hp_len.go(t, Nat.add(n, 1n))

def hp_len(+ents: List<&2, H2Hdr>) -> Nat:
  hp_len.go(ents, 0n)

def hp_fit.go(+fuel: Nat, fit: Bool, +ents: List<&2, H2Hdr>, +size: U32, +max: U32) ->
  List<&2, H2Hdr> & U32:
  match fuel:
    case 0n:
      (ents, size)
    case 1n+f:
      match fit:
        case True{}:
          (ents, size)
        case False{}:
          match ents:
            case Nil{}:
              (Nil{}, 0)
            case H2Hdr{n, v} <> t:
              +ns = U32.sub(size, hp_entry_size(n, v))
              hp_fit.go(f, U32.is_le(ns, max), t, ns, max)

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
  +rev = hp_rev(ents)
  hp_done(hp_fit.go(hp_len(rev), U32.is_le(size, max), rev, size, max), max)

def hp_insert.do(+ents: List<&2, H2Hdr>, +size: U32, +max: U32, +name: String, +value: String) -> HpDyn:
  +ns = (size + hp_entry_size(name, value) : U32)
  hp_insert.trim(H2Hdr{name, value} <> ents, ns, max)

def hp_insert.fit(+ents: List<&2, H2Hdr>, +size: U32, +max: U32, +name: String, +value: String, fits: Bool) -> HpDyn:
  match fits:
    case False{}:
      HpDyn{Nil{}, 0, max}
    case True{}:
      hp_insert.do(ents, size, max, name, value)

def hp_insert.go(+tab: HpDyn, +name: String, +value: String) -> HpDyn:
  match tab:
    case HpDyn{+ents, +size, +max}:
      hp_insert.fit(ents, size, max, name, value, U32.is_le(hp_entry_size(name, value), max))

def hp_insert(+tab: HpDyn, +name: String, +value: String) -> HpDyn:
  hp_insert.go(tab, name, value)

def hp_resize.go(+tab: HpDyn, +max: U32) -> HpDyn:
  match tab:
    case HpDyn{+ents, +size, +old}:
      hp_insert.trim(ents, size, max)

def hp_resize(+tab: HpDyn, +max: U32) -> HpDyn:
  hp_resize.go(tab, max)

def hp_lookup.at(+ents: List<&2, H2Hdr>, +k: Nat) -> H2Hdr:
  match ents:
    case Nil{}:
      H2Hdr{"", ""}
    case H2Hdr{n, v} <> t:
      match k:
        case 0n:
          H2Hdr{n, v}
        case 1n+m:
          hp_lookup.at(t, m)

def hp_lookup.go(+ents: List<&2, H2Hdr>, +idx: U32, ok: Bool) ->
  Result<&1, &1, U32 & String, H2Hdr>:
  match ok:
    case False{}:
      Fail{(502, "hpack dyn bounds")}
    case True{}:
      Done{hp_lookup.at(ents, U32.to_nat(idx))}

def hp_lookup(+tab: HpDyn, +idx: U32) -> Result<&1, &1, U32 & String, H2Hdr>:
  match tab:
    case HpDyn{+ents, +size, +max}:
      hp_lookup.go(ents, idx, U32.is_lt(idx, U32.from_nat(hp_len(ents))))

def hp_addr.static(sp: String & String) -> H2Hdr:
  (n, v) = sp
  H2Hdr{n, v}

def hp_addr.go(+tab: HpDyn, +idx: U32, is_static: Bool) ->
  Result<&1, &1, U32 & String, H2Hdr>:
  match is_static:
    case True{}:
      Done{hp_addr.static(hp_static_pair(idx))}
    case False{}:
      hp_lookup(tab, (idx - 62 : U32))

def hp_addr(+tab: HpDyn, +idx: U32) -> Result<&1, &1, U32 & String, H2Hdr>:
  hp_addr.go(tab, idx, U32.is_le(idx, 61))

def hpack_hdr.done(+name: String, +tab: HpDyn, r: Result<&1, &1, U32 & String, String & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(value, rest)}:
      Done{HdrGot{name, value, rest, tab, True{}}}

def hpack_hdr.lit.put(+name: String, +value: String, +rest: List<&2, U32>, +tab: HpDyn, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match is_incr:
    case False{}:
      Done{HdrGot{name, value, rest, tab, True{}}}
    case True{}:
      Done{HdrGot{name, value, rest, hp_insert(tab, name, value), True{}}}

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
          Done{HdrGot{n, v, rest, tab, True{}}}

def hpack_hdr.indexed.go(+idx: U32, +rest: List<&2, U32>, +tab: HpDyn, ok: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack bad index")}
    case True{}:
      hpack_hdr.indexed.at(rest, tab, hp_addr(tab, idx))

def hpack_hdr.indexed.num(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest)}:
      hpack_hdr.indexed.go(idx, rest, tab, U32.is_ge(idx, 1))

def hpack_hdr.indexed.go2(+b0: U32, +rest: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.indexed.num(hpack_int.dec.go(b0, 127, rest), tab)

def hpack_hdr.table.sized(+rest: List<&2, U32>, +tab: HpDyn, +ns: U32, ok: Bool) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack table too big")}
    case True{}:
      Done{HdrGot{"", "", rest, hp_resize(tab, ns), False{}}}

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
      hpack_hdr.indexed.go2(b0, rest, tab)
    case False{}:
      hpack_hdr.after_incr(b0, rest, tab, U32.is_ge(b0, 64))

def hpack_hdr.go(+b0: U32, +rest: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.after_idx(b0, rest, tab, U32.is_ge(b0, 128))

def hpack_hdr.dec(+bs: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match bs:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest:
      hpack_hdr.go(b0, rest, tab)

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

def h2_preface() -> List<&2, U32>:
  str_bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

def h2_settings_empty() -> List<&2, U32>:
  h2_frame_write(h2_t_settings(), 0, 0, Nil{})

def h2_settings_ack() -> List<&2, U32>:
  h2_frame_write(h2_t_settings(), h2_f_ack(), 0, Nil{})

def h2_send_frame(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, h2_frame_write(typ, flags, sid, pay))

def h2_send_window_update(sock: Socket, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_frame(sock, h2_t_window_update(), 0, sid, h2_window_update_pay(inc))

def h2_send_wu2.next(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +inc: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{e}))
    case Done{u}:
      h2_send_window_update(s2, sid, inc)

# Replenish both ledgers after inbound DATA (RFC 9113 section 6.9):
# connection window first, then the stream window. Empty DATA needs
# no credit (increment 0 would be a connection error).
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

# Narrow carrier leaves for the flow sender: best-effort credit
# mapping plus fresh-only SETTINGS ack (shared with the DATA runs).
def h2_round.wu_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +rest: List<&2, U32>) -> Socket & H2Got:
  (s, r) = sent
  (s, H2GotOk{H2Frame{typ, flags, sid2, payload}, rest})

def h2_round.wu_typ(sock: Socket, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +rest: List<&2, U32>) -> IO(Socket & H2Got):
  match typ:
    case 0:
      do IO<Socket & H2Got>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_wu_len(sock, sid2, U32.from_nat(b_len(payload)))
        IO.pure(Socket & H2Got, h2_round.wu_kept(sent, typ, flags, sid2, payload, rest))
    case _:
      IO.pure(Socket & H2Got, (sock, H2GotOk{H2Frame{typ, flags, sid2, payload}, rest}))

def h2_round.wu_data(sock: Socket, +frame: H2Frame, +rest: List<&2, U32>) -> IO(Socket & H2Got):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      h2_round.wu_typ(sock, typ, flags, sid2, payload, rest)


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
      h2_read.loop.done(s, chunk, buf, Nat.is_eq(b_len(chunk), 0n))

@unsafe
def h2_read_loop(state: Socket & H2FrameOut & List<&2, U32>) -> IO(Socket & H2Got):
  (s0, out, buf) = state
  match out:
    case H2FrameOk{frame, rest}:
      h2_round.wu_data(s0, frame, rest)
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (s0, H2GotErr{code, msg}))
    case H2NeedMore{missing}:
      do IO<Socket & H2Got>:
        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s0, 16384)
        h2_read_loop(h2_read.loop.grow(r1, buf))

def h2_read_frame(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_read_loop((sock, h2_frame_read(buf), buf))

def h2_wu_best_effort(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2Got:
  (s, r) = sent
  match r:
    case Fail{e}:
      (s, H2GotErr{0, "next"})
    case Done{u}:
      (s, H2GotErr{0, "next"})

def h2_tail_ack.go(sock: Socket, g: H2Got, +flags: U32, fresh: Bool) -> IO(Socket & H2Got):
  match fresh:
    case True{}:
      do IO<Socket & H2Got>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
        IO.pure(Socket & H2Got, h2_wu_best_effort(sent))
    case False{}:
      IO.pure(Socket & H2Got, (sock, g))

def h2_tail_ack(prev: Socket & H2Got, +flags: U32) -> IO(Socket & H2Got):
  (s, g) = prev
  h2_tail_ack.go(s, g, flags, U32.is_eq(U32.and(flags, h2_f_ack()), 0))

# Flow-aware DATA sender (Phase 3 flow): slices to 16 KB and honors
# the peer's connection + stream windows (RFC 9113 section 6.9),
# waiting for WINDOW_UPDATE credit when exhausted. Initial windows
# are the RFC defaults (65535); the peer SETTINGS INITIAL_WINDOW_SIZE
# is picked up on the fly (delta edge vs already-open streams is
# ignored: the announcement always precedes our first DATA here).
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
    case Fail{e}:
      (s, H2GotErr{616, "tls io"})
    case Done{u}:
      (s, H2GotErr{0, "next"})

def h2_chunk_of(+cw: U32, +sw: U32, +blen: Nat) -> U32:
  h2_u32_min(h2_u32_min(h2_u32_min(cw, sw), 16384), U32.from_nat(blen))

def h2_settings.iw_found(+cur: U32, +val: U32, is_four: Bool) -> U32:
  match is_four:
    case True{}:
      val
    case False{}:
      cur

def h2_settings.iw_of.go(+fuel: Nat, +pay: List<&2, U32>, +cur: U32) -> U32:
  match fuel:
    case 0n:
      cur
    case 1n+f:
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
                              h2_settings.iw_of.go(f, rest, h2_settings.iw_found(cur, u32_of4(b2, b3, b4, b5), U32.is_eq((b0 * 256 + b1 : U32), 4)))

def h2_settings.iw_of(+pay: List<&2, U32>, +cur: U32) -> U32:
  h2_settings.iw_of.go(b_len(pay), pay, cur)

@unsafe
def h2_send_data_flow(+phase: U32, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, prev: Socket & H2Got, +buf: List<&2, U32>, +need_read: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match phase:
    case 0:
      match body:
        case Nil{}:
          (se, ge) = prev
          match ge:
            case H2GotErr{code, msg}:
              match code:
                case 0:
                  h2_send_frame(se, h2_t_data(), h2_f_end_stream(), sid, Nil{})
                case _:
                  IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (se, Fail{(code, msg)}))
            case H2GotOk{frame0, buf0}:
              h2_send_data_flow(0, sid, body, cw, sw, (se, H2GotErr{0, "next"}), buf0, False{})
        case +b <> r:
          h2_send_data_flow(1, sid, body, cw, sw, prev, buf, U32.is_eq(h2_chunk_of(cw, sw, b_len(body)), 0))
    case 1:
      (s1, g1) = prev
      match need_read:
        case True{}:
          h2_send_data_flow(2, sid, body, cw, sw, (s1, g1), buf, need_read)
        case False{}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(s1, h2_t_data(), 0, sid, b_take(U32.to_nat(h2_chunk_of(cw, sw, b_len(body))), body))
            h2_send_data_flow(0, sid, b_drop(U32.to_nat(h2_chunk_of(cw, sw, b_len(body))), body), (cw - h2_chunk_of(cw, sw, b_len(body)) : U32), (sw - h2_chunk_of(cw, sw, b_len(body)) : U32), h2_flow_sent(sent), buf, False{})
    case 2:
      (s2, g2) = prev
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        got2 : Socket & H2Got <- h2_read_frame(s2, buf)
        h2_send_data_flow(3, sid, body, cw, sw, got2, buf, False{})
    case _:
      (s3, g3) = prev
      match g3:
        case H2GotErr{code3, msg3}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s3, Fail{(code3, msg3)}))
        case H2GotOk{+frame3, +buf3}:
          match frame3:
            case H2Frame{+typ, +flags, +sid2, +payload}:
              match typ:
                case 8:
                  h2_send_data_flow(0, sid, body, h2_flow_cw(h2_flow_credit.go(cw, sw, sid, sid2, h2_flow_wu_inc(payload), h2_window_update_ok(payload))), h2_flow_sw(h2_flow_credit.go(cw, sw, sid, sid2, h2_flow_wu_inc(payload), h2_window_update_ok(payload))), (s3, H2GotErr{0, "next"}), buf3, False{})
                case 4:
                  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
                    c4 : Socket & H2Got <- h2_tail_ack((s3, g3), flags)
                    h2_send_data_flow(2, sid, body, cw, h2_settings.iw_of(payload, sw), c4, buf3, False{})
                case 6:
                  h2_send_data_flow(2, sid, body, cw, sw, (s3, H2GotErr{0, "next"}), buf3, False{})
                case 3:
                  IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s3, Fail{(502, "rst_stream")}))
                case 7:
                  IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s3, Fail{(502, "goaway")}))
                case 9:
                  IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s3, Fail{(502, "continuation")}))
                case _:
                  IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s3, Fail{(502, "flow blocked")}))

def h2_send_data_start(sock: Socket, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_data_flow(0, sid, body, 65535, 65535, (sock, H2GotErr{0, "next"}), Nil{}, False{})

# Receive-side flow credit, centralized at the single frame-read
# choke point every loop (chain, tails, flow sender, mux) funnels
# through. INITIAL_WINDOW_SIZE only raises per-STREAM windows; the
# CONNECTION window always starts at 65535 and stalls any peer past
# it (nghttp2 stops at exactly 65535) unless we replenish. So every
# inbound DATA earns connection + stream WINDOW_UPDATE immediately
# (best-effort: a failed credit still delivers the frame; a dead
# connection fails at the next read; empty DATA needs no credit).

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

def h2_head.phase(emit: Bool) -> U32:
  match emit:
    case True{}:
      2
    case False{}:
      3

@unsafe def h2_head.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: H2Head, +tab: HpDyn) ->
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
            case Done{HdrGot{+name, +value, +rrest, +tab2, +emit2}}:
              h2_head.go(f, h2_head.phase(emit2), rrest, Fail{(0, "")}, name, value, st, tab2)
        case 2:
          +st2 = h2_head.apply(st, name, value, String.eq(name, ":status"))
          h2_head.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          h2_head.go(f, 0, bs, r, "", "", st, tab)

def h2_head.decode(+bs: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, H2Head & HpDyn>:
  h2_head.go(512n, 0, bs, Fail{(0, "")}, "", "", H2Head{0, Nil{}}, tab)

def h2_head.of(r: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  Result<&1, &1, U32 & String, H2Head>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(h, t)}:
      Done{h}

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

def h2_reqhead.phase(emit: Bool) -> U32:
  match emit:
    case True{}:
      2
    case False{}:
      3

@unsafe def h2_reqhead.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: H2ReqHead, +tab: HpDyn) ->
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
            case Done{HdrGot{+name, +value, +rrest, +tab2, +emit2}}:
              h2_reqhead.go(f, h2_reqhead.phase(emit2), rrest, Fail{(0, "")}, name, value, st, tab2)
        case 2:
          +st2 = h2_reqhead.apply(st, name, value, String.eq(name, ":method"), String.eq(name, ":path"))
          h2_reqhead.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          h2_reqhead.go(f, 0, bs, r, "", "", st, tab)

def h2_reqhead.decode(+bs: List<&2, U32>, +tab: HpDyn) ->
  Result<&1, &1, U32 & String, H2ReqHead & HpDyn>:
  h2_reqhead.go(512n, 0, bs, Fail{(0, "")}, "", "", H2ReqHead{"", "", Nil{}}, tab)

def h2_reqhead.of(r: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  Result<&1, &1, U32 & String, H2ReqHead>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(h, t)}:
      Done{h}

def h2_reqhead.tab_of(r: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) -> HpDyn:
  match r:
    case Fail{e}:
      hp_empty()
    case Done{(h, t)}:
      t

def h2_next_sid(+sid: U32) -> U32:
  (sid + 2 : U32)

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

# Connection-level frames (sid 0) the old classifier skipped: fresh
# SETTINGS (ack), PING (ack), GOAWAY (graceful), WINDOW_UPDATE
# (skip when valid, Fail when not). Stream RST/CONTINUATION surface
# as 7/8; sid-0 RST/CONTINUATION are connection errors, surfaced the
# same way so the rounds Fail instead of skipping.
def h2_resp.mine_conn(+typ: U32, is_conn: Bool) -> Bool:
  match is_conn:
    case True{}:
      Bool.or(Bool.or(U32.is_eq(typ, 3), U32.is_eq(typ, 9)), Bool.or(Bool.or(U32.is_eq(typ, 4), U32.is_eq(typ, 6)), Bool.or(U32.is_eq(typ, 7), U32.is_eq(typ, 8))))
    case False{}:
      False{}

def h2_resp.mine_of(+typ: U32, +sid2: U32, +sid: U32) -> Bool:
  Bool.or(Bool.and(U32.is_eq(sid2, sid), U32.is_gt(sid2, 0)), h2_resp.mine_conn(typ, U32.is_eq(sid2, 0)))

def h2_resp.conn_cls.wu(+payload: List<&2, U32>) -> U32:
  h2_resp.cls_wu_ok(h2_window_update_ok(payload))

# Fresh-only surfacing (RFC 9113 section 6.5): an ACK echo must not
# earn another ACK, or the two sides ping-pong forever. Stale
# SETTINGS/PING ACKs skip like any housekeeping.
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
      h2_resp.conn_cls.wu(payload)
    case _:
      0

def h2_resp.cls_mine(+typ: U32, +flags: U32, +payload: List<&2, U32>, mine: Bool, +sid2: U32) -> U32:
  match mine:
    case True{}:
      h2_resp.cls_wu(typ, payload)
    case False{}:
      h2_resp.conn_cls(typ, flags, payload)

def h2_resp.cls2(+typ: U32, +flags: U32, +payload: List<&2, U32>, +sid2: U32, +sid: U32) -> U32:
  h2_resp.cls_mine(typ, flags, payload, h2_resp.mine_of(typ, sid2, sid), sid2)

def h2_resp.classify(+frame: H2Frame, +sid: U32) -> U32:
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      h2_resp.cls2(typ, flags, payload, sid2, sid)






def h2_resp.head_done(sock: Socket, +head: H2Head, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match head:
    case H2Head{+status, +headers}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Done{H2Response{status, headers, body}}))

def h2_resp.finish2(sock: Socket, head: Maybe<&2, H2Head>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match head:
    case Some{+h}:
      h2_resp.head_done(sock, h, body)
    case None{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "no headers")}))

def h2_resp.finish(sock: Socket, +st: H2RespSt) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match st:
    case H2RespSt{head, body, hp}:
      h2_resp.finish2(sock, head, body)


def h2_resp.st_add(+st: H2RespSt, +pay: List<&2, U32>) -> H2RespSt:
  match st:
    case H2RespSt{+head, +body, +hp}:
      H2RespSt{head, List.append(&2, U32, body, pay), hp}

# Phase 4: client response HPACK table. The server already threads
# HpDyn per connection (H2SrvSt.hp); the client used hp_empty() per
# response, so any peer dynamic-table index from an earlier block
# decoded as 502. Every headN now decodes with st.hp and stores the
# resulting table back (mirrors h2_srv.st_hp).
def h2_resp.st_hp(+st: H2RespSt) -> HpDyn:
  match st:
    case H2RespSt{head, body, hp}:
      hp

# Phase 4: CONTINUATION / RST_STREAM / GOAWAY (RFC 9113 6.10/6.4/7.1).
# A HEADERS without END_HEADERS opens a header block; CONTINUATION*
# with the same nonzero sid accumulate until END_HEADERS. Any other
# frame inside the block is a connection error (PROTOCOL_ERROR).
def h2_needs_cont(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, h2_t_headers()), U32.is_eq(U32.and(flags, h2_f_end_headers()), 0))

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

def h2_send_goaway(sock: Socket, +last_sid: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_send_frame(sock, h2_t_goaway(), 0, 0, h2_goaway_pay(last_sid, code))

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

# Connection-error exit: best-effort GOAWAY (PROTOCOL_ERROR=1 or
# INTERNAL_ERROR=2) before the Fail that makes the caller tls_close,
# so the peer sees a graceful close instead of a TCP drop.
def h2_resp.goaway_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s, Fail{e}))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s, Fail{(502, msg)}))

def h2_resp.goaway_fail(sock: Socket, +wire: U32, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_goaway(sock, 0, wire)
    h2_resp.goaway_sent(sent, msg)

# Graceful GOAWAY: a pending response still completes; with no
# response open the exchange fails cleanly (caller closes).
def h2_resp.goaway_none(sock: Socket, head: Maybe<&2, H2Head>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match head:
    case Some{+h}:
      h2_resp.head_done(sock, h, body)
    case None{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.goaway_fin(sock: Socket, +st: H2RespSt) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match st:
    case H2RespSt{head, body, hp}:
      h2_resp.goaway_none(sock, head, body)




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

































































# Unbounded DATA run: takes over where round8 fails so a long
# response body (many DATA frames) never hits "response too long".
# Narrow single-@unsafe phased loop: phase 0 reads or decomposes one
# frame, phase 1 dispatches on cls (DATA appends, valid WINDOW_UPDATE
# skips, anything else keeps the old overflow error), phase 2 settles
# END_STREAM or fires best-effort WINDOW_UPDATE credit first.
@unsafe
def h2_resp.data_run(+phase: U32, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32, prev: Socket & H2Got, +cls: U32, +is_end: Bool, +dlen: U32, +payload: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match phase:
    case 0:
      (s0, g0) = prev
      match g0:
        case H2GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
                got2 : Socket & H2Got <- h2_read_frame(s0, buf)
                h2_resp.data_run(0, st, buf, sid, got2, 0, False{}, 0, Nil{})
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s0, Fail{(code, msg)}))
        case H2GotOk{+frame, +buf2}:
          match frame:
            case H2Frame{+typ, +flags, +sid2, +payload2}:
              h2_resp.data_run(1, st, buf2, sid, (s0, H2GotOk{H2Frame{typ, flags, sid2, payload2}, buf2}), h2_resp.cls2(typ, flags, payload2, sid2, sid), U32.is_eq(U32.and(flags, h2_f_end_stream()), h2_f_end_stream()), U32.from_nat(b_len(payload2)), payload2)
    case 1:
      (s1, g1) = prev
      match cls:
        case 3:
          h2_resp.data_run(2, h2_resp.st_add(st, payload), buf, sid, (s1, g1), cls, is_end, dlen, Nil{})
        case 0:
          h2_resp.data_run(0, st, buf, sid, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{})
        case 1:
          h2_resp.data_run(0, st, buf, sid, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{})
        case 4:
          h2_resp.data_run(0, st, buf, sid, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{})
        case 6:
          h2_resp.data_run(0, st, buf, sid, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{})
        case 5:
          h2_resp.finish(s1, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s1, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(s1, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s1, Fail{(502, "response too long")}))
    case 2:
      (s2, g2) = prev
      match is_end:
        case True{}:
          h2_resp.finish(s2, st)
        case False{}:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_wu_len(s2, sid, dlen)
            h2_resp.data_run(0, st, buf, sid, h2_wu_best_effort(sent), 0, False{}, 0, Nil{})
    case _:
      (sx, gx) = prev
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sx, Fail{(502, "bad phase")}))

def h2_resp.round8(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  h2_resp.data_run(0, st, buf, sid, (sock, H2GotErr{0, "next"}), 0, False{}, 0, Nil{})



def h2_resp.head7.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round8(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head7.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head7.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head7(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head7.done(sock, st, sid, buf, end, hd)

def h2_resp.acked7(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round8(sock, st, buf, sid)

def h2_resp.data7.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round8(sock, st, buf, sid)

def h2_resp.data7(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data7.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

# Phase 4: a HEADERS without END_HEADERS opens a CONTINUATION
# block; finish it before HPACK decode, then run the usual head.
def h2_resp.head7_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head7(s2, st, sid, block, rest, end)

def h2_resp.head7_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head7_got(got, st, sid, end)
    case False{}:
      h2_resp.head7(sock, st, sid, payload, buf, end)

def h2_resp.next7(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round8(sock, st, buf, sid)
        case 6:
          h2_resp.round8(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked7(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked7(sent, st, sid, buf)
        case 2:
          h2_resp.head7_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data7(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick7(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next7(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round7(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick7(got, st, sid)

def h2_resp.data6.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round7(sock, st, buf, sid)

def h2_resp.data6(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data6.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.head6.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round7(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head6.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head6.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head6(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head6.done(sock, st, sid, buf, end, hd)

def h2_resp.acked6(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round7(sock, st, buf, sid)

def h2_resp.head6_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head6(s2, st, sid, block, rest, end)

def h2_resp.head6_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head6_got(got, st, sid, end)
    case False{}:
      h2_resp.head6(sock, st, sid, payload, buf, end)

def h2_resp.next6(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round7(sock, st, buf, sid)
        case 6:
          h2_resp.round7(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked6(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked6(sent, st, sid, buf)
        case 2:
          h2_resp.head6_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data6(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick6(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next6(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round6(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick6(got, st, sid)

def h2_resp.head5.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round6(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head5.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head5.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head5(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head5.done(sock, st, sid, buf, end, hd)

def h2_resp.acked5(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round6(sock, st, buf, sid)

def h2_resp.data5.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round6(sock, st, buf, sid)

def h2_resp.data5(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data5.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.head5_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head5(s2, st, sid, block, rest, end)

def h2_resp.head5_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head5_got(got, st, sid, end)
    case False{}:
      h2_resp.head5(sock, st, sid, payload, buf, end)

def h2_resp.next5(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round6(sock, st, buf, sid)
        case 6:
          h2_resp.round6(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked5(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked5(sent, st, sid, buf)
        case 2:
          h2_resp.head5_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data5(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick5(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next5(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round5(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick5(got, st, sid)

def h2_resp.head4.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round5(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head4.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head4.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head4(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head4.done(sock, st, sid, buf, end, hd)

def h2_resp.acked4(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round5(sock, st, buf, sid)

def h2_resp.data4.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round5(sock, st, buf, sid)

def h2_resp.data4(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data4.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.head4_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head4(s2, st, sid, block, rest, end)

def h2_resp.head4_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head4_got(got, st, sid, end)
    case False{}:
      h2_resp.head4(sock, st, sid, payload, buf, end)

def h2_resp.next4(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round5(sock, st, buf, sid)
        case 6:
          h2_resp.round5(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked4(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked4(sent, st, sid, buf)
        case 2:
          h2_resp.head4_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data4(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick4(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next4(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round4(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick4(got, st, sid)

def h2_resp.acked3(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round4(sock, st, buf, sid)

def h2_resp.head3.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round4(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head3.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head3.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head3(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head3.done(sock, st, sid, buf, end, hd)

def h2_resp.data3.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round4(sock, st, buf, sid)

def h2_resp.data3(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data3.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.head3_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head3(s2, st, sid, block, rest, end)

def h2_resp.head3_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head3_got(got, st, sid, end)
    case False{}:
      h2_resp.head3(sock, st, sid, payload, buf, end)

def h2_resp.next3(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round4(sock, st, buf, sid)
        case 6:
          h2_resp.round4(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked3(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked3(sent, st, sid, buf)
        case 2:
          h2_resp.head3_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data3(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick3(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next3(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round3(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick3(got, st, sid)

def h2_resp.acked2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round3(sock, st, buf, sid)

def h2_resp.data2.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round3(sock, st, buf, sid)

def h2_resp.data2(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data2.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.head2.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round3(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head2.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head2.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head2(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head2.done(sock, st, sid, buf, end, hd)

def h2_resp.head2_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head2(s2, st, sid, block, rest, end)

def h2_resp.head2_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head2_got(got, st, sid, end)
    case False{}:
      h2_resp.head2(sock, st, sid, payload, buf, end)

def h2_resp.next2(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round3(sock, st, buf, sid)
        case 6:
          h2_resp.round3(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked2(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked2(sent, st, sid, buf)
        case 2:
          h2_resp.head2_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data2(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick2(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next2(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round2(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick2(got, st, sid)

def h2_resp.acked1(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round2(sock, st, buf, sid)

def h2_resp.data1.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round2(sock, st, buf, sid)

def h2_resp.data1(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data1.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.head1.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round2(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head1.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head1.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head1(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head1.done(sock, st, sid, buf, end, hd)

def h2_resp.head1_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head1(s2, st, sid, block, rest, end)

def h2_resp.head1_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head1_got(got, st, sid, end)
    case False{}:
      h2_resp.head1(sock, st, sid, payload, buf, end)

def h2_resp.next1(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round2(sock, st, buf, sid)
        case 6:
          h2_resp.round2(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked1(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked1(sent, st, sid, buf)
        case 2:
          h2_resp.head1_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data1(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick1(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next1(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round1(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick1(got, st, sid)

def h2_resp.data0.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.finish(sock, st)
    case False{}:
      h2_resp.round1(sock, st, buf, sid)

def h2_resp.data0(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    st2 : H2RespSt = h2_resp.st_add(st, payload)
    h2_resp.data0.fin(sock, st2, sid, buf, end, U32.is_eq(end, 1))

def h2_resp.acked0(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round1(sock, st, buf, sid)

def h2_resp.head0.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, +tab: HpDyn, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round1(sock, H2RespSt{Some{head}, Nil{}, tab}, buf, sid)

def h2_resp.head0.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{(+head, +tab)}:
      h2_resp.head0.fin(sock, st, sid, buf, end, head, tab, U32.is_eq(end, 1))

def h2_resp.head0(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head & HpDyn> = h2_head.decode(payload, h2_resp.st_hp(st))
    h2_resp.head0.done(sock, st, sid, buf, end, hd)

def h2_resp.head0_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2RespSt, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{e}))
    case Done{H2Cont{+block, +rest}}:
      h2_resp.head0(s2, st, sid, block, rest, end)

def h2_resp.head0_pre(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +flags: U32, +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid, payload, buf)
        h2_resp.head0_got(got, st, sid, end)
    case False{}:
      h2_resp.head0(sock, st, sid, payload, buf, end)

def h2_resp.next0(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round1(sock, st, buf, sid)
        case 6:
          h2_resp.round1(sock, st, buf, sid)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "bad window_update")}))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked0(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked0(sent, st, sid, buf)
        case 2:
          h2_resp.head0_pre(sock, st, sid, payload, buf, flags, U32.and(flags, h2_f_end_stream()), h2_needs_cont(1, flags))
        case 3:
          h2_resp.data0(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 5:
          h2_resp.goaway_fin(sock, st)
        case 7:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "rst_stream")}))
        case 8:
          h2_resp.goaway_fail(sock, 1, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "goaway")}))

def h2_resp.pick0(got: Socket & H2Got, +st: H2RespSt, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_resp.next0(s2, st, sid, frame, buf, h2_resp.classify(frame, sid))

def h2_resp.round0(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_resp.pick0(got, st, sid)

# Response entry drain: skips unbounded housekeeping (leftover
# WINDOW_UPDATEs from our own upload, late SETTINGS ACKs, PINGs)
# before the chain starts, so a late HEADERS never overflows the
# finite round budget. Returns the carrier holding the first stream
# HEADERS/DATA. Skips never ack (Bend never acks; Node never blocks
# on a missing ack mid-exchange); GOAWAY and bad WINDOW_UPDATE fail.
# Narrow single-@unsafe loop (5 params): phase 0 reads or
# decomposes one frame, phase 1 dispatches on cls.
@unsafe
def h2_resp.drain(+phase: U32, +sid: U32, prev: Socket & H2Got, +buf: List<&2, U32>, +cls: U32) ->
  IO(Socket & H2Got):
  match phase:
    case 0:
      (s0, g0) = prev
      match g0:
        case H2GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & H2Got>:
                got2 : Socket & H2Got <- h2_read_frame(s0, buf)
                h2_resp.drain(0, sid, got2, buf, 0)
            case _:
              IO.pure(Socket & H2Got, (s0, H2GotErr{code, msg}))
        case H2GotOk{+frame, +buf2}:
          h2_resp.drain(1, sid, (s0, H2GotOk{frame, buf2}), buf2, h2_resp.classify(frame, sid))
    case _:
      (s1, g1) = prev
      match cls:
        case 2:
          IO.pure(Socket & H2Got, (s1, g1))
        case 3:
          IO.pure(Socket & H2Got, (s1, g1))
        case 5:
          IO.pure(Socket & H2Got, (s1, H2GotErr{502, "goaway"}))
        case 7:
          IO.pure(Socket & H2Got, (s1, H2GotErr{502, "rst_stream"}))
        case 8:
          IO.pure(Socket & H2Got, (s1, H2GotErr{502, "continuation"}))
        case 9:
          IO.pure(Socket & H2Got, (s1, H2GotErr{502, "bad window_update"}))
        case _:
          h2_resp.drain(0, sid, (s1, H2GotErr{0, "next"}), buf, 0)

def h2_resp.drain_done(got: Socket & H2Got, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  h2_resp.pick0(got, H2RespSt{None{}, Nil{}, hp_empty()}, sid)

def h2_request.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{u}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        got : Socket & H2Got <- h2_resp.drain(0, sid, (sock, H2GotErr{0, "next"}), Nil{}, 0)
        h2_resp.drain_done(got, sid)

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
      h2_request.data(sock, sid, body, Nat.is_eq(b_len(body), 0n))

def h2_request.send(sock: Socket, +sid: U32, +method: String, +path: String, hs: List<&2, H2Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_headers(), h2_f_end_headers(), sid, h2_request.head(method, path, hs))
    h2_request.body(sent, sid, body)

def h2_b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def h2_srv.preface_ok(+buf: List<&2, U32>) -> U32:
  b_eq(b_take(24n, buf), h2_preface())

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
        flags : U32 = (h2_f_end_headers() + h2_b2u(Nat.is_eq(b_len(body), 0n)) : U32)
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_headers(), flags, sid, hpack_block(hs))
        h2_srv.resp_body(sent, sid, body, Nat.is_eq(b_len(body), 0n))

def h2_srv.st_hp(+st: H2SrvSt) -> HpDyn:
  match st:
    case H2SrvSt{head, body, sid, hp}:
      hp

def h2_srv.st_add_head(+st: H2SrvSt, +head: H2ReqHead) -> H2SrvSt:
  match st:
    case H2SrvSt{old_head, +body, +sid, +hp}:
      H2SrvSt{Some{head}, body, sid, hp}

def h2_srv.st_add_body(+st: H2SrvSt, +pay: List<&2, U32>) -> H2SrvSt:
  match st:
    case H2SrvSt{+head, +body, +sid, +hp}:
      H2SrvSt{head, List.append(&2, U32, body, pay), sid, hp}

# Phase 4: aborting a stream keeps the connection alive. Reset drops
# the pending head/body and frees the slot but preserves the
# connection HPACK table.
def h2_srv.rst_reset(+st: H2SrvSt) -> H2SrvSt:
  match st:
    case H2SrvSt{head, body, sid, hp}:
      H2SrvSt{None{}, Nil{}, 0, hp}

def h2_srv.goaway_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +tab: HpDyn, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s, Fail{e}, tab))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s, Fail{(502, msg)}, tab))

def h2_srv.goaway_fail(sock: Socket, +wire: U32, +tab: HpDyn, +msg: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_goaway(sock, 0, wire)
    h2_srv.goaway_sent(sent, tab, msg)

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

def h2_srv.conn_cls.wu(+payload: List<&2, U32>) -> U32:
  h2_srv.cls_wu_ok(h2_window_update_ok(payload))

# Phase 4: the old even-sid branch skipped everything, so the server
# never acked PING (node:http2 pinging Bend timed out) and never
# acked fresh SETTINGS. Connection-level frames now surface: 1
# SETTINGS (ack), 4 PING (ack), 5 GOAWAY (graceful), 7/9 WU.
# Fresh-only (same ACK ping-pong guard as the client): stale ACK
# echoes skip.
def h2_srv.conn_cls(+typ: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 4:
      h2_resp.set_ack(U32.is_eq(U32.and(flags, h2_f_ack()), 0))
    case 6:
      h2_resp.ping_ack(U32.is_eq(U32.and(flags, h2_f_ack()), 0))
    case 7:
      5
    case 8:
      h2_srv.conn_cls.wu(payload)
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

def h2_srv.cls(+typ: U32, +sid2: U32, +flags: U32, +payload: List<&2, U32>) -> U32:
  h2_srv.cls_odd(typ, U32.and(sid2, 1), flags, payload)

def h2_srv.classify(+frame: H2Frame) -> U32:
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      h2_srv.cls(typ, sid2, flags, payload)

# Server DATA-run leaves: request projection (pure) and
# send-receipt wrap, mirroring answer2/answer3.wrap without looping.
def h2_srv.tail_req(+rh: H2ReqHead, +body: List<&2, U32>) -> H2Request:
  match rh:
    case H2ReqHead{+method, +path, +headers}:
      H2Request{method, path, headers, body}

def h2_srv.tail_req_head(head: Maybe<&2, H2ReqHead>, +body: List<&2, U32>) ->
  Result<&1, &1, U32 & String, H2Request>:
  match head:
    case None{}:
      Fail{(502, "no request head")}
    case Some{+rh}:
      Done{h2_srv.tail_req(rh, body)}

def h2_srv.tail_req_st(+st: H2SrvSt) -> Result<&1, &1, U32 & String, H2Request>:
  match st:
    case H2SrvSt{head, body, sid, hp}:
      h2_srv.tail_req_head(head, body)

def h2_srv.tail_wrapped(sent: Socket & Result<&1, &1, U32 & String, Unit>, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s, Fail{e}, tab))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s, Done{u}, tab))

# Unbounded server DATA run: takes over where round6 fails so a long
# request body never hits "request too long". Same narrow shape as
# h2_resp.data_run, plus the handler, the HPACK table ledger and an
# answer phase. PING is skipped here (rounds ack it); RST resets the
# stream, unexpected CONTINUATION fails after a GOAWAY.
@unsafe
def h2_srv.data_run(+phase: U32, +st: H2SrvSt, +buf: List<&2, U32>, prev: Socket & H2Got, +cls: U32, +is_end: Bool, +dlen: U32, +payload: List<&2, U32>, +sid2: U32, hreq: Result<&1, &1, U32 & String, H2Request>, +tab: HpDyn, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match phase:
    case 0:
      (s0, g0) = prev
      match g0:
        case H2GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
                got2 : Socket & H2Got <- h2_read_frame(s0, buf)
                h2_srv.data_run(0, st, buf, got2, 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s0, Fail{(code, msg)}, hp_empty()))
        case H2GotOk{+frame, +buf2}:
          match frame:
            case H2Frame{+typ, +flags, +sid22, +payload2}:
              h2_srv.data_run(1, st, buf2, (s0, H2GotOk{H2Frame{typ, flags, sid22, payload2}, buf2}), h2_srv.cls(typ, sid22, flags, payload2), U32.is_eq(U32.and(flags, h2_f_end_stream()), h2_f_end_stream()), U32.from_nat(b_len(payload2)), payload2, sid22, Fail{(0, "")}, tab, handler)
    case 1:
      (s1, g1) = prev
      match cls:
        case 6:
          h2_srv.data_run(2, h2_srv.st_add_body(st, payload), buf, (s1, g1), cls, is_end, dlen, Nil{}, sid2, Fail{(0, "")}, tab, handler)
        case 0:
          h2_srv.data_run(0, st, buf, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
        case 1:
          h2_srv.data_run(0, st, buf, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
        case 7:
          h2_srv.data_run(0, st, buf, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
        case 2:
          h2_srv.data_run(0, H2SrvSt{None{}, Nil{}, 0, tab}, buf, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
        case 4:
          h2_srv.data_run(0, st, buf, (s1, H2GotErr{0, "next"}), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s1, Fail{(502, "goaway")}, hp_empty()))
        case 8:
          h2_srv.goaway_fail(s1, 1, tab, "continuation")
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s1, Fail{(502, "request too long")}, hp_empty()))
    case 2:
      (s2, g2) = prev
      match is_end:
        case True{}:
          h2_srv.data_run(4, H2SrvSt{None{}, Nil{}, 0, hp_empty()}, buf, (s2, g2), cls, is_end, dlen, Nil{}, sid2, h2_srv.tail_req_st(st), tab, handler)
        case False{}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_wu_len(s2, sid2, dlen)
            h2_srv.data_run(0, st, buf, h2_wu_best_effort(sent), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, tab, handler)
    case 3:
      (sx, gx) = prev
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sx, Fail{(502, "bad phase")}, hp_empty()))
    case _:
      (s4, g4) = prev
      match hreq:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s4, Fail{e}, hp_empty()))
        case Done{+req}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            resp : H2Response <- handler(req)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_srv.send_resp(s4, sid2, resp)
            h2_srv.tail_wrapped(sent, tab)

def h2_srv.round6(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.data_run(0, st, buf, (sock, H2GotErr{0, "next"}), 0, False{}, 0, Nil{}, 0, Fail{(0, "")}, h2_srv.st_hp(st), handler)

def h2_srv.answer3.wrap(m: Socket & Result<&1, &1, U32 & String, Unit>, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s, Fail{e}, tab))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s, Done{u}, tab))

def h2_srv.answer3.send(sock: Socket, +sid: U32, +resp: H2Response, +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_srv.send_resp(sock, sid, resp)
    h2_srv.answer3.wrap(sent, tab)

def h2_srv.answer3(sock: Socket, +rh: H2ReqHead, +body: List<&2, U32>, +sid: U32, handler: H2Request -> IO(H2Response), +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match rh:
    case H2ReqHead{+method, +path, +headers}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        req : H2Request = H2Request{method, path, headers, body}
        resp : H2Response <- handler(req)
        h2_srv.answer3.send(sock, sid, resp, tab)


def h2_srv.answer2(sock: Socket, head: Maybe<&2, H2ReqHead>, +body: List<&2, U32>, +sid: U32, handler: H2Request -> IO(H2Response), +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match head:
    case None{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "no request head")}, hp_empty()))
    case Some{+rh}:
      h2_srv.answer3(sock, rh, body, sid, handler, tab)


def h2_srv.answer(sock: Socket, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match st:
    case H2SrvSt{+head, +body, +sid, +hp}:
      h2_srv.answer2(sock, head, body, sid, handler, hp)

# Graceful GOAWAY (RFC 9113 section 7.1): a pending request still
# runs to completion; with no stream open the serve succeeds
# empty-handed so the caller closes instead of failing.
def h2_srv.goaway_open(sock: Socket, head: Maybe<&2, H2ReqHead>, +body: List<&2, U32>, +sid: U32, +hp: HpDyn, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match head:
    case Some{+rh}:
      h2_srv.answer(sock, H2SrvSt{Some{rh}, body, sid, hp}, handler)
    case None{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Done{Unit{}}, hp))

def h2_srv.goaway_fin(sock: Socket, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match st:
    case H2SrvSt{head, body, sid, hp}:
      h2_srv.goaway_open(sock, head, body, sid, hp, handler)

def h2_srv.head5.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round6(sock, st, buf, handler)

def h2_srv.head5.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{(+rh, +tab2)}:
      h2_srv.head5.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2, tab2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.data5.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round6(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data5.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_data:
    case True{}:
      h2_srv.data5.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round6(sock, st, buf, handler)

def h2_srv.head5_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{H2Cont{+block, +rest}}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(block, h2_srv.st_hp(st))
        h2_srv.head5.done(s2, st, typ, flags, sid2, block, rest, handler, end, hd)

def h2_srv.head5_pre(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid2, payload, buf)
        h2_srv.head5_got(got, st, typ, flags, sid2, handler, end)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, h2_srv.st_hp(st))
        h2_srv.head5.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)

def h2_srv.stream5.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_head:
    case True{}:
      h2_srv.head5_pre(sock, st, typ, flags, sid2, payload, buf, handler, end, h2_needs_cont(typ, flags))
    case False{}:
      h2_srv.data5.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream5(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.stream5.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked5(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(c, m)}, hp_empty()))
    case Done{u}:
      h2_srv.round6(sock, st, buf, handler)

def h2_srv.next5(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round6(sock, st, buf, handler)
        case 7:
          h2_srv.round6(sock, st, buf, handler)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "bad window_update")}, hp_empty()))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked5(sent, st, buf, handler)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_srv.acked5(sent, st, buf, handler)
        case 5:
          h2_srv.goaway_fin(sock, st, handler)
        case 2:
          h2_srv.round6(sock, h2_srv.rst_reset(st), buf, handler)
        case 8:
          h2_srv.goaway_fail(sock, 1, h2_srv.st_hp(st), "continuation")
        case 6:
          h2_srv.stream5(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round6(sock, st, buf, handler)

def h2_srv.pick5(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{(code, msg)}, hp_empty()))
    case H2GotOk{+frame, buf}:
      h2_srv.next5(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round5(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick5(got, st, handler)

def h2_srv.acked4(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(c, m)}, hp_empty()))
    case Done{u}:
      h2_srv.round5(sock, st, buf, handler)

def h2_srv.data4.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round5(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data4.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_data:
    case True{}:
      h2_srv.data4.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round5(sock, st, buf, handler)

def h2_srv.head4.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round5(sock, st, buf, handler)

def h2_srv.head4.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{(+rh, +tab2)}:
      h2_srv.head4.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2, tab2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.head4_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{H2Cont{+block, +rest}}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(block, h2_srv.st_hp(st))
        h2_srv.head4.done(s2, st, typ, flags, sid2, block, rest, handler, end, hd)

def h2_srv.head4_pre(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid2, payload, buf)
        h2_srv.head4_got(got, st, typ, flags, sid2, handler, end)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, h2_srv.st_hp(st))
        h2_srv.head4.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)

def h2_srv.stream4.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_head:
    case True{}:
      h2_srv.head4_pre(sock, st, typ, flags, sid2, payload, buf, handler, end, h2_needs_cont(typ, flags))
    case False{}:
      h2_srv.data4.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream4(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.stream4.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.next4(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round5(sock, st, buf, handler)
        case 7:
          h2_srv.round5(sock, st, buf, handler)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "bad window_update")}, hp_empty()))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked4(sent, st, buf, handler)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_srv.acked4(sent, st, buf, handler)
        case 5:
          h2_srv.goaway_fin(sock, st, handler)
        case 2:
          h2_srv.round5(sock, h2_srv.rst_reset(st), buf, handler)
        case 8:
          h2_srv.goaway_fail(sock, 1, h2_srv.st_hp(st), "continuation")
        case 6:
          h2_srv.stream4(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round5(sock, st, buf, handler)

def h2_srv.pick4(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{(code, msg)}, hp_empty()))
    case H2GotOk{+frame, buf}:
      h2_srv.next4(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round4(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick4(got, st, handler)

def h2_srv.head3.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round4(sock, st, buf, handler)

def h2_srv.head3.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{(+rh, +tab2)}:
      h2_srv.head3.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2, tab2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.data3.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round4(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data3.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_data:
    case True{}:
      h2_srv.data3.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round4(sock, st, buf, handler)

def h2_srv.head3_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{H2Cont{+block, +rest}}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(block, h2_srv.st_hp(st))
        h2_srv.head3.done(s2, st, typ, flags, sid2, block, rest, handler, end, hd)

def h2_srv.head3_pre(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid2, payload, buf)
        h2_srv.head3_got(got, st, typ, flags, sid2, handler, end)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, h2_srv.st_hp(st))
        h2_srv.head3.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)

def h2_srv.stream3.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_head:
    case True{}:
      h2_srv.head3_pre(sock, st, typ, flags, sid2, payload, buf, handler, end, h2_needs_cont(typ, flags))
    case False{}:
      h2_srv.data3.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream3(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.stream3.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked3(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(c, m)}, hp_empty()))
    case Done{u}:
      h2_srv.round4(sock, st, buf, handler)

def h2_srv.next3(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round4(sock, st, buf, handler)
        case 7:
          h2_srv.round4(sock, st, buf, handler)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "bad window_update")}, hp_empty()))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked3(sent, st, buf, handler)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_srv.acked3(sent, st, buf, handler)
        case 5:
          h2_srv.goaway_fin(sock, st, handler)
        case 2:
          h2_srv.round4(sock, h2_srv.rst_reset(st), buf, handler)
        case 8:
          h2_srv.goaway_fail(sock, 1, h2_srv.st_hp(st), "continuation")
        case 6:
          h2_srv.stream3(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round4(sock, st, buf, handler)

def h2_srv.pick3(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{(code, msg)}, hp_empty()))
    case H2GotOk{+frame, buf}:
      h2_srv.next3(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round3(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick3(got, st, handler)

def h2_srv.data2.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round3(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data2.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_data:
    case True{}:
      h2_srv.data2.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round3(sock, st, buf, handler)

def h2_srv.head2.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round3(sock, st, buf, handler)

def h2_srv.head2.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{(+rh, +tab2)}:
      h2_srv.head2.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2, tab2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.head2_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{H2Cont{+block, +rest}}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(block, h2_srv.st_hp(st))
        h2_srv.head2.done(s2, st, typ, flags, sid2, block, rest, handler, end, hd)

def h2_srv.head2_pre(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid2, payload, buf)
        h2_srv.head2_got(got, st, typ, flags, sid2, handler, end)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, h2_srv.st_hp(st))
        h2_srv.head2.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)

def h2_srv.stream2.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_head:
    case True{}:
      h2_srv.head2_pre(sock, st, typ, flags, sid2, payload, buf, handler, end, h2_needs_cont(typ, flags))
    case False{}:
      h2_srv.data2.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream2(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.stream2.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(c, m)}, hp_empty()))
    case Done{u}:
      h2_srv.round3(sock, st, buf, handler)

def h2_srv.next2(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round3(sock, st, buf, handler)
        case 7:
          h2_srv.round3(sock, st, buf, handler)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "bad window_update")}, hp_empty()))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked2(sent, st, buf, handler)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_srv.acked2(sent, st, buf, handler)
        case 5:
          h2_srv.goaway_fin(sock, st, handler)
        case 2:
          h2_srv.round3(sock, h2_srv.rst_reset(st), buf, handler)
        case 8:
          h2_srv.goaway_fail(sock, 1, h2_srv.st_hp(st), "continuation")
        case 6:
          h2_srv.stream2(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round3(sock, st, buf, handler)

def h2_srv.pick2(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{(code, msg)}, hp_empty()))
    case H2GotOk{+frame, buf}:
      h2_srv.next2(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round2(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick2(got, st, handler)

def h2_srv.head1.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round2(sock, st, buf, handler)

def h2_srv.head1.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{(+rh, +tab2)}:
      h2_srv.head1.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2, tab2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.data1.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round2(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data1.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_data:
    case True{}:
      h2_srv.data1.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round2(sock, st, buf, handler)

def h2_srv.head1_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{H2Cont{+block, +rest}}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(block, h2_srv.st_hp(st))
        h2_srv.head1.done(s2, st, typ, flags, sid2, block, rest, handler, end, hd)

def h2_srv.head1_pre(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid2, payload, buf)
        h2_srv.head1_got(got, st, typ, flags, sid2, handler, end)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, h2_srv.st_hp(st))
        h2_srv.head1.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)

def h2_srv.stream1.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_head:
    case True{}:
      h2_srv.head1_pre(sock, st, typ, flags, sid2, payload, buf, handler, end, h2_needs_cont(typ, flags))
    case False{}:
      h2_srv.data1.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream1(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.stream1.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked1(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(c, m)}, hp_empty()))
    case Done{u}:
      h2_srv.round2(sock, st, buf, handler)

def h2_srv.next1(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round2(sock, st, buf, handler)
        case 7:
          h2_srv.round2(sock, st, buf, handler)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "bad window_update")}, hp_empty()))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked1(sent, st, buf, handler)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_srv.acked1(sent, st, buf, handler)
        case 5:
          h2_srv.goaway_fin(sock, st, handler)
        case 2:
          h2_srv.round2(sock, h2_srv.rst_reset(st), buf, handler)
        case 8:
          h2_srv.goaway_fail(sock, 1, h2_srv.st_hp(st), "continuation")
        case 6:
          h2_srv.stream1(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round2(sock, st, buf, handler)

def h2_srv.pick1(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{(code, msg)}, hp_empty()))
    case H2GotOk{+frame, buf}:
      h2_srv.next1(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round1(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick1(got, st, handler)

def h2_srv.data0.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round1(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data0.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_data:
    case True{}:
      h2_srv.data0.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round1(sock, st, buf, handler)

def h2_srv.head0.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round1(sock, st, buf, handler)

def h2_srv.head0.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead & HpDyn>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{(+rh, +tab2)}:
      h2_srv.head0.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2, tab2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.head0_got(got: Socket & Result<&1, &1, U32 & String, H2Cont>, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = got
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{H2Cont{+block, +rest}}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(block, h2_srv.st_hp(st))
        h2_srv.head0.done(s2, st, typ, flags, sid2, block, rest, handler, end, hd)

def h2_srv.head0_pre(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, needs: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match needs:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        got : Socket & Result<&1, &1, U32 & String, H2Cont> <- h2_cont_start(sock, sid2, payload, buf)
        h2_srv.head0_got(got, st, typ, flags, sid2, handler, end)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        hd : Result<&1, &1, U32 & String, H2ReqHead & HpDyn> = h2_reqhead.decode(payload, h2_srv.st_hp(st))
        h2_srv.head0.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)

def h2_srv.stream0.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match is_head:
    case True{}:
      h2_srv.head0_pre(sock, st, typ, flags, sid2, payload, buf, handler, end, h2_needs_cont(typ, flags))
    case False{}:
      h2_srv.data0.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream0(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.stream0.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked0(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(c, m)}, hp_empty()))
    case Done{u}:
      h2_srv.round1(sock, st, buf, handler)

def h2_srv.next0(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round1(sock, st, buf, handler)
        case 7:
          h2_srv.round1(sock, st, buf, handler)
        case 9:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(502, "bad window_update")}, hp_empty()))
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked0(sent, st, buf, handler)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_srv.acked0(sent, st, buf, handler)
        case 5:
          h2_srv.goaway_fin(sock, st, handler)
        case 2:
          h2_srv.round1(sock, h2_srv.rst_reset(st), buf, handler)
        case 8:
          h2_srv.goaway_fail(sock, 1, h2_srv.st_hp(st), "continuation")
        case 6:
          h2_srv.stream0(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round1(sock, st, buf, handler)

def h2_srv.pick0(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{(code, msg)}, hp_empty()))
    case H2GotOk{+frame, buf}:
      h2_srv.next0(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.build(+rh: H2ReqHead, +body: List<&2, U32>) -> H2Request:
  match rh:
    case H2ReqHead{+method, +path, +headers}:
      H2Request{method, path, headers, body}

def h2_srv.round0(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick0(got, st, handler)

def h2_srv.preface4(sent: Socket & Result<&1, &1, U32 & String, Unit>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{e}, hp_empty()))
    case Done{u}:
      h2_srv.round0(sock, H2SrvSt{None{}, Nil{}, 0, hp_empty()}, b_drop(24n, buf), handler)

def h2_srv.preface3b(sock: Socket, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match ok:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), 0, 0, h2_settings_initial_pay())
        h2_srv.preface4(sent, buf, handler)
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (sock, Fail{(503, "bad preface")}, hp_empty()))

def h2_srv.preface3(sock: Socket, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), magic: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.preface3b(sock, buf, handler, U32.is_eq(magic, 1))

def h2_srv.preface2(sock: Socket, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    magic : U32 = h2_srv.preface_ok(buf)
    h2_srv.preface3(sock, buf, handler, magic)

def h2_serve_once.got2(r2: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +chunk: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = r2
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{chunk2}:
      h2_srv.preface2(s2, List.append(&2, U32, chunk, chunk2), handler)


def h2_serve_once.short(sock: Socket, +chunk: List<&2, U32>, handler: H2Request -> IO(H2Response), short: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  match short:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
        r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        h2_serve_once.got2(r2, chunk, handler)
    case False{}:
      h2_srv.preface2(sock, chunk, handler)

def h2_serve_once.got1(r1: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  (s2, r) = r1
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn, (s2, Fail{e}, hp_empty()))
    case Done{+chunk}:
      h2_serve_once.short(s2, chunk, handler, Nat.is_lt(b_len(chunk), 24n))

def h2_serve_once(sock: Socket, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    h2_serve_once.got1(r1, handler)

def h2_connect_insecure(host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  do IO<Result<&1, &1, U32 & String, Socket>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(host, port)
    h2_connect.go(conn)

# h2_request: one request/response exchange on stream sid (1, 3, 5,
# ...). The caller threads the socket and the next sid.

def h2_request(sock: Socket, +sid: U32, +method: String, +path: String, hs: List<&2, H2Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  h2_request.send(sock, sid, method, path, hs, body)

# h2_serve_next: like h2_serve_once but for an ESTABLISHED connection
# (preface + SETTINGS already exchanged by a first h2_serve_once).
# Serves one more request stream and hands the socket back, so a caller
# threads socket + fuel for sequential keep-alive (sid 1, 3, 5, ... on
# one TLS connection, no new handshake). Fail codes match serve_once.

def h2_serve_next.got(got: Socket & H2Got, handler: H2Request -> IO(H2Response), +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  h2_srv.pick0(got, H2SrvSt{None{}, Nil{}, 0, tab}, handler)

def h2_serve_next(sock: Socket, handler: H2Request -> IO(H2Response), +tab: HpDyn) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & HpDyn):
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & HpDyn>:
    got : Socket & H2Got <- h2_read_frame(sock, Nil{})
    h2_serve_next.got(got, handler, tab)
