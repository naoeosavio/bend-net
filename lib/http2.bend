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
  H2RespSt{head: Maybe<&2, H2Head>, body: List<&2, U32>}

type H2Response is Data:
  H2Response{status: U32, headers: List<&2, H2Hdr>, body: List<&2, U32>}

type H2Request is Data:
  H2Request{method: String, path: String, headers: List<&2, H2Hdr>, body: List<&2, U32>}

type H2SrvSt is Data:
  H2SrvSt{head: Maybe<&2, H2ReqHead>, body: List<&2, U32>, sid: U32}

type H2Frame is Data:
  H2Frame{typ: U32, flags: U32, sid: U32, payload: List<&2, U32>}

type H2FrameOut is Data:
  H2FrameOk{frame: H2Frame, rest: List<&2, U32>}
  H2NeedMore{missing: Nat}
  H2FrameBad{code: U32, msg: String}

type HdrGot is Data:
  HdrGot{name: String, value: String, rest: List<&2, U32>}

type H2Buf is Data:
  H2BufOk{buf: List<&2, U32>}
  H2BufErr{code: U32, msg: String}

type H2Got is Data:
  H2GotOk{frame: H2Frame, buf: List<&2, U32>}
  H2GotErr{code: U32, msg: String}


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

def u32_of4.go(b3: U32, b2: U32, b1: U32, b0: U32) -> U32:
  (((b3 * 16777216 + b2 * 65536 + b1 * 256 + b0 : U32)))

def u32_of4(b3: U32, b2: U32, b1: U32, b0: U32) -> U32:
  u32_of4.go(b3, b2, b1, b0)

def h2_frame.fin4(typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, len: U32) -> H2FrameOut:
  +n = U32.to_nat(len)
  H2NeedMore{(n - b_len(b_take(n, rest)) : Nat)}

def h2_frame.fin3(typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, len: U32) -> H2FrameOut:
  +n = U32.to_nat(len)
  +taken = b_take(n, rest)
  H2FrameOk{H2Frame{typ, flags, sid, taken}, b_drop(n, rest)}

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
      h2_frame.go2(typ, flags, sid, rest7, len24, U32.is_le(len24, 16384))
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

def hpack_int.dec.more(+f: Nat, more: Bool) -> Nat:
  match more:
    case True{}:
      f
    case False{}:
      0n

def hpack_int.dec.fin(+fuel: Nat, acc: U32, +rest: List<&2, U32>) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match fuel:
    case 0n:
      Done{(acc, rest)}
    case 1n+f:
      Fail{(400, "hpack eof")}

def hpack_int.dec.go2(+rest: List<&2, U32>, +fuel: Nat, acc: U32, +m: U32) -> Result<&1, &1, U32 & String, U32 & List<&2, U32>>:
  match rest:
    case Nil{}:
      hpack_int.dec.fin(fuel, acc, rest)
    case +b <> rest2:
      +acc2 = (acc + m * U32.and(b, 127) : U32)
      hpack_int.dec.go2(rest2, hpack_int.dec.more(fuel, U32.is_eq(U32.and(b, 128), 128)), acc2, (m * 128 : U32))

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
      hpack_str.dec.len(n, rest, U32.is_le(n, 4096))

def hpack_str.dec.huf(+b0: U32, +rest2: List<&2, U32>, huf: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match huf:
    case True{}:
      Fail{(502, "huffman refused")}
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

def hpack_hdr.done(name: String, r: Result<&1, &1, U32 & String, String & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(value, rest)}:
      Done{HdrGot{name, value, rest}}

def hpack_hdr.lit.name(r: Result<&1, &1, U32 & String, String & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(name, rest2)}:
      r2 = hpack_str.dec.go(rest2)
      hpack_hdr.done(name, r2)

def hpack_hdr.lit.staticname(+idx: U32, +in_static: Bool, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match in_static:
    case True{}:
      r2 = hpack_str.dec.go(rest)
      hpack_hdr.done(hp_static_name(idx), r2)
    case False{}:
      Fail{(502, "hpack dynamic name refused")}

def hpack_hdr.lit.idxname(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest)}:
      hpack_hdr.lit.staticname(idx, U32.is_le(idx, 61), rest)

def hpack_hdr.lit.go3(b0: U32, rest: List<&2, U32>, low: U32) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match low:
    case 0:
      r = hpack_str.dec.go(rest)
      hpack_hdr.lit.name(r)
    case _:
      r = hpack_int.dec6(b0, rest)
      hpack_hdr.lit.idxname(r)

def hpack_hdr.lit(+b0: U32, +rest: List<&2, U32>) -> Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.lit.go3(b0, rest, U32.and(b0, 15))

def hpack_hdr.indexed.done(sp: String & String) -> Result<&1, &1, U32 & String, HdrGot>:
  (n, v) = sp
  Done{HdrGot{n, v, Nil{}}}

def hpack_hdr.indexed.go(idx: U32, ok: Bool) -> Result<&1, &1, U32 & String, HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack dynamic ref refused")}
    case True{}:
      hpack_hdr.indexed.done(hp_static_pair(idx))

def hpack_hdr.indexed.go2(b0: U32, ok: Bool) -> Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.indexed.go(U32.and(b0, 127), ok)

def hpack_hdr.go3(+b0: U32, +rest: List<&2, U32>, kind: U32) ->
  Result<&1, &1, U32 & String, HdrGot>:
  match kind:
    case 0:
      hpack_hdr.lit(b0, rest)
    case 1:
      hpack_hdr.lit(b0, rest)
    case 2:
      Fail{(502, "hpack table update refused")}
    case 3:
      hpack_hdr.indexed.go2(b0, U32.is_le(U32.and(b0, 127), 61))
    case _:
      hpack_hdr.lit(b0, rest)

def hpack_hdr.go2(b0: U32, rest: List<&2, U32>, top: U32) ->
  Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.go3(b0, rest, top)

def hpack_hdr.go(+b0: U32, +rest: List<&2, U32>) -> Result<&1, &1, U32 & String, HdrGot>:
  hpack_hdr.go2(b0, rest, U32.and(U32.shrn(b0, 4n), 15))

def hpack_hdr.dec(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, HdrGot>:
  match bs:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest:
      hpack_hdr.go(b0, rest)

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

def h2_round.done4(sock: Socket, +buf: List<&2, U32>, out: H2FrameOut) -> IO(Socket & H2Got):
  match out:
    case H2FrameOk{frame, rest}:
      IO.pure(Socket & H2Got, (sock, H2GotOk{frame, rest}))
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{code, msg}))
    case _:
      IO.pure(Socket & H2Got, (sock, H2GotErr{400, "eof"}))

def h2_round4(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_round.done4(sock, buf, h2_frame_read(buf))

def h2_round.eof3(sock: Socket, +buf: List<&2, U32>, +chunk: List<&2, U32>, +missing: Nat, is_eof: Bool) ->
  IO(Socket & H2Got):
  match is_eof:
    case True{}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{400, "eof"}))
    case False{}:
      h2_round4(sock, b_append(buf, chunk))

def h2_round.after3(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>, +missing: Nat) ->
  IO(Socket & H2Got):
  (s2, r) = got
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & H2Got, (s2, H2GotErr{c, m}))
    case Done{+chunk}:
      h2_round.eof3(s2, buf, chunk, missing, Nat.is_eq(b_len(chunk), 0n))

def h2_round.done3(sock: Socket, +buf: List<&2, U32>, out: H2FrameOut) -> IO(Socket & H2Got):
  match out:
    case H2FrameOk{frame, rest}:
      IO.pure(Socket & H2Got, (sock, H2GotOk{frame, rest}))
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{code, msg}))
    case H2NeedMore{missing}:
      do IO<Socket & H2Got>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        h2_round.after3(got, buf, missing)

def h2_round3(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_round.done3(sock, buf, h2_frame_read(buf))

def h2_round.eof2(sock: Socket, +buf: List<&2, U32>, +chunk: List<&2, U32>, +missing: Nat, is_eof: Bool) ->
  IO(Socket & H2Got):
  match is_eof:
    case True{}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{400, "eof"}))
    case False{}:
      h2_round3(sock, b_append(buf, chunk))

def h2_round.after2(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>, +missing: Nat) ->
  IO(Socket & H2Got):
  (s2, r) = got
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & H2Got, (s2, H2GotErr{c, m}))
    case Done{+chunk}:
      h2_round.eof2(s2, buf, chunk, missing, Nat.is_eq(b_len(chunk), 0n))

def h2_round.done2(sock: Socket, +buf: List<&2, U32>, out: H2FrameOut) -> IO(Socket & H2Got):
  match out:
    case H2FrameOk{frame, rest}:
      IO.pure(Socket & H2Got, (sock, H2GotOk{frame, rest}))
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{code, msg}))
    case H2NeedMore{missing}:
      do IO<Socket & H2Got>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        h2_round.after2(got, buf, missing)

def h2_round2(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_round.done2(sock, buf, h2_frame_read(buf))

def h2_round.eof1(sock: Socket, +buf: List<&2, U32>, +chunk: List<&2, U32>, +missing: Nat, is_eof: Bool) ->
  IO(Socket & H2Got):
  match is_eof:
    case True{}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{400, "eof"}))
    case False{}:
      h2_round2(sock, b_append(buf, chunk))

def h2_round.after1(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>, +missing: Nat) ->
  IO(Socket & H2Got):
  (s2, r) = got
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & H2Got, (s2, H2GotErr{c, m}))
    case Done{+chunk}:
      h2_round.eof1(s2, buf, chunk, missing, Nat.is_eq(b_len(chunk), 0n))

def h2_round.done1(sock: Socket, +buf: List<&2, U32>, out: H2FrameOut) -> IO(Socket & H2Got):
  match out:
    case H2FrameOk{frame, rest}:
      IO.pure(Socket & H2Got, (sock, H2GotOk{frame, rest}))
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{code, msg}))
    case H2NeedMore{missing}:
      do IO<Socket & H2Got>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        h2_round.after1(got, buf, missing)

def h2_round1(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_round.done1(sock, buf, h2_frame_read(buf))

def h2_round.eof0(sock: Socket, +buf: List<&2, U32>, +chunk: List<&2, U32>, +missing: Nat, is_eof: Bool) ->
  IO(Socket & H2Got):
  match is_eof:
    case True{}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{400, "eof"}))
    case False{}:
      h2_round1(sock, b_append(buf, chunk))

def h2_round.after0(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>, +missing: Nat) ->
  IO(Socket & H2Got):
  (s2, r) = got
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & H2Got, (s2, H2GotErr{c, m}))
    case Done{+chunk}:
      h2_round.eof0(s2, buf, chunk, missing, Nat.is_eq(b_len(chunk), 0n))

def h2_round.done0(sock: Socket, +buf: List<&2, U32>, out: H2FrameOut) -> IO(Socket & H2Got):
  match out:
    case H2FrameOk{frame, rest}:
      IO.pure(Socket & H2Got, (sock, H2GotOk{frame, rest}))
    case H2FrameBad{code, msg}:
      IO.pure(Socket & H2Got, (sock, H2GotErr{code, msg}))
    case H2NeedMore{missing}:
      do IO<Socket & H2Got>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        h2_round.after0(got, buf, missing)

def h2_round0(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_round.done0(sock, buf, h2_frame_read(buf))

def h2_read_frame(sock: Socket, buf: List<&2, U32>) -> IO(Socket & H2Got):
  h2_round0(sock, buf)

def h2_send_frame(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, h2_frame_write(typ, flags, sid, pay))

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

@unsafe def h2_head.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: H2Head) ->
  Result<&1, &1, U32 & String, H2Head>:
  match fuel:
    case 0n:
      Fail{(502, "too many headers")}
    case 1n+f:
      match phase:
        case 0:
          match bs:
            case Nil{}:
              Done{st}
            case _:
              h2_head.go(f, 1, bs, hpack_hdr.dec(bs), "", "", st)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HdrGot{+name, +value, rrest}}:
              h2_head.go(f, 2, rrest, Fail{(0, "")}, name, value, st)
        case _:
          +st2 = h2_head.apply(st, name, value, String.eq(name, ":status"))
          h2_head.go(f, 0, bs, r, "", "", st2)

def h2_head.decode(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, H2Head>:
  h2_head.go(64n, 0, bs, Fail{(0, "")}, "", "", H2Head{0, Nil{}})

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

@unsafe def h2_reqhead.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HdrGot>, +name: String, +value: String, st: H2ReqHead) ->
  Result<&1, &1, U32 & String, H2ReqHead>:
  match fuel:
    case 0n:
      Fail{(502, "too many headers")}
    case 1n+f:
      match phase:
        case 0:
          match bs:
            case Nil{}:
              Done{st}
            case _:
              h2_reqhead.go(f, 1, bs, hpack_hdr.dec(bs), "", "", st)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HdrGot{+name, +value, rrest}}:
              h2_reqhead.go(f, 2, rrest, Fail{(0, "")}, name, value, st)
        case _:
          +st2 = h2_reqhead.apply(st, name, value, String.eq(name, ":method"), String.eq(name, ":path"))
          h2_reqhead.go(f, 0, bs, r, "", "", st2)

def h2_reqhead.decode(bs: List<&2, U32>) -> Result<&1, &1, U32 & String, H2ReqHead>:
  h2_reqhead.go(64n, 0, bs, Fail{(0, "")}, "", "", H2ReqHead{"", "", Nil{}})

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
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, b_append(h2_preface(), h2_settings_empty()))
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

def h2_resp.cls2(+typ: U32, +flags: U32, +payload: List<&2, U32>, mine: Bool) -> U32:
  match mine:
    case True{}:
      h2_resp.cls3(typ)
    case False{}:
      0

def h2_resp.classify(+frame: H2Frame, +sid: U32) -> U32:
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      h2_resp.cls2(typ, flags, payload, Bool.and(U32.is_eq(sid2, sid), U32.is_gt(sid2, 0)))






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
    case H2RespSt{head, body}:
      h2_resp.finish2(sock, head, body)


def h2_resp.st_add(+st: H2RespSt, +pay: List<&2, U32>) -> H2RespSt:
  match st:
    case H2RespSt{+head, +body}:
      H2RespSt{head, List.append(&2, U32, body, pay)}





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

































































def h2_resp.round8(sock: Socket, +st: H2RespSt, +buf: List<&2, U32>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(502, "response too long")}))



def h2_resp.head7.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round8(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head7.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head7.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head7(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
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

def h2_resp.next7(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round8(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked7(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked7(sent, st, sid, buf)
        case 2:
          h2_resp.head7(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data7(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head6.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round7(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head6.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head6.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head6(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
    h2_resp.head6.done(sock, st, sid, buf, end, hd)

def h2_resp.acked6(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_resp.round7(sock, st, buf, sid)

def h2_resp.next6(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round7(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked6(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked6(sent, st, sid, buf)
        case 2:
          h2_resp.head6(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data6(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head5.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round6(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head5.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head5.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head5(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
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

def h2_resp.next5(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round6(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked5(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked5(sent, st, sid, buf)
        case 2:
          h2_resp.head5(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data5(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head4.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round5(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head4.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head4.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head4(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
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

def h2_resp.next4(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round5(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked4(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked4(sent, st, sid, buf)
        case 2:
          h2_resp.head4(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data4(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head3.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round4(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head3.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head3.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head3(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
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

def h2_resp.next3(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round4(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked3(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked3(sent, st, sid, buf)
        case 2:
          h2_resp.head3(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data3(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head2.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round3(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head2.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head2.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head2(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
    h2_resp.head2.done(sock, st, sid, buf, end, hd)

def h2_resp.next2(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round3(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked2(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked2(sent, st, sid, buf)
        case 2:
          h2_resp.head2(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data2(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head1.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round2(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head1.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head1.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head1(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
    h2_resp.head1.done(sock, st, sid, buf, end, hd)

def h2_resp.next1(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round2(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked1(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked1(sent, st, sid, buf)
        case 2:
          h2_resp.head1(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data1(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_resp.head0.fin(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, +head: H2Head, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_end:
    case True{}:
      h2_resp.head_done(sock, head, Nil{})
    case False{}:
      h2_resp.round1(sock, H2RespSt{Some{head}, Nil{}}, buf, sid)

def h2_resp.head0.done(sock: Socket, +st: H2RespSt, +sid: U32, +buf: List<&2, U32>, +end: U32, hd: Result<&1, &1, U32 & String, H2Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{+head}:
      h2_resp.head0.fin(sock, st, sid, buf, end, head, U32.is_eq(end, 1))

def h2_resp.head0(sock: Socket, +st: H2RespSt, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
    hd : Result<&1, &1, U32 & String, H2Head> = h2_head.decode(payload)
    h2_resp.head0.done(sock, st, sid, buf, end, hd)

def h2_resp.next0(sock: Socket, +st: H2RespSt, +sid: U32, +frame: H2Frame, +buf: List<&2, U32>, cls: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_resp.round1(sock, st, buf, sid)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_resp.acked0(sent, st, sid, buf)
        case 4:
          do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_ping(), h2_f_ack(), 0, payload)
            h2_resp.acked0(sent, st, sid, buf)
        case 2:
          h2_resp.head0(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
        case 3:
          h2_resp.data0(sock, st, sid, payload, buf, U32.and(flags, h2_f_end_stream()))
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

def h2_request.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, H2Response>, (sock, Fail{e}))
    case Done{u}:
      h2_resp.round0(sock, H2RespSt{None{}, Nil{}}, Nil{}, sid)

def h2_request.data(sock: Socket, +sid: U32, +body: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, H2Response>):
  match is_empty:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_data(), h2_f_end_stream(), sid, Nil{})
        h2_request.sent(sent, sid)
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, H2Response>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_data(), h2_f_end_stream(), sid, body)
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
      h2_send_frame(sock, h2_t_data(), h2_f_end_stream(), sid, body)

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

def h2_srv.st_add_head(+st: H2SrvSt, +head: H2ReqHead) -> H2SrvSt:
  match st:
    case H2SrvSt{old_head, +body, +sid}:
      H2SrvSt{Some{head}, body, sid}

def h2_srv.st_add_body(+st: H2SrvSt, +pay: List<&2, U32>) -> H2SrvSt:
  match st:
    case H2SrvSt{+head, +body, +sid}:
      H2SrvSt{head, List.append(&2, U32, body, pay), sid}

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

def h2_srv.cls2(+typ: U32, +odd: U32, is_odd: Bool) -> U32:
  match is_odd:
    case True{}:
      h2_srv.cls3(typ)
    case False{}:
      0

def h2_srv.cls_odd(+typ: U32, +odd: U32) -> U32:
  h2_srv.cls2(typ, odd, U32.is_eq(odd, 1))

def h2_srv.cls(+typ: U32, +sid2: U32) -> U32:
  h2_srv.cls_odd(typ, U32.and(sid2, 1))

def h2_srv.classify(+frame: H2Frame) -> U32:
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      h2_srv.cls(typ, sid2)

def h2_srv.round6(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "request too long")}))

def h2_srv.answer3(sock: Socket, +rh: H2ReqHead, +body: List<&2, U32>, +sid: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match rh:
    case H2ReqHead{+method, +path, +headers}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        req : H2Request = H2Request{method, path, headers, body}
        resp : H2Response <- handler(req)
        h2_srv.send_resp(sock, sid, resp)


def h2_srv.answer2(sock: Socket, head: Maybe<&2, H2ReqHead>, +body: List<&2, U32>, +sid: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match head:
    case None{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "no request head")}))
    case Some{+rh}:
      h2_srv.answer3(sock, rh, body, sid, handler)


def h2_srv.answer(sock: Socket, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match st:
    case H2SrvSt{+head, +body, +sid}:
      h2_srv.answer2(sock, head, body, sid, handler)

def h2_srv.head5.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round6(sock, st, buf, handler)

def h2_srv.head5.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{+rh}:
      h2_srv.head5.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.data5.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round6(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data5.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_data:
    case True{}:
      h2_srv.data5.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round6(sock, st, buf, handler)

def h2_srv.stream5.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_head:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hd : Result<&1, &1, U32 & String, H2ReqHead> = h2_reqhead.decode(payload)
        h2_srv.head5.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)
    case False{}:
      h2_srv.data5.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream5(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.stream5.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked5(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_srv.round6(sock, st, buf, handler)

def h2_srv.next5(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round6(sock, st, buf, handler)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked5(sent, st, buf, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "goaway")}))
        case 6:
          h2_srv.stream5(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round6(sock, st, buf, handler)

def h2_srv.pick5(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_srv.next5(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round5(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick5(got, st, handler)

def h2_srv.acked4(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_srv.round5(sock, st, buf, handler)

def h2_srv.data4.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round5(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data4.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_data:
    case True{}:
      h2_srv.data4.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round5(sock, st, buf, handler)

def h2_srv.head4.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round5(sock, st, buf, handler)

def h2_srv.head4.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{+rh}:
      h2_srv.head4.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.stream4.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_head:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hd : Result<&1, &1, U32 & String, H2ReqHead> = h2_reqhead.decode(payload)
        h2_srv.head4.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)
    case False{}:
      h2_srv.data4.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream4(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.stream4.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.next4(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round5(sock, st, buf, handler)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked4(sent, st, buf, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "goaway")}))
        case 6:
          h2_srv.stream4(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round5(sock, st, buf, handler)

def h2_srv.pick4(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_srv.next4(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round4(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick4(got, st, handler)

def h2_srv.head3.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round4(sock, st, buf, handler)

def h2_srv.head3.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{+rh}:
      h2_srv.head3.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.data3.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round4(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data3.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_data:
    case True{}:
      h2_srv.data3.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round4(sock, st, buf, handler)

def h2_srv.stream3.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_head:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hd : Result<&1, &1, U32 & String, H2ReqHead> = h2_reqhead.decode(payload)
        h2_srv.head3.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)
    case False{}:
      h2_srv.data3.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream3(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.stream3.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked3(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_srv.round4(sock, st, buf, handler)

def h2_srv.next3(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round4(sock, st, buf, handler)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked3(sent, st, buf, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "goaway")}))
        case 6:
          h2_srv.stream3(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round4(sock, st, buf, handler)

def h2_srv.pick3(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_srv.next3(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round3(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick3(got, st, handler)

def h2_srv.data2.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round3(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data2.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_data:
    case True{}:
      h2_srv.data2.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round3(sock, st, buf, handler)

def h2_srv.head2.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round3(sock, st, buf, handler)

def h2_srv.head2.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{+rh}:
      h2_srv.head2.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.stream2.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_head:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hd : Result<&1, &1, U32 & String, H2ReqHead> = h2_reqhead.decode(payload)
        h2_srv.head2.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)
    case False{}:
      h2_srv.data2.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream2(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.stream2.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_srv.round3(sock, st, buf, handler)

def h2_srv.next2(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round3(sock, st, buf, handler)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked2(sent, st, buf, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "goaway")}))
        case 6:
          h2_srv.stream2(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round3(sock, st, buf, handler)

def h2_srv.pick2(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_srv.next2(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round2(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick2(got, st, handler)

def h2_srv.head1.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round2(sock, st, buf, handler)

def h2_srv.head1.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{+rh}:
      h2_srv.head1.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.data1.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round2(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data1.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_data:
    case True{}:
      h2_srv.data1.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round2(sock, st, buf, handler)

def h2_srv.stream1.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_head:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hd : Result<&1, &1, U32 & String, H2ReqHead> = h2_reqhead.decode(payload)
        h2_srv.head1.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)
    case False{}:
      h2_srv.data1.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream1(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.stream1.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked1(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_srv.round2(sock, st, buf, handler)

def h2_srv.next1(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round2(sock, st, buf, handler)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked1(sent, st, buf, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "goaway")}))
        case 6:
          h2_srv.stream1(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round2(sock, st, buf, handler)

def h2_srv.pick1(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_srv.next1(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.round1(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick1(got, st, handler)

def h2_srv.data0.fin(sock: Socket, +st: H2SrvSt, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, h2_srv.st_add_body(st, payload), handler)
    case False{}:
      h2_srv.round1(sock, h2_srv.st_add_body(st, payload), buf, handler)

def h2_srv.data0.done(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_data: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_data:
    case True{}:
      h2_srv.data0.fin(sock, st, sid2, payload, buf, handler, end, U32.is_eq(end, 1))
    case False{}:
      h2_srv.round1(sock, st, buf, handler)

def h2_srv.head0.fin(sock: Socket, +st: H2SrvSt, +typ: U32, +sid2: U32, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_end: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_end:
    case True{}:
      h2_srv.answer(sock, st, handler)
    case False{}:
      h2_srv.round1(sock, st, buf, handler)

def h2_srv.head0.done(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, hd: Result<&1, &1, U32 & String, H2ReqHead>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match hd:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{+rh}:
      h2_srv.head0.fin(sock, H2SrvSt{Some{rh}, Nil{}, sid2}, typ, sid2, buf, handler, end, U32.is_eq(end, 1))

def h2_srv.stream0.go(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32, is_head: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match is_head:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        hd : Result<&1, &1, U32 & String, H2ReqHead> = h2_reqhead.decode(payload)
        h2_srv.head0.done(sock, st, typ, flags, sid2, payload, buf, handler, end, hd)
    case False{}:
      h2_srv.data0.done(sock, st, typ, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_data()))

def h2_srv.stream0(sock: Socket, +st: H2SrvSt, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.stream0.go(sock, st, typ, flags, sid2, payload, buf, handler, end, U32.is_eq(typ, h2_t_headers()))

def h2_srv.acked0(sent: Socket & Result<&1, &1, U32 & String, Unit>, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{(c, m)}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(c, m)}))
    case Done{u}:
      h2_srv.round1(sock, st, buf, handler)

def h2_srv.next0(sock: Socket, +st: H2SrvSt, +frame: H2Frame, +buf: List<&2, U32>, cls: U32, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match frame:
    case H2Frame{+typ, +flags, +sid2, +payload}:
      match cls:
        case 0:
          h2_srv.round1(sock, st, buf, handler)
        case 1:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), h2_f_ack(), 0, Nil{})
            h2_srv.acked0(sent, st, buf, handler)
        case 5:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(502, "goaway")}))
        case 6:
          h2_srv.stream0(sock, st, typ, flags, sid2, payload, buf, handler, U32.and(flags, h2_f_end_stream()))
        case _:
          h2_srv.round1(sock, st, buf, handler)

def h2_srv.pick0(got: Socket & H2Got, +st: H2SrvSt, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, g) = got
  match g:
    case H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{(code, msg)}))
    case H2GotOk{+frame, buf}:
      h2_srv.next0(s2, st, frame, buf, h2_srv.classify(frame), handler)

def h2_srv.build(+rh: H2ReqHead, +body: List<&2, U32>) -> H2Request:
  match rh:
    case H2ReqHead{+method, +path, +headers}:
      H2Request{method, path, headers, body}

def h2_srv.round0(sock: Socket, +st: H2SrvSt, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, buf)
    h2_srv.pick0(got, st, handler)

def h2_srv.preface4(sent: Socket & Result<&1, &1, U32 & String, Unit>, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{e}))
    case Done{u}:
      h2_srv.round0(sock, H2SrvSt{None{}, Nil{}, 0}, b_drop(24n, buf), handler)

def h2_srv.preface3b(sock: Socket, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match ok:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- h2_send_frame(sock, h2_t_settings(), 0, 0, Nil{})
        h2_srv.preface4(sent, buf, handler)
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Fail{(503, "bad preface")}))

def h2_srv.preface3(sock: Socket, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response), magic: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.preface3b(sock, buf, handler, U32.is_eq(magic, 1))

def h2_srv.preface2(sock: Socket, +buf: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    magic : U32 = h2_srv.preface_ok(buf)
    h2_srv.preface3(sock, buf, handler, magic)

def h2_serve_once.got2(r2: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +chunk: List<&2, U32>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, r) = r2
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{e}))
    case Done{chunk2}:
      h2_srv.preface2(s2, List.append(&2, U32, chunk, chunk2), handler)


def h2_serve_once.short(sock: Socket, +chunk: List<&2, U32>, handler: H2Request -> IO(H2Response), short: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match short:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        h2_serve_once.got2(r2, chunk, handler)
    case False{}:
      h2_srv.preface2(sock, chunk, handler)

def h2_serve_once.got1(r1: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s2, r) = r1
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s2, Fail{e}))
    case Done{+chunk}:
      h2_serve_once.short(s2, chunk, handler, Nat.is_lt(b_len(chunk), 24n))

def h2_serve_once(sock: Socket, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
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

def h2_serve_next.got(got: Socket & H2Got, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  h2_srv.pick0(got, H2SrvSt{None{}, Nil{}, 0}, handler)

def h2_serve_next(sock: Socket, handler: H2Request -> IO(H2Response)) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    got : Socket & H2Got <- h2_read_frame(sock, Nil{})
    h2_serve_next.got(got, handler)
