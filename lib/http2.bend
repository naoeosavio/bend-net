# HTTP2: the H2 wire and its lanes (RFC 9113/7541). It owns the 9-byte
# frame parser, the HPACK codec (Huffman and the dynamic table), the
# SETTINGS, PING, GOAWAY, RST_STREAM and WINDOW_UPDATE frames, the flow
# pump, the client loop and the server loops.
#
# Public format: <name>.<form><cardinality><transport>. Empty form is
# buffered, `stream` is events; cardinality is once (1), on (N in order)
# and concurrent (N in flight); empty transport is TLS/ALPN, `_insecure`
# is TLS without chain verification.
#
# Client entries, in this order:
#   client.connect, client.stream.once, client.stream.on,
#   client.stream.concurrent, client.request, request, request_bytes,
#   fetch, fetch_bytes, client.once, client.on, client.concurrent.
# One client loop, two modes: `client.loop` carries `+mode` (`on` runs one
# exchange at a time, `concurrent` keeps N streams in flight), and the
# mode picks the act table. `client.loop.on` is the ordered lane over the
# mode `on`; `client.loop.concurrent` is the projection of the mode
# `concurrent`. `client.stream.once` is that ordered lane with one request.
#
# Dial owner: the client dials itself. TLS.tls_connect offers h2 alone and
# answers 615 on a peer that does not answer h2; the client sends the
# preface. The server accepts here too, through `TLS.tls_accept` behind the
# six accept entries. Each side owns its transport; no facade sits in the
# path, and the core (./http.bend) owns the types.
#
# Server entries, in this order:
#   server.stream.once / .on / .concurrent   stream form (pure handler)
#   server.once / .on / .concurrent          buffered form (IO handler)
# One loop, two forms and two admission modes: `server.loop` takes the pure
# handler (~H) and the IO handler (~B), and the form picks the act table.
# `on` serves one stream at a time for a connection and refuses a second
# HEADERS with RST_STREAM 7 (REFUSED_STREAM) after decoding its block,
# because the HPACK table is the connection's; `concurrent` interleaves
# every open stream.
#
# Callee above caller; match scrutinees are params or pattern-bound vars;
# self-recursion only, and @unsafe keeps the fuel-bounded loops.
#
# Import as: import ./http2.bend as HTTP2 (from lib).
import Base
import ./http.bend as HTTP
import ./tls.bend as TLS

# Consts
# ------

def x_f_ack() -> U32:
  1

def x_f_end_stream() -> U32:
  1

def x_f_end_headers() -> U32:
  4

# The flag tests of the frame loops, named.
def x_fin(flags: U32) -> U32:
  U32.and(flags, x_f_end_stream())

def x_fin_hdr(flags: U32) -> U32:
  U32.and(flags, x_f_end_headers())

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

# The cap of one header block, in bytes: the HEADERS frame plus every
# CONTINUATION of the same block. RFC 9113 puts no cap on a block, so the
# peer picks it; 64 KiB holds a request with a large cookie and still
# stops a peer that never sets END_HEADERS.
def x_max_block() -> U32:
  65536

# The cap of open streams of one connection. The server announces it in
# SETTINGS (id 3) and enforces it at admission with RST_STREAM 7
# (REFUSED_STREAM), so the connection lives and the peer may retry the
# refused stream (RFC 9113 section 6.5.2 and 8.7).
# shortcut: our client never reads the peer SETTINGS, so a batch of more
# than 100 requests on one connection fails on the refused streams; read
# SETTINGS in the client when a caller needs bigger batches.
def x_max_streams() -> U32:
  100

# The cap of a buffered body, in bytes, for one stream. The buffered form
# holds the whole request in memory. One body byte costs one cons cell per
# spine, so the peer controls the total. The total needs a bound. Past the
# cap the lane answers RST_STREAM 8 (CANCEL) and drops the stream. The
# handler never sees the request. A body past the cap belongs on the
# stream lane.
# shortcut: the count is the declared DATA length, padding included; use
# the stream lanes for a body past the cap.
def x_max_body() -> U32:
  16777216

# True when a DATA frame of LEN bytes pushes a body of N bytes past the
# cap of x_max_body().
def x_body_over(+n: U32, +len: U32) -> Bool:
  U32.is_gt((n + len : U32), x_max_body())

# The two admission modes of the server stream loop. `on` serves one
# stream at a time per connection and refuses a second HEADERS with
# RST_STREAM 7 (REFUSED_STREAM); `concurrent` interleaves every open
# stream of the connection.
def x_mode.on() -> U32:
  0

def x_mode.concurrent() -> U32:
  1

# The two forms of the server loop. `stream` answers each event with the
# pure handler; `buffered` collects the whole request and answers it once
# with the IO handler. The act tables carry the form; the loop only reads
# the act.
def x_form.stream() -> U32:
  1

def x_form.buffered() -> U32:
  0

# The handler a form does not use. The stream form never calls the IO one,
# and the buffered form never calls the event one.
def server.no_event(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  HTTP.Continue{}

def server.no_buffered(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{0, Nil{}, Nil{}})

def x_b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" as bytes (no String compare needed).
def x_preface() -> List<&2, U32>:
  [80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10]

# Initial SETTINGS we announce (RFC 9113 section 6.5), in ascending id
# order: ENABLE_PUSH 0 (this library serves no pushed stream, and a peer
# must not push), MAX_CONCURRENT_STREAMS 100 (the cap server.admit
# enforces), INITIAL_WINDOW_SIZE 65535 and MAX_FRAME_SIZE 65535 (dono
# decision; Chrome announces 6MB but 65535 is the RFC default and what node
# uses). Sent at all 4 preface points; ACKs stay empty (ack-with-payload
# would be a protocol error).
def x_be16(+v: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(v, 8n), 255), U32.and(v, 255)]

def x_settings_initial_pay() -> List<&2, U32>:
  +head : List<&2, U32> = List.append(&2, U32, List.append(&2, U32, x_be16(2), HTTP.x_be32(0)), List.append(&2, U32, x_be16(3), HTTP.x_be32(x_max_streams())))
  +tail : List<&2, U32> = List.append(&2, U32, List.append(&2, U32, x_be16(4), HTTP.x_be32(x_init_window())), List.append(&2, U32, x_be16(5), HTTP.x_be32(x_max_str())))
  List.append(&2, U32, head, tail)

# True when the open header block plus one more fragment passes
# x_max_block(). Both lists are byte lists, so the two lengths are the
# block so far and the new fragment.
def x_block_over(+old: List<&2, U32>, +new: List<&2, U32>) -> Bool:
  U32.is_gt((HTTP.x_len32(old) + HTTP.x_len32(new) : U32), x_max_block())

# Frame write
# -----------

def x_frame_write.hdr(+len: U32, +typ: U32, +flags: U32, +sid: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(len, 16n), 255), U32.and(U32.shrn(len, 8n), 255), U32.and(len, 255),
   U32.and(typ, 255), U32.and(flags, 255),
   U32.and(U32.shrn(sid, 24n), 255), U32.and(U32.shrn(sid, 16n), 255),
   U32.and(U32.shrn(sid, 8n), 255), U32.and(sid, 255)]

def x_frame_write_len(+typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>, +len: U32) -> List<&2, U32>:
  # List.append recurses on the header, nine cells, whatever the payload
  # holds: measured at 78 ms for a 1 MiB payload with the length walk in.
  List.append(&2, U32, x_frame_write.hdr(len, typ, flags, sid), pay)

def x_frame_write(+typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> List<&2, U32>:
  x_frame_write_len(typ, flags, sid, pay, HTTP.x_len32(pay))

def x_send_frame(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, x_frame_write(typ, flags, sid, pay))

# The steady DATA turn knows the payload length from the pump, so it skips
# the second walk and shares the header append above.
def x_send_frame_len(sock: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>, +len: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, x_frame_write_len(typ, flags, sid, pay, len))

def x_send_goaway.pay(+last: U32, +code: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_be32(last), HTTP.x_be32(code))

def x_send_goaway(sock: Socket, +last: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_goaway(), 0, 0, x_send_goaway.pay(last, code))

# Frame parse (split-safe: NeedMore carries the missing count)
# ------------------------------------------------------------

def x_strip_pad.go(+pay: List<&2, U32>, +n: U32, +m: U32) -> List<&2, U32>:
  HTTP.x_take32(n, HTTP.x_drop32(m, pay))

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
      HTTP.x_drop32(5, pay)

# A DATA frame keeps its padding in the payload: the flow credit counts
# the declared length of the frame (RFC 9113 section 6.9.1), so the
# padding must still be there when the loop credits it. x_data_body strips
# it where the body itself is read.
def x_has_pad(+typ: U32, +flags: U32) -> Bool:
  match typ:
    case 0:
      False{}
    case _:
      U32.is_eq(U32.and(flags, 8), 8)

def x_frame_payload(+pay: List<&2, U32>, +typ: U32, +flags: U32, +len: U32) -> List<&2, U32>:
  x_strip_prio(x_strip_pad(pay, x_has_pad(typ, flags), len), U32.is_eq(U32.and(flags, 32), 32))

# The body of a DATA frame: the declared payload minus its padding. An
# unpadded frame is handed over untouched, so the length walk runs only for
# the padded case; the eager argument used to walk every 16 KiB DATA payload
# (bench_h2: strip_lazy 22 ms against strip_eager 74 ms on 2.5 MiB).
def x_data_body.dec(padded: Bool, +payload: List<&2, U32>) -> List<&2, U32>:
  match padded:
    case False{}:
      payload
    case True{}:
      x_strip_pad(payload, True{}, HTTP.x_len32(payload))

def x_data_body(+payload: List<&2, U32>, +flags: U32) -> List<&2, U32>:
  x_data_body.dec(U32.is_eq(U32.and(flags, 8), 8), payload)

# END_STREAM is flag bit 0, and it is the protocol-neutral fin of the
# shared outcome.
def x_frame.end_of(+flags: U32) -> Bool:
  U32.is_eq(x_fin(flags), 1)

# The 3 length bytes and the 4 stream id bytes of the frame header
# (RFC 9113 section 4.1), as arithmetic. They are here, and not written
# twice, because this lane has two readers of the header: the walk below,
# which peels the bytes off a shrinking buffer one at a time, and
# x_frame_of, which reads them by position out of a whole frame. Same two
# numbers, one code each.
def x_frame.len3(+l0: U32, +l1: U32, +l2: U32) -> U32:
  (l0 * 65536 + l1 * 256 + l2 : U32)

# The R bit is the MSB of the FIRST of the four bytes (RFC 9113 section
# 4.1), so it is s0 that gets masked: masking s3 (the low byte) dropped
# bit 7 of every stream id whose low byte had it set -- sid 129 read back
# as 1, sid 255 as 127 -- which misroutes every frame above the 64th
# stream. TASK-042 phase 5, found while reusing this reader for the
# GOAWAY last-stream-id.
def x_frame.sid4(+s0: U32, +s1: U32, +s2: U32, +s3: U32) -> U32:
  (U32.and(s0, 127) * 16777216 + s1 * 65536 + s2 * 256 + s3 : U32)

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

def x_frame_of(+unit: List<&2, U32>) -> HTTP.Frame:
  +hd = List.take(&2, U32, unit, 9n)
  +len = x_frame.len3(x_frame_of.at_i(hd, 0), x_frame_of.at_i(hd, 1), x_frame_of.at_i(hd, 2))
  +typ = x_frame_of.at_i(hd, 3)
  +flags = x_frame_of.at_i(hd, 4)
  +sid = x_frame.sid4(x_frame_of.at_i(hd, 5), x_frame_of.at_i(hd, 6), x_frame_of.at_i(hd, 7), x_frame_of.at_i(hd, 8))
  HTTP.Frame{typ, flags, sid, len, x_frame_payload(HTTP.x_drop32(9, unit), typ, flags, len)}

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
# The pad length byte is the first payload byte and must stay below the
# declared length (RFC 9113 section 6.1). A frame that pads past its own
# payload is a protocol error, not an empty payload.
def x_frame.pad_ok(payload: List<&2, U32>, +len: U32, padded: Bool) -> Bool:
  match payload padded:
    case _ False{}:
      True{}
    case +p0 <> r True{}:
      U32.is_gt(len, p0)
    case Nil{} True{}:
      False{}

def x_frame.fin4(ok: Bool, got: HTTP.UnitOut) -> HTTP.UnitOut:
  match ok:
    case True{}:
      got
    case False{}:
      HTTP.Bad{1, "bad padding"}

def x_frame.fin3(+orig: List<&2, U32>, +flags: U32, +len: U32) -> HTTP.UnitOut:
  +whole = (9 + len : U32)
  +payload : List<&2, U32> = HTTP.x_take32(whole, orig)
  +padded : Bool = U32.is_eq(U32.and(flags, 8), 8)
  +got : HTTP.UnitOut = HTTP.Got{payload, x_frame.end_of(flags), HTTP.x_drop32(whole, orig)}
  x_frame.fin4(x_frame.pad_ok(HTTP.x_drop32(9, payload), len, padded), got)

# Pad/prio strip (RFC 9113 6.1/6.2): PADDED rides flag 8 with a pad
# length prefix (must be < payload, else protocol error), PRIORITY
# rides flag 32 with a 5-byte fixed field. Frames without the flags come
# through untouched (passthrough gate in x_strip_pad.dec).
def x_frame.fin2(orig: List<&2, U32>, typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32, ok: Bool) ->
  HTTP.UnitOut:
  match ok:
    case True{}:
      x_frame.fin3(orig, flags, len)
    case False{}:
      HTTP.NeedMore{(len - HTTP.x_len_upto(len, rest) : U32), rest}

# "Did the payload arrive?" is asked with has_at_least and answered with
# len_upto — both stop at len — instead of materializing the slice with
# take to measure it and then materializing it again to hand it over
# (TASK-023 Phase 12 item 12.3). x_frame.fin3 is where the frame IS
# materialized, once, from the buffer the walk started with.
def x_frame.fin(orig: List<&2, U32>, typ: U32, flags: U32, sid: U32, +rest: List<&2, U32>, +len: U32) ->
  HTTP.UnitOut:
  x_frame.fin2(orig, typ, flags, sid, rest, len, HTTP.x_has_at_least(len, rest))

def x_frame.len_ok(orig: List<&2, U32>, +len24: U32, +typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>, ok_len: Bool) ->
  HTTP.UnitOut:
  match ok_len:
    case False{}:
      HTTP.Bad{413, "frame too large"}
    case True{}:
      x_frame.fin(orig, typ, flags, sid, rest, len24)

def x_frame.hd9.go(orig: List<&2, U32>, +len24: U32, +typ: U32, +flags: U32, +sid: U32, +rest: List<&2, U32>) ->
  HTTP.UnitOut:
  x_frame.len_ok(orig, len24, typ, flags, sid, rest, U32.is_le(len24, x_max_frame()))

def x_frame.hd9.b8(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +s2: U32, +rest8: List<&2, U32>) -> HTTP.UnitOut:
  match rest8:
    case +s3 <> rest:
      x_frame.hd9.go(orig, x_frame.len3(len_hi, b1, b2), typ, flags, x_frame.sid4(s0, s1, s2, s3), rest)
    case Nil{}:
      HTTP.NeedMore{1, rest8}

def x_frame.hd9.b7(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +s1: U32, +rest7: List<&2, U32>) -> HTTP.UnitOut:
  match rest7:
    case +s2 <> rest8:
      x_frame.hd9.b8(orig, len_hi, b1, b2, typ, flags, s0, s1, s2, rest8)
    case Nil{}:
      HTTP.NeedMore{2, rest7}

def x_frame.hd9.b6(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +s0: U32, +rest6: List<&2, U32>) -> HTTP.UnitOut:
  match rest6:
    case +s1 <> rest7:
      x_frame.hd9.b7(orig, len_hi, b1, b2, typ, flags, s0, s1, rest7)
    case Nil{}:
      HTTP.NeedMore{3, rest6}

def x_frame.hd9.b5(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +flags: U32, +rest5: List<&2, U32>) -> HTTP.UnitOut:
  match rest5:
    case +s0 <> rest6:
      x_frame.hd9.b6(orig, len_hi, b1, b2, typ, flags, s0, rest6)
    case Nil{}:
      HTTP.NeedMore{4, rest5}

def x_frame.hd9.b4(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +typ: U32, +rest4: List<&2, U32>) -> HTTP.UnitOut:
  match rest4:
    case +fl <> rest5:
      x_frame.hd9.b5(orig, len_hi, b1, b2, typ, fl, rest5)
    case Nil{}:
      HTTP.NeedMore{5, rest4}

def x_frame.hd9.b3(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +b2: U32, +rest3: List<&2, U32>) -> HTTP.UnitOut:
  match rest3:
    case +typ <> rest4:
      x_frame.hd9.b4(orig, len_hi, b1, b2, typ, rest4)
    case Nil{}:
      HTTP.NeedMore{6, rest3}

def x_frame.hd9.b2(orig: List<&2, U32>, +len_hi: U32, +b1: U32, +rest2: List<&2, U32>) -> HTTP.UnitOut:
  match rest2:
    case +b2 <> rest3:
      x_frame.hd9.b3(orig, len_hi, b1, b2, rest3)
    case Nil{}:
      HTTP.NeedMore{7, rest2}

def x_frame.hd9.b1(orig: List<&2, U32>, +len_hi: U32, +rest: List<&2, U32>) -> HTTP.UnitOut:
  match rest:
    case +b1 <> rest2:
      x_frame.hd9.b2(orig, len_hi, b1, rest2)
    case Nil{}:
      HTTP.NeedMore{8, rest}

def x_frame.hd9.b0(orig: List<&2, U32>, +rest: List<&2, U32>) -> HTTP.UnitOut:
  match rest:
    case +len_hi <> rest2:
      x_frame.hd9.b1(orig, len_hi, rest2)
    case Nil{}:
      HTTP.NeedMore{9, rest}

def x_parse.short(orig: List<&2, U32>, +bs: List<&2, U32>, +have: U32, short: Bool) -> HTTP.UnitOut:
  match short:
    case True{}:
      HTTP.NeedMore{(9 - have : U32), bs}
    case False{}:
      x_frame.hd9.b0(orig, bs)

# The header's nine bytes are the only thing the walk has to count for
# itself: len_upto(9) answers "short or not" and the exact count when it
# is short, without walking the payload that follows (TASK-023 Phase 12
# item 12.3: the full len for a 9-byte question was the expensive shape).
def x_parse(+bs: List<&2, U32>) -> HTTP.UnitOut:
  +have = HTTP.x_len_upto(9, bs)
  x_parse.short(bs, bs, have, U32.is_lt(have, 9))

# Frame read loop (no flow-credit sends: responses stay small)
# ------------------------------------------------------------

def x_read.done(s: Socket, +chunk: List<&2, U32>, +buf: List<&2, U32>, is_eof: Bool) ->
  Socket & HTTP.UnitOut & List<&2, U32>:
  match is_eof:
    case True{}:
      (s, HTTP.Bad{400, "eof"}, buf)
    case False{}:
      # Tail append: buf grows to one whole frame (up to 65535 bytes), and
      # List.append recurses on it, so a frame past 32768 bytes killed the
      # machine stack. Reverse buf and push it onto the new chunk: two
      # tail passes, same bytes (TASK-063 phase 6b).
      +buf2 = HTTP.x_cat.go(List.reverse(&2, U32, buf), chunk)
      (s, x_parse(buf2), buf2)

def x_read.grow(r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +buf: List<&2, U32>) ->
  Socket & HTTP.UnitOut & List<&2, U32>:
  (s, res) = r
  match res:
    case Fail{(code, msg)}:
      (s, HTTP.Bad{code, msg}, buf)
    case Done{+chunk}:
      x_read.done(s, chunk, buf, List.is_empty(&2, U32, chunk))

@unsafe
def x_read_loop(state: Socket & HTTP.UnitOut & List<&2, U32>) -> IO(Socket & HTTP.Got):
  (s0, out, buf) = state
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      IO.pure(Socket & HTTP.Got, (s0, HTTP.GotOk{x_frame_of(unit), rest}))
    case HTTP.Bad{code, msg}:
      IO.pure(Socket & HTTP.Got, (s0, HTTP.GotErr{code, msg}))
    case HTTP.NeedMore{missing, rest}:
      do IO<Socket & HTTP.Got>:
        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s0, 16384)
        x_read_loop(x_read.grow(r1, buf))
    case HTTP.End{rest}:
      # Nothing in this lane produces End (see the walk's note). If it ever
      # does, the only true reading is "the connection is done", which is
      # the answer the eof already gives.
      IO.pure(Socket & HTTP.Got, (s0, HTTP.GotErr{400, "eof"}))

def x_read_frame(sock: Socket, +buf: List<&2, U32>) -> IO(Socket & HTTP.Got):
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

def x_huff_bits.octet(+b: U32) -> List<&2, U32>:
  [U32.and(U32.shrn(b, 7n), 1), U32.and(U32.shrn(b, 6n), 1),
   U32.and(U32.shrn(b, 5n), 1), U32.and(U32.shrn(b, 4n), 1),
   U32.and(U32.shrn(b, 3n), 1), U32.and(U32.shrn(b, 2n), 1),
   U32.and(U32.shrn(b, 1n), 1), U32.and(b, 1)]

# Bit stream builder, tail-recursive: per-byte work stays bounded by
# the 8-bit frag (reversed push, one un-reverse at the finish), so a
# capped 64 KiB Huffman string answers flat instead of faulting.
def x_huff_bits.go(+bs: List<&2, U32>, acc: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Nil{}:
      HTTP.x_cat(acc)
    case h <> t:
      x_huff_bits.go(t, HTTP.x_rev_push(x_huff_bits.octet(h), acc))

def x_huff_bits(bs: List<&2, U32>) -> List<&2, U32>:
  x_huff_bits.go(bs, Nil{})

def x_huff_hit(+code: U32, +len: U32) -> Bool:
  +i = (len - 5 : U32)
  +cnt = x_huff_nth(x_huff_counts(), i)
  +fst = x_huff_nth(x_huff_firsts(), i)
  Bool.and(U32.is_ge(code, fst), U32.is_lt((code - fst : U32), cnt))

def x_huff_at(+code: U32, +len: U32) -> U32:
  +i = (len - 5 : U32)
  +fst = x_huff_nth(x_huff_firsts(), i)
  x_huff_nth(x_huff_order(), (x_huff_nth(x_huff_starts(), i) + (code - fst : U32) : U32))

# All-ones scan, tail-recursive: the conjunction rides in acc, so a
# 512 Kbit padding scan answers flat.
def x_huff_ones.go(+bits: List<&2, U32>, ok: Bool) -> Bool:
  match bits:
    case Nil{}:
      ok
    case b <> t:
      x_huff_ones.go(t, Bool.and(ok, U32.is_eq(b, 1)))

def x_huff_ones(+bits: List<&2, U32>) -> Bool:
  x_huff_ones.go(bits, True{})

def x_huff_pad(+bits: List<&2, U32>) -> Bool:
  Bool.and(Bool.not(HTTP.x_has_at_least(8, bits)), x_huff_ones(bits))

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
  x_huff_entry.empty(bits, List.is_empty(&2, U32, bits), x_huff_pad(bits))

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
          Done{HTTP.x_cat(acc)}
        case 2:
          Done{HTTP.x_cat(acc)}
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
  x_huff_dec.go(x_huff_decode.fuel(HTTP.x_len(bits)), 0, bits, Nil{}, 0, 0, 0)

# HPACK strings (raw or Huffman; cap 65535)
# -----------------------------------------

def x_str.whole(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>, whole: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match whole:
    case True{}:
      Done{(HTTP.x_bytes_str(taken), HTTP.x_drop32(n, rest))}
    case False{}:
      Fail{(400, "hpack eof str")}

def x_str.fin(+n: U32, +rest: List<&2, U32>, +taken: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  x_str.whole(n, rest, taken, HTTP.x_has_at_least(n, rest))

def x_str.capped(+n: U32, +rest: List<&2, U32>, capped: Bool) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match capped:
    case False{}:
      Fail{(413, "hpack str too large")}
    case True{}:
      x_str.fin(n, rest, HTTP.x_take32(n, rest))

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
      Done{(HTTP.x_bytes_str(bs), rest)}
    case False{}:
      Fail{(400, "hpack eof str")}

def x_str.huffed(+n: U32, +rest: List<&2, U32>, r: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{bs}:
      x_str.huffin(bs, HTTP.x_drop32(n, rest), HTTP.x_has_at_least(n, rest))

def x_str.huf2(+n: U32, +rest: List<&2, U32>) ->
  Result<&1, &1, U32 & String, String & List<&2, U32>>:
  x_str.huffed(n, rest, x_huff_decode(HTTP.x_take32(n, rest)))

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
  List.append(&2, U32, x_int.enc(0, HTTP.x_str_len32(s)), HTTP.x_str_bytes(s))

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

def x_tab.empty() -> HTTP.Tab:
  HTTP.Tab{Nil{}, 0, 4096}

def x_tab.entry_size(+name: String, +value: String) -> U32:
  (HTTP.x_str_len32(name) + HTTP.x_str_len32(value) + 32 : U32)

# Structural eviction (no fuel: recurses on the tail, like x_tab.rev.go;
# the Nil arm returns (Nil,0) — trim only calls with empty ents at size 0).
def x_tab.fit.go(+ents: List<&2, HTTP.Hdr>, fit: Bool, +size: U32, +max: U32) ->
  List<&2, HTTP.Hdr> & U32:
  match ents:
    case Nil{}:
      (Nil{}, 0)
    case HTTP.Hdr{n, v} <> t:
      match fit:
        case True{}:
          (HTTP.Hdr{n, v} <> t, size)
        case False{}:
          +ns = U32.sub(size, x_tab.entry_size(n, v))
          x_tab.fit.go(t, U32.is_le(ns, max), ns, max)

def x_tab.rev.go(+ents: List<&2, HTTP.Hdr>, acc: List<&2, HTTP.Hdr>) -> List<&2, HTTP.Hdr>:
  match ents:
    case Nil{}:
      acc
    case h <> t:
      x_tab.rev.go(t, h <> acc)

def x_tab.rev(+ents: List<&2, HTTP.Hdr>) -> List<&2, HTTP.Hdr>:
  x_tab.rev.go(ents, Nil{})

def x_tab.done(p: List<&2, HTTP.Hdr> & U32, +max: U32) -> HTTP.Tab:
  (kept, sz) = p
  HTTP.Tab{x_tab.rev(kept), sz, max}

def x_tab.trim(+ents: List<&2, HTTP.Hdr>, +size: U32, +max: U32) -> HTTP.Tab:
  +rev = x_tab.rev(ents)
  x_tab.done(x_tab.fit.go(rev, U32.is_le(size, max), size, max), max)

def x_tab.do(+ents: List<&2, HTTP.Hdr>, +size: U32, +max: U32, +name: String, +value: String, +es: U32) -> HTTP.Tab:
  +ns = (size + es : U32)
  x_tab.trim(HTTP.Hdr{name, value} <> ents, ns, max)

def x_tab.ins_fit(+ents: List<&2, HTTP.Hdr>, +size: U32, +max: U32, +name: String, +value: String, fits: Bool, +es: U32) -> HTTP.Tab:
  match fits:
    case False{}:
      HTTP.Tab{Nil{}, 0, max}
    case True{}:
      x_tab.do(ents, size, max, name, value, es)

def x_tab.insert(+tab: HTTP.Tab, +name: String, +value: String) -> HTTP.Tab:
  match tab:
    case HTTP.Tab{+ents, +size, +max}:
      +es = x_tab.entry_size(name, value)
      x_tab.ins_fit(ents, size, max, name, value, U32.is_le(es, max), es)

def x_tab.resize.go(+tab: HTTP.Tab, +max: U32) -> HTTP.Tab:
  match tab:
    case HTTP.Tab{+ents, +size, +old}:
      x_tab.trim(ents, size, max)

def x_tab.resize(+tab: HTTP.Tab, +max: U32) -> HTTP.Tab:
  x_tab.resize.go(tab, max)

# got: bounds-check + fetch in one walk (was lookup.go len-full + at-partial).
def x_tab.lookup.got(+ents: List<&2, HTTP.Hdr>, +k: U32) -> Result<&1, &1, U32 & String, HTTP.Hdr>:
  match ents:
    case Nil{}:
      Fail{(502, "hpack dyn bounds")}
    case HTTP.Hdr{n, v} <> t:
      match k:
        case 0:
          Done{HTTP.Hdr{n, v}}
        case _:
          x_tab.lookup.got(t, (k - 1 : U32))

def x_tab.lookup(+tab: HTTP.Tab, +idx: U32) -> Result<&1, &1, U32 & String, HTTP.Hdr>:
  match tab:
    case HTTP.Tab{+ents, +size, +max}:
      x_tab.lookup.got(ents, idx)

def x_tab.static_hdr(sp: String & String) -> HTTP.Hdr:
  (n, v) = sp
  HTTP.Hdr{n, v}

def x_tab.addr.go(+tab: HTTP.Tab, +idx: U32, is_static: Bool) ->
  Result<&1, &1, U32 & String, HTTP.Hdr>:
  match is_static:
    case True{}:
      Done{x_tab.static_hdr(x_static.go(idx))}
    case False{}:
      x_tab.lookup(tab, (idx - 62 : U32))

def x_tab.addr(+tab: HTTP.Tab, +idx: U32) -> Result<&1, &1, U32 & String, HTTP.Hdr>:
  x_tab.addr.go(tab, idx, U32.is_le(idx, 61))

# One header field (incremental entries update the table)
# -------------------------------------------------------

# The static table lives in x_static.go; this def only shapes the HdrGot
# (task-062 phase 7: one table, not two).
def x_hdr.full.done(hof: String & String, +rest: List<&2, U32>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match hof:
    case (name, value):
      Done{HTTP.HdrGot{name, value, rest, tab}}

def x_hdr.full.go(ok: Bool, +idx: U32, +rest: List<&2, U32>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match ok:
    case True{}:
      x_hdr.full.done(x_static.go(idx), rest, tab)
    case False{}:
      Fail{(502, "hpack dyn")}

def x_hdr.full(+idx: U32, +rest: List<&2, U32>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  x_hdr.full.go(Bool.and(U32.is_ge(idx, 1), U32.is_le(idx, 61)), idx, rest, tab)

def x_hdr.dyn.at(+rest: List<&2, U32>, +tab: HTTP.Tab, r: Result<&1, &1, U32 & String, HTTP.Hdr>) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      match h:
        case HTTP.Hdr{+n, +v}:
          Done{HTTP.HdrGot{n, v, rest, tab}}

def x_hdr.dyn.go(+idx: U32, +rest: List<&2, U32>, +tab: HTTP.Tab, static: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match static:
    case True{}:
      x_hdr.full(idx, rest, tab)
    case False{}:
      x_hdr.dyn.at(rest, tab, x_tab.addr(tab, idx))

def x_hdr.dyn.num(r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest)}:
      x_hdr.dyn.go(idx, rest, tab, U32.is_le(idx, 61))

def x_hdr.lit.put(+name: String, +value: String, +rest: List<&2, U32>, +tab: HTTP.Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match is_incr:
    case False{}:
      Done{HTTP.HdrGot{name, value, rest, tab}}
    case True{}:
      Done{HTTP.HdrGot{name, value, rest, x_tab.insert(tab, name, value)}}

def x_hdr.lit.val(+name: String, +tab: HTTP.Tab, is_incr: Bool, r: Result<&1, &1, U32 & String, String & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(value, rest)}:
      x_hdr.lit.put(name, value, rest, tab, is_incr)

def x_hdr.lit.name(r: Result<&1, &1, U32 & String, String & List<&2, U32>>, +tab: HTTP.Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(name, rest2)}:
      x_hdr.lit.val(name, tab, is_incr, x_str.dec.go(rest2))

def x_hdr.lit.named(+rest: List<&2, U32>, +tab: HTTP.Tab, is_incr: Bool, r: Result<&1, &1, U32 & String, HTTP.Hdr>) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{h}:
      match h:
        case HTTP.Hdr{+n, +v}:
          x_hdr.lit.val(n, tab, is_incr, x_str.dec.go(rest))

def x_hdr.lit.nameat(+idx: U32, +rest: List<&2, U32>, +tab: HTTP.Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  x_hdr.lit.named(rest, tab, is_incr, x_tab.addr(tab, idx))

def x_hdr.lit.zero(+rest: List<&2, U32>, +tab: HTTP.Tab, is_incr: Bool, +idx: U32, is_new: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match is_new:
    case True{}:
      x_hdr.lit.name(x_str.dec.go(rest), tab, is_incr)
    case False{}:
      x_hdr.lit.nameat(idx, rest, tab, is_incr)

def x_hdr.lit.go(+b0: U32, +rest: List<&2, U32>, +tab: HTTP.Tab, r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+idx, +rest2)}:
      x_hdr.lit.zero(rest2, tab, is_incr, idx, U32.is_eq(idx, 0))

def x_hdr.lit(+b0: U32, +rest: List<&2, U32>, is_incr: Bool, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match is_incr:
    case True{}:
      x_hdr.lit.go(b0, rest, tab, x_int.dec.go(b0, 63, rest), True{})
    case False{}:
      x_hdr.lit.go(b0, rest, tab, x_int.dec.go(b0, 15, rest), False{})

def x_hdr.table.sized(+rest: List<&2, U32>, +tab: HTTP.Tab, +ns: U32, ok: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match ok:
    case False{}:
      Fail{(502, "hpack table too big")}
    case True{}:
      Done{HTTP.HdrGot{"", "", rest, x_tab.resize(tab, ns)}}

def x_hdr.table.go(+tab: HTTP.Tab, r: Result<&1, &1, U32 & String, U32 & List<&2, U32>>) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{(+ns, +rest)}:
      x_hdr.table.sized(rest, tab, ns, U32.is_le(ns, 4096))

def x_hdr.after_table(+b0: U32, +rest: List<&2, U32>, +tab: HTTP.Tab, is_table: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match is_table:
    case True{}:
      x_hdr.table.go(tab, x_int.dec.go(b0, 31, rest))
    case False{}:
      x_hdr.lit(b0, rest, False{}, tab)

def x_hdr.after_incr(+b0: U32, +rest: List<&2, U32>, +tab: HTTP.Tab, is_incr: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match is_incr:
    case True{}:
      x_hdr.lit(b0, rest, True{}, tab)
    case False{}:
      x_hdr.after_table(b0, rest, tab, U32.is_ge(b0, 32))

def x_hdr.after_idx(+b0: U32, +rest: List<&2, U32>, +tab: HTTP.Tab, is_idx: Bool) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match is_idx:
    case True{}:
      x_hdr.dyn.num(x_int.dec.go(b0, 127, rest), tab)
    case False{}:
      x_hdr.after_incr(b0, rest, tab, U32.is_ge(b0, 64))

def x_hdr.dec(+bs: List<&2, U32>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.HdrGot>:
  match bs:
    case Nil{}:
      Fail{(400, "hpack eof")}
    case +b0 <> rest:
      x_hdr.after_idx(b0, rest, tab, U32.is_ge(b0, 128))

# Header block -> request head (phased loop, fuel-bounded)
# --------------------------------------------------------

def x_req.pick2(+method: String, +path: String, +headers: List<&2, HTTP.Hdr>, +name: String, +value: String, +is_path: Bool) -> HTTP.ReqHead:
  match is_path:
    case True{}:
      HTTP.ReqHead{method, value, headers}
    case False{}:
      HTTP.ReqHead{method, path, headers}

def x_req.pick(+method: String, +path: String, +headers: List<&2, HTTP.Hdr>, +name: String, +value: String, +is_meth: Bool, +is_path: Bool) -> HTTP.ReqHead:
  match is_meth:
    case True{}:
      HTTP.ReqHead{value, path, headers}
    case False{}:
      x_req.pick2(method, path, headers, name, value, is_path)

def x_req.apply3(+method: String, +path: String, +headers: List<&2, HTTP.Hdr>, +name: String, +value: String, is_meth: Bool, is_path: Bool, pseudo: Bool) -> HTTP.ReqHead:
  match pseudo:
    case True{}:
      x_req.pick(method, path, headers, name, value, is_meth, is_path)
    case False{}:
      HTTP.ReqHead{method, path, List.append(&2, HTTP.Hdr, headers, [HTTP.Hdr{name, value}])}

def x_req.apply2(+method: String, +path: String, +headers: List<&2, HTTP.Hdr>, +name: String, +value: String, +is_meth: Bool, +is_path: Bool) -> HTTP.ReqHead:
  x_req.apply3(method, path, headers, name, value, is_meth, is_path, String.starts_with(name, ":"))

def x_req.apply(+st: HTTP.ReqHead, +name: String, +value: String, is_meth: Bool, is_path: Bool) -> HTTP.ReqHead:
  match st:
    case HTTP.ReqHead{+method, +path, +headers}:
      x_req.apply2(method, path, headers, name, value, is_meth, is_path)

# An empty name is not a field: the HPACK table-size update answers one,
# and the old code appended a phantom Hdr{"", ""} to every block that
# resized the dynamic table.
def x_req.step(empty: Bool, +st: HTTP.ReqHead, +name: String, +value: String, is_meth: Bool, is_path: Bool) -> HTTP.ReqHead:
  match empty:
    case True{}:
      st
    case False{}:
      x_req.apply(st, name, value, is_meth, is_path)

# A request head needs :method and :path (RFC 9113 section 8.3.1). A block
# without them is a decode failure, never a request with empty fields.
# shortcut: CONNECT carries :authority and no :path, so a CONNECT block
# fails here; add the CONNECT arm when the library serves tunnels.
def x_req.done_go(is_meth_empty: Bool, is_path_empty: Bool, +method: String, +path: String, +headers: List<&2, HTTP.Hdr>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>:
  match is_meth_empty is_path_empty:
    case True{} _:
      Fail{(502, "no :method")}
    case _ True{}:
      Fail{(502, "no :path")}
    case _ _:
      Done{(HTTP.ReqHead{method, path, headers}, tab)}

def x_req.done(st: HTTP.ReqHead, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>:
  match st:
    case HTTP.ReqHead{+method, +path, +headers}:
      x_req.done_go(String.eq(method, ""), String.eq(path, ""), method, path, headers, tab)

def x_req.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HTTP.HdrGot>, +name: String, +value: String, st: HTTP.ReqHead, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>:
  match fuel:
    case 0n:
      Fail{(502, "too many headers")}
    case 1n+f:
      match phase:
        case 0:
          match bs:
            case Nil{}:
              x_req.done(st, tab)
            case _:
              x_req.go(f, 1, bs, x_hdr.dec(bs, tab), "", "", st, tab)
        case 1:
          match r:
            case Fail{e}:
              Fail{e}
            case Done{HTTP.HdrGot{+n, +v, +rrest, +tab2}}:
              x_req.go(f, 2, rrest, Fail{(0, "")}, n, v, st, tab2)
        case 2:
          +st2 = x_req.step(String.eq(name, ""), st, name, value, String.eq(name, ":method"), String.eq(name, ":path"))
          x_req.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          x_req.go(f, 0, bs, r, "", "", st, tab)

def x_req.decode(+bs: List<&2, U32>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>:
  x_req.go(512n, 0, bs, Fail{(0, "")}, "", "", HTTP.ReqHead{"", "", Nil{}}, tab)

def x_req.tab(r: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> HTTP.Tab:
  match r:
    case Fail{e}:
      HTTP.Tab{Nil{}, 0, 4096}
    case Done{(h, +t)}:
      t

# got (Phase 14 A-cirurgia, piloto server.loop): 1 match responde a tripla;
# o caller nunca desdobra — a fase 7 do loop casa o param e ventila.
def x_req.got(dr: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> HTTP.ReqHead & Bool & HTTP.Tab:
  match dr:
    case Fail{e}:
      (HTTP.ReqHead{"", "", Nil{}}, False{}, HTTP.Tab{Nil{}, 0, 4096})
    case Done{(+h, +t)}:
      (h, True{}, t)

def x_req.no_got() -> HTTP.ReqHead & Bool & HTTP.Tab:
  (HTTP.ReqHead{"", "", Nil{}}, False{}, HTTP.Tab{Nil{}, 0, 4096})

# Response head decode (mirror of x_req.go, apply on :status)
# ------------------------------------------------------------

# A pseudo-header other than :status is not a field and is not stored.
def x_resp.field(is_pseudo: Bool, status: U32, +headers: List<&2, HTTP.Hdr>, +name: String, +value: String) -> HTTP.Head:
  match is_pseudo:
    case True{}:
      HTTP.Head{status, headers}
    case False{}:
      HTTP.Head{status, List.append(&2, HTTP.Hdr, headers, [HTTP.Hdr{name, value}])}

def x_resp.apply2(+status: U32, +headers: List<&2, HTTP.Hdr>, +name: String, +value: String, +is_status: Bool) -> HTTP.Head:
  match is_status:
    case True{}:
      HTTP.Head{Maybe.default(&2, U32, U32.read(value), 0), headers}
    case False{}:
      x_resp.field(String.starts_with(name, ":"), status, headers, name, value)

def x_resp.apply(+st: HTTP.Head, +name: String, +value: String, is_status: Bool) -> HTTP.Head:
  match st:
    case HTTP.Head{+status, +headers}:
      x_resp.apply2(status, headers, name, value, is_status)

# An empty name is the table-size update, never a field.
def x_resp.step(empty: Bool, +st: HTTP.Head, +name: String, +value: String) -> HTTP.Head:
  match empty:
    case True{}:
      st
    case False{}:
      x_resp.apply(st, name, value, String.eq(name, ":status"))

def x_resp.go(+fuel: Nat, +phase: U32, +bs: List<&2, U32>, r: Result<&1, &1, U32 & String, HTTP.HdrGot>, +name: String, +value: String, st: HTTP.Head, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>:
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
            case Done{HTTP.HdrGot{+n, +v, +rrest, +tab2}}:
              x_resp.go(f, 2, rrest, Fail{(0, "")}, n, v, st, tab2)
        case 2:
          +st2 = x_resp.step(String.eq(name, ""), st, name, value)
          x_resp.go(f, 0, bs, r, "", "", st2, tab)
        case _:
          x_resp.go(f, 0, bs, r, "", "", st, tab)

def x_resp.decode(+bs: List<&2, U32>, +tab: HTTP.Tab) ->
  Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>:
  x_resp.go(512n, 0, bs, Fail{(0, "")}, "", "", HTTP.Head{0, Nil{}}, tab)

def x_resp.rh(r: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> HTTP.Head:
  match r:
    case Fail{e}:
      HTTP.Head{0, Nil{}}
    case Done{(+h, t)}:
      h

def x_resp.ok(r: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{(h, t)}:
      True{}

def x_resp.tab(r: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> HTTP.Tab:
  match r:
    case Fail{e}:
      HTTP.Tab{Nil{}, 0, 4096}
    case Done{(h, +t)}:
      t

# Header block encode (literal-only)
# ----------------------------------

def x_lit.enc(+name: String, +value: String) -> List<&2, U32>:
  List.append(&2, U32, [0], List.append(&2, U32, x_str.enc(name), x_str.enc(value)))

def x_block.go(hs: List<&2, HTTP.Hdr>, acc: List<&2, U32>) -> List<&2, U32>:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{n, v} <> t:
      x_block.go(t, List.append(&2, U32, acc, x_lit.enc(n, v)))

def x_block(hs: List<&2, HTTP.Hdr>) -> List<&2, U32>:
  x_block.go(hs, Nil{})

# Classify / preface / responses
# ------------------------------

def x_preface_ok(+buf: List<&2, U32>) -> U32:
  HTTP.x_eq(HTTP.x_take32(24, buf), x_preface())

def x_needs_cont(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, x_t_headers()), U32.is_eq(x_fin_hdr(flags), 0))

def x_wu.val(+v: U32) -> Bool:
  Bool.and(U32.is_gt(v, 0), U32.is_lt(v, 2147483648))

def x_wu_ok.go(+b0: U32, +b1: U32, +b2: U32, +b3: U32) -> Bool:
  x_wu.val((((b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 : U32))))

# RFC 9113 section 6.9: the increment field is exactly 4 bytes, so a
# WINDOW_UPDATE with any other length is a connection error. The old
# x_wu_ok stopped after 4 bytes and ignored the tail, which let a 5+ byte
# frame through as a valid credit (found porting h2_rst.bend to httpx_rst).
def x_wu_ok.go4(+b0: U32, +b1: U32, +b2: U32, +b3: U32, +rest: List<&2, U32>) -> Bool:
  Bool.and(x_wu_ok.go(b0, b1, b2, b3), List.is_empty(&2, U32, rest))

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
      x_b2u(U32.is_eq(U32.and(flags, x_f_ack()), 0))
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

def x_classify(+frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      x_cls(typ, sid, flags, payload)

# H2 control-frame errors (TASK-042 phase 5)
# ------------------------------------------
# RFC 9113 section 7: every connection and stream error carries a wired
# U32 code. The names are the registered ones (section 7.1), so a Fail
# says which error the peer sent instead of a bare "goaway"/"rst_stream",
# and the caller that wants to repeat a request reads the code (503 for
# "not processed", 502 for "the peer may have acted on it"), not the text.
def x_h2_err.name(+code: U32) -> String:
  match code:
    case 0:
      "NO_ERROR"
    case 1:
      "PROTOCOL_ERROR"
    case 2:
      "INTERNAL_ERROR"
    case 3:
      "FLOW_CONTROL_ERROR"
    case 4:
      "SETTINGS_TIMEOUT"
    case 5:
      "STREAM_CLOSED"
    case 6:
      "FRAME_SIZE_ERROR"
    case 7:
      "REFUSED_STREAM"
    case 8:
      "CANCEL"
    case 9:
      "COMPRESSION_ERROR"
    case 10:
      "CONNECT_ERROR"
    case 11:
      "ENHANCE_YOUR_CALM"
    case 12:
      "INADEQUATE_SECURITY"
    case 13:
      "HTTP_1_1_REQUIRED"
    case _:
      "UNKNOWN"

def x_h2_err.text(+code: U32) -> String:
  x_h2_err.name(code) ++ "(" ++ U32.show(code) ++ ")"

def x_h2_err.frame_size() -> U32:
  6

# The Fail code of a control-frame error: 503 when the peer said the
# stream was not processed (safe to repeat), 502 when it may have been.
def x_fail_status(is_retry: Bool) -> U32:
  match is_retry:
    case True{}:
      503
    case False{}:
      502

# The 4-byte big-endian field reader, 0 when the payload is shorter than
# the field. x_flow_wu_inc shares this body: one arithmetic for the
# WINDOW_UPDATE increment, the GOAWAY error code and the RST_STREAM code.
def x_be32_rd(+pay: List<&2, U32>) -> U32:
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
                  (b0 * 16777216 + b1 * 65536 + b2 * 256 + b3 : U32)

# RFC 9113 section 6.8: a GOAWAY payload is the last-stream-id (31 bits,
# the R bit reserved) plus the error code, and may carry debug data. Fewer
# than 8 bytes is a connection error (FRAME_SIZE_ERROR), so the readers
# answer fail-closed: x_goaway.none is the largest U32, which no stream is
# above, so nothing looks safe to repeat, and the code is FRAME_SIZE_ERROR.
def x_goaway.none() -> U32:
  4294967295

# The 31 bits of a stream identifier (the R bit is the 32nd).
def x_sid31_mask() -> U32:
  2147483647

def x_goaway.last_go(is_short: Bool, +pay: List<&2, U32>) -> U32:
  match is_short:
    case True{}:
      x_goaway.none()
    case False{}:
      U32.and(x_be32_rd(pay), x_sid31_mask())

def x_goaway.last(+pay: List<&2, U32>) -> U32:
  x_goaway.last_go(U32.is_lt(HTTP.x_len32(pay), 8), pay)

def x_goaway.code_go(is_short: Bool, +pay: List<&2, U32>) -> U32:
  match is_short:
    case True{}:
      x_h2_err.frame_size()
    case False{}:
      x_be32_rd(HTTP.x_drop32(4, pay))

def x_goaway.code(+pay: List<&2, U32>) -> U32:
  x_goaway.code_go(U32.is_lt(HTTP.x_len32(pay), 8), pay)

# RFC 9113 section 8.7: a stream above the last-stream-id was not
# processed, so repeating the request is allowed; at or below it the peer
# may have acted on the stream, so the failure is real.
def x_goaway.retry(+pay: List<&2, U32>, +sid: U32) -> Bool:
  U32.is_lt(x_goaway.last(pay), sid)

def x_goaway.status(+pay: List<&2, U32>, +sid: U32) -> U32:
  x_fail_status(x_goaway.retry(pay, sid))

def x_goaway.last_text_go(is_short: Bool, +pay: List<&2, U32>) -> String:
  match is_short:
    case True{}:
      "short"
    case False{}:
      "last=" ++ U32.show(x_goaway.last(pay))

def x_goaway.reason(+pay: List<&2, U32>, +sid: U32) -> String:
  "goaway " ++ x_h2_err.text(x_goaway.code(pay)) ++ " "
    ++ x_goaway.last_text_go(U32.is_lt(HTTP.x_len32(pay), 8), pay)
    ++ " sid=" ++ U32.show(sid)

# RFC 9113 section 6.8: RST_STREAM carries exactly one 4-byte error code,
# so any other length is FRAME_SIZE_ERROR (a connection error).
def x_rst.code_go(is_exact: Bool, +pay: List<&2, U32>) -> U32:
  match is_exact:
    case True{}:
      x_be32_rd(pay)
    case False{}:
      x_h2_err.frame_size()

def x_rst.code(+pay: List<&2, U32>) -> U32:
  x_rst.code_go(U32.is_eq(HTTP.x_len32(pay), 4), pay)

# REFUSED_STREAM is the peer saying "I did not process this stream", the
# same "safe to repeat" signal a GOAWAY above the stream id gives.
def x_rst.retry(+pay: List<&2, U32>) -> Bool:
  U32.is_eq(x_rst.code(pay), 7)

def x_rst.status(+pay: List<&2, U32>) -> U32:
  x_fail_status(x_rst.retry(pay))

def x_rst.reason(+pay: List<&2, U32>) -> String:
  "rst_stream " ++ x_h2_err.text(x_rst.code(pay))

def x_send_data_frame(sock: Socket, +sid: U32, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_data(), x_f_end_stream(), sid, body)

# Flow pump v2 (item 2, nghttp2 mold): one @unsafe phased def + small
# leafs; got destructures at arm tops, fresh re-created pairs hop to hop.
# Phases: 0 pump, 4 slice (blen = head chunk length, chunk = x_chunk_of),
# 5 send|park, 6 continue/END_STREAM, 9 parked read, 12 service (WU
# credit / SETTINGS ack+IW / PING ack / consume / RST-GOAWAY-CONT
# fail-closed).
# The body arrives as x_chunks() slices of x_max_send() bytes, so the
# steady path pops one chunk per turn: it keeps the head chunk whole when
# the two windows cover it (no take32 copy, no drop32 walk) and takes a
# part of it only when a window is smaller (the partial-chunk path).
# The length walk asks the head chunk, so it stops at x_max_send() and
# the whole send stays linear (bench_h2: 4x body cost 4.0x, against
# 14.9x before TASK-063 phase 2).
def x_pick(cond: Bool, +then_value: U32, +else_value: U32) -> U32:
  match cond:
    case True{}:
      then_value
    case False{}:
      else_value

def x_flow_min(+a: U32, +b: U32) -> U32:
  x_pick(U32.is_le(a, b), a, b)

# The increment of a WINDOW_UPDATE payload: the shared 4-byte big-endian
# reader (x_be32_rd), named for the field this lane reads with it.
def x_flow_wu_inc(+pay: List<&2, U32>) -> U32:
  x_be32_rd(pay)

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

def x_flow_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

def x_chunk_of(+cw: U32, +sw: U32, +blen: U32) -> U32:
  x_flow_min(x_flow_min(x_flow_min(cw, sw), x_max_send()), blen)

def x_chunk_pos(+chunk: U32) -> Bool:
  U32.is_gt(chunk, 0)

# The sender splits the body into x_max_send()-byte chunks, so the steady
# path pops one chunk in each turn. The chunk list holds the bytes in
# order: every chunk has x_max_send() bytes, except the last one of the
# body and, inside a batch, the rest chunk that closes it. One pass builds
# each chunk backwards and one pass reverses it. The take32/drop32 builder
# costs four passes (length, copy, reverse, drop) and measured 1.7-2.6x
# slower (bench_h2: send_chunks_e2e against send_chunks_td).
#
# A split is a batch of x_split_batch() chunks: it answers those chunks,
# then the rest of the body as one chunk, and the pump splits that chunk
# when it reaches it. The whole split costs one more copy of the body, so
# a 100 MB buffered response held the body twice (4.8 GB at peak); the
# batch keeps the chunk spine at one MiB for every body size (TASK-063
# phase 12).
def x_split_batch() -> Nat:
  64n

# More chunks than any body the runtime can hold: the whole-body split.
def x_split_all() -> Nat:
  1000000n

# One chunk: the first k cells of the body, reversed and put in order, and
# the rest of the body.
@unsafe
def x_chunks.take(body: List<&2, U32>, k: Nat, acc: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match body k:
    case _ 0n:
      (List.reverse(&2, U32, acc), body)
    case Nil{} _:
      (List.reverse(&2, U32, acc), Nil{})
    case h <> t 1n+p:
      x_chunks.take(t, p, h <> acc)

# Adds one taken chunk to the reversed chunk list and continues the batch.
@unsafe
def x_chunks.step(chunked: List<&2, U32> & List<&2, U32>, left: Nat, acc: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  (chunk, rest) = chunked
  x_chunks.go(rest, left, chunk <> acc)

# Ends a batch: the rest of the body as one chunk, unless the body ended.
def x_chunks.fin(+rest: List<&2, U32>, acc: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match rest:
    case Nil{}:
      List.reverse(&2, List<&2, U32>, acc)
    case _:
      List.reverse(&2, List<&2, U32>, rest <> acc)

@unsafe
def x_chunks.go(+body: List<&2, U32>, left: Nat, acc: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match body left:
    case _ 0n:
      x_chunks.fin(body, acc)
    case Nil{} _:
      List.reverse(&2, List<&2, U32>, acc)
    case h <> t 1n+p:
      x_chunks.step(x_chunks.take(body, U32.to_nat(x_max_send()), Nil{}), p, acc)

# The chunks of the first `left` chunks of a body in wire order, then the
# rest of the body as one chunk. The sender used to take and drop one
# slice per turn: the length walk, the copy and the drop cost three passes
# more than this split (bench_h2: send_chunks_e2e against send_take_drop).
def x_chunks(+left: Nat, +body: List<&2, U32>) -> List<&2, List<&2, U32>>:
  x_chunks.go(body, left, Nil{})

# The split question of the pump: a chunk that holds more than one frame.
# Such a chunk is a batch remainder, and the pump splits it before it
# walks the length (TASK-063 phase 12).
def x_chunk_long(chunk: List<&2, U32>) -> Bool:
  HTTP.x_has_at_least((x_max_send() + 1 : U32), chunk)

# One pump turn for the head chunk. Only the last element of a batch can
# hold more than one frame: every batch chunk but the rest chunk has
# x_max_send() bytes, and a partial send puts a short rest at the head with
# a list behind it, so the probe runs once per batch and not per turn
# (TASK-063 phase 12).
@unsafe
def x_flow.head(t: List<&2, List<&2, U32>>, +h: List<&2, U32>, s4: Socket, +sid: U32, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, ok: Bool, +sid2p: U32, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  match t:
    case Nil{}:
      x_flow.tail(x_chunk_long(h), h, Nil{}, s4, sid, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
    case _:
      +blen : U32 = HTTP.x_len32(h)
      x_send_data_flow(5, (s4, HTTP.GotErr{0, "next"}), sid, h <> t, cw, sw, piw, buf, cl, blen, Nil{}, x_chunk_pos(x_chunk_of(cw, sw, blen)), sid2p, seed)

# The last element of a batch: a rest chunk past one frame is split into a
# new batch, and a short chunk goes to phase 5 with its length.
@unsafe
def x_flow.tail(long: Bool, +h: List<&2, U32>, +t: List<&2, List<&2, U32>>, s4: Socket, +sid: U32, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, ok: Bool, +sid2p: U32, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  match long:
    case True{}:
      x_send_data_flow(4, (s4, HTTP.GotErr{0, "next"}), sid, List.append(&2, List<&2, U32>, x_chunks(x_split_batch(), h), t), cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
    case False{}:
      +blen : U32 = HTTP.x_len32(h)
      x_send_data_flow(5, (s4, HTTP.GotErr{0, "next"}), sid, h <> t, cw, sw, piw, buf, cl, blen, Nil{}, x_chunk_pos(x_chunk_of(cw, sw, blen)), sid2p, seed)

# Peer SETTINGS ledger (mold h2_settings.iw_of): current INITIAL_WINDOW_SIZE
# (id 4) or the running default when the peer never announces it.
# A peer INITIAL_WINDOW_SIZE replaces the value the peer announced before.
# An open stream window moves by the difference of the two values. It never
# goes below zero (RFC 9113 section 6.9.2). The old shape measured the
# difference against the 65535 default. A second SETTINGS of one session
# therefore shifted the window by the wrong amount (TASK-067 phase 8).
def x_settings.iw_cut(under: Bool, +sw: U32, +cut: U32) -> U32:
  match under:
    case True{}:
      0
    case False{}:
      (sw - cut : U32)

def x_settings.iw_delta_go(grow: Bool, +old: U32, +iw: U32, +sw: U32) -> U32:
  match grow:
    case True{}:
      (sw + (iw - old : U32) : U32)
    case False{}:
      x_settings.iw_cut(U32.is_lt(sw, (old - iw : U32)), sw, (old - iw : U32))

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
                          x_settings.iw_of(rest, x_pick(U32.is_eq((b0 * 256 + b1 : U32), 4), (((b2 * 16777216 + b3 * 65536 + b4 * 256 + b5 : U32))), cur))

def x_flow.acked(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) -> Socket & HTTP.Got:
  (s2, r2) = sent
  match r2:
    case Fail{(code, msg)}:
      (s2, HTTP.GotErr{code, msg})
    case Done{u}:
      (s2, HTTP.GotOk{HTTP.Frame{0, 0, 0, 0, Nil{}}, buf})

# One SETTINGS step of a send: the new peer window and the stream window
# it shifted. The base is the value the peer announced before. Two SETTINGS
# in one session then move the window by their own difference (TASK-067
# phase 8).
def x_settings.iw_step(+pay: List<&2, U32>, +sw: U32, +cur: U32) -> U32 & U32:
  +iw : U32 = x_settings.iw_of(pay, cur)
  (iw, x_settings.iw_delta_go(U32.is_ge(iw, cur), cur, iw, sw))

def x_settings.iw_base(p: U32 & U32) -> U32:
  (b, w) = p
  b

def x_settings.iw_win(p: U32 & U32) -> U32:
  (b, w) = p
  w

def x_flow.ack(got: Socket & HTTP.Got, buf: List<&2, U32>) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_settings(), x_f_ack(), 0, Nil{})
    IO.pure(Socket & HTTP.Got, x_flow.acked(sent, buf))

# Flow sends hand back a read seed: the wire bytes of the frames the
# sender read while it waited for credit but did not consume. It stopped
# on its own stream's HEADERS (the response arriving while the body is
# still going, TASK-042 phase 2b) or stashed a frame of another stream and
# kept sending (TASK-042 phase 2e), so the caller's read path starts from
# those bytes instead of losing the frames. A send that read nothing else
# carries the empty seed. x_flow_drop is the explicit discard for the
# sequential lane, which answers one request at a time by design.
# Tail append for the read seed: List.append recurses on its first list,
# and a seed holds the frames stashed while a big response waited for
# credit (one whole 64 KiB body per stream), so the plain append died with
# a machine stack overflow. Reverse the seed and push it onto the tail:
# two tail passes, the same bytes (TASK-063 phase 7d).
def x_flow_join(+seed: List<&2, U32>, +buf: List<&2, U32>) -> List<&2, U32>:
  HTTP.x_cat.go(List.reverse(&2, U32, seed), buf)

def x_flow_keep(sent: Socket & Result<&1, &1, U32 & String, Unit>, +seed: List<&2, U32>, +cw: U32) ->
  Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32:
  (s, r) = sent
  (s, r, seed, cw)

def x_flow_wu_bad(got: Socket & HTTP.Got, +seed: List<&2, U32>, +cw: U32) ->
  Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32:
  (s, g) = got
  (s, Fail{(502, "bad window_update")}, seed, cw)

def x_flow.pair(got: Socket & HTTP.Got) -> Socket & HTTP.Got:
  (s, g) = got
  (s, HTTP.GotErr{0, "next"})

@unsafe
def x_send_data_flow(+phase: U32, got: Socket & HTTP.Got, +sid: U32, +chunks: List<&2, List<&2, U32>>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, +ok: Bool, +sid2p: U32, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  match phase:
    case 0:
      (s0, g0) = got
      match g0:
        case HTTP.GotErr{code0, msg0}:
          match code0:
            case 0:
              match chunks:
                case Nil{}:
                  do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
                    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s0, x_t_data(), x_f_end_stream(), sid, Nil{})
                    IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, x_flow_keep(sent, x_flow_join(seed, buf), cw))
                case +b <> r:
                  x_send_data_flow(4, (s0, HTTP.GotErr{0, "next"}), sid, b <> r, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
            case _:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s0, Fail{(code0, msg0)}, seed, cw))
        case HTTP.GotOk{+frame0, +buf0}:
          x_send_data_flow(0, (s0, HTTP.GotErr{0, "next"}), sid, chunks, cw, sw, piw, buf0, 0, 0, Nil{}, True{}, sid2p, seed)
    case 4:
      (s4, g4) = got
      match chunks:
        case Nil{}:
          x_send_data_flow(0, (s4, HTTP.GotErr{0, "next"}), sid, Nil{}, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
        case +h <> t:
          x_flow.head(t, h, s4, sid, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
    case 5:
      (s5, g5) = got
      x_flow.chunker(got, sid, chunks, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
    case 6:
      (s6, g6) = got
      x_flow.reste(got, sid, chunks, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
    case 9:
      (s9, g9) = got
      match g9:
        case HTTP.GotErr{code9, msg9}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s9, Fail{(code9, msg9)}, seed, cw))
        case HTTP.GotOk{+frame9, +buf9}:
          match frame9:
            case HTTP.Frame{+typ9, +flags9, +sid29, +flen9, +payload9}:
              x_send_data_flow(x_flow.route(typ9, sid29, sid, x_flow.cls(typ9, flags9)), got, sid, chunks, cw, sw, piw, buf9, x_flow.cls(typ9, flags9), ful, payload9, x_wu_ok(payload9), sid29, seed)
    case 12:
      (s12, g12) = got
      x_flow.do_act(got, sid, chunks, cw, sw, piw, buf, cl, sid2p, pay2, seed)
    case 13:
      (s13, g13) = got
      match g13:
        case HTTP.GotErr{code13, msg13}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s13, Fail{(code13, msg13)}, seed, cw))
        case HTTP.GotOk{+frame13, +buf13}:
          match frame13:
            case HTTP.Frame{+typ13, +flags13, +sid213, +flen13, +payload13}:
              IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s13, Done{Unit{}}, x_flow.seed_add(seed, typ13, flags13, sid213, payload13, buf13), cw))
    case 14:
      (s14, g14) = got
      match g14:
        case HTTP.GotErr{code14, msg14}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s14, Fail{(code14, msg14)}, seed, cw))
        case HTTP.GotOk{+frame14, +buf14}:
          match frame14:
            case HTTP.Frame{+typ14, +flags14, +sid214, +flen14, +payload14}:
              x_send_data_flow(4, (s14, HTTP.GotErr{0, "next"}), sid, chunks, cw, sw, piw, buf14, 0, 0, Nil{}, True{}, sid214, x_flow.seed_add(seed, typ14, flags14, sid214, payload14, Nil{}))
    case _:
      (s13, g13) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s13, Fail{(502, "flow bad phase")}, Nil{}, cw))

# PADDED (0x8) and PRIORITY (0x20): x_frame_of strips both fields out of
# the payload but leaves the bits in the flags it answers, so a frame
# re-encoded for the read seed must clear them -- otherwise the reader
# would strip bytes that are no longer there.
def x_f_padded() -> U32:
  8

def x_f_priority() -> U32:
  32

def x_f_seed(+flags: U32) -> U32:
  U32.and(flags, U32.sub(255, (x_f_padded() + x_f_priority() : U32)))

# The sender keeps the rest of the recv as its own read buffer after a
# stash: the frames behind the stashed one can hold the WINDOW_UPDATE the
# send waits for, and the old shape put them in the caller's seed, where
# nothing applies them (measured on 2026-10-16: a client reset of a
# sibling stream while the server sent a 70000-byte body left the sender
# with cw=0 and the credit in the seed; both peers waited). The seed
# carries only the frames the caller must see, in wire order.
#
# Where the sender goes after reading a frame while it waits for credit:
# 13 stops the send (a HEADERS for the stream it is feeding is the answer
# arriving while the body is still going: the wire bytes go back as the
# caller's read seed, TASK-042 phase 2b); 14 keeps sending and stashes the
# frame (DATA or HEADERS of another stream, PRIORITY, PUSH_PROMISE — what
# the old routing dropped, TASK-042 phase 2e — plus a sibling's RST_STREAM,
# see x_flow.keep_cls); 12 is the frames the sender answers itself
# (WINDOW_UPDATE, SETTINGS, PING, the RST_STREAM of the stream being sent,
# GOAWAY). The bools take their own def because a match cannot scrutinize a
# computed value.
def x_flow.route_go(is_head: Bool, same: Bool, is_keep: Bool) -> U32:
  match is_head same is_keep:
    case _ _ False{}:
      12
    case True{} True{} _:
      13
    case _ _ _:
      14

# The frames the sender hands to the caller instead of acting on them: the
# class-0 bucket (DATA, HEADERS, PRIORITY, PUSH_PROMISE) and a RST_STREAM
# of another stream. The sibling RST is the node:http2 shape -- a peer
# resets a stream it already answered while the next request's body is
# still going -- and the drain is the one place that decides whose frame it
# is (client.route.stream_cls), so the sender stashes it like any other
# foreign frame. The RST of the stream being sent is not kept: it stops the
# send with the typed error.
def x_flow.keep_cls(+cls: U32, same: Bool) -> Bool:
  match cls same:
    case 0 _:
      True{}
    case 3 False{}:
      True{}
    case _ _:
      False{}

def x_flow.route(+typ: U32, +sid29: U32, +sid: U32, +cls: U32) -> U32:
  x_flow.route_go(U32.is_eq(typ, 1), U32.is_eq(sid29, sid), x_flow.keep_cls(cls, U32.is_eq(sid29, sid)))

# The bytes a stopping or stashed frame adds to the caller's read seed: the
# frame re-encoded the way the reader expects it, followed by the rest of
# the recv (which may hold more frames). The accumulated seed comes first;
# it holds bytes that arrived earlier on the wire.
def x_flow.seed_add(+seed: List<&2, U32>, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +buf: List<&2, U32>) -> List<&2, U32>:
  +frag : List<&2, U32> = x_frame_write(typ, x_f_seed(flags), sid, payload)
  x_flow_join(seed, HTTP.x_cat.go(List.reverse(&2, U32, frag), buf))

def x_flow.cls_typ(+typ: U32) -> U32:
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

# RFC 9113 section 6.5/6.7: a peer never answers an ACK. A SETTINGS or PING
# ACK read while the flow pump waits for credit is therefore a foreign
# frame (class 0): the pump hands it to the caller, which ignores it. The
# old table answered it, and a second SETTINGS ACK on the wire made a
# node:http2 peer fail the session with PROTOCOL_ERROR.
def x_flow.cls_ack(+cls: U32, fresh: Bool) -> U32:
  match cls fresh:
    case 4 False{}:
      0
    case 6 False{}:
      0
    case _ _:
      cls

def x_flow.cls(+typ: U32, +flags: U32) -> U32:
  x_flow.cls_ack(x_flow.cls_typ(typ), U32.is_eq(U32.and(flags, x_f_ack()), 0))

# The bytes of this turn: the head chunk whole when the two windows cover
# it, a take of it when they do not (the partial-chunk path).
def x_flow_part(full: Bool, +chunk: U32, +h: List<&2, U32>) -> List<&2, U32>:
  match full:
    case True{}:
      h
    case False{}:
      HTTP.x_take32(chunk, h)

# The chunks left after this turn: the tail when the head went whole, the
# rest of the head in front of the tail when it went in part.
def x_flow_rest(full: Bool, +chunk: U32, +h: List<&2, U32>, +t: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match full:
    case True{}:
      t
    case False{}:
      HTTP.x_drop32(chunk, h) <> t

def x_flow.chunker(got: Socket & HTTP.Got, +sid: U32, +chunks: List<&2, List<&2, U32>>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, ok: Bool, +sid2p: U32, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  (s5, g5) = got
  match chunks:
    case Nil{}:
      x_send_data_flow(6, (s5, HTTP.GotErr{0, "next"}), sid, Nil{}, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)
    case +h <> t:
      match ok:
        case True{}:
          +chunk : U32 = x_chunk_of(cw, sw, ful)
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame_len(s5, x_t_data(), 0, sid, x_flow_part(U32.is_eq(chunk, ful), chunk, h), chunk)
            x_send_data_flow(6, x_flow_sent(sent), sid, x_flow_rest(U32.is_eq(chunk, ful), chunk, h, t), (cw - chunk : U32), (sw - chunk : U32), piw, buf, 0, 0, Nil{}, True{}, sid2p, seed)
        case False{}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
            got2 : Socket & HTTP.Got <- x_read_frame(s5, buf)
            x_send_data_flow(9, got2, sid, h <> t, cw, sw, piw, buf, cl, ful, pay2, ok, sid2p, seed)

def x_flow.reste(got: Socket & HTTP.Got, +sid: U32, +chunks: List<&2, List<&2, U32>>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +cl: U32, +ful: U32, +pay2: List<&2, U32>, +ok: Bool, +sid2p: U32, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  (s6, g6) = got
  match chunks:
    case Nil{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s6, x_t_data(), x_f_end_stream(), sid, Nil{})
        IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, x_flow_keep(sent, x_flow_join(seed, buf), cw))
    case +b <> r:
      x_send_data_flow(0, (s6, HTTP.GotErr{0, "next"}), sid, b <> r, cw, sw, piw, buf, 0, 0, Nil{}, True{}, sid2p, seed)

@unsafe
def x_flow.do_act(got: Socket & HTTP.Got, +sid: U32, +chunks: List<&2, List<&2, U32>>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +cl: U32, +sid2p: U32, +pay2: List<&2, U32>, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  (s, g) = got
  match cl:
    case 2:
      x_flow.wu(got, sid, chunks, cw, sw, piw, buf, sid2p, x_flow_wu_inc(pay2), x_wu_ok(pay2), seed)
    case 4:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
        got2 : Socket & HTTP.Got <- x_flow.ack(got, buf)
        +step : U32 & U32 = x_settings.iw_step(pay2, sw, piw)
        x_send_data_flow(4, got2, sid, chunks, cw, x_settings.iw_win(step), x_settings.iw_base(step), buf, 0, 0, Nil{}, True{}, sid2p, seed)
    case 6:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_ping(), x_f_ack(), 0, pay2)
        x_send_data_flow(4, x_flow_sent(sent), sid, chunks, cw, sw, piw, buf, 0, 0, Nil{}, True{}, sid2p, seed)
    case 3:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s, Fail{(x_rst.status(pay2), x_rst.reason(pay2))}, Nil{}, cw))
    case 7:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s, Fail{(x_goaway.status(pay2, sid), x_goaway.reason(pay2, sid))}, Nil{}, cw))
    case 9:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (s, Fail{(502, "continuation")}, Nil{}, cw))
    case _:
      x_send_data_flow(4, (s, HTTP.GotErr{0, "next"}), sid, chunks, cw, sw, piw, buf, 0, 0, Nil{}, True{}, sid2p, seed)

@unsafe
def x_flow.wu(got: Socket & HTTP.Got, +sid: U32, +chunks: List<&2, List<&2, U32>>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>, +sid2p: U32, +inc: U32, ok: Bool, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  match ok:
    case True{}:
      +cream = x_flow_credit.go(cw, sw, sid, sid2p, inc, True{})
      x_send_data_flow(4, x_flow.pair(got), sid, chunks, x_flow_cw(cream), x_flow_sw(cream), piw, buf, 0, 0, Nil{}, True{}, sid2p, seed)
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, x_flow_wu_bad(got, seed, cw))

# The send takes the connection window, the stream window and the peer
# INITIAL_WINDOW_SIZE from its caller. A stream opens with the peer
# SETTINGS INITIAL_WINDOW_SIZE. The server loop carries that value from the
# SETTINGS it read and seeds the send with it (TASK-067). The same value is
# the base of a SETTINGS read mid-send. The shift is then the difference
# between two announced values (TASK-067 phase 8). The client upload still
# seeds the RFC default for both, because its lane does not carry the peer
# setting yet. The caller carries the connection window across sends
# (TASK-063 phase 7e).
def x_send_data_start.go(sock: Socket, +sid: U32, +body: List<&2, U32>, single: Bool, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  match single:
    case True{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_data_frame(sock, sid, body)
        IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, x_flow_keep(sent, buf, (cw - HTTP.x_len32(body) : U32)))
    case False{}:
      x_send_data_flow(0, (sock, HTTP.GotErr{0, "next"}), sid, x_chunks(x_split_batch(), body), cw, sw, piw, buf, 0, 0, Nil{}, True{}, 0, Nil{})

# The single-frame lane question: the body fits one DATA frame and the
# caller's connection window covers it. The lane writes the whole body at
# once and answers `cw - len`, so a body past the caller window overran
# the peer window and the answer wrapped below zero in U32; such a body
# takes the pump path, which sends what the window allows and waits for
# credit (TASK-063 phase 7d). The probe stops at the smaller of the cap
# and the window, so this send costs at most x_max_send() + 1 list cells
# instead of the whole body (TASK-063 phase 8).
def x_send_probe(+cw: U32, +sw: U32) -> U32:
  (U32.min(U32.min(cw, sw), x_max_send()) + 1 : U32)

def x_send_single(+cw: U32, +sw: U32, body: List<&2, U32>) -> Bool:
  Bool.not(HTTP.x_has_at_least(x_send_probe(cw, sw), body))

def x_send_data_start(sock: Socket, +sid: U32, +body: List<&2, U32>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  x_send_data_start.go(sock, sid, body, x_send_single(cw, sw, body), cw, sw, piw, buf)

# The server's response sender hands the read seed out like the client's
# does (TASK-042 phase 2e): the flow sender stashes every frame it reads
# while waiting for credit (a pipelined request HEADERS, the DATA of
# another stream) instead of dropping it, and the server loop reads those
# bytes first.
def x_send_resp_head(sent: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +body: List<&2, U32>, is_empty: Bool, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, (sock, Fail{e}, Nil{}, cw))
    case Done{u}:
      match is_empty:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, x_flow_keep((sock, Done{Unit{}}), buf, cw))
        case False{}:
          x_send_data_start(sock, sid, body, cw, sw, piw, buf)

# The socket of a sent pair, for the chains that carry only the last
# Result and keep sending on the same connection.
def httpx.sock_of(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = sent
  s

# One header block of any size: the first 16384 bytes ride HEADERS and
# every later slice rides one CONTINUATION, with END_HEADERS on the last
# frame. 16384 is the minimum legal MAX_FRAME_SIZE, so the send never has
# to read the peer SETTINGS, and CONTINUATION carries END_HEADERS only
# (RFC 9113 section 6.10): END_STREAM stays on the HEADERS frame.
# CONTINUATION frames a block needs: one per full slice after the first,
# which is the floor of (n - 1) over the slice size.
def x_send_block.fuel(+n: U32) -> Nat:
  match n:
    case 0:
      0n
    case _:
      Nat.div(U32.to_nat((n - 1 : U32)), U32.to_nat(x_max_send()))

@unsafe
def x_send_block.step(sock: Socket, +sid: U32, +blk: List<&2, U32>, +fuel: Nat, +typ: U32, +end_stream: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match fuel:
    case 0n:
      x_send_frame(sock, typ, (x_f_end_headers() + end_stream : U32), sid, blk)
    case 1n+p:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(sock, typ, end_stream, sid, HTTP.x_take32(x_max_send(), blk))
        x_send_block.step(httpx.sock_of(sent), sid, HTTP.x_drop32(x_max_send(), blk), p, x_t_cont(), 0)

def x_send_block(sock: Socket, +sid: U32, +blk: List<&2, U32>, +end_stream: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_block.step(sock, sid, blk, x_send_block.fuel(HTTP.x_len32(blk)), x_t_headers(), end_stream)

def x_send_resp.go(sock: Socket, +sid: U32, +status: U32, +headers: List<&2, HTTP.Hdr>, +body: List<&2, U32>, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  hs = List.append(&2, HTTP.Hdr, [HTTP.Hdr{":status", U32.show(status)}], headers)
  blk = x_block(hs)
  +empty = List.is_empty(&2, U32, body)
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_block(sock, sid, blk, x_b2u(empty))
    x_send_resp_head(sent, sid, body, empty, cw, sw, piw, buf)

def x_send_resp(sock: Socket, +sid: U32, +resp: HTTP.Response, +cw: U32, +sw: U32, +piw: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      x_send_resp.go(sock, sid, status, headers, body, cw, sw, piw, buf)

# Httpx slots (unbounded List<St>; single-traversal take in Data wrapper)
# -----------------------------------------------------------------------

def httpx.sid_of(st: HTTP.St) -> U32:
  match st:
    case HTTP.St{head, body, +sid, n}:
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
# The two slot questions of the frame loops, named.
def x_same_sid(st: HTTP.St, sid: U32) -> Bool:
  U32.is_eq(httpx.sid_of(st), sid)

def x_cls_of(frame: HTTP.Frame, flags: U32) -> U32:
  httpx.cls_fix(x_classify(frame), flags)

def httpx.again(s: Socket) -> Socket & HTTP.Got:
  (s, HTTP.GotOk{HTTP.Frame{0, 0, 0, 0, Nil{}}, Nil{}})

def httpx.close_got(got: Socket & HTTP.Got) -> IO(Unit):
  (s, g) = got
  TLS.tls_close(s)

# Housekeeping sends keep the connection alive even if the write fails:
# the next read answers the dead socket and closes the connection.
def httpx.sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  httpx.again(s2)

# The read seed a send hands back (TASK-042 phase 2e) rides in the Got's
# buffer. The send started from the caller's buffer, so the seed already
# holds every byte the caller did not read; the caller passes an empty
# prefix and takes the seed as its new buffer (TASK-063 phase 7d). A Fail
# keeps the GotErr (the loop closes on it and the seed is moot).
# The first three fields of a flow-pump answer: the socket, the result and
# the read seed. The fourth field is the connection window the pump has
# left (TASK-063 phase 7b); a caller that does not seed the next send drops
# it here.
def httpx.sent3(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32) ->
  Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>:
  match sent:
    case (s, r, seed, cw):
      (s, r, seed)

# The connection window the pump has left (TASK-063 phase 7c).
def httpx.sent_cw(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32) -> U32:
  match sent:
    case (s, r, seed, cw):
      cw

def httpx.sent_seed(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, +buf: List<&2, U32>) -> Socket & HTTP.Got:
  (s2, r, seed) = sent
  match r:
    case Fail{(code, msg)}:
      (s2, HTTP.GotErr{code, msg})
    case Done{u}:
      (s2, HTTP.GotOk{HTTP.Frame{0, 0, 0, 0, Nil{}}, List.append(&2, U32, buf, seed)})

# The buffer a loop reads from. A leaf that hands bytes back (the response
# sender after a stash) rides them in the Got's buffer and those bytes win;
# a Got with an empty buffer carries nothing, so the loop's own leftover is
# still the right place to read from (the ack/ping leaves answer with an
# empty Got and would otherwise drop bytes already received). Every other
# transition keeps both in sync. TASK-042 phase 2e.
def httpx.carry(g: HTTP.Got, +buf: List<&2, U32>) -> List<&2, U32>:
  match g:
    case HTTP.GotOk{frame, +b}:
      match b:
        case Nil{}:
          buf
        case _:
          b
    case HTTP.GotErr{code, msg}:
      buf

def httpx.ack(got: Socket & HTTP.Got) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_settings(), x_f_ack(), 0, Nil{})
    IO.pure(Socket & HTTP.Got, httpx.sent(sent))

def httpx.ack_ping(got: Socket & HTTP.Got, +payload: List<&2, U32>) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s, x_t_ping(), x_f_ack(), 0, payload)
    IO.pure(Socket & HTTP.Got, httpx.sent(sent))

def httpx.body_of(st: HTTP.St) -> List<&2, U32>:
  match st:
    case HTTP.St{head, +body, sid, n}:
      body

def httpx.req_of(+rh: HTTP.ReqHead, +body: List<&2, U32>) -> HTTP.Request:
  match rh:
    case HTTP.ReqHead{+method, +path, +headers}:
      HTTP.Request{method, path, headers, body}

# Request straight from the slot, no +rh/+body. Thin projection style:
# the caller holds one reusable Taken bind.
def httpx.req_of_st(st: HTTP.St, +payload: List<&2, U32>) -> HTTP.Request:
  match st:
    case HTTP.St{head, +body, +sid, n}:
      match head:
        case Some{HTTP.SlotReq{+rh}}:
          match rh:
            case HTTP.ReqHead{+method, +path, +headers}:
              HTTP.Request{method, path, headers, HTTP.x_cat(HTTP.x_rev_push(payload, body))}
        case _:
          HTTP.Request{"", "", Nil{}, HTTP.x_cat(HTTP.x_rev_push(payload, body))}

def ledger.no_slots() -> List<&2, HTTP.St>:
  Nil{}

def ledger.no_fends() -> List<&2, U32>:
  Nil{}

def ledger.has(slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      Bool.or(x_same_sid(st, sid), ledger.has(t, sid))

# The buffered body bytes the stream with SID received, or zero when the
# ledger has no entry.
def ledger.n_go(is_same: Bool, n: U32, rec: U32) -> U32:
  match is_same:
    case True{}:
      n
    case False{}:
      rec

def ledger.n_of(xs: List<&2, HTTP.St>, +sid: U32) -> U32:
  match xs:
    case Nil{}:
      0
    case +st <> t:
      match st:
        case HTTP.St{head, body, +sid2, +n}:
          ledger.n_go(U32.is_eq(sid2, sid), n, ledger.n_of(t, sid))

# Single-traversal fragment probe: slot with sid exists AND head is None.
# 2 traversals + S clones -> 1 traversal, S incs (sids unique via put).
def ledger.has_some_go(eq: Bool, st: HTTP.St, rec: Bool) -> Bool:
  match eq:
    case True{}:
      match st:
        case HTTP.St{head, body, sid, n}:
          match head:
            case None{}:
              True{}
            case Some{rh}:
              False{}
    case False{}:
      rec

def ledger.has_some(slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  match slots:
    case Nil{}:
      False{}
    case +st <> t:
      ledger.has_some_go(x_same_sid(st, sid), st, ledger.has_some(t, sid))

def ledger.del_go(eq: Bool, +st: HTTP.St, rest: List<&2, HTTP.St>) -> List<&2, HTTP.St>:
  match eq:
    case True{}:
      rest
    case False{}:
      st <> rest

def ledger.del(slots: List<&2, HTTP.St>, +sid: U32) -> List<&2, HTTP.St>:
  match slots:
    case Nil{}:
      Nil{}
    case +st <> t:
      ledger.del_go(x_same_sid(st, sid), st, ledger.del(t, sid))

# Single-traversal take in a Data wrapper (a top-level A & B pair is not
# Data and admits no + reuse). 1x O(S) always: strict args run the tail
# even on early match; sids unique via put so the tail found nothing.
def ledger.take_go(eq: Bool, +st: HTTP.St, p: HTTP.Taken) -> HTTP.Taken:
  match eq:
    case True{}:
      match p:
        case HTTP.Taken{+slots, st2}:
          HTTP.Taken{slots, st}
    case False{}:
      match p:
        case HTTP.Taken{+slots2, +found2}:
          HTTP.Taken{(st <> slots2), found2}

def ledger.take_del(slots: List<&2, HTTP.St>, +sid: U32) -> HTTP.Taken:
  match slots:
    case Nil{}:
      HTTP.Taken{Nil{}, HTTP.St{None{}, Nil{}, 0, 0}}
    case +st <> t:
      ledger.take_go(x_same_sid(st, sid), st, ledger.take_del(t, sid))

def ledger.taken_slots(p: HTTP.Taken) -> List<&2, HTTP.St>:
  match p:
    case HTTP.Taken{+slots, st}:
      slots

def ledger.taken_st(p: HTTP.Taken) -> HTTP.St:
  match p:
    case HTTP.Taken{slots, +st}:
      st

# DATA continue: keep the slot with the pushed rev-body, hp-less.
def ledger.data_cont_slots(p: HTTP.Taken, +payload: List<&2, U32>, +len: U32) -> List<&2, HTTP.St>:
  match p:
    case HTTP.Taken{+rest, st}:
      match st:
        case HTTP.St{head, +body, +sid, +n}:
          match head:
            case None{}:
              ((HTTP.St{Some{HTTP.SlotReq{HTTP.ReqHead{"", "", Nil{}}}}, HTTP.x_rev_push(payload, body), sid, (n + len : U32)} <> rest))
            case Some{+sh}:
              ((HTTP.St{Some{sh}, HTTP.x_rev_push(payload, body), sid, (n + len : U32)} <> rest))

# CONTINUATION fragment: head stays None, rev-body grows.
def ledger.frag_cont_slots(p: HTTP.Taken, +payload: List<&2, U32>) -> List<&2, HTTP.St>:
  match p:
    case HTTP.Taken{+rest, st}:
      match st:
        case HTTP.St{head, +body, +sid, n}:
          ((HTTP.St{None{}, HTTP.x_rev_push(payload, body), sid, n} <> rest))

def ledger.put(slots: List<&2, HTTP.St>, +st: HTTP.St) -> List<&2, HTTP.St>:
  st <> ledger.del(slots, httpx.sid_of(st))

def ledger.fdel_go(eq: Bool, +x: U32, rest: List<&2, U32>) -> List<&2, U32>:
  match eq:
    case True{}:
      rest
    case False{}:
      x <> rest

def ledger.fdel(fends: List<&2, U32>, +sid: U32) -> List<&2, U32>:
  match fends:
    case Nil{}:
      Nil{}
    case +x <> t:
      ledger.fdel_go(U32.is_eq(x, sid), x, ledger.fdel(t, sid))

# Fused fends take: find + remove + flag in one traversal (2 -> 1).
def ledger.fdel_flag_go(eq: Bool, +x: U32, p: HTTP.FendTaken) -> HTTP.FendTaken:
  match eq:
    case True{}:
      match p:
        case HTTP.FendTaken{+rest, flag}:
          HTTP.FendTaken{rest, 1}
    case False{}:
      match p:
        case HTTP.FendTaken{+rest2, +flag2}:
          HTTP.FendTaken{(x <> rest2), flag2}

def ledger.fdel_flag(fends: List<&2, U32>, +sid: U32) -> HTTP.FendTaken:
  match fends:
    case Nil{}:
      HTTP.FendTaken{Nil{}, 0}
    case +x <> t:
      ledger.fdel_flag_go(U32.is_eq(x, sid), x, ledger.fdel_flag(t, sid))

def ledger.ftaken_fends(p: HTTP.FendTaken) -> List<&2, U32>:
  match p:
    case HTTP.FendTaken{+fends, flag}:
      fends

def ledger.ftaken_flag(p: HTTP.FendTaken) -> U32:
  match p:
    case HTTP.FendTaken{fends, +flag}:
      flag

def ledger.fput(fends: List<&2, U32>, +sid: U32) -> List<&2, U32>:
  sid <> ledger.fdel(fends, sid)

def ledger.fend_up(fends: List<&2, U32>, +sid: U32, is_end: Bool) -> List<&2, U32>:
  match is_end:
    case True{}:
      ledger.fput(fends, sid)
    case False{}:
      ledger.fdel(fends, sid)

def ledger.frag_has(+slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  ledger.has_some(slots, sid)

# HEADERS action codes: 0 claim slot, 1 answer now, 5 decode fail,
# 6 park header fragment (HEADERS without END_HEADERS).
def ledger.head_act(need: U32, ok: Bool, +end: U32) -> U32:
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
def ledger.decide_data(has: Bool, +end: U32) -> U32:
  match has end:
    case False{} _:
      4
    case True{} 1:
      1
    case _ _:
      0

# CONTINUATION action codes: 0 append fragment, 1 finish block,
# 2 block past x_max_block(), 4 connection error (no open fragment).
def ledger.decide_cont(over: Bool, has_frag: Bool, +endh: U32) -> U32:
  match over has_frag endh:
    case True{} _ _:
      2
    case False{} False{} _:
      4
    case False{} True{} 0:
      0
    case False{} True{} 4:
      1
    case False{} _ _:
      4

def ledger.need_u(+typ: U32, +flags: U32) -> U32:
  x_b2u(x_needs_cont(typ, flags))

# Both arms close the socket: no match needed (same shape as httpx.sent).
def ledger.cont_failed(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = sent
  TLS.tls_close(s)

# GOAWAY with the given code, then close. The server's answer to a peer
# that breaks a connection-level rule: no last-stream-id, because the
# peer cannot resend anything on this connection.
def x_fatal(sock: Socket, +code: U32) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(sock, 0, code)
    ledger.cont_failed(sent)

# The wired GOAWAY codes this module sends (RFC 9113 section 7.1).
def x_goaway.protocol() -> U32:
  1

def x_goaway.calm() -> U32:
  11

# The GOAWAY code of a local frame-parse failure: a frame past the cap is
# FRAME_SIZE_ERROR (RFC 9113 section 6.5.2), anything else the parser
# rejects is PROTOCOL_ERROR.
def x_fatal.code(code: U32) -> U32:
  match code:
    case 413:
      x_h2_err.frame_size()
    case _:
      x_goaway.protocol()

# x_fatal on a loop carrier: the socket comes out of the Got pair.
def x_fatal_got(got: Socket & HTTP.Got, +code: U32) -> IO(Unit):
  (s, g) = got
  x_fatal(s, code)

# A read that failed: a frame past the cap answers GOAWAY FRAME_SIZE_ERROR,
# every other failure (eof, socket) just closes. The Bool rides an argument:
# a match cannot scrutinize a call.
def x_fatal_close_go(is_big: Bool, sock: Socket, +code: U32) -> IO(Unit):
  match is_big:
    case True{}:
      x_fatal(sock, x_fatal.code(code))
    case False{}:
      TLS.tls_close(sock)

def x_fatal_close(sock: Socket, +code: U32) -> IO(Unit):
  x_fatal_close_go(U32.is_eq(code, 413), sock, code)

# --- receive credit: batched WINDOW_UPDATE ----------------------------
# A receive turn credits the declared length of a DATA frame back to the
# connection window and to the stream window (RFC 9113 section 6.9.1).
# Crediting every frame costs one TLS write of two frames, so the loop
# batches the credit: it adds the lengths to a pending counter and
# writes the sums when they reach half of the initial window. The peer
# then holds at most x_wu_half() bytes of uncredited body, so its window
# cannot reach zero. The connection counter rides one loop argument and
# one ledger entry per live stream rides another, because the two
# windows move apart when streams interleave (TASK-063 phase 6b).
def x_wu_half() -> U32:
  32768

# The pending credit of one stream: the id and the bytes the peer sent
# since the last WINDOW_UPDATE of that stream.
type Pnd is Data:
  Pnd{sid: U32, n: U32}

# The bytes of one WINDOW_UPDATE frame.
def x_wu_frame(+sid: U32, +inc: U32) -> List<&2, U32>:
  x_frame_write(x_t_wu(), 0, sid, HTTP.x_be32(inc))

def x_wu.of_go(is_same: Bool, n: U32, rec: U32) -> U32:
  match is_same:
    case True{}:
      n
    case False{}:
      rec

# The pending of one stream, or zero when the ledger has no entry.
def x_wu.of(xs: List<&2, Pnd>, +sid: U32) -> U32:
  match xs:
    case Nil{}:
      0
    case Pnd{s, n} <> t:
      x_wu.of_go(U32.is_eq(s, sid), n, x_wu.of(t, sid))

def x_wu.del_go(is_same: Bool, e: Pnd, rec: List<&2, Pnd>) -> List<&2, Pnd>:
  match is_same:
    case True{}:
      rec
    case False{}:
      e <> rec

# The ledger without the entry of the sid. A stream that ends leaves no
# entry, so the walk follows the live streams only.
def x_wu.del(xs: List<&2, Pnd>, +sid: U32) -> List<&2, Pnd>:
  match xs:
    case Nil{}:
      Nil{}
    case Pnd{+s, +n} <> t:
      x_wu.del_go(U32.is_eq(s, sid), Pnd{s, n}, x_wu.del(t, sid))

def x_wu.set_go(is_zero: Bool, xs: List<&2, Pnd>, +sid: U32, +n: U32) ->
  List<&2, Pnd>:
  match is_zero:
    case True{}:
      x_wu.del(xs, sid)
    case False{}:
      Pnd{sid, n} <> x_wu.del(xs, sid)

# The ledger with the pending of the sid set. A zero value prunes the
# entry: the flush already credited those bytes.
def x_wu.set(xs: List<&2, Pnd>, +sid: U32, +n: U32) -> List<&2, Pnd>:
  x_wu.set_go(U32.is_eq(n, 0), xs, sid, n)

# The connection pending after one DATA frame.
def x_wu.cp1(cpend: U32, +flen: U32) -> U32:
  (cpend + flen : U32)

# The stream pending after one DATA frame.
def x_wu.sp1(spend: List<&2, Pnd>, +sid: U32, +flen: U32) -> U32:
  (x_wu.of(spend, sid) + flen : U32)

# True when the connection credit goes out on this frame: the pending
# reaches the half window, or the body ends.
def x_wu.flush_cp(cp1: U32, is_end: Bool) -> Bool:
  match is_end:
    case True{}:
      U32.is_gt(cp1, 0)
    case False{}:
      U32.is_ge(cp1, x_wu_half())

# True when the stream credit goes out: its pending reaches the half
# window. A body that ends sends no stream credit, because the peer
# sends no more DATA on that stream.
def x_wu.flush_sp(sp1: U32, is_end: Bool) -> Bool:
  match is_end:
    case True{}:
      False{}
    case False{}:
      U32.is_ge(sp1, x_wu_half())

def x_wu.reset_cp(is_flush: Bool, +cp1: U32) -> U32:
  match is_flush:
    case True{}:
      0
    case False{}:
      cp1

# The connection pending after the frame.
def x_wu.next_cpend(cpend: U32, +flen: U32, is_end: Bool) -> U32:
  +cp1 : U32 = x_wu.cp1(cpend, flen)
  x_wu.reset_cp(x_wu.flush_cp(cp1, is_end), cp1)

def x_wu.spend_set(is_flush: Bool, spend: List<&2, Pnd>, +sid: U32, is_end: Bool, +sp1: U32) ->
  List<&2, Pnd>:
  match is_flush is_end:
    case True{} _:
      x_wu.del(spend, sid)
    case False{} True{}:
      x_wu.del(spend, sid)
    case False{} False{}:
      x_wu.set(spend, sid, sp1)

# The stream ledger after the frame.
def x_wu.next_spend(+spend: List<&2, Pnd>, +sid: U32, +flen: U32, +is_end: Bool) ->
  List<&2, Pnd>:
  +sp1 : U32 = x_wu.sp1(spend, sid, flen)
  x_wu.spend_set(x_wu.flush_sp(sp1, is_end), spend, sid, is_end, sp1)

# The WINDOW_UPDATE bytes of one DATA frame: the connection frame, the
# stream frame, both, or none. Both frames ride one write.
def x_wu.build(fc: Bool, fs: Bool, +cp1: U32, +sid: U32, +sp1: U32) ->
  List<&2, U32>:
  match fc fs:
    case True{} True{}:
      List.append(&2, U32, x_wu_frame(0, cp1), x_wu_frame(sid, sp1))
    case True{} False{}:
      x_wu_frame(0, cp1)
    case False{} True{}:
      x_wu_frame(sid, sp1)
    case False{} False{}:
      Nil{}

def x_wu.bytes(cpend: U32, spend: List<&2, Pnd>, +sid: U32, +flen: U32, +is_end: Bool) ->
  List<&2, U32>:
  +cp1 : U32 = x_wu.cp1(cpend, flen)
  +sp1 : U32 = x_wu.sp1(spend, sid, flen)
  x_wu.build(x_wu.flush_cp(cp1, is_end), x_wu.flush_sp(sp1, is_end), cp1, sid, sp1)

# The connection credit of a DATA frame of a stream that is gone: the
# stream window is meaningless, but the bytes still count against the
# connection window (RFC 9113 section 6.9.1).
def x_wu.stray_cpend(cpend: U32, +flen: U32) -> U32:
  +cp1 : U32 = x_wu.cp1(cpend, flen)
  x_wu.reset_cp(x_wu.flush_cp(cp1, False{}), cp1)

def x_wu.stray_bytes(cpend: U32, +flen: U32) -> List<&2, U32>:
  +cp1 : U32 = x_wu.cp1(cpend, flen)
  x_wu.build(x_wu.flush_cp(cp1, False{}), False{}, cp1, 0, 0)

def x_send_rst(sock: Socket, +sid: U32, +code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_frame(sock, x_t_rst(), 0, sid, HTTP.x_be32(code))

def httpx.wo(got: Socket & HTTP.Got) -> Socket:
  (sx, gx) = got
  sx

def httpx.wu_kept(sent: Socket & Result<&1, &1, U32 & String, Unit>, buf: List<&2, U32>) ->
  Socket & HTTP.Got:
  (s, r) = sent
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotOk{HTTP.Frame{0, 0, 0, 0, Nil{}}, buf})

def x_wu.send_go(is_empty: Bool, got: Socket & HTTP.Got, buf: List<&2, U32>, +bytes: List<&2, U32>) ->
  IO(Socket & HTTP.Got):
  match is_empty:
    case True{}:
      IO.pure(Socket & HTTP.Got, got)
    case False{}:
      (s, g) = got
      do IO<Socket & HTTP.Got>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, bytes)
        IO.pure(Socket & HTTP.Got, httpx.wu_kept(sent, buf))

# Credits one DATA frame: writes the pending bytes of the step, if any,
# and answers the read seed. A step with nothing to flush writes nothing,
# so a small body costs one write at its end and no write before.
def x_wu.send(got: Socket & HTTP.Got, buf: List<&2, U32>, +bytes: List<&2, U32>) ->
  IO(Socket & HTTP.Got):
  x_wu.send_go(List.is_empty(&2, U32, bytes), got, buf, bytes)

# Client API (TASK-058). The public entries, in call order. One byte loop
# serves them all: `client.loop` runs in mode `on` or `concurrent`. The
# ordered lane `client.loop.on` drives the mode `on` (one exchange at a
# time) and `client.loop.concurrent` projects the mode `concurrent`.
#   client.connect            dial; the caller owns the socket
#   client.stream.once        one exchange, mode on
#   client.stream.on          N in order, mode on
#   client.stream.concurrent  N in flight, mode concurrent
#   client.request             one exchange on a caller socket
#   request / request_bytes    one-shot text / bytes
#   fetch / fetch_bytes        GET by URL, text / bytes
#   client.once                one-shot Response
#   client.on                  N in order, Response list
#   client.concurrent          N in flight, handler sum
# The server section follows; the legacy facade legs come last.
# ---------------------------------------------------------------------

# Client H2 (Phase 8: A x_resp above; B once; E stream; C keep-alive;
# D concurrent; F server stream). Only Base+tls imports are kept: all
# codec pieces reuse x_* above, validation is local (same Fail 400).
# ---------------------------------------------------------------------

# Authority + request block (mirror https with_authority, Hdr)
# ---------------------------------------------------------------

# The connection fields of RFC 9113 section 8.2.2 plus :authority, which
# client.req.with_authority rebuilds from the dial.
def client.req.hop(+n: String) -> Bool:
  Bool.or(String.eq(n, "connection"),
    Bool.or(String.eq(n, "keep-alive"),
      Bool.or(String.eq(n, "proxy-connection"),
        Bool.or(String.eq(n, "transfer-encoding"),
          Bool.or(String.eq(n, "upgrade"), String.eq(n, "te"))))))

def client.req.drop_name(+n: String) -> Bool:
  Bool.or(String.eq(n, ":authority"), client.req.hop(n))

def client.req.drop.go(+n: String, +v: String, rec: List<&2, HTTP.Hdr>, drop: Bool) ->
  List<&2, HTTP.Hdr>:
  match drop:
    case True{}:
      rec
    case False{}:
      HTTP.Hdr{n, v} <> rec

def client.req.drop(hs: List<&2, HTTP.Hdr>) -> List<&2, HTTP.Hdr>:
  match hs:
    case Nil{}:
      Nil{}
    case HTTP.Hdr{n, v} <> t:
      +nn = n
      +vv = v
      client.req.drop.go(nn, vv, client.req.drop(t), client.req.drop_name(nn))

def client.req.with_authority(+host: String, +port: U32, hs: List<&2, HTTP.Hdr>) ->
  List<&2, HTTP.Hdr>:
  HTTP.Hdr{":authority", host ++ ":" ++ U32.show(port)} <> client.req.drop(hs)

def client.req.hdrs(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>) ->
  List<&2, HTTP.Hdr>:
  List.append(&2, HTTP.Hdr, [HTTP.Hdr{":method", method}, HTTP.Hdr{":path", path}, HTTP.Hdr{":scheme", "https"}], client.req.with_authority(host, port, hs))

def client.req.block(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>) ->
  List<&2, U32>:
  x_block(client.req.hdrs(host, port, method, path, hs))

# Window-update + RST sends (best-effort credit, mold h2_send_wu_len)
# -------------------------------------------------------------------

# CONTINUATION finish for client HEADERS without END_HEADERS
# (mirror h2_cont_read; narrow single-@unsafe loop)
# ----------------------------------------------------------

def client.cont.end(last: Bool) -> U32:
  match last:
    case True{}:
      0
    case False{}:
      1

def client.cont.ok(+typ: U32, +sid: U32, +exp: U32) -> Bool:
  Bool.and(U32.is_eq(typ, x_t_cont()), Bool.and(U32.is_eq(sid, exp), U32.is_gt(sid, 0)))

def client.cont.last(+flags: U32) -> Bool:
  U32.is_eq(x_fin_hdr(flags), x_f_end_headers())

# 0 ends the block, 1 reads another fragment, 2 is not a CONTINUATION for
# this block, 3 is a block past x_max_block().
def client.cont.cls(over: Bool, ok: Bool, +typ: U32, +sid2: U32, +sid: U32, +flags: U32) -> U32:
  match over ok:
    case True{} _:
      3
    case False{} True{}:
      client.cont.end(client.cont.last(flags))
    case False{} False{}:
      2

def client.cont.cls_of(+typ: U32, +sid2: U32, +sid: U32, +flags: U32, over: Bool) -> U32:
  client.cont.cls(over, client.cont.ok(typ, sid2, sid), typ, sid2, sid, flags)

def client.resp.status(+head: HTTP.Head) -> U32:
  match head:
    case HTTP.Head{+status, headers}:
      status

def client.resp.has_head(+head: HTTP.Head) -> Bool:
  U32.is_ne(client.resp.status(head), 0)

# A response head must carry :status; only a trailer block may leave it
# at 0. A status-less first block is a decode failure, not an empty
# answer.
def client.resp.head_ok(ok: Bool, is_tr: Bool, +status: U32) -> Bool:
  match ok:
    case False{}:
      False{}
    case True{}:
      Bool.or(is_tr, U32.is_ne(status, 0))

def client.route.mine.go(+cls: U32, is_stream: Bool, is_mine: Bool) -> U32:
  match is_stream is_mine:
    case True{} False{}:
      0
    case _ _:
      cls

# Classes that belong to exactly one stream, so a drain that opened
# another sid must not act on them: DATA and HEADERS (6) and RST_STREAM
# (2). A sibling's RST is legitimate -- a peer resets a stream it already
# answered (node:http2 sends RST_STREAM NO_ERROR once the response is out
# and the request body is still coming) and a pushed stream is reset
# freely -- so treating it as ours failed the request with a bare 502.
# CONTINUATION (8) stays unfiltered: RFC 9113 section 6.10 makes a
# CONTINUATION for another stream while a block is open a connection
# error, which is exactly the fail-closed arm the drains already have.
def client.route.stream_cls(+cls: U32) -> Bool:
  match cls:
    case 2:
      True{}
    case 6:
      True{}
    case _:
      False{}

def client.route.mine.cls(+cls: U32, +sid2: U32, +exp: U32) -> U32:
  client.route.mine.go(cls, client.route.stream_cls(cls), U32.is_eq(sid2, exp))

def ledger.is_trailer(+old: HTTP.Head, +new: HTTP.Head) -> Bool:
  Bool.and(client.resp.has_head(old), Bool.not(client.resp.has_head(new)))

def ledger.head_keep_go(+old: HTTP.Head, +new: HTTP.Head, is_trailer: Bool) -> HTTP.Head:
  match is_trailer:
    case True{}:
      old
    case False{}:
      new

# A trailer ends the body (act 1, the stored head and body ride out); a
# trailer without END_STREAM is a protocol error (act 5, fail closed).
def ledger.trailer_act(+end: U32) -> U32:
  match end:
    case 1:
      1
    case _:
      5

# The trailer decision only applies to a complete block: a fragmented
# HEADERS (need 1) has to walk the CONTINUATION path first, because the
# END_STREAM that closes a trailer rides the last CONTINUATION frame, not
# this one (a HEADERS with END_STREAM and without END_HEADERS is a
# protocol error anyway). x_resp.decode on a partial block answers status
# 0, so without the gate a fragmented trailer looked like a trailer with
# the END_STREAM missing (act 5) instead of act 6.
def ledger.head_act2(is_trailer: Bool, +need: U32, ok: Bool, +end: U32) -> U32:
  match is_trailer need:
    case True{} 0:
      ledger.trailer_act(end)
    case _ _:
      ledger.head_act(need, ok, end)

# Preface and the request send: the dial sends the preface, the loops
# send one request (HEADERS + one DATA). Helpers above the entries.
# ---------------------------------------------------------------------

def client.preface.bytes() -> List<&2, U32>:
  List.append(&2, U32, x_preface(), x_frame_write(x_t_settings(), 0, 0, x_settings_initial_pay()))

def client.conn_pre.send(sock: Socket) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  TLS.tls_send_bytes(sock, client.preface.bytes())

def client.conn_pre.ack(pre: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  (sock, r) = pre
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, Socket>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{u}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Done{sock})

# Transport (TASK-058 phase 0): the H2 client dials itself. The module is
# H2 only, so the dial offers h2 alone and a peer that does not answer h2 is
# refused 615 in the handshake: no HTTP/1.1 arm exists here. The preface and
# the is_h2 stamp travel with the socket.
# ---------------------------------------------------------------------

def client.conn_of(pre: Result<&1, &1, U32 & String, Socket>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>):
  match pre:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, Fail{e})
    case Done{sock}:
      IO.pure(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>,
        Done{(sock, HTTP.CliSt{1, x_tab.empty(), True{}, x_init_window()})})

def client.conn_h2(conn: Result<&1, &1, U32 & String, Socket>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, Socket & HTTP.CliSt>>:
        pre : Socket & Result<&1, &1, U32 & String, Unit> <- client.conn_pre.send(sock)
        r : Result<&1, &1, U32 & String, Socket> <- client.conn_pre.ack(pre)
        client.conn_of(r)

def client.connect(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>):
  do IO<Result<&1, &1, U32 & String, Socket & HTTP.CliSt>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect(host, port)
    client.conn_h2(conn)

def client.connect_insecure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>):
  do IO<Result<&1, &1, U32 & String, Socket & HTTP.CliSt>>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(host, port)
    client.conn_h2(conn)

# Request send (HEADERS + one DATA; upload cap 16KB checked by caller)
# --------------------------------------------------------------------

def client.req.send_head(sock: Socket, +sid: U32, +block: List<&2, U32>, is_empty: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  x_send_block(sock, sid, block, x_b2u(is_empty))

# The request send hands back the read seed a flow body may have left
# (TASK-042 phase 2b): an empty body or a one-frame body never stops on
# a frame, a body that outruns the window can stop on the response. The
# fourth field is the connection window the pump has left, and `buf` is
# the bytes an earlier send of the same pipeline already read (TASK-063
# phase 7e): the pump must parse them before it reads the socket.
def client.req.send(sock: Socket, +sid: U32, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>, +cw: U32, +buf: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32):
  +empty = List.is_empty(&2, U32, body)
  do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- client.req.send_head(sock, sid, client.req.block(host, port, method, path, hs), empty)
    x_send_resp_head(sent, sid, body, empty, cw, x_init_window(), x_init_window(), buf)

# Streaming download (Phase E): H2 HEADERS/DATA to a pure handler, O(1)
# per chunk (counts only, no body accumulation). WU per non-fin DATA
# (best-effort, mold h2_send_wu_len); Cancel sends RST_STREAM (8) + Fail.
# ---------------------------------------------------------------------

def client.stream.is_cont(+out: HTTP.StreamOut) -> Bool:
  match out:
    case HTTP.StreamContinue{}:
      True{}
    case HTTP.StreamCancel{}:
      False{}

def client.stream.act(is_cont: Bool, +need: U32, ok: Bool, +end: U32) -> U32:
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

def client.stream.data_act(is_cont: Bool, has: Bool, +end: U32) -> U32:
  match is_cont has end:
    case False{} _ _:
      7
    case True{} False{} _:
      4
    case True{} True{} 1:
      1
    case _ _ _:
      0

# The streaming handler sees a StreamHead only for a complete, real head.
# A fragmented block (need 1) has no decoded head yet — x_resp.decode on
# the first fragment answers status 0 — and the last CONTINUATION frame
# rejoins phase 4 handler-free, so the old code handed the handler a
# StreamHead{0} it could only cancel on. A trailer is recognized but
# never becomes an event either (TASK-042 phase 3): it closes the body
# (ledger.trailer_act) or fails closed when its END_STREAM is missing.
def client.stream.head_act(~H: HTTP.StreamEv -> HTTP.StreamOut, ev: HTTP.StreamEv, is_tr: Bool, +need: U32, ok: Bool, +end: U32) -> U32:
  match is_tr need:
    case _ 1:
      ledger.head_act(need, ok, end)
    case True{} _:
      ledger.trailer_act(end)
    case False{} _:
      client.stream.act(client.stream.is_cont(H(ev)), need, ok, end)

# The terminals of the merged client loop: a cancel sends RST_STREAM and
# fails 8, and the credit and send helpers answer the socket beside the
# counts. The merged loop attaches the table and the sink below.
def client.loop.cancel_done(rst: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes>):
  (s2, r2) = rst
  IO.pure(Socket & Result<&1, &1, U32 & String, LoopRes>, (s2, Fail{(8, "cancelled")}))

def client.loop.cancelled(got: Socket & HTTP.Got, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes>):
  (s, g) = got
  do IO<Socket & Result<&1, &1, U32 & String, LoopRes>>:
    rst : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(s, sid, 8)
    client.loop.cancel_done(rst)

# CONTINUATION inline leaves for sdrop (Phase 15 item 2): fresh Err-next
# pair to (re)enter the cont-read phase, and GOAWAY-fail mapping for a
# bad CONT frame (mirror client.on.cont_failed, sdrop result shape).
# The phase 7 entry re-reads `end` from the frame that completed the
# block: the END_STREAM that closes a fragmented head (or trailer) rides
# the last CONTINUATION, never the first HEADERS (TASK-042 phase 3b).
# Pure leaves above the loop (callee-above-caller, no ~H inside).
# ---------------------------------------------------------------------

def client.loop.next_got(s: Socket) -> Socket & HTTP.Got:
  (s, HTTP.GotErr{0, "next"})

def client.loop.sendfail(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, LoopRes>, (s, Fail{e}))
    case Done{u}:
      IO.pure(Socket & Result<&1, &1, U32 & String, LoopRes>, (s, Fail{(502, "continuation")}))

# The loop result carries the HPACK table beside the counts: the next
# request on the same connection decodes against it (TASK-058 phase 1).
# The concurrent lanes keep the bare pair, so the wrappers are the only
# difference between the two shapes (callee above caller).
# ---------------------------------------------------------------------

type Sink is Data:
  Sink{head: HTTP.Head, rev: List<&2, U32>}

# The answer of the merged client loop: the body byte count, the finished
# stream count, the ledger and the connection send window the loop has
# left (TASK-063 phase 7c). A four-field & chain cannot ride inside
# Result as a type argument, so it is a Data type.
type LoopRes is Data:
  LoopRes{t: U32, f: U32, ss: List<&2, HTTP.St>, cw: U32}

# act + the body being built + the collect flag ride in one Data: the
# checker refuses a second match after a tuple destructure.
type Act is Data:
  Act{act: U32, rev: List<&2, U32>, collect: Bool}

def client.sink.resp(sink: Sink) -> HTTP.Response:
  match sink:
    case Sink{head, rev}:
      match head:
        case HTTP.Head{+status, +headers}:
          HTTP.Response{status, headers, HTTP.x_cat(rev)}

def client.loop.push.go(is_on: Bool, +payload: List<&2, U32>, +rev: List<&2, U32>) -> List<&2, U32>:
  match is_on:
    case True{}:
      HTTP.x_rev_push(payload, rev)
    case False{}:
      rev

def client.loop.push(is_on: Bool, +payload: List<&2, U32>, +rev: List<&2, U32>) -> List<&2, U32>:
  client.loop.push.go(is_on, payload, rev)

# The once lane answers counts only: this def drops the ledger of the
# merged loop answer.
def client.loop.counts(r: Result<&1, &1, U32 & String, LoopRes>) ->
  Result<&1, &1, U32 & String, U32 & U32>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{c}:
      match c:
        case LoopRes{+t, +f, ss, +cw2}:
          Done{(t, f)}

# The merged loop answers the wide shape, so each terminal attaches the
# table and the sink of the once lane; the concurrent lane drops both in
# its projection.
def client.loop.attach(out: Socket & Result<&1, &1, U32 & String, LoopRes>, +tab: HTTP.Tab, +head: HTTP.Head, +rev: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  (s, r) = out
  IO.pure(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink, (s, r, tab, Sink{head, rev}))

def client.loop.fail_s(s: Socket, +code: U32, +msg: String, +tab: HTTP.Tab, +head: HTTP.Head, +rev: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  client.loop.attach((s, Fail{(code, msg)}), tab, head, rev)

def client.loop.fail_t(got: Socket & HTTP.Got, +code: U32, +msg: String, +tab: HTTP.Tab, +head: HTTP.Head, +rev: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  (s, g) = got
  client.loop.fail_s(s, code, msg, tab, head, rev)

def client.loop.done_t(got: Socket & HTTP.Got, +total: U32, +fins: U32, +slots: List<&2, HTTP.St>, +cw: U32, +tab: HTTP.Tab, +head: HTTP.Head, +rev: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  (s, g) = got
  client.loop.attach((s, Done{LoopRes{total, fins, slots, cw}}), tab, head, rev)

def client.loop.cancelled_t(got: Socket & HTTP.Got, +sid: U32, +tab: HTTP.Tab, +head: HTTP.Head, +rev: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
    out : Socket & Result<&1, &1, U32 & String, LoopRes> <- client.loop.cancelled(got, sid)
    client.loop.attach(out, tab, head, rev)

def client.loop.sendfail_t(sent: Socket & Result<&1, &1, U32 & String, Unit>, +tab: HTTP.Tab, +head: HTTP.Head, +rev: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
    out : Socket & Result<&1, &1, U32 & String, LoopRes> <- client.loop.sendfail(sent)
    client.loop.attach(out, tab, head, rev)

# Stream-lane close helpers: they drop the loop shape each lane needs
# and close the socket. Shared by the content lanes and the legacy leg.
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

# The concurrent mode answers counts beside the ledger; this lane counts
# and closes (one loop serves both concurrent lanes).
def client_stream.counted(out: Socket & Result<&1, &1, U32 & String, LoopRes>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, r) = out
  client_stream.drained((s, client.loop.counts(r)))

def client.loop.st_sid(+st: HTTP.CliSt) -> U32:
  match st:
    case HTTP.CliSt{+sid, tab, h2, cw}:
      sid

def client.loop.st_tab(+st: HTTP.CliSt) -> HTTP.Tab:
  match st:
    case HTTP.CliSt{sid, +tab, h2, cw}:
      tab

def client.loop.next_sid(+sid: U32) -> U32:
  (sid + 2 : U32)

# The connection window the client has left, and the setter the send
# chain uses to store what the pump of the last body returned
# (TASK-063 phase 7c).
def client.loop.st_cw(+st: HTTP.CliSt) -> U32:
  match st:
    case HTTP.CliSt{sid, tab, h2, cw}:
      cw

def client.loop.st_set_cw(+st: HTTP.CliSt, +cw: U32) -> HTTP.CliSt:
  match st:
    case HTTP.CliSt{+sid, tab, +h2, old}:
      HTTP.CliSt{sid, tab, h2, cw}

def client.loop.next_st(+st: HTTP.CliSt, +tab: HTTP.Tab) -> HTTP.CliSt:
  match st:
    case HTTP.CliSt{+sid, old, +h2, cw}:
      HTTP.CliSt{client.loop.next_sid(sid), tab, h2, cw}

# The CliSt after one exchange: the next sid, the loop table and the
# window the loop has left (TASK-063 phase 7c). Both fold paths call it.
def client.loop.st_after(+st: HTTP.CliSt, +tab: HTTP.Tab, +cw: U32) -> HTTP.CliSt:
  client.loop.st_set_cw(client.loop.next_st(st, tab), cw)

# Concurrent slots (Phase D): response assembly per sid. The client lane
# keeps one ledger entry for each open stream, in the shared St type: its
# head rides SlotResp, so no slot op copies a head (TASK-055 phase 4a).
# Ops mirror the httpxn slot walkers: single-traversal, clone-free (S
# incs, no clones). fends/CONT stays Fail 502 (single-HEADERS peers);
# fdel_flag remains for later CONT if a peer fragments.
# ---------------------------------------------------------------------

def httpxc.head_of(st: HTTP.St) -> HTTP.Head:
  match st:
    case HTTP.St{head, body, sid, n}:
      match head:
        case Some{HTTP.SlotResp{+h}}:
          h
        case _:
          HTTP.Head{0, Nil{}}

# Head stored for one sid, or Head{0, Nil{}} when the ledger has no
# entry. Reads the slots list without rebuilding it (the shape
# ledger.has/has_some use), and ledger.is_trailer needs the stored head
# to tell a trailer block from a real one (TASK-042 phase 3b).
def httpxc.head_lookup_go(eq: Bool, +st: HTTP.St, rec: HTTP.Head) -> HTTP.Head:
  match eq:
    case True{}:
      httpxc.head_of(st)
    case False{}:
      rec

def httpxc.head_lookup(slots: List<&2, HTTP.St>, +sid: U32) -> HTTP.Head:
  match slots:
    case Nil{}:
      HTTP.Head{0, Nil{}}
    case +st <> t:
      httpxc.head_lookup_go(x_same_sid(st, sid), st, httpxc.head_lookup(t, sid))

def httpxc.req_of_st(st: HTTP.St, +payload: List<&2, U32>) -> HTTP.Response:
  match st:
    case HTTP.St{head, +body, +sid, n}:
      match head:
        case Some{HTTP.SlotResp{+rh}}:
          match rh:
            case HTTP.Head{+status, +headers}:
              HTTP.Response{status, headers, HTTP.x_cat(HTTP.x_rev_push(payload, body))}
        case _:
          HTTP.Response{0, Nil{}, HTTP.x_cat(HTTP.x_rev_push(payload, body))}

def httpxc.data_cont_slots(p: HTTP.Taken, +payload: List<&2, U32>) -> List<&2, HTTP.St>:
  match p:
    case HTTP.Taken{+rest, st}:
      match st:
        case HTTP.St{head, +body, +sid, n}:
          match head:
            case None{}:
              ((HTTP.St{Some{HTTP.SlotResp{HTTP.Head{0, Nil{}}}}, HTTP.x_rev_push(payload, body), sid, n} <> rest))
            case Some{+sh}:
              ((HTTP.St{Some{sh}, HTTP.x_rev_push(payload, body), sid, n} <> rest))

# Concurrent send-all (pipelined HEADERS+DATA, sids 1,3,5…; aborts on
# first send Fail; caller validates bodies/paths upfront)
# ---------------------------------------------------------------------

# The concurrent lane pipelines every request before it drains, so a
# frame that stopped a send (an early response mid-body) has nowhere to go
# yet: it is kept and handed to the loop once the pipeline is done
# (TASK-042 follow-up 2b). Before, the frame was dropped, the early
# answer never reached the loop and the call ended in Fail 502 (stray
# DATA) or hung for a response that had already arrived. Seeds accumulate
# in wire order: bytes read during an earlier send are always ahead of the
# ones read during a later one.
@unsafe
def client_conc.send_next(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32, +sid: U32, +host: String, +port: U32, reqs: List<&2, HTTP.Request>, +acc: List<&2, U32>, +cw: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>):
  (s, r, rest, cw2) = sent
  client_conc.send_after(r, s, sid, host, port, reqs, acc, rest, cw2)

@unsafe
def client_conc.send_all(sock: Socket, +sid: U32, +host: String, +port: U32, reqs: List<&2, HTTP.Request>, +acc: List<&2, U32>, +cw: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>):
  match reqs:
    case Nil{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, (sock, Done{Unit{}}, acc))
    case HTTP.Request{+method, +path, +headers, +body} <> t:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <- client.req.send(sock, sid, host, port, method, path, headers, body, cw, acc)
        client_conc.send_next(sent, sid, host, port, t, acc, cw)

# The answer of the last send picks the next step: a Fail keeps it, a
# Done hands the read seed and the window the pump left to the next send.
def client_conc.send_after(r: Result<&1, &1, U32 & String, Unit>, s: Socket, +sid: U32, +host: String, +port: U32, reqs: List<&2, HTTP.Request>, +acc: List<&2, U32>, +rest: List<&2, U32>, +cw2: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>):
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, (s, Fail{e}, acc))
    case Done{u}:
      client_conc.send_all(s, (sid + 2 : U32), host, port, reqs, rest, cw2)

# Concurrent leaf of the loop: the phase a finished stream leaves it on
# (7 when it was the last one, else 0).
# --------------------------------------------------------------------

def client_conc.finish_next(+pending: U32) -> U32:
  match pending:
    case 1:
      11
    case _:
      0

# One stream left in flight: never below zero.
def client_conc.pending_dec(+pending: U32) -> U32:
  match pending:
    case 0:
      0
    case _:
      (pending - 1 : U32)

# The highest sid a concurrent batch opened. The batch opens 1, 3, 5 ...
# so the request count gives it, and neither the loop nor the send needs a
# list of sids. The count travels as `high` because a cancel lowers
# pending without raising fins.
def client_conc.high_go(+n: U32) -> U32:
  match n:
    case 0:
      0
    case _:
      (2 * n - 1 : U32)

def client_conc.high(+pending: U32, +fins: U32) -> U32:
  client_conc.high_go(U32.add(pending, fins))

# True when the batch opened sid: odd and at or below the highest.
def client_conc.opened_go(is_odd: Bool, +sid: U32, +high: U32) -> Bool:
  match is_odd:
    case True{}:
      U32.is_le(sid, high)
    case False{}:
      False{}

def client_conc.opened(+sid: U32, +high: U32) -> Bool:
  client_conc.opened_go(U32.is_eq(U32.and(sid, 1), 1), sid, high)

# The answer for a HEADERS block that ends a stream. A real head (status
# present) answers from itself with no body, the ledger untouched: the
# old path, still O(1). A trailer block — x_resp.decode answers status 0
# when no :status is present, and a stored head is what makes it a
# trailer (ledger.is_trailer) — answers from the slot entry it closes,
# taken out so the ledger neither leaks nor loses the accumulated body.
# Both ride out through ClTaken, so the caller keeps the usual
# taken_slots/taken_st pair and httpxc.req_of_st builds the response.
# has arrives as a parameter: a match cannot scrutinize a call.
def client_conc.answer_go(has: Bool, slots: List<&2, HTTP.St>, +sid2: U32, +nh: HTTP.Head) -> HTTP.Taken:
  match has:
    case True{}:
      HTTP.Taken{slots, HTTP.St{Some{HTTP.SlotResp{nh}}, Nil{}, sid2, 0}}
    case False{}:
      ledger.take_del(slots, sid2)

def client_conc.answer(slots: List<&2, HTTP.St>, +sid2: U32, +nh: HTTP.Head) -> HTTP.Taken:
  client_conc.answer_go(client.resp.has_head(nh), slots, sid2, nh)

# The batch opens sids 1, 3, 5, ... (client_conc.exch starts at 1), so the
# first one is the lowest: a GOAWAY at or below it may have been acted on
# by the peer, and the batch fails as a whole, so that is the sid the
# retry verdict is read against.
def client_conc.first_sid() -> U32:
  1

# Concurrent streaming client (TASK-054 phase 3): the third client
# family. StreamEv/StreamOut carry no slot, so a pure handler cannot
# separate two downloads on one connection (discovery C2). This family
# puts the slot in each event and in each answer, and the drain loop
# keeps one ledger entry for each open stream (St, the ledger
# client.loop.concurrent uses).
#
# A CStreamCancel{slot} sends RST_STREAM(slot, 8): that stream ends and
# the siblings continue. The stream keeps a tombstone entry
# (St{None{}, Nil{}, sid}) and the pending count drops by one, because
# the frames of that stream can still be in flight (the library server
# sends the whole response in one write). A DATA frame for a stream
# without a stored head is skipped, and only the connection window takes
# the credit (the rule of httpxs.data_act_of, act 8). A head block for a
# tombstoned stream is skipped the same way, and its HPACK block still
# decodes, so the dynamic table stays in step.
#
# The trailer test reads the ledger (httpxc.head_lookup), never a loop
# argument: two streams share this loop, and the head of one stream is
# not the head of the other. The answer is (total bytes, finished
# streams): a cancelled stream is not finished, and its bytes are not
# counted.
# ---------------------------------------------------------------------

# Pure leaves (no IO, no ~H): the loop below calls them for the act code.
# ---------------------------------------------------------------------

def client_cstream.is_cancel(+out: HTTP.CStreamOut) -> Bool:
  match out:
    case HTTP.CStreamContinue{slot}:
      False{}
    case HTTP.CStreamCancel{slot}:
      True{}

def client_cstream.out_slot(+out: HTTP.CStreamOut) -> U32:
  match out:
    case HTTP.CStreamContinue{+slot}:
      slot
    case HTTP.CStreamCancel{+slot}:
      slot

# The answer names the stream it answers. A handler that mixes two slots
# is a handler bug: the lane fails closed (502) and never resets the
# wrong stream.
def client_cstream.slot_ok(+out: HTTP.CStreamOut, +sid: U32) -> Bool:
  U32.is_eq(client_cstream.out_slot(out), sid)

# A stream the ledger knows with no stored head: the batch dropped it
# (cancel or peer reset). Its frames in flight are skipped, never read as
# a new response.
# Ledger predicates. ledger.has answers "the sid is in the ledger".
# ledger.has_some answers "that entry has no head yet" -- the shape an
# open fragment has, and the opposite of what the name suggests
# (ledger.has_some_go: None is true, Some is false; ledger.frag_has is
# its one user). This lane stores a head for every open stream and a None
# head for every dropped one, so:
#   live = known and not headless (a stream with a stored head);
#   dead = known and headless (a tombstone: cancel or peer reset).
# The Bools ride argument positions: a match cannot scrutinize a call or
# a local binder (the discipline of this file).
def client_cstream.is_live_go(known: Bool, headless: Bool) -> Bool:
  match known:
    case False{}:
      False{}
    case True{}:
      Bool.not(headless)

def client_cstream.is_live(+slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  client_cstream.is_live_go(ledger.has(slots, sid), ledger.has_some(slots, sid))

def client_cstream.is_dead_go(known: Bool, headless: Bool) -> Bool:
  match known:
    case False{}:
      False{}
    case True{}:
      headless

def client_cstream.is_dead(+slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  client_cstream.is_dead_go(ledger.has(slots, sid), ledger.has_some(slots, sid))

# The state of a sid in the concurrent ledger: 0 finished (tombstoned),
# 1 in flight with a head, 2 in flight without one, 3 a sid the batch
# never opened (the batch opens 1, 3, 5 ... client_conc.opened).
def client_cstream.sid_state(is_dead: Bool, is_live: Bool, is_open: Bool) -> U32:
  match is_dead is_live is_open:
    case True{} _ _:
      0
    case False{} _ False{}:
      3
    case False{} False{} True{}:
      2
    case False{} True{} True{}:
      1

# Head act: 4 skip the block of a tombstoned stream, 6 read the
# CONTINUATION frames, 1 finish (a trailer with END_STREAM), 5 fail (a
# trailer without END_STREAM), 8 slot mismatch (a sid the batch never
# opened), 9 ask the handler.
def client_cstream.head_frame(state: U32, is_tr: Bool, +need: U32, +end: U32) -> U32:
  match state:
    case 0:
      match need:
        case 1:
          6
        case _:
          4
    case 3:
      8
    case 2:
      9
    case _:
      match is_tr need:
        case _ 1:
          6
        case True{} _:
          ledger.trailer_act(end)
        case False{} _:
          9

# Frame act for a DATA frame: 0 ask the handler (a live stream), 4 skip
# the frame (a dropped stream, or one the batch never opened).
def client_cstream.live_act(is_live: Bool) -> U32:
  match is_live:
    case True{}:
      0
    case False{}:
      4

# Peer reset act: 0 ignores the reset of a stream already finished (a
# peer may reset after the answer, the node:http2 shape), 8 is a sid the
# batch never opened, 18 fails the call for a stream still in flight: a
# silent drop would read as "nothing was there" instead of "the answer
# was lost".
def client_cstream.rst_act(state: U32) -> U32:
  match state:
    case 0:
      0
    case 3:
      8
    case _:
      18

# Head act for a block the handler saw: 8 slot mismatch, 7 cancel, else
# the shared ledger.head_act (0 store, 1 finish, 5 decode fail). The
# variant and the slot of the answer ride arguments: a match cannot
# scrutinize a call (the discipline of this file).
def client_cstream.head_out_act(is_slot: Bool, is_cancel: Bool, ok: Bool, +end: U32) -> U32:
  match is_slot:
    case False{}:
      8
    case True{}:
      match is_cancel:
        case True{}:
          7
        case False{}:
          ledger.head_act(0, ok, end)

# The act from the handler answer alone: the answer names its slot, so
# the caller calls the handler once and reads the answer twice.
def client_cstream.head_out_go(sid: U32, +out: HTTP.CStreamOut, ok: Bool, +end: U32) -> U32:
  client_cstream.head_out_act(client_cstream.slot_ok(out, sid), client_cstream.is_cancel(out), ok, end)

# Data act for a live stream: 8 slot mismatch, 7 cancel, else the shared
# ledger.decide_data (0 credit and continue, 1 credit and finish).
def client_cstream.data_out_act(is_slot: Bool, is_cancel: Bool, +end: U32) -> U32:
  match is_slot:
    case False{}:
      8
    case True{}:
      match is_cancel:
        case True{}:
          7
        case False{}:
          ledger.decide_data(True{}, end)

# The act from the handler answer alone (one call to the handler).
def client_cstream.data_out_go(sid: U32, +out: HTTP.CStreamOut, +end: U32) -> U32:
  client_cstream.data_out_act(client_cstream.slot_ok(out, sid), client_cstream.is_cancel(out), end)

# A dropped stream stays in the ledger without a head.
def client_cstream.tombstone(slots: List<&2, HTTP.St>, +sid: U32) -> List<&2, HTTP.St>:
  ledger.put(slots, HTTP.St{None{}, Nil{}, sid, 0})

# Collect mode of the concurrent mode (TASK-058 phase 3.5). The buffered
# lane asks the loop for the ledger, never for a handler answer, so the
# acts that ask the handler and the two that drop a finished stream
# change shape. The stream lane passes collect = False and keeps every
# byte out of the ledger.
# ---------------------------------------------------------------------

def client.concurrent.drop(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  HTTP.CStreamContinue{0}

# The head act of collect mode is the table of the old buffered drain
# (ledger.head_act2): it never asks the handler and it reads a fragmented
# block, so an unknown stream still walks its CONTINUATION frames. The
# stream lane keeps head_frame, which asks the handler. A dropped stream
# skip (4) is the same in both tables.
def client.concurrent.head_act(is_collect: Bool, is_tr: Bool, ok: Bool, +need: U32, +end: U32, +act: U32) -> U32:
  match is_collect act:
    case False{} _:
      act
    case True{} 4:
      4
    case True{} 8:
      8
    case True{} _:
      ledger.head_act2(is_tr, need, ok, end)

# The head block that closes a stream: collect keeps it, the stream lane
# drops it. answer names the block, so a trailer keeps the stored head
# and body instead of overwriting them with the trailer fields.
def client.concurrent.answer_slots(+p: HTTP.Taken) -> List<&2, HTTP.St>:
  ledger.put(ledger.taken_slots(p), ledger.taken_st(p))

def client.concurrent.finish_slots(is_collect: Bool, slots: List<&2, HTTP.St>, +head: HTTP.Head, +sid2: U32) -> List<&2, HTTP.St>:
  match is_collect:
    case False{}:
      client_cstream.tombstone(slots, sid2)
    case True{}:
      client.concurrent.answer_slots(client_conc.answer(slots, sid2, head))

def client.concurrent.data_slots(is_collect: Bool, slots: List<&2, HTTP.St>, +sid2: U32, +payload: List<&2, U32>) -> List<&2, HTTP.St>:
  match is_collect:
    case False{}:
      slots
    case True{}:
      httpxc.data_cont_slots(ledger.take_del(slots, sid2), payload)

def client.concurrent.end_slots(is_collect: Bool, slots: List<&2, HTTP.St>, +sid2: U32, +payload: List<&2, U32>) -> List<&2, HTTP.St>:
  match is_collect:
    case False{}:
      client_cstream.tombstone(slots, sid2)
    case True{}:
      httpxc.data_cont_slots(ledger.take_del(slots, sid2), payload)

# The merged client loop (TASK-061): one machine, two modes. `on` is the
# ordered lane, one exchange at a time (client.loop.on); `concurrent`
# keeps N streams in flight (client.loop.concurrent). The mode picks the act table; the
# loop reads the act, so the phases, the HPACK decode, the flow pump and
# the frame dispatch are shared. Every computed code rides an argument
# and the next phase matches the parameter (a match cannot scrutinize a
# call). Act codes of the once lane and of the concurrent lane are
# disjoint, so the loop never branches on the mode.
# ---------------------------------------------------------------------

# The cls of a frame, by mode. `on` drops the stream-scoped frames of a
# sibling stream (client.route.mine); `concurrent` acts on every frame.
def client.loop.cls_of(+mode: U32, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +sid2: U32, +exp: U32) -> U32:
  match mode:
    case 0:
      client.route.mine.cls(httpx.cls_fix(x_cls(typ, sid, flags, payload), flags), sid2, exp)
    case _:
      httpx.cls_fix(x_cls(typ, sid, flags, payload), flags)

# A HEADERS act of the once lane: 0 means "keep the head, read on", which
# the loop spells as 4 (skip the frame state and read again).
def client.loop.go_act(+act: U32) -> U32:
  match act:
    case 0:
      4
    case _:
      act

# A HEADERS act of the concurrent lane: 0 stores the head, 1 finishes the
# stream, 7 cancels it. The loop spells them 10, 11 and 17.
def client.loop.conc_act(+act: U32) -> U32:
  match act:
    case 0:
      10
    case 1:
      11
    case 7:
      17
    case _:
      act

# A DATA act of the concurrent lane: 0 appends, 1 answers and finishes,
# 7 cancels. The loop spells them 13, 14 and 17.
def client.loop.conc_data(+act: U32) -> U32:
  match act:
    case 0:
      13
    case 1:
      14
    case 7:
      17
    case _:
      act

# A trailer test by mode: `on` keeps the head in the loop, `concurrent`
# reads it from the ledger of its stream.
def client.loop.is_tr(+mode: U32, +slots: List<&2, HTTP.St>, +head: HTTP.Head, +sid2: U32, nh: HTTP.Head) -> Bool:
  match mode:
    case 0:
      ledger.is_trailer(head, nh)
    case _:
      ledger.is_trailer(httpxc.head_lookup(slots, sid2), nh)

# The head the loop carries out of a HEADERS block: `on` keeps the stored
# head when the block is a trailer, `concurrent` always carries the decode.
def client.loop.head3_keep(+mode: U32, +head: HTTP.Head, nh: HTTP.Head, +is_tr: Bool) -> HTTP.Head:
  match mode:
    case 0:
      ledger.head_keep_go(head, nh, is_tr)
    case _:
      nh

# The HEADERS act, by mode: `on` asks the pure handler for a real head,
# `concurrent` reads the ledger (a tombstoned stream skips its block, a
# live one asks the handler in phase 4).
def client.loop.head_act3(~S: HTTP.StreamEv -> HTTP.StreamOut, +mode: U32, +c3: Bool, +slots: List<&2, HTTP.St>, +sid2: U32, nh: HTTP.Head, +need: U32, +ok: Bool, +end: U32, +is_tr: Bool, is_open: Bool) -> U32:
  match mode:
    case 0:
      client.loop.go_act(client.stream.head_act(~S, HTTP.StreamHead{nh}, is_tr, need, ok, end))
    case _:
      +state : U32 = client_cstream.sid_state(client_cstream.is_dead(slots, sid2), client_cstream.is_live(slots, sid2), is_open)
      client.loop.conc_act(client.concurrent.head_act(c3, is_tr, ok, need, end, client_cstream.head_frame(state, is_tr, need, end)))

# The CONTINUATION finish act, by mode.
def client.loop.cont_act(+mode: U32, +c7: Bool, +slots: List<&2, HTTP.St>, +sid2: U32, nh: HTTP.Head, +ok: Bool, +end: U32, +is_tr: Bool, is_open: Bool) -> U32:
  match mode:
    case 0:
      client.loop.go_act(ledger.head_act2(is_tr, 0, ok, end))
    case _:
      +state : U32 = client_cstream.sid_state(client_cstream.is_dead(slots, sid2), client_cstream.is_live(slots, sid2), is_open)
      client.loop.conc_act(client.concurrent.head_act(c7, is_tr, ok, 0, end, client_cstream.head_frame(state, is_tr, 0, end)))

# The stream a CONTINUATION frame must name: `on` expects the one sid of
# the exchange, `concurrent` the sid of the open block.
def client.loop.cont_sid(+mode: U32, +exp: U32, +sid2: U32) -> U32:
  match mode:
    case 0:
      exp
    case _:
      sid2

# The phase a DATA frame goes to: 5 answers it on the once lane, 10 is
# the ledger gate of the concurrent lane.
def client.loop.data_phase(+mode: U32) -> U32:
  match mode:
    case 0:
      5
    case _:
      10

# The DATA act, by mode: 0 asks the handler (once) or the ledger gate
# (concurrent), 1 answers (once), 4 skips a dead stream (concurrent).
def client.loop.data_act3(~S: HTTP.StreamEv -> HTTP.StreamOut, +mode: U32, +slots: List<&2, HTTP.St>, +sid2: U32, +head: HTTP.Head, +payload: List<&2, U32>, +end: U32) -> U32:
  match mode:
    case 0:
      +fin : Bool = U32.is_eq(end, 1)
      client.stream.data_act(client.stream.is_cont(S(HTTP.StreamData{payload, fin})), client.resp.has_head(head), end)
    case _:
      client_cstream.live_act(client_cstream.is_live(slots, sid2))

# The act of a peer reset, by mode: 18 fails the once exchange with the
# wired code, the concurrent lane ignores a reset for a dropped stream
# (0) and drops the live one.
def client.loop.rst_act(+mode: U32, +slots: List<&2, HTTP.St>, +sid2: U32, is_open: Bool) -> U32:
  match mode:
    case 0:
      18
    case _:
      client_cstream.rst_act(client_cstream.sid_state(client_cstream.is_dead(slots, sid2), client_cstream.is_live(slots, sid2), is_open))

# The frame a hop carries rides as four scalars plus its declared length
# (+flen): the credit of a DATA frame is that length (RFC 9113 section
# 6.9.1), so the loop never walks the payload to count it. A hop that
# carries no frame passes 0.
@unsafe
def client.loop(~S: HTTP.StreamEv -> HTTP.StreamOut, ~C: HTTP.CStreamEv -> HTTP.CStreamOut, +mode: U32, phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +tab: HTTP.Tab, +exp: U32, +slots: List<&2, HTTP.St>, +cpend: U32, +spend: List<&2, Pnd>, +cw: U32, +pending: U32, +high: U32, +head: HTTP.Head, +ok: Bool, +total: U32, +fins: U32, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +flen: U32, +cls: U32, +end: U32, act: Act) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
        got2 : Socket & HTTP.Got <- x_read_frame(s0, buf)
        client.loop(~S, ~C, mode, 1, got2, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, act)
    case 1:
      (s1, g1) = got
      match g1 act:
        case HTTP.GotErr{code1, msg1} Act{+a1, +r1, +c1}:
          client.loop.fail_s(s1, code1, msg1, tab, head, r1)
        case HTTP.GotOk{HTTP.Frame{+typ2, +flags2, +sid22, +flen2, +payload2}, +buf2} Act{+a1, +r1, +c1}:
          client.loop(~S, ~C, mode, 2, (s1, HTTP.GotOk{HTTP.Frame{typ2, flags2, sid22, flen2, payload2}, buf2}), buf2, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ2, flags2, sid22, payload2, flen2, client.loop.cls_of(mode, typ2, flags2, sid22, payload2, sid22, exp), x_fin(flags2), Act{4, r1, c1})
    case 2:
      match cls act:
        case 1 Act{+a2, +r2, +c2}:
          do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
            got2 : Socket & HTTP.Got <- httpx.ack(got)
            client.loop(~S, ~C, mode, 0, got2, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r2, c2})
        case 4 Act{+a2, +r2, +c2}:
          do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
            gotp : Socket & HTTP.Got <- httpx.ack_ping(got, payload)
            client.loop(~S, ~C, mode, 0, gotp, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r2, c2})
        case 5 Act{+a2, +r2, +c2}:
          client.loop.fail_t(got, x_goaway.status(payload, exp), x_goaway.reason(payload, exp), tab, head, r2)
        case 7 Act{+a2, +r2, +c2}:
          client.loop(~S, ~C, mode, 0, got, buf, tab, exp, slots, cpend, spend, client.loop.wu_cw(cw, sid2, payload), pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r2, c2})
        case 9 Act{+a2, +r2, +c2}:
          client.loop.fail_t(got, 502, "bad window_update", tab, head, r2)
        case 8 Act{+a2, +r2, +c2}:
          client.loop.fail_t(got, 502, "continuation", tab, head, r2)
        case 2 Act{+a2, +r2, +c2}:
          client.loop(~S, ~C, mode, 9, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{client.loop.rst_act(mode, slots, sid2, client_conc.opened(sid2, high)), r2, c2})
        case 6 Act{+a2, +r2, +c2}:
          client.loop(~S, ~C, mode, 3, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{4, r2, c2})
        case 0 Act{+a2, +r2, +c2}:
          client.loop(~S, ~C, mode, 0, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r2, c2})
        case _ Act{+a2, +r2, +c2}:
          client.loop(~S, ~C, mode, 0, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r2, c2})
    case 3:
      match typ act:
        case 1 Act{+a3, +r3, +c3}:
          +dr : Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab> = x_resp.decode(payload, tab)
          +nh : HTTP.Head = x_resp.rh(dr)
          +nt : HTTP.Tab = x_resp.tab(dr)
          +is_tr : Bool = client.loop.is_tr(mode, slots, head, sid2, nh)
          +ok3 : Bool = client.resp.head_ok(x_resp.ok(dr), is_tr, client.resp.status(nh))
          +need : U32 = ledger.need_u(typ, flags)
          +a3x : U32 = client.loop.head_act3(~S, mode, c3, slots, sid2, nh, need, ok3, end, is_tr, client_conc.opened(sid2, high))
          client.loop(~S, ~C, mode, 4, got, buf, nt, exp, slots, cpend, spend, cw, pending, high, client.loop.head3_keep(mode, head, nh, is_tr), ok3, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{a3x, r3, c3})
        case 0 Act{+a3, +r3, +c3}:
          +body3 : List<&2, U32> = x_data_body(payload, flags)
          client.loop(~S, ~C, mode, client.loop.data_phase(mode), got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{client.loop.data_act3(~S, mode, slots, sid2, head, body3, end), r3, c3})
        case _ Act{+a3, +r3, +c3}:
          client.loop(~S, ~C, mode, 0, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r3, c3})
    case 4:
      match act:
        case Act{+a4, +r4, +c4}:
          match a4:
            case 1:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +wbz : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, 0, True{})
                gotz : Socket & HTTP.Got <- x_wu.send(got, buf, wbz)
                client.loop.done_t(gotz, total, (fins + 1 : U32), Nil{}, cw, tab, head, r4)
            case 4:
              client.loop(~S, ~C, mode, 0, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r4, c4})
            case 5:
              client.loop.fail_t(got, 502, "head decode", tab, head, r4)
            case 6:
              client.loop(~S, ~C, mode, 6, client.loop.next_got(httpx.wo(got)), buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, HTTP.x_cat(payload), flen, 0, end, Act{0, r4, c4})
            case 7:
              client.loop.cancelled_t(got, sid2, tab, head, r4)
            case 8:
              client.loop.fail_t(got, 502, "slot mismatch", tab, head, r4)
            case 9:
              client.loop(~S, ~C, mode, 4, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{client.loop.conc_act(client_cstream.head_out_go(sid2, C(HTTP.CStreamHead{sid2, head}), ok, end)), r4, c4})
            case 10:
              client.loop(~S, ~C, mode, 0, got, buf, tab, exp, ledger.put(slots, HTTP.St{Some{HTTP.SlotResp{head}}, Nil{}, sid2, 0}), cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r4, c4})
            case 11:
              client.loop(~S, ~C, mode, client_conc.finish_next(pending), got, buf, tab, exp, client.concurrent.finish_slots(c4, slots, head, sid2), cpend, spend, cw, client_conc.pending_dec(pending), high, head, ok, total, (fins + 1 : U32), 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r4, c4})
            case 17:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                rst : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(httpx.wo(got), sid2, 8)
                client.loop(~S, ~C, mode, client_conc.finish_next(pending), httpx.sent(rst), buf, tab, exp, client_cstream.tombstone(slots, sid2), cpend, x_wu.del(spend, sid2), cw, client_conc.pending_dec(pending), high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r4, c4})
            case _:
              client.loop.fail_t(got, 502, "head", tab, head, r4)
    case 5:
      match act:
        case Act{+a5, +r5, +c5}:
          match a5:
            case 0:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +fin : Bool = U32.is_eq(end, 1)
                +wb : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin)
                got2 : Socket & HTTP.Got <- x_wu.send(got, buf, wb)
                client.loop(~S, ~C, mode, 0, got2, buf, tab, exp, slots, x_wu.next_cpend(cpend, flen, fin), x_wu.next_spend(spend, sid2, flen, fin), cw, pending, high, head, ok, (total + flen : U32), fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, client.loop.push(c5, payload, r5), c5})
            case 1:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +fin1 : Bool = U32.is_eq(end, 1)
                +wb1 : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin1)
                got2 : Socket & HTTP.Got <- x_wu.send(got, buf, wb1)
                client.loop.done_t(got2, (total + flen : U32), (fins + 1 : U32), Nil{}, cw, tab, head, client.loop.push(c5, payload, r5))
            case 4:
              client.loop.fail_t(got, 502, "stray data", tab, head, r5)
            case 7:
              client.loop.cancelled_t(got, sid2, tab, head, r5)
            case 8:
              client.loop.fail_t(got, 502, "slot mismatch", tab, head, r5)
            case 13:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +fin13 : Bool = U32.is_eq(end, 1)
                +wb13 : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin13)
                got2 : Socket & HTTP.Got <- x_wu.send(got, buf, wb13)
                client.loop(~S, ~C, mode, 0, got2, buf, tab, exp, client.concurrent.data_slots(c5, slots, sid2, x_data_body(payload, flags)), x_wu.next_cpend(cpend, flen, fin13), x_wu.next_spend(spend, sid2, flen, fin13), cw, pending, high, head, ok, (total + flen : U32), fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r5, c5})
            case 14:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +fin14 : Bool = U32.is_eq(end, 1)
                +wb14 : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin14)
                got2 : Socket & HTTP.Got <- x_wu.send(got, buf, wb14)
                client.loop(~S, ~C, mode, client_conc.finish_next(pending), got2, buf, tab, exp, client.concurrent.end_slots(c5, slots, sid2, x_data_body(payload, flags)), x_wu.next_cpend(cpend, flen, fin14), x_wu.next_spend(spend, sid2, flen, fin14), cw, client_conc.pending_dec(pending), high, head, ok, (total + flen : U32), (fins + 1 : U32), 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r5, c5})
            case 17:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +wb17 : List<&2, U32> = x_wu.stray_bytes(cpend, flen)
                got17 : Socket & HTTP.Got <- x_wu.send(got, buf, wb17)
                rst : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(httpx.wo(got17), sid2, 8)
                client.loop(~S, ~C, mode, client_conc.finish_next(pending), httpx.sent(rst), buf, tab, exp, client_cstream.tombstone(slots, sid2), x_wu.stray_cpend(cpend, flen), x_wu.del(spend, sid2), cw, client_conc.pending_dec(pending), high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r5, c5})
            case _:
              client.loop.fail_t(got, 502, "data", tab, head, r5)
    case 6:
      (s6, g6) = got
      match g6 act:
        case HTTP.GotErr{0, msg6} Act{+a6, +r6, +c6}:
          do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
            got6 : Socket & HTTP.Got <- x_read_frame(s6, buf)
            client.loop(~S, ~C, mode, 6, got6, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, sid2, payload, flen, 0, end, Act{0, r6, c6})
        case HTTP.GotErr{code6, msg6} Act{+a6, +r6, +c6}:
          client.loop.fail_s(s6, code6, msg6, tab, head, r6)
        case HTTP.GotOk{HTTP.Frame{+typ6, +flags6, +sid6, +flen6, +pay6}, +buf6} Act{+a6, +r6, +c6}:
          client.loop(~S, ~C, mode, 7, (s6, HTTP.GotOk{HTTP.Frame{typ6, flags6, sid6, flen6, pay6}, buf6}), buf6, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ6, flags6, sid2, HTTP.x_rev_push(pay6, payload), flen6, client.cont.cls_of(typ6, sid6, client.loop.cont_sid(mode, exp, sid2), flags6, x_block_over(payload, pay6)), x_fin(flags6), Act{0, r6, c6})
    case 7:
      (s7, g7) = got
      match cls act:
        case 0 Act{+a7, +r7, +c7}:
          +dr7 : Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab> = x_resp.decode(HTTP.x_cat(payload), tab)
          +nh7 : HTTP.Head = x_resp.rh(dr7)
          +is_tr7 : Bool = client.loop.is_tr(mode, slots, head, sid2, nh7)
          +ok7 : Bool = client.resp.head_ok(x_resp.ok(dr7), is_tr7, client.resp.status(nh7))
          +a7x : U32 = client.loop.cont_act(mode, c7, slots, sid2, nh7, ok7, end, is_tr7, client_conc.opened(sid2, high))
          client.loop(~S, ~C, mode, 4, client.loop.next_got(s7), buf, x_resp.tab(dr7), exp, slots, cpend, spend, cw, pending, high, client.loop.head3_keep(mode, head, nh7, is_tr7), ok7, total, fins, typ, flags, sid2, Nil{}, 0, cls, end, Act{a7x, r7, c7})
        case 1 Act{+a7, +r7, +c7}:
          client.loop(~S, ~C, mode, 6, client.loop.next_got(s7), buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, sid2, payload, flen, 0, end, Act{0, r7, c7})
        case 3 Act{+a7, +r7, +c7}:
          client.loop.fail_s(s7, 431, "header block too large", tab, head, r7)
        case _ Act{+a7, +r7, +c7}:
          do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_goaway(s7, 0, 1)
            client.loop.sendfail_t(sent, tab, head, r7)
    case 9:
      match act:
        case Act{+a9, +r9, +c9}:
          match a9:
            case 0:
              client.loop(~S, ~C, mode, 0, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r9, c9})
            case 8:
              client.loop.fail_t(got, 502, "slot mismatch", tab, head, r9)
            case 18:
              client.loop.fail_t(got, x_rst.status(payload), x_rst.reason(payload), tab, head, r9)
            case _:
              client.loop(~S, ~C, mode, client_conc.finish_next(pending), got, buf, tab, exp, client_cstream.tombstone(slots, sid2), cpend, x_wu.del(spend, sid2), cw, client_conc.pending_dec(pending), high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r9, c9})
    case 10:
      match act:
        case Act{+a10, +r10, +c10}:
          match a10:
            case 0:
              match c10:
                case True{}:
                  client.loop(~S, ~C, mode, 5, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{client.loop.conc_data(ledger.decide_data(True{}, end)), r10, c10})
                case False{}:
                  client.loop(~S, ~C, mode, 5, got, buf, tab, exp, slots, cpend, spend, cw, pending, high, head, ok, total, fins, typ, flags, sid2, payload, flen, cls, end, Act{client.loop.conc_data(client_cstream.data_out_go(sid2, C(HTTP.CStreamData{sid2, x_data_body(payload, flags), U32.is_eq(end, 1)}), end)), r10, c10})
            case _:
              do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
                +wb10 : List<&2, U32> = x_wu.stray_bytes(cpend, flen)
                got2 : Socket & HTTP.Got <- x_wu.send(got, buf, wb10)
                client.loop(~S, ~C, mode, 0, got2, buf, tab, exp, slots, x_wu.stray_cpend(cpend, flen), x_wu.del(spend, sid2), cw, pending, high, head, ok, total, fins, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, r10, c10})
    case 11:
      do IO<Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink>:
        +wbz : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, 0, True{})
        gotz : Socket & HTTP.Got <- x_wu.send(got, buf, wbz)
        client.loop.done_t(gotz, total, fins, slots, cw, tab, head, Nil{})
    case _:
      client.loop.fail_t(got, 502, "bad phase", tab, head, Nil{})

# The two dummies: each mode passes the handler it does not call.
def client.no_event(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  HTTP.StreamContinue{}

def client.no_cstream(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  HTTP.CStreamContinue{0}

# N in flight: the merged loop with mode concurrent and the pure handler
# idle. The table and the sink the wide answer carries are dropped here.
def client.loop.wide_t(out: Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes>):
  (s, r, tab, k) = out
  IO.pure(Socket & Result<&1, &1, U32 & String, LoopRes>, (s, r))

def client.loop.concurrent(~H: HTTP.CStreamEv -> HTTP.CStreamOut, phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +tab: HTTP.Tab, +slots: List<&2, HTTP.St>, +cpend: U32, +spend: List<&2, Pnd>, +cw: U32, +pending: U32, +total: U32, +fins: U32, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +cls: U32, +end: U32, +head: HTTP.Head, +ok: Bool, act: Act) ->
  IO(Socket & Result<&1, &1, U32 & String, LoopRes>):
  do IO<Socket & Result<&1, &1, U32 & String, LoopRes>>:
    out : Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink <-
      client.loop(~client.no_event, ~H, x_mode.concurrent(), phase, got, buf, tab, client_conc.first_sid(), slots, cpend, spend, cw, pending, client_conc.high(pending, 0), head, ok, total, fins, typ, flags, sid2, payload, 0, cls, end, act)
    client.loop.wide_t(out)

# Sequential lane over the merged loop (TASK-058 phase 1, form A of E1):
# one request is send + client.loop in mode on, and loop.on is that
# exchange repeated with a new sid. A pays one def entry, one Result and
# one CliSt for each request; it pays nothing for each frame.
# ---------------------------------------------------------------------

# The same fold for the sequential lane: counts plus the next CliSt.
def client.loop.exch.out(s: Socket, r: Result<&1, &1, U32 & String, LoopRes>, +tab: HTTP.Tab, +st: HTTP.CliSt) ->
  Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt:
  match r:
    case Fail{e}:
      (s, Fail{e}, st)
    case Done{+done}:
      match done:
        case LoopRes{+t, +f, ss, +cw}:
          (s, Done{(t, f)}, client.loop.st_after(st, tab, cw))

def client.loop.exch.tabbed(out: Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink, +st: HTTP.CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  (s, r, tab, k) = out
  IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt,
    client.loop.exch.out(s, r, tab, st))

def client.loop.exch.sent(~H: HTTP.StreamEv -> HTTP.StreamOut, sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, +st: HTTP.CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  (sock, r, seed) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt,
        (sock, Fail{e}, st))
    case Done{u}:
      do IO<Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt>:
        out : Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink <-
          client.loop(~H, ~client.no_cstream, x_mode.on(), 0, (sock, HTTP.GotErr{0, "next"}), seed, client.loop.st_tab(st), client.loop.st_sid(st), Nil{}, 0, Nil{}, client.loop.st_cw(st), 1, client_conc.first_sid(), HTTP.Head{0, Nil{}}, False{}, 0, 0, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, Nil{}, False{}})
        client.loop.exch.tabbed(out, st)

def client.loop.exch(~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32, req: HTTP.Request) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  match req:
    case HTTP.Request{method, path, headers, body}:
      do IO<Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt>:
        sent4 : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <-
          client.req.send(sock, client.loop.st_sid(st), host, port,
            method, path, headers, body, client.loop.st_cw(st), Nil{})
        client.loop.exch.sent(~H, httpx.sent3(sent4), st)

# Streaming entries (TASK-058 phase 2): one, N in order and N in flight.
# Each dials, runs its loop and closes on every exit.
# ---------------------------------------------------------------------

def client.stream.closed(out: Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, r, st) = out
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(Result<&1, &1, U32 & String, U32 & U32>, r)

# One stream (phase 2): dial, run the ordered loop, close on every exit.
# ---------------------------------------------------------------------

def client.stream.once.conn(~H: HTTP.StreamEv -> HTTP.StreamOut, conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        out : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
          client.loop.exch(~H, sock, st, host, port, HTTP.Request{method, path, hs, body})
        client.stream.closed(out)

def client.stream.once(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect(host, port)
    client.stream.once.conn(~H, conn, host, port, method, path, hs, body)

def client.stream.once_insecure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect_insecure(host, port)
    client.stream.once.conn(~H, conn, host, port, method, path, hs, body)

def client.loop.on.go(~H: HTTP.StreamEv -> HTTP.StreamOut, rest: List<&2, HTTP.Request>, +total: U32, +fins: U32, got: Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt, +host: String, +port: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  match rest:
    case Nil{}:
      (s0, r0, st0) = got
      match r0:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt,
            (s0, Fail{e}, st0))
        case Done{counts}:
          match counts:
            case (tot2, fin2):
              IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt,
                (s0, Done{((total + tot2 : U32), (fins + fin2 : U32))}, st0))
    case req <> t:
      (s2, r2, st2) = got
      match r2:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt,
            (s2, Fail{e}, st2))
        case Done{counts}:
          match counts:
            case (tot2, fin2):
              do IO<Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt>:
                got3 : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
                  client.loop.exch(~H, s2, st2, host, port, req)
                client.loop.on.go(~H, t, (total + tot2 : U32),
                  (fins + fin2 : U32), got3, host, port)

def client.loop.on(~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) ->
  IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  client.loop.on.go(~H, reqs, 0, 0, (sock, Done{(0, 0)}, st), host, port)

# N in order (phase 2): the same lane over loop.on.
# ---------------------------------------------------------------------

def client.stream.on.conn(~H: HTTP.StreamEv -> HTTP.StreamOut, conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        out : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
          client.loop.on(~H, sock, st, host, port, reqs)
        client.stream.closed(out)

def client.stream.on(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect(host, port)
    client.stream.on.conn(~H, conn, host, port, reqs)

def client.stream.on_insecure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect_insecure(host, port)
    client.stream.on.conn(~H, conn, host, port, reqs)

# N in flight (phase 2): send the batch, run the collect=false loop and
# count. The buffered concurrent lane follows below.
# ---------------------------------------------------------------------

def client_cstream.after_send(~H: HTTP.CStreamEv -> HTTP.CStreamOut, sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (sock, r, seed) = sent
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        drained : Socket & Result<&1, &1, U32 & String, LoopRes> <- client.loop.concurrent(~H, 0, client.loop.next_got(sock), seed, x_tab.empty(), Nil{}, 0, Nil{}, x_init_window(), pending, 0, 0, 0, 0, 0, Nil{}, 0, 0, HTTP.Head{0, Nil{}}, False{}, Act{4, Nil{}, False{}})
        client_stream.counted(drained)

# N in flight (phase 2): send the batch, run the collect=false loop and
# count. The buffered concurrent lane follows below.
# ---------------------------------------------------------------------

def client.stream.concurrent.conn(~H: HTTP.CStreamEv -> HTTP.CStreamOut, conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> <- client_conc.send_all(sock, client_conc.first_sid(), host, port, reqs, Nil{}, x_init_window())
        client_cstream.after_send(~H, sent, HTTP.client_conc.count(reqs))

# An empty batch answers Done{(0, 0)} with no dial, the contract the
# legacy facade kept in client_cstream.fit_n.
def client.stream.concurrent.go(~H: HTTP.CStreamEv -> HTTP.CStreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>, +pending: U32, insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  match pending:
    case 0:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Done{(0, 0)})
    case _:
      match insecure:
        case True{}:
          do IO<Result<&1, &1, U32 & String, U32 & U32>>:
            conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect_insecure(host, port)
            client.stream.concurrent.conn(~H, conn, host, port, reqs)
        case False{}:
          do IO<Result<&1, &1, U32 & String, U32 & U32>>:
            conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect(host, port)
            client.stream.concurrent.conn(~H, conn, host, port, reqs)

def client.stream.concurrent(~H: HTTP.CStreamEv -> HTTP.CStreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  client.stream.concurrent.go(~H, host, port, reqs, HTTP.client_conc.count(reqs), False{})

def client.stream.concurrent_insecure(~H: HTTP.CStreamEv -> HTTP.CStreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  client.stream.concurrent.go(~H, host, port, reqs, HTTP.client_conc.count(reqs), True{})

# Buffered core (TASK-058 phase 3, form D). The loop keeps every body
# chunk when collect is true; the Sink rides inside the Result, because a
# 4-field split of the loop answer blocks the match that follows.
# ---------------------------------------------------------------------

def client.sink.drop(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  HTTP.StreamContinue{}

# The buffered answer of the loop: the Sink, the two counts and the
# connection window the loop has left. A Data type and not a four-field
# pair, because a pair cannot ride inside Result as a type argument
# (TASK-063 phase 7c).
type SinkOut is Data:
  SinkOut{sink: Sink, t: U32, f: U32, cw: U32}

# This def puts the Sink beside the counts and the window.
def client.loop.fuse(r: Result<&1, &1, U32 & String, LoopRes>, +sink: Sink) ->
  Result<&1, &1, U32 & String, SinkOut>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{counts}:
      match counts:
        case LoopRes{+t, +f, ss, +cw2}:
          Done{SinkOut{sink, t, f, cw2}}

def client.loop.sink_in(out: Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink) ->
  IO(Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab):
  (s, r, tab, k) = out
  IO.pure(Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab, (s, client.loop.fuse(r, k), tab))

# One match folds the answer into the Response and the next CliSt: the
# loop table, the next sid and the window the loop has left (TASK-063
# phase 7c). A Fail keeps the old CliSt: the connection is gone, and a
# zero window would park the next send.
def client.request.out(s: Socket, r: Result<&1, &1, U32 & String, SinkOut>, +tab: HTTP.Tab, +st: HTTP.CliSt) ->
  Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt:
  match r:
    case Fail{e}:
      (s, Fail{e}, st)
    case Done{+done}:
      match done:
        case SinkOut{+sink, t, f, +cw}:
          (s, Done{client.sink.resp(sink)}, client.loop.st_after(st, tab, cw))

def client.request.tabbed(out: Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab, +st: HTTP.CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt):
  (s, r, tab) = out
  IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt,
    client.request.out(s, r, tab, st))

def client.request.sent(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, +st: HTTP.CliSt) ->
  IO(Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab):
  (sock, r, seed) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab,
        (sock, Fail{e}, client.loop.st_tab(st)))
    case Done{u}:
      do IO<Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab>:
        out : Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink <-
          client.loop(~client.sink.drop, ~client.no_cstream, x_mode.on(), 0, (sock, HTTP.GotErr{0, "next"}), seed, client.loop.st_tab(st), client.loop.st_sid(st), Nil{}, 0, Nil{}, client.loop.st_cw(st), 1, client_conc.first_sid(), HTTP.Head{0, Nil{}}, False{}, 0, 0, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, Nil{}, True{}})
        client.loop.sink_in(out)

# One exchange on a connection the caller owns: it never closes, and the
# returned CliSt carries the next sid and the HPACK table.
def client.request(sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32, +req: HTTP.Request) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt):
  match req:
    case HTTP.Request{method, path, headers, body}:
      do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt>:
        sent4 : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <-
          client.req.send(sock, client.loop.st_sid(st), host, port,
            method, path, headers, body, client.loop.st_cw(st), Nil{})
        do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt>:
          out : Socket & Result<&1, &1, U32 & String, SinkOut> & HTTP.Tab <- client.request.sent(httpx.sent3(sent4), st)
          client.request.tabbed(out, st)

# One-shot buffered exchange: dial, one request, close. It is the shared
# body of client.once and of the fetch/request entries. The helpers split
# the triple the way client.once.closed used to do -- a bind of three
# values cannot be destructured inside a `do`.
# ---------------------------------------------------------------------

def client.exch_once.done(out: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt) ->
  IO(Result<&1, &1, U32 & String, HTTP.Response>):
  (sock, r, st) = out
  do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
    x : Unit <- TLS.tls_close(sock)
    IO.pure(Result<&1, &1, U32 & String, HTTP.Response>, r)

def client.exch_once.conn(pre: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +host: String, +port: U32, +req: HTTP.Request) ->
  IO(Result<&1, &1, U32 & String, HTTP.Response>):
  match pre:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, HTTP.Response>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- client.request(sock, st, host, port, req)
        client.exch_once.done(out)

def client.exch_once(+host: String, +port: U32, +req: HTTP.Request, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, HTTP.Response>):
  match insecure:
    case True{}:
      do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
        pre : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect_insecure(host, port)
        client.exch_once.conn(pre, host, port, req)
    case False{}:
      do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
        pre : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect(host, port)
        client.exch_once.conn(pre, host, port, req)

# URL reader (TASK-058 phase 2): the H2 lane is TLS only, so https is the
# scheme and 443 is the default port. The facade keeps the general reader
# (httpx_url.*); this narrow copy exists because http2 cannot import httpx
# (the facade imports this module; a back import would be a cycle). The
# two must unify when the core owns the URL parse.
# ---------------------------------------------------------------------

def h2_url.bracket_end.put(h: Char, t: String, +acc: String, rec: String & String, is_end: Bool) -> String & String:
  match is_end:
    case True{}:
      (acc ++ Char.show(h), t)
    case False{}:
      rec

def h2_url.bracket_end(s: String, +acc: String) -> String & String:
  match s:
    case SNil{}:
      (acc, SNil{})
    case SCon{+h, +t}:
      h2_url.bracket_end.put(h, t, acc, h2_url.bracket_end(t, acc ++ Char.show(h)), Char.is_eq(h, ']'))

# The port part after the host: drop the leading colon.
def h2_url.port_rest.go(h: Char, t: String, is_colon: Bool) -> String:
  match is_colon:
    case True{}:
      t
    case False{}:
      SCon{h, t}

def h2_url.port_rest(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, +t}:
      h2_url.port_rest.go(h, t, Char.is_eq(h, ':'))

def h2_url.split_port.v6.done(hp: String & String) -> String & String:
  (host, rest) = hp
  (host, h2_url.port_rest(rest))

def h2_url.split_port.v6(s: String) -> String & String:
  h2_url.split_port.v6.done(h2_url.bracket_end(s, SNil{}))

def h2_url.split_port.put(h: Char, t: String, +host: String, rec: String & String, is_colon: Bool) -> String & String:
  match is_colon:
    case True{}:
      (host, t)
    case False{}:
      rec

def h2_url.split_port.go(s: String, +host: String) -> String & String:
  match s:
    case SNil{}:
      (host, SNil{})
    case SCon{+h, +t}:
      h2_url.split_port.put(h, t, host, h2_url.split_port.go(t, host ++ Char.show(h)), Char.is_eq(h, ':'))

def h2_url.split_port.kind(is_v6: Bool, s: String) -> String & String:
  match is_v6:
    case True{}:
      h2_url.split_port.v6(s)
    case False{}:
      h2_url.split_port.go(s, SNil{})

def h2_url.split_port(+s: String) -> String & String:
  h2_url.split_port.kind(String.starts_with(s, "["), s)

def h2_url.split_path.put(h: Char, t: String, +acc: String, rec: String & String, is_end: Bool) -> String & String:
  match is_end:
    case True{}:
      (acc, SCon{h, t})
    case False{}:
      rec

def h2_url.split_path.go(s: String, +acc: String) -> String & String:
  match s:
    case SNil{}:
      (acc, SNil{})
    case SCon{+h, +t}:
      h2_url.split_path.put(h, t, acc, h2_url.split_path.go(t, acc ++ Char.show(h)), Bool.or(Char.is_eq(h, '/'), Char.is_eq(h, '?')))

def h2_url.split_path(s: String) -> String & String:
  h2_url.split_path.go(s, SNil{})

# The path of a URL: "/" when the URL has none, and "/" before a query
# that starts right after the host (RFC 3986 section 3.3).
def h2_url.norm_path.go(h: Char, t: String, is_query: Bool) -> String:
  match is_query:
    case True{}:
      String.append("/", SCon{h, t})
    case False{}:
      SCon{h, t}

def h2_url.norm_path(p: String) -> String:
  match p:
    case SNil{}:
      "/"
    case SCon{+h, +t}:
      h2_url.norm_path.go(h, t, Char.is_eq(h, '?'))

def h2_url.done(host: String, port: U32, path: String, ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match ok:
    case True{}:
      Done{(True{}, host, port, path)}
    case False{}:
      Fail{(400, "bad url")}

def h2_url.port_read(host: String, p: Maybe<&2, U32>, +path: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match p:
    case None{}:
      Fail{(400, "bad port")}
    case Some{port}:
      +c = port
      h2_url.done(host, c, path, Bool.and(HTTP.client.on.valid_port(c), HTTP.client.on.valid_path(path)))

def h2_url.port_empty(host: String, +portstr: String, +path: String, no_port: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match no_port:
    case True{}:
      h2_url.done(host, 443, path, HTTP.client.on.valid_path(path))
    case False{}:
      h2_url.port_read(host, U32.read(portstr), path)

def h2_url.host(host: String, +portstr: String, path: String, host_ok: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match host_ok:
    case False{}:
      Fail{(400, "bad host")}
    case True{}:
      h2_url.port_empty(host, portstr, path, String.is_empty(portstr))

def h2_url.after_host(hp: String & String, path: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  (host, portstr) = hp
  +h1 = String.trim(host)
  h2_url.host(h1, portstr, path, HTTP.client.on.valid_host(h1))

def h2_url.after_path(hp: String & String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  (hostport, path0) = hp
  h2_url.after_host(h2_url.split_port(hostport), h2_url.norm_path(path0))

def h2_url.parts(rest: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  h2_url.after_path(h2_url.split_path(rest))

def h2_url.scheme(url: String, is_https: Bool) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  match is_https:
    case True{}:
      h2_url.parts(HTTP.x_str_drop32(url, 8))
    case False{}:
      Fail{(400, "bad scheme")}

def h2_url.read(+url: String) ->
  Result<&1, &1, U32 & String, Bool & String & U32 & String>:
  h2_url.scheme(url, String.starts_with(url, "https://"))

# The response projections: text decodes UTF-8 with the core machine, raw
# hands the bytes over. Both take the lane result, so the failure path is
# carried instead of swallowed.
# ---------------------------------------------------------------------

def fetch.text(r: Result<&1, &1, U32 & String, HTTP.Response>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, String>, Done{HTTP.x_utf8_decode(body)})

def fetch.raw(r: Result<&1, &1, U32 & String, HTTP.Response>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Done{body})

# request: any method with a String body; answers the response body as
# String. request_bytes takes raw bytes in and answers raw bytes. Both
# gate the request through the core validators and refuse a bad request
# with 400 before the dial, like the facade does.
# ---------------------------------------------------------------------

def request.go(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: String, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- client.exch_once(host, port, HTTP.Request{method, path, hs, HTTP.x_utf8_encode(body)}, insecure)
    fetch.text(r)

def request.fit(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: String, +insecure: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match fit:
    case True{}:
      request.go(host, port, path, method, hs, body, insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad request")})

def request(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  request.fit(host, port, path, method, hs, body, False{}, HTTP.client.on.valid.go(host, port, path))

def request_insecure(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  request.fit(host, port, path, method, hs, body, True{}, HTTP.client.on.valid.go(host, port, path))

def request_bytes.go(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- client.exch_once(host, port, HTTP.Request{method, path, hs, body}, insecure)
    fetch.raw(r)

def request_bytes.fit(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>, +insecure: Bool, fit: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match fit:
    case True{}:
      request_bytes.go(host, port, path, method, hs, body, insecure)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad request")})

def request_bytes(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  request_bytes.fit(host, port, path, method, hs, body, False{}, HTTP.client.on.valid.go(host, port, path))

def request_bytes_insecure(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  request_bytes.fit(host, port, path, method, hs, body, True{}, HTTP.client.on.valid.go(host, port, path))

# fetch: GET by URL. The parsed tuple keeps the secure flag the reader
# answers, so a later shared reader fits here; the H2 lane is TLS only and
# answers 400 bad scheme for the cleartext arm, which is the H1 module's.
# ---------------------------------------------------------------------

def fetch.url.go(secure: Bool, +host: String, port: U32, path: String, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match secure:
    case True{}:
      do IO<Result<&1, &1, U32 & String, String>>:
        r : Result<&1, &1, U32 & String, HTTP.Response> <- client.exch_once(host, port, HTTP.Request{"GET", path, Nil{}, Nil{}}, insecure)
        fetch.text(r)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad scheme")})

def fetch_bytes.url.go(secure: Bool, +host: String, port: U32, path: String, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match secure:
    case True{}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        r : Result<&1, &1, U32 & String, HTTP.Response> <- client.exch_once(host, port, HTTP.Request{"GET", path, Nil{}, Nil{}}, insecure)
        fetch.raw(r)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{(400, "bad scheme")})

def fetch.url(u: Bool & String & U32 & String, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  (secure, host, port, path) = u
  fetch.url.go(secure, host, port, path, insecure)

def fetch_bytes.url(u: Bool & String & U32 & String, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  (secure, host, port, path) = u
  fetch_bytes.url.go(secure, host, port, path, insecure)

def fetch.r(parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, String>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{e})
    case Done{u}:
      fetch.url(u, insecure)

def fetch_bytes.r(parsed: Result<&1, &1, U32 & String, Bool & String & U32 & String>, +insecure: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match parsed:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>, Fail{e})
    case Done{u}:
      fetch_bytes.url(u, insecure)

def fetch(+url: String) -> IO(Result<&1, &1, U32 & String, String>):
  fetch.r(h2_url.read(url), False{})

def fetch_insecure(+url: String) -> IO(Result<&1, &1, U32 & String, String>):
  fetch.r(h2_url.read(url), True{})

def fetch_bytes(+url: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  fetch_bytes.r(h2_url.read(url), False{})

def fetch_bytes_insecure(+url: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  fetch_bytes.r(h2_url.read(url), True{})

# The public one-shot names: the shared body above owns the dial and the
# close, so the two entries are one line each.
# ---------------------------------------------------------------------

def client.once(+host: String, +port: U32, +req: HTTP.Request) ->
  IO(Result<&1, &1, U32 & String, HTTP.Response>):
  client.exch_once(host, port, req, False{})

def client.once_insecure(+host: String, +port: U32, +req: HTTP.Request) ->
  IO(Result<&1, &1, U32 & String, HTTP.Response>):
  client.exch_once(host, port, req, True{})

# N requests in order on one connection, answers in the request order.
def client.on.rev.go(+xs: List<&2, HTTP.Response>, +acc: List<&2, HTTP.Response>) -> List<&2, HTTP.Response>:
  match xs:
    case Nil{}:
      acc
    case +h <> t:
      client.on.rev.go(t, h <> acc)

def client.on.rev(+xs: List<&2, HTTP.Response>) -> List<&2, HTTP.Response>:
  client.on.rev.go(xs, Nil{})

def client.on.go(rest: List<&2, HTTP.Request>, +acc: List<&2, HTTP.Response>, got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +host: String, +port: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt):
  match rest:
    case Nil{}:
      (s0, r0, st0) = got
      match r0:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt, (s0, Fail{e}, st0))
        case Done{+resp}:
          IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt, (s0, Done{client.on.rev(resp <> acc)}, st0))
    case req <> t:
      (s2, r2, st2) = got
      match r2:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt, (s2, Fail{e}, st2))
        case Done{+resp}:
          do IO<Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt>:
            got3 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <-
              client.request(s2, st2, host, port, req)
            client.on.go(t, resp <> acc, got3, host, port)

# The dummy answer the batch starts with is not a response: the first
# request is fetched before the accumulate loop starts.
def client.on.first(rest: List<&2, HTTP.Request>, sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt):
  match rest:
    case Nil{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt, (sock, Done{Nil{}}, st))
    case req <> t:
      do IO<Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt>:
        got : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <-
          client.request(sock, st, host, port, req)
        client.on.go(t, Nil{}, got, host, port)

def client.on.closed(out: Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt) ->
  IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  (s, r, st) = out
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>, r)

def client.on.conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, HTTP.Response>> & HTTP.CliSt <-
          client.on.first(reqs, sock, st, host, port)
        client.on.closed(out)

def client.on(+host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect(host, port)
    client.on.conn(conn, host, port, reqs)

def client.on_insecure(+host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect_insecure(host, port)
    client.on.conn(conn, host, port, reqs)

# The buffered concurrent lane (TASK-058 phase 3.5). The loop runs in
# collect mode, so it calls no handler while frames flow; this fold
# answers every finished response to the handler at the end. The sum is
# the one the old drain answered per response; the instant is not.
# ---------------------------------------------------------------------

def client.concurrent.fold(~H: HTTP.Response -> U32, slots: List<&2, HTTP.St>, +acc: U32) -> U32:
  match slots:
    case Nil{}:
      acc
    case +st <> t:
      match st:
        case HTTP.St{head, body, sid, n}:
          match head:
            case Some{HTTP.SlotResp{rh}}:
              client.concurrent.fold(~H, t, (acc + H(httpxc.req_of_st(st, Nil{})) : U32))
            case Some{HTTP.SlotReq{rh}}:
              # A request fragment never reaches this lane; skip it.
              client.concurrent.fold(~H, t, acc)
            case None{}:
              # A tombstone: a dropped stream was never answered.
              client.concurrent.fold(~H, t, acc)

def client.concurrent.drained(~H: HTTP.Response -> U32, drained: Socket & Result<&1, &1, U32 & String, LoopRes>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  (s, r) = drained
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(Result<&1, &1, U32 & String, U32>, Fail{e})
    case Done{c}:
      match c:
        case LoopRes{+t, +f, ss, +cw2}:
          do IO<Result<&1, &1, U32 & String, U32>>:
            x : Unit <- TLS.tls_close(s)
            IO.pure(Result<&1, &1, U32 & String, U32>, Done{client.concurrent.fold(~H, ss, 0)})

def client.concurrent.after_send(~H: HTTP.Response -> U32, sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32>):
  (sock, r, seed) = sent
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, U32>, Fail{e})
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, U32>>:
        drained : Socket & Result<&1, &1, U32 & String, LoopRes> <-
          client.loop.concurrent(~client.concurrent.drop, 0, client.loop.next_got(sock), seed, x_tab.empty(), Nil{}, 0, Nil{}, x_init_window(), pending, 0, 0, 0, 0, 0, Nil{}, 0, 0, HTTP.Head{0, Nil{}}, False{}, Act{4, Nil{}, True{}})
        client.concurrent.drained(~H, drained)

# N in flight on one connection: pipeline N requests, let the loop collect
# every answer, and close. The answer is the handler sum over the ledger.
def client.concurrent.conn(~H: HTTP.Response -> U32, conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32>, Fail{e})
    case Done{value}:
      (sock, st) = value
      do IO<Result<&1, &1, U32 & String, U32>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> <- client_conc.send_all(sock, client_conc.first_sid(), host, port, reqs, Nil{}, x_init_window())
        client.concurrent.after_send(~H, sent, HTTP.client_conc.count(reqs))

def client.concurrent(~H: HTTP.Response -> U32, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  do IO<Result<&1, &1, U32 & String, U32>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect(host, port)
    client.concurrent.conn(~H, conn, host, port, reqs)

def client.concurrent_insecure(~H: HTTP.Response -> U32, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) ->
  IO(Result<&1, &1, U32 & String, U32>):
  do IO<Result<&1, &1, U32 & String, U32>>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- client.connect_insecure(host, port)
    client.concurrent.conn(~H, conn, host, port, reqs)

# Server (TASK-058): the buffered interleave loop, the stream lanes and
# the sequential loop. They share the wire helpers above.
# ---------------------------------------------------------------------

# Main interleave loop (single @unsafe self-recursive def; phase-0 reset
# spelled out at each site). Single Socket carrier threaded whole, slot
# decisions as Bool/U32 params computed in caller arg position, open
# streams as List<St> + fragment END_STREAM ledger fends.
# Phases: 0 read, 1 decompose, 2 connection dispatch (cls),
# 3 stream dispatch (typ), 4 HEADERS-complete, 5 DATA, 6 CONTINUATION.
# 13 params + handler (was 14 + handler with the HpDyn tab).

# Server stream (phase F): the event lanes of the H2 server, beside the
# buffered interleave loop. They share the same wire pieces.
# ---------------------------------------------------------------------

def httpxs.head_act_from_out(+out: HTTP.SrvOut, +end: U32) -> U32:
  match out:
    case HTTP.Continue{}:
      match end:
        case 1:
          7
        case _:
          0
    case HTTP.RespondEarly{resp}:
      1
    case HTTP.Cancel{}:
      2

def httpxs.resp_from_out(+out: HTTP.SrvOut) -> HTTP.Response:
  match out:
    case HTTP.Continue{}:
      HTTP.Response{0, Nil{}, Nil{}}
    case HTTP.RespondEarly{+resp}:
      resp
    case HTTP.Cancel{}:
      HTTP.Response{0, Nil{}, Nil{}}

def httpxs.data_act_from_out(+out: HTTP.SrvOut, fin: Bool) -> U32:
  match out:
    case HTTP.Continue{}:
      match fin:
        case True{}:
          7
        case False{}:
          0
    case HTTP.RespondEarly{resp}:
      1
    case HTTP.Cancel{}:
      2

# After a complete early response, a request whose HEADERS did not carry
# END_STREAM still owes a body this server will never read: tell the peer
# to stop with RST_STREAM (RFC 9113 section 8.1 -- complete response
# first, then the reset; the code is CANCEL, the "stream no longer
# needed" the client lane already sends in client.on.sdrop). Once per
# stream, because the early answer frees the slot once; DATA already in
# flight is credited by httpxs.wu_conn, never reset twice. end == 1 means
# the head ended the stream and there is no body to stop.

def httpxs.rst_early.go(sock: Socket, +sid: U32, +end: U32, no_body: Bool, +seed: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>):
  match no_body:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, (sock, Done{Unit{}}, seed))
    case False{}:
      do IO<Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(sock, sid, 8)
        IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, httpx.sent3(x_flow_keep(sent, seed, x_init_window())))

def httpxs.rst_early(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, +sid: U32, +end: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>):
  (s, r, seed) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>, (s, Fail{e}, seed))
    case Done{u}:
      httpxs.rst_early.go(s, sid, end, U32.is_eq(end, 1), seed)

def httpxs.head_act_of(~H: HTTP.SrvEv -> HTTP.SrvOut, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> U32:
  match ok need:
    case _ 1:
      6
    case False{} 0:
      5
    case True{} 0:
      httpxs.head_act_from_out(H(HTTP.SrvReqHead{sid, nh}), end)
    case _ _:
      5

def httpxs.head_resp_of(~H: HTTP.SrvEv -> HTTP.SrvOut, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> HTTP.Response:
  match ok need:
    case _ 1:
      HTTP.Response{0, Nil{}, Nil{}}
    case False{} 0:
      HTTP.Response{0, Nil{}, Nil{}}
    case True{} 0:
      httpxs.resp_from_out(H(HTTP.SrvReqHead{sid, nh}))
    case _ _:
      HTTP.Response{0, Nil{}, Nil{}}

# The buffered head act: the table of ledger.head_act, with 1 replaced by
# 10, the act that answers with the IO handler.
def server.head_act.buffered(need: U32, ok: Bool, +end: U32) -> U32:
  match need ok end:
    case 1 _ _:
      6
    case 0 False{} _:
      5
    case 0 True{} 1:
      10
    case _ _ _:
      0

# The buffered data act: 10 finishes the request and calls the handler.
# 8 credits the connection window of a stream the ledger does not hold
# and reads on (a DATA whose HEADERS never arrived, or arrived after the
# stream was answered). 7 is the reset: the frame pushes the body past
# x_max_body(). The lane then answers RST_STREAM 8 and drops the stream,
# which is the act the stream form already uses for a canceled body. The
# stream form answers the same act.
def server.data_act.buffered(has: Bool, over: Bool, +end: U32) -> U32:
  match has over end:
    case False{} _ _:
      8
    case True{} True{} _:
      7
    case True{} False{} 1:
      10
    case _ _ _:
      0

def server.head_resp.stream(~H: HTTP.SrvEv -> HTTP.SrvOut, act: U32, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> HTTP.Response:
  match act:
    case 9:
      HTTP.Response{0, Nil{}, Nil{}}
    case _:
      httpxs.head_resp_of(~H, ok, need, end, nh, nt, sid)

# The buffered form has no answer before the IO handler runs.
def server.head_resp.buffered() -> HTTP.Response:
  HTTP.Response{0, Nil{}, Nil{}}

def server.head_resp(~H: HTTP.SrvEv -> HTTP.SrvOut, +form: U32, act: U32, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> HTTP.Response:
  match form:
    case 0:
      server.head_resp.buffered()
    case _:
      server.head_resp.stream(~H, act, ok, need, end, nh, nt, sid)

def httpxs.data_act_of(~H: HTTP.SrvEv -> HTTP.SrvOut, has: Bool, +payload: List<&2, U32>, +fin: Bool, +sid: U32) -> U32:
  match has:
    case False{}:
      8
    case True{}:
      httpxs.data_act_from_out(H(HTTP.SrvReqData{sid, payload, fin}), fin)

def httpxs.data_resp_of(~H: HTTP.SrvEv -> HTTP.SrvOut, has: Bool, +payload: List<&2, U32>, +fin: Bool, +sid: U32) -> HTTP.Response:
  match has:
    case False{}:
      HTTP.Response{0, Nil{}, Nil{}}
    case True{}:
      httpxs.resp_from_out(H(HTTP.SrvReqData{sid, payload, fin}))

def server.data_act(~H: HTTP.SrvEv -> HTTP.SrvOut, +form: U32, has: Bool, +payload: List<&2, U32>, +fin: Bool, +end: U32, +sid: U32, over: Bool) -> U32:
  match form:
    case 0:
      server.data_act.buffered(has, over, end)
    case _:
      httpxs.data_act_of(~H, has, payload, fin, sid)

# DATA continue of one form. The buffered form keeps the rev-body in the
# slot. The stream form already handed the chunk to the handler, so its
# slot keeps the head only and the body stays flat (TASK-066 phase 3).
def server.data_slots(+form: U32, slots: List<&2, HTTP.St>, +sid2: U32, +payload: List<&2, U32>, +flen: U32) -> List<&2, HTTP.St>:
  match form:
    case 0:
      ledger.data_cont_slots(ledger.take_del(slots, sid2), payload, flen)
    case _:
      slots

def server.data_resp.buffered() -> HTTP.Response:
  HTTP.Response{0, Nil{}, Nil{}}

def server.data_resp(~H: HTTP.SrvEv -> HTTP.SrvOut, +form: U32, has: Bool, +payload: List<&2, U32>, +fin: Bool, +sid: U32) -> HTTP.Response:
  match form:
    case 0:
      server.data_resp.buffered()
    case _:
      httpxs.data_resp_of(~H, has, payload, fin, sid)

# Admission of a new stream. `on` looks at the ledger: a non-empty
# `slots` means one stream is in course, so the second HEADERS is
# refused with act 9. The refused stream never enters the ledger and the
# handler never sees it. `concurrent` admits streams up to
# x_max_streams, the cap announced in SETTINGS, and refuses the rest with
# the same act 9 (RST_STREAM 7, REFUSED_STREAM).
def server.admit.idle.stream(~H: HTTP.SrvEv -> HTTP.SrvOut, slots: List<&2, HTTP.St>, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> U32:
  match slots:
    case Nil{}:
      httpxs.head_act_of(~H, ok, need, end, nh, nt, sid)
    case _:
      9

def server.admit.idle.buffered(slots: List<&2, HTTP.St>, ok: Bool, +need: U32, +end: U32) -> U32:
  match slots:
    case Nil{}:
      server.head_act.buffered(need, ok, end)
    case _:
      9

# True when the connection already holds x_max_streams open streams. The
# count is the ledger length; the ledger never passes the cap, so the
# walk stays short.
def server.admit.capped(slots: List<&2, HTTP.St>) -> Bool:
  U32.is_ge(U32.from_nat(List.length(&2, HTTP.St, slots)), x_max_streams())

# The act of an admitted stream under the cap: 9 refuses it
# (RST_STREAM 7, REFUSED_STREAM), the table act decides otherwise.
def server.admit.cap_act(is_cap: Bool, act: U32) -> U32:
  match is_cap:
    case True{}:
      9
    case False{}:
      act

# The stream form keeps the handler lazy: a refused stream never calls it.
def server.admit.stream_act(~H: HTTP.SrvEv -> HTTP.SrvOut, is_cap: Bool, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> U32:
  match is_cap:
    case True{}:
      9
    case False{}:
      httpxs.head_act_of(~H, ok, need, end, nh, nt, sid)

def server.admit.buffered(mode: U32, slots: List<&2, HTTP.St>, ok: Bool, +need: U32, +end: U32) -> U32:
  match mode:
    case 0:
      server.admit.idle.buffered(slots, ok, need, end)
    case _:
      server.admit.cap_act(server.admit.capped(slots), server.head_act.buffered(need, ok, end))

def server.admit.stream(~H: HTTP.SrvEv -> HTTP.SrvOut, mode: U32, slots: List<&2, HTTP.St>, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> U32:
  match mode:
    case 0:
      server.admit.idle.stream(~H, slots, ok, need, end, nh, nt, sid)
    case _:
      server.admit.stream_act(~H, server.admit.capped(slots), ok, need, end, nh, nt, sid)

def server.admit(~H: HTTP.SrvEv -> HTTP.SrvOut, +form: U32, mode: U32, slots: List<&2, HTTP.St>, ok: Bool, +need: U32, +end: U32, +nh: HTTP.ReqHead, +nt: HTTP.Tab, +sid: U32) -> U32:
  match form:
    case 0:
      server.admit.buffered(mode, slots, ok, need, end)
    case _:
      server.admit.stream(~H, mode, slots, ok, need, end, nh, nt, sid)

# The head answer of an admitted stream: a refused stream (act 9) never
# reaches the handler, so its answer is a dummy.
# The server stream loop: one machine, two forms and two admission modes.
# The form and the mode change only which act table decides a frame; the
# phases, the HPACK, the flow pump and the event tables are shared.
# The same declared length rides the server loop, and its credit leaf
# (httpx.wu_er) takes the count instead of the payload.
# The client side of the same counter (TASK-063 phase 7c): a connection
# WINDOW_UPDATE raises the send window the client loop tracks, so the
# next request body seeds from the honest remaining window.
def client.loop.wu_cw_go(is_conn: Bool, cw: U32, +payload: List<&2, U32>) -> U32:
  match is_conn:
    case True{}:
      (cw + x_be32_rd(payload) : U32)
    case False{}:
      cw

def client.loop.wu_cw(cw: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  client.loop.wu_cw_go(U32.is_eq(sid, 0), cw, payload)

# A connection WINDOW_UPDATE raises the send window the server loop
# tracks (RFC 9113 section 6.9.1). A stream WU only refills one stream,
# and the flow pump of that stream reads it itself, so the loop counts
# the connection frames only.
def server.wu_cw_go(is_conn: Bool, cw: U32, +payload: List<&2, U32>) -> U32:
  match is_conn:
    case True{}:
      (cw + x_be32_rd(payload) : U32)
    case False{}:
      cw

def server.wu_cw(cw: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  server.wu_cw_go(U32.is_eq(sid, 0), cw, payload)

@unsafe
def server.loop(~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), +form: U32, +mode: U32, phase: U32, got: Socket & HTTP.Got, +slots: List<&2, HTTP.St>, +cpend: U32, +spend: List<&2, Pnd>, +cw: U32, +iw: U32, +fends: List<&2, U32>, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +flen: U32, +cls: U32, +end: U32, +rh: HTTP.ReqHead, act: U32, +resp: HTTP.Response, +tab: HTTP.Tab, +drt: HTTP.ReqHead & Bool & HTTP.Tab) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- x_read_frame(s0, httpx.carry(g0, buf))
        server.loop(~H, ~B, form, mode, 1, got2, slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code1, msg1}:
          x_fatal_close(s1, code1)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid22, +flen2, +payload2}:
              server.loop(~H, ~B, form, mode, 2, (s1, HTTP.GotOk{frame, buf2}), slots, cpend, spend, cw, iw, fends, buf2, typ2, flags2, sid22, payload2, flen2, x_cls_of(frame, flags2), x_fin(flags2), HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 2:
      match cls:
        case 1:
          do IO<Unit>:
            got2 : Socket & HTTP.Got <- httpx.ack(got)
            +iw1 : U32 = x_settings.iw_of(payload, iw)
            server.loop(~H, ~B, form, mode, 0, got2, slots, cpend, spend, cw, iw1, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 4:
          do IO<Unit>:
            gotp : Socket & HTTP.Got <- httpx.ack_ping(got, payload)
            server.loop(~H, ~B, form, mode, 0, gotp, slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 5:
          httpx.close_got(got)
        case 2:
          server.loop(~H, ~B, form, mode, 0, got, ledger.del(slots, sid2), cpend, spend, cw, iw, ledger.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 7:
          server.loop(~H, ~B, form, mode, 0, got, slots, cpend, spend, server.wu_cw(cw, sid2, payload), iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 9:
          x_fatal_got(got, x_goaway.protocol())
        case 8:
          +body8 : List<&2, U32> = httpx.body_of(ledger.taken_st(ledger.take_del(slots, sid2)))
          +over8 : Bool = x_block_over(body8, payload)
          server.loop(~H, ~B, form, mode, 6, got, slots, cpend, spend, cw, iw, fends, buf, typ, flags, sid2, payload, flen, cls, x_fin_hdr(flags), HTTP.ReqHead{"", "", Nil{}}, ledger.decide_cont(over8, ledger.frag_has(slots, sid2), x_fin_hdr(flags)), HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 6:
          server.loop(~H, ~B, form, mode, 3, got, slots, cpend, spend, cw, iw, fends, buf, typ, flags, sid2, payload, flen, cls, end, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 0:
          server.loop(~H, ~B, form, mode, 0, got, slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case _:
          server.loop(~H, ~B, form, mode, 0, got, slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 3:
      match typ:
        case 1:
          server.loop(~H, ~B, form, mode, 7, got, slots, cpend, spend, cw, iw, fends, buf, typ, flags, sid2, payload, flen, cls, end, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.got(x_req.decode(payload, tab)))
        case 0:
          +has3 : Bool = ledger.has(slots, sid2)
          +fin3 : Bool = U32.is_eq(end, 1)
          +body3 : List<&2, U32> = x_data_body(payload, flags)
          +over3 : Bool = x_body_over(ledger.n_of(slots, sid2), flen)
          server.loop(~H, ~B, form, mode, 5, got, slots, cpend, spend, cw, iw, fends, buf, typ, flags, sid2, payload, flen, cls, end, HTTP.ReqHead{"", "", Nil{}}, server.data_act(~H, form, has3, body3, fin3, end, sid2, over3), server.data_resp(~H, form, has3, body3, fin3, sid2), tab, x_req.no_got())
        case _:
          server.loop(~H, ~B, form, mode, 0, got, slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case 4:
      (s4, g4) = got
      match act:
        case 0:
          server.loop(~H, ~B, form, mode, 0, got, ledger.put(slots, HTTP.St{Some{HTTP.SlotReq{rh}}, Nil{}, sid2, 0}), cpend, spend, cw, iw, ledger.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 1:
          do IO<Unit>:
            +sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <- x_send_resp(s4, sid2, resp, cw, iw, iw, buf)
            rst : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> <- httpxs.rst_early(httpx.sent3(sent), sid2, end)
            server.loop(~H, ~B, form, mode, 0, httpx.sent_seed(rst, Nil{}), ledger.del(slots, sid2), cpend, spend, httpx.sent_cw(sent), iw, ledger.fdel(fends, sid2), Nil{}, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 6:
          server.loop(~H, ~B, form, mode, 0, got, ledger.put(slots, HTTP.St{None{}, HTTP.x_cat(payload), sid2, 0}), cpend, spend, cw, iw, ledger.fend_up(fends, sid2, U32.is_eq(end, 1)), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 10:
          do IO<Unit>:
            req : HTTP.Request = httpx.req_of(rh, Nil{})
            resp : HTTP.Response <- B(req)
            +sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <- x_send_resp(s4, sid2, resp, cw, iw, iw, buf)
            server.loop(~H, ~B, form, mode, 0, httpx.sent_seed(httpx.sent3(sent), Nil{}), ledger.del(slots, sid2), cpend, spend, httpx.sent_cw(sent), iw, ledger.fdel(fends, sid2), Nil{}, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 9:
          server.loop(~H, ~B, form, mode, 8, got, slots, cpend, spend, cw, iw, fends, buf, typ, flags, sid2, Nil{}, 0, cls, end, rh, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 2:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(s4, sid2, 8)
            server.loop(~H, ~B, form, mode, 0, httpx.sent(sent), ledger.del(slots, sid2), cpend, spend, cw, iw, ledger.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 5:
          TLS.tls_close(s4)
        case 7:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(s4, sid2, 8)
            server.loop(~H, ~B, form, mode, 0, httpx.sent(sent), ledger.del(slots, sid2), cpend, spend, cw, iw, ledger.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case _:
          TLS.tls_close(s4)
    case 5:
      (sb2, gb2) = got
      match act:
        case 0:
          do IO<Unit>:
            +fin : Bool = U32.is_eq(end, 1)
            +wb : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin)
            got2 : Socket & HTTP.Got <- x_wu.send((sb2, gb2), buf, wb)
            server.loop(~H, ~B, form, mode, 0, got2, server.data_slots(form, slots, sid2, x_data_body(payload, flags), flen), x_wu.next_cpend(cpend, flen, fin), x_wu.next_spend(spend, sid2, flen, fin), cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 1:
          do IO<Unit>:
            +fin : Bool = U32.is_eq(end, 1)
            +wb : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin)
            got2 : Socket & HTTP.Got <- x_wu.send((sb2, gb2), buf, wb)
            +sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <- x_send_resp(httpx.wo(got2), sid2, resp, cw, iw, iw, buf)
            server.loop(~H, ~B, form, mode, 0, httpx.sent_seed(httpx.sent3(sent), Nil{}), ledger.taken_slots(ledger.take_del(slots, sid2)), x_wu.next_cpend(cpend, flen, fin), x_wu.next_spend(spend, sid2, flen, fin), httpx.sent_cw(sent), iw, ledger.fdel(fends, sid2), Nil{}, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 10:
          do IO<Unit>:
            +fin : Bool = U32.is_eq(end, 1)
            +wb : List<&2, U32> = x_wu.bytes(cpend, spend, sid2, flen, fin)
            got2 : Socket & HTTP.Got <- x_wu.send((sb2, gb2), buf, wb)
            +tp : HTTP.Taken = ledger.take_del(slots, sid2)
            req : HTTP.Request = httpx.req_of_st(ledger.taken_st(tp), x_data_body(payload, flags))
            resp : HTTP.Response <- B(req)
            +sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <- x_send_resp(httpx.wo(got2), sid2, resp, cw, iw, iw, buf)
            server.loop(~H, ~B, form, mode, 0, httpx.sent_seed(httpx.sent3(sent), Nil{}), ledger.taken_slots(tp), x_wu.next_cpend(cpend, flen, fin), x_wu.next_spend(spend, sid2, flen, fin), httpx.sent_cw(sent), iw, ledger.fdel(fends, sid2), Nil{}, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 8:
          do IO<Unit>:
            +wb8 : List<&2, U32> = x_wu.stray_bytes(cpend, flen)
            got8 : Socket & HTTP.Got <- x_wu.send((sb2, gb2), buf, wb8)
            server.loop(~H, ~B, form, mode, 0, got8, slots, x_wu.stray_cpend(cpend, flen), spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 2:
          do IO<Unit>:
            +wb2 : List<&2, U32> = x_wu.stray_bytes(cpend, flen)
            got2 : Socket & HTTP.Got <- x_wu.send((sb2, gb2), buf, wb2)
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(httpx.wo(got2), sid2, 8)
            server.loop(~H, ~B, form, mode, 0, httpx.sent(sent), ledger.del(slots, sid2), x_wu.stray_cpend(cpend, flen), x_wu.del(spend, sid2), cw, iw, ledger.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 7:
          do IO<Unit>:
            +wb7 : List<&2, U32> = x_wu.stray_bytes(cpend, flen)
            got7 : Socket & HTTP.Got <- x_wu.send((sb2, gb2), buf, wb7)
            rst : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(httpx.wo(got7), sid2, 8)
            server.loop(~H, ~B, form, mode, 0, httpx.sent(rst), ledger.del(slots, sid2), x_wu.stray_cpend(cpend, flen), x_wu.del(spend, sid2), cw, iw, ledger.fdel(fends, sid2), buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case _:
          httpx.close_got((sb2, gb2))
    case 6:
      (s6, g6) = got
      match act:
        case 0:
          server.loop(~H, ~B, form, mode, 0, got, ledger.frag_cont_slots(ledger.take_del(slots, sid2), payload), cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
        case 1:
          +tp2 : HTTP.Taken = ledger.take_del(slots, sid2)
          +full : List<&2, U32> = HTTP.x_cat(HTTP.x_rev_push(payload, httpx.body_of(ledger.taken_st(tp2))))
          +dr6 : Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab> = x_req.decode(full, tab)
          +fp : HTTP.FendTaken = ledger.fdel_flag(fends, sid2)
          +ff : U32 = ledger.ftaken_flag(fp)
          server.loop(~H, ~B, form, mode, 7, got, ledger.taken_slots(tp2), cpend, spend, cw, iw, ledger.ftaken_fends(fp), buf, typ, flags, sid2, Nil{}, 0, cls, ff, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, x_req.tab(dr6), x_req.got(dr6))
        case 2:
          x_fatal(s6, x_goaway.calm())
        case _:
          x_fatal(s6, x_goaway.protocol())
    case 7:
      match drt:
        case (+h, +ot):
          match ot:
            case (+ok, +t):
              +nu = ledger.need_u(typ, flags)
              +a7 = server.admit(~H, form, mode, slots, ok, nu, end, h, t, sid2)
              server.loop(~H, ~B, form, mode, 4, got, slots, cpend, spend, cw, iw, fends, buf, typ, flags, sid2, payload, flen, cls, end, h, a7, server.head_resp(~H, form, a7, ok, nu, end, h, t, sid2), t, x_req.no_got())
    case 8:
      (s8, g8) = got
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_rst(s8, sid2, 7)
        server.loop(~H, ~B, form, mode, 0, httpx.sent(sent), slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())
    case _:
      server.loop(~H, ~B, form, mode, 0, got, slots, cpend, spend, cw, iw, fends, buf, 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, tab, x_req.no_got())

# Streaming accept plumbing: the accept is H2 only behind tls_accept, which
# asks for h2 at the handshake -- a peer whose offered list has no overlap
# is refused 615 (fatal alert). The HTTP/1.1 dispatch stays out of this
# module. The form and the admission mode travel from the entry to
# `server.loop` through this plumbing.
# ---------------------------------------------------------------------

@unsafe
def server.pre(~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), +form: U32, +mode: U32, phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, +ok: U32, short: Bool) ->
  IO(Unit):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          TLS.tls_close(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          server.pre(~H, ~B, form, mode, 1, (s0, Done{chunk}), acc2, x_preface_ok(acc2), Bool.not(HTTP.x_has_at_least(24, acc2)))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<Unit>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            server.pre(~H, ~B, form, mode, 0, r2, acc, 0, False{})
        case False{}:
          server.pre(~H, ~B, form, mode, 2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          do IO<Unit>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- x_send_frame(s2, x_t_settings(), 0, 0, x_settings_initial_pay())
            server.loop(~H, ~B, form, mode, 0, httpx.sent(sent), ledger.no_slots(), 0, Nil{}, x_init_window(), x_init_window(), ledger.no_fends(), HTTP.x_drop32(24, acc), 0, 0, 0, Nil{}, 0, 0, 0, HTTP.ReqHead{"", "", Nil{}}, 4, HTTP.Response{0, Nil{}, Nil{}}, x_tab.empty(), x_req.no_got())
        case _:
          TLS.tls_close(s2)
    case _:
      (s9, r9) = rs
      TLS.tls_close(s9)

def server.start(~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), +form: U32, +mode: U32, sock: Socket) ->
  IO(Unit):
  do IO<Unit>:
    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    server.pre(~H, ~B, form, mode, 0, r1, Nil{}, 0, False{})

def server.spawn(~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), +form: U32, +mode: U32, sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, server.start(~H, ~B, form, mode, sock))
    return l

def server.conn(~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), +form: U32, +mode: U32, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      server.spawn(~H, ~B, form, mode, sock, l)

# The stream form: the pure handler answers each event.
# ---------------------------------------------------------------------

def server.stream.on.conn(~H: HTTP.SrvEv -> HTTP.SrvOut, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  server.conn(~H, ~server.no_buffered, x_form.stream(), x_mode.on(), m)

def server.stream.concurrent.conn(~H: HTTP.SrvEv -> HTTP.SrvOut, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  server.conn(~H, ~server.no_buffered, x_form.stream(), x_mode.concurrent(), m)

# The buffered form: the loop collects the whole request and the IO
# handler answers it once.
# ---------------------------------------------------------------------

def server.buffered.on.conn(~B: HTTP.Request -> IO(HTTP.Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  server.conn(~server.no_event, ~B, x_form.buffered(), x_mode.on(), m)

def server.buffered.concurrent.conn(~B: HTTP.Request -> IO(HTTP.Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  server.conn(~server.no_event, ~B, x_form.buffered(), x_mode.concurrent(), m)

# The accept entries: the module accepts, so no facade sits in the path.
# `once` counts connections, not streams.
# ---------------------------------------------------------------------

def server.stream.once(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.stream.on.conn(~H, m)
    return Unit{}

@unsafe
def server.stream.on(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.stream.on.conn(~H, m)
    z : Unit <- server.stream.on(~H, l2, cert, key)
    return z

@unsafe
def server.stream.concurrent(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.stream.concurrent.conn(~H, m)
    z : Unit <- server.stream.concurrent(~H, l2, cert, key)
    return z

def server.once(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.buffered.on.conn(~B, m)
    return Unit{}

@unsafe
def server.on(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.buffered.on.conn(~B, m)
    z : Unit <- server.on(~B, l2, cert, key)
    return z

@unsafe
def server.concurrent(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) ->
  IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, cert, key)
    l2 : Listener <- server.buffered.concurrent.conn(~B, m)
    z : Unit <- server.concurrent(~B, l2, cert, key)
    return z

# Legacy (TASK-058 phase 5): the H2 legs the facade calls on a socket
# from the handshake. They die in the facade task; they stay last.
# ---------------------------------------------------------------------

# Dead code: these defs have no caller. They stay last for record.

def x_static.name(sp: String & String) -> String:
  (n, v) = sp
  n

def x_tab.len.go(+ents: List<&2, HTTP.Hdr>, +n: U32) -> U32:
  match ents:
    case Nil{}:
      n
    case _ <> t:
      x_tab.len.go(t, (n + 1 : U32))

def x_tab.len(+ents: List<&2, HTTP.Hdr>) -> U32:
  x_tab.len.go(ents, 0)

def x_req.rh(r: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> HTTP.ReqHead:
  match r:
    case Fail{e}:
      HTTP.ReqHead{"", "", Nil{}}
    case Done{(+h, t)}:
      h

def x_req.ok(r: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{(h, t)}:
      True{}

def x_flow_drop(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>) ->
  Socket & Result<&1, &1, U32 & String, Unit>:
  (s, r, rest) = sent
  (s, r)

def client.resp.of(+head: HTTP.Head, +body: List<&2, U32>) -> HTTP.Response:
  match head:
    case HTTP.Head{+status, +headers}:
      HTTP.Response{status, headers, body}

def client.resp.head_flags(is_empty: Bool) -> U32:
  match is_empty:
    case True{}:
      (x_f_end_headers() + x_f_end_stream() : U32)
    case False{}:
      x_f_end_headers()

# The loop answers the counts beside the table; a one-shot lane drops the
# table and closes through the same helper every other lane uses.
def client_stream.drained_t(drained: Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, r, t, k) = drained
  client_stream.drained((s, client.loop.counts(r)))

def server.stream.on.start(~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket) ->
  IO(Unit):
  server.start(~H, ~server.no_buffered, x_form.stream(), x_mode.on(), sock)

def server.stream.on.spawn(~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket, l: Listener) ->
  IO(Listener):
  server.spawn(~H, ~server.no_buffered, x_form.stream(), x_mode.on(), sock, l)

def server.stream.concurrent.start(~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket) ->
  IO(Unit):
  server.start(~H, ~server.no_buffered, x_form.stream(), x_mode.concurrent(), sock)

def server.stream.concurrent.spawn(~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket, l: Listener) ->
  IO(Listener):
  server.spawn(~H, ~server.no_buffered, x_form.stream(), x_mode.concurrent(), sock, l)

def server.buffered.on.start(~B: HTTP.Request -> IO(HTTP.Response), sock: Socket) ->
  IO(Unit):
  server.start(~server.no_event, ~B, x_form.buffered(), x_mode.on(), sock)

def server.buffered.on.spawn(~B: HTTP.Request -> IO(HTTP.Response), sock: Socket, l: Listener) ->
  IO(Listener):
  server.spawn(~server.no_event, ~B, x_form.buffered(), x_mode.on(), sock, l)

def server.buffered.concurrent.start(~B: HTTP.Request -> IO(HTTP.Response), sock: Socket) ->
  IO(Unit):
  server.start(~server.no_event, ~B, x_form.buffered(), x_mode.concurrent(), sock)

def server.buffered.concurrent.spawn(~B: HTTP.Request -> IO(HTTP.Response), sock: Socket, l: Listener) ->
  IO(Listener):
  server.spawn(~server.no_event, ~B, x_form.buffered(), x_mode.concurrent(), sock, l)

def client_stream.sent(~H: HTTP.StreamEv -> HTTP.StreamOut, sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  (sock, r, rest) = sent
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        x : Unit <- TLS.tls_close(sock)
        IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{u}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        drained : Socket & Result<&1, &1, U32 & String, LoopRes> & HTTP.Tab & Sink <- client.loop(~H, ~client.no_cstream, x_mode.on(), 0, (sock, HTTP.GotErr{0, "next"}), rest, x_tab.empty(), 1, Nil{}, 0, Nil{}, x_init_window(), 1, client_conc.first_sid(), HTTP.Head{0, Nil{}}, False{}, 0, 0, 0, 0, 0, Nil{}, 0, 0, 0, Act{4, Nil{}, False{}})
        client_stream.drained_t(drained)

def client_stream.exch(~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    sent4 : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <- client.req.send(sock, 1, host, port, method, path, hs, body, x_init_window(), Nil{})
    client_stream.sent(~H, httpx.sent3(sent4))

def client_cstream.exch(~H: HTTP.CStreamEv -> HTTP.CStreamOut, sock: Socket, +host: String, +port: U32, reqs: List<&2, HTTP.Request>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> <- client_conc.send_all(sock, client_conc.first_sid(), host, port, reqs, Nil{}, x_init_window())
    client_cstream.after_send(~H, sent, pending)

# The facade leg keeps the name and the socket: it sends the batch on a
# connection the caller owns, runs the same loop and fold, and closes.
def client_conc.exch(~H: HTTP.Response -> U32, sock: Socket, +host: String, +port: U32, reqs: List<&2, HTTP.Request>, +pending: U32) ->
  IO(Result<&1, &1, U32 & String, U32>):
  do IO<Result<&1, &1, U32 & String, U32>>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> <- client_conc.send_all(sock, client_conc.first_sid(), host, port, reqs, Nil{}, x_init_window())
    client.concurrent.after_send(~H, sent, pending)

# Old helper names (tests and the facade): one line each over the live
# helper above. They die in the facade task.
# ---------------------------------------------------------------------

def client.on.has_head(+head: HTTP.Head) -> Bool:
  client.resp.has_head(head)

def client.on.mine_cls(+cls: U32, +sid2: U32, +exp: U32) -> U32:
  client.route.mine.cls(cls, sid2, exp)

def client.on.next_sid(+sid: U32) -> U32:
  client.loop.next_sid(sid)

def client.on.preface_bytes() -> List<&2, U32>:
  client.preface.bytes()

def client.on.req_block(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>) ->
  List<&2, U32>:
  client.req.block(host, port, method, path, hs)

def client.on.resp_of(+head: HTTP.Head, +body: List<&2, U32>) -> HTTP.Response:
  client.resp.of(head, body)

def httpxn.decide_data(has: Bool, +end: U32) -> U32:
  ledger.decide_data(has, end)

def httpxn.del(slots: List<&2, HTTP.St>, +sid: U32) -> List<&2, HTTP.St>:
  ledger.del(slots, sid)

def httpxn.has(slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  ledger.has(slots, sid)

def httpxn.has_some(slots: List<&2, HTTP.St>, +sid: U32) -> Bool:
  ledger.has_some(slots, sid)

def httpxn.head_keep_go(+old: HTTP.Head, +new: HTTP.Head, is_trailer: Bool) -> HTTP.Head:
  ledger.head_keep_go(old, new, is_trailer)

def httpxn.put(slots: List<&2, HTTP.St>, +st: HTTP.St) -> List<&2, HTTP.St>:
  ledger.put(slots, st)

def httpxn.take_del(slots: List<&2, HTTP.St>, +sid: U32) -> HTTP.Taken:
  ledger.take_del(slots, sid)

def httpxn.taken_slots(p: HTTP.Taken) -> List<&2, HTTP.St>:
  ledger.taken_slots(p)

def httpxn.taken_st(p: HTTP.Taken) -> HTTP.St:
  ledger.taken_st(p)
