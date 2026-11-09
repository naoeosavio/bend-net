# lib (lib_httpx_frame_read): the mini-H2 frame reader must be a single
# unbounded loop, not a fixed number of reads: any public peer splits a
# response over many TLS records (Cloudflare ships ~1.4KB per record, so a
# 3.6KB HEADERS block alone needs three reads), and a reader with a read
# budget answers "truncated" on a perfectly good stream.
#
# Pure half pins the parser contract: NeedMore on an empty buffer and on a
# half header, an exact write->parse roundtrip (type, flags, sid, payload
# length, trailing bytes kept), Bad 413 over the 65535 frame cap, the
# PRIORITY strip, and the DATA padding kept for the credit plus stripped by
# x_data_body. IO half is a loopback where a canned raw peer paces
# the answer: the head block in 128-byte pieces and the body as four 512B
# DATA frames, one TLS record (so one read) each, all small enough for the
# interpreter, and the real client HTTPX.client.once_insecure must assemble the
# whole 2048-byte body. Ported from h2_frame_read.bend (same peer shape, same
# 2048B assertion) when the old H2 codec was retired.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Parser contract. Frame header on the wire is len(3) type(1) flags(1) sid(4),
# so a 9-byte buffer is the smallest complete header.

def is_need_more(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.NeedMore{missing, rest}:
      1
    case _:
      0

def need_exact(out: HTTP.UnitOut, want: U32) -> U32:
  match out:
    case HTTP.NeedMore{missing, rest}:
      b2u(U32.is_eq(missing, want))
    case _:
      0

def is_bad_413(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Bad{code, msg}:
      b2u(U32.is_eq(code, 413))
    case _:
      0

def frame_payload_len(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{typ, flags, sid,+flen, payload}:
      HTTP.x_len32(payload)

def frame_sid_of(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{typ, flags, sid,+flen, payload}:
      sid

def frame_len(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{unit, fin, rest}:
      frame_payload_len(HTTP2.x_frame_of(unit))
    case _:
      0

def frame_sid(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{unit, fin, rest}:
      frame_sid_of(HTTP2.x_frame_of(unit))
    case _:
      0

def frame_rest(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{unit, fin, rest}:
      HTTP.x_len32(rest)
    case _:
      0

def data_frame() -> List<&2, U32>:
  HTTP2.x_frame_write(0, 1, 1, [104, 105])

def v_empty() -> U32:
  need_exact(HTTP2.x_parse(Nil{}), 9)

def v_half_header() -> U32:
  need_exact(HTTP2.x_parse([0, 0, 4, 0, 0, 0, 0, 1]), 1)

# The payload counter in NeedMore is not pinned: the loops only branch on
# the constructor (x_read_loop ignores the count), so a truncated frame just
# has to come back as NeedMore.
def v_short_payload() -> U32:
  is_need_more(HTTP2.x_parse(HTTP.x_drop32(1, data_frame())))

def v_roundtrip() -> U32:
  +out = HTTP2.x_parse(data_frame())
  (frame_len(out) + frame_sid(out) + frame_rest(out) : U32)

# 16385 bytes is one past the announced MAX_FRAME_SIZE (RFC 9113 4.2): the
# 24-bit length field is read first, so only the first three bytes matter.
def v_over_cap() -> U32:
  is_bad_413(HTTP2.x_parse([0, 64, 1, 0, 0, 0, 0, 0, 0]))

# A DATA frame keeps its padding in the payload: the flow credit counts
# the declared length of the frame (RFC 9113 section 6.9.1) and x_data_body
# strips the padding where the body is read (task-062 phase 6).
def data_body_of(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{typ, flags, sid,+flen, payload}:
      HTTP.x_len32(HTTP2.x_data_body(payload, flags))

def data_body_len(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{unit, fin, rest}:
      data_body_of(HTTP2.x_frame_of(unit))
    case _:
      0

def v_padded_strip() -> U32:
  +out = HTTP2.x_parse(HTTP2.x_frame_write(0, 8, 1, [1, 0, 104, 105]))
  b2u(Bool.and(U32.is_eq(frame_len(out), 4), U32.is_eq(data_body_len(out), 2)))

def v_priority_strip() -> U32:
  frame_len(HTTP2.x_parse(HTTP2.x_frame_write(0, 32, 1, [0, 0, 0, 0, 0, 104])))

# The stream id is a 31-bit field whose R bit is the MSB of the FIRST id
# byte (RFC 9113 4.1): a reader that masks the last byte instead drops bit
# 7 of every low byte, so sid 129 read back as 1 and sid 255 as 127 --
# every frame above the 64th stream was misrouted (TASK-042 phase 5).
def sid_frame(sid: U32) -> List<&2, U32>:
  HTTP2.x_frame_write(0, 0, sid, Nil{})

def v_sid_above_127() -> U32:
  (b2u(U32.is_eq(frame_sid(HTTP2.x_parse(sid_frame(129))), 129))
    + b2u(U32.is_eq(frame_sid(HTTP2.x_parse(sid_frame(255))), 255))
    + b2u(U32.is_eq(frame_sid(HTTP2.x_parse(sid_frame(2147483647))), 2147483647)) : U32)

def chk_parser() -> U32:
  (v_empty() + v_half_header() + v_short_payload() + v_roundtrip() + v_over_cap()
    + v_padded_strip() + v_priority_strip() + v_sid_above_127() : U32)

# The head block the paced peer ships: 8 pad headers of 64 chars each, so the
# encoded block is well over 640 bytes and needs several 128-byte sends.

# The head block a big response ships: 8 pad headers of 64 chars each, so
# the encoded block is far past one TLS record (the reader must be able to
# assemble a head frame split across reads).

def pads.go(n: Nat, acc: List<&2, HTTP.Hdr>) -> List<&2, HTTP.Hdr>:
  match n:
    case 0n:
      acc
    case 1n+k:
      HTTP.Hdr{"x-pad",
        "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv"} <> pads.go(k, acc)

def pads(n: Nat) -> List<&2, HTTP.Hdr>:
  pads.go(n, Nil{})

def head_block() -> List<&2, HTTP.Hdr>:
  HTTP.Hdr{":status", "200"} <> (pads(8n))

def chk_pieces() -> U32:
  b2u(U32.is_gt(HTTP.x_len32(HTTP2.x_block(head_block())), 300))

law main:
  IO(U32)

def main():
  do IO<U32>:
    +score : U32 = (chk_parser() + chk_pieces() : U32)
    +pass : U32 = b2u(U32.is_eq(score, 13))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
