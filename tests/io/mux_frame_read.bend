# lib (lib_mux_frame_read): the mini-H2 frame reader must be a single
# unbounded loop, not a fixed number of reads: any public peer splits a
# response over many TLS records (Cloudflare ships ~1.4KB per record, so a
# 3.6KB HEADERS block alone needs three reads), and a reader with a read
# budget answers "truncated" on a perfectly good stream.
#
# Pure half pins the parser contract: NeedMore on an empty buffer and on a
# half header, an exact write->parse roundtrip (type, flags, sid, payload
# length, trailing bytes kept), Bad 413 over the 65535 frame cap, and the
# PADDED/PRIORITY strip. IO half is a loopback where a canned raw peer paces
# the answer: the head block in 128-byte pieces and the body as four 512B
# DATA frames, one TLS record (so one read) each, all small enough for the
# interpreter, and the real client HTTPX.client_once_insecure must assemble the
# whole 2048-byte body. Ported from h2_frame_read.bend (same peer shape, same
# 2048B assertion) when the http2.bend codec was retired.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Parser contract. Frame header on the wire is len(3) type(1) flags(1) sid(4),
# so a 9-byte buffer is the smallest complete header.

def is_need_more(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.NeedMore{missing, rest}:
      1
    case _:
      0

def need_exact(out: HTTPX.UnitOut, want: U32) -> U32:
  match out:
    case HTTPX.NeedMore{missing, rest}:
      b2u(U32.is_eq(missing, want))
    case _:
      0

def is_bad_413(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.Bad{code, msg}:
      b2u(U32.is_eq(code, 413))
    case _:
      0

def frame_payload_len(frame: HTTPX.Frame) -> U32:
  match frame:
    case HTTPX.Frame{typ, flags, sid, payload}:
      HTTPX.x_len32(payload)

def frame_sid_of(frame: HTTPX.Frame) -> U32:
  match frame:
    case HTTPX.Frame{typ, flags, sid, payload}:
      sid

def frame_len(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.Got{unit, fin, rest}:
      frame_payload_len(HTTPX.x_frame_of(unit))
    case _:
      0

def frame_sid(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.Got{unit, fin, rest}:
      frame_sid_of(HTTPX.x_frame_of(unit))
    case _:
      0

def frame_rest(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.Got{unit, fin, rest}:
      HTTPX.x_len32(rest)
    case _:
      0

def data_frame() -> List<&2, U32>:
  HTTPX.x_frame_write(0, 1, 1, [104, 105])

def v_empty() -> U32:
  need_exact(HTTPX.x_parse(Nil{}), 9)

def v_half_header() -> U32:
  need_exact(HTTPX.x_parse([0, 0, 4, 0, 0, 0, 0, 1]), 1)

# The payload counter in NeedMore is not pinned: the loops only branch on
# the constructor (x_read_loop ignores the count), so a truncated frame just
# has to come back as NeedMore.
def v_short_payload() -> U32:
  is_need_more(HTTPX.x_parse(HTTPX.x_drop32(1, data_frame())))

def v_roundtrip() -> U32:
  +out = HTTPX.x_parse(data_frame())
  (frame_len(out) + frame_sid(out) + frame_rest(out) : U32)

# 65537 bytes is one past the announced MAX_FRAME_SIZE (RFC 9113 4.2): the
# 24-bit length field is read first, so only the first three bytes matter.
def v_over_cap() -> U32:
  is_bad_413(HTTPX.x_parse([1, 0, 1, 0, 0, 0, 0, 0, 0]))

def v_padded_strip() -> U32:
  frame_len(HTTPX.x_parse(HTTPX.x_frame_write(0, 8, 1, [1, 0, 104, 105])))

def v_priority_strip() -> U32:
  frame_len(HTTPX.x_parse(HTTPX.x_frame_write(0, 32, 1, [0, 0, 0, 0, 0, 104])))

def chk_parser() -> U32:
  (v_empty() + v_half_header() + v_short_payload() + v_roundtrip() + v_over_cap()
    + v_padded_strip() + v_priority_strip() : U32)

# The head block the paced peer ships: 8 pad headers of 64 chars each, so the
# encoded block is well over 640 bytes and needs several 128-byte sends.

# The head block a big response ships: 8 pad headers of 64 chars each, so
# the encoded block is far past one TLS record (the reader must be able to
# assemble a head frame split across reads).

def pads.go(n: Nat, acc: List<&2, HTTPX.Hdr>) -> List<&2, HTTPX.Hdr>:
  match n:
    case 0n:
      acc
    case 1n+k:
      HTTPX.Hdr{"x-pad",
        "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv"} <> pads.go(k, acc)

def pads(n: Nat) -> List<&2, HTTPX.Hdr>:
  pads.go(n, Nil{})

def head_block() -> List<&2, HTTPX.Hdr>:
  HTTPX.Hdr{":status", "200"} <> (pads(8n))

def chk_pieces() -> U32:
  b2u(U32.is_gt(HTTPX.x_len32(HTTPX.x_block(head_block())), 300))

law main:
  IO(U32)

def main():
  do IO<U32>:
    +score : U32 = (chk_parser() + chk_pieces() : U32)
    +pass : U32 = b2u(U32.is_eq(score, 11))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
