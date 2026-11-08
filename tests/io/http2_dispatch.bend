# io (http2_dispatch): the pure server dispatch of task-070 phase 1.
# No socket: every case calls HTTP2.server.cls_final, HTTP2.x_frame.size_ok,
# HTTP2.x_prio.self or HTTP2.x_parse with the values the wire would carry.
#
# Act codes: 0 ignore, 1 settings ack, 2 rst_stream, 4 ping ack, 5 close,
# 6 stream frame, 7 credit, 8 continuation, 9 goaway protocol, 12 goaway
# frame size, 13 rst_stream stream closed.
#
# Score: one point per case, golden 77.
import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as HTTP2

def ACT_IGNORE() -> U32:
  0

def ACT_ACK() -> U32:
  1

def ACT_RST() -> U32:
  2

def ACT_PING() -> U32:
  4

def ACT_CLOSE() -> U32:
  5

def ACT_STREAM() -> U32:
  6

def ACT_CREDIT() -> U32:
  7

def ACT_CONT() -> U32:
  8

def ACT_PROTOCOL() -> U32:
  9

def ACT_FRAME_SIZE() -> U32:
  12

def ACT_STREAM_CLOSED() -> U32:
  13

def LAST() -> U32:
  1

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def point(want: U32, got: U32) -> U32:
  b2u(U32.is_eq(want, got))

# The act of one frame. `open_block` and `has` are the two connection
# facts the loop computes before the call.
def act(typ: U32, flags: U32, sid: U32, len: U32, pay: List<&2, U32>, last: U32, open_block: Bool, has: Bool) -> U32:
  HTTP2.server.cls_final(typ, flags, sid, len, pay, last, open_block, has)

def nil() -> List<&2, U32>:
  Nil{}

# A PRIORITY payload whose dependency is one stream id.
def prio_pay(dep: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_be32(dep), [16])

# A PRIORITY frame with a 9-byte header, a given sid and dependency.
def prio_unit(sid: U32, dep: U32) -> List<&2, U32>:
  List.append(&2, U32, [0, 0, 5, 2, 0, 0, 0, 0, U32.and(sid, 255)], prio_pay(dep))

# A HEADERS frame with PADDED and PRIORITY, pad length 0, dep in field.
def hdr_padded_unit(sid: U32, dep: U32) -> List<&2, U32>:
  List.append(&2, U32, [0, 0, 6, 1, 40, 0, 0, 0, U32.and(sid, 255), 0], prio_pay(dep))

def is_bad_go(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Bad{+code, +msg}:
      1
    case HTTP.Got{+unit2, fin, +rest}:
      0
    case HTTP.NeedMore{+missing, +rest}:
      0
    case HTTP.End{+rest}:
      0

def is_bad(unit: List<&2, U32>) -> U32:
  is_bad_go(HTTP2.x_parse(unit))

# The request head rules (RFC 9113 sections 8.2 and 8.3), one block each.
def dec_ok(block: List<&2, U32>) -> U32:
  b2u(HTTP2.x_req.ok(HTTP2.x_req.decode(block, HTTP2.x_tab.empty())))

def hdr(name: String, value: String) -> HTTP.Hdr:
  HTTP.Hdr{name, value}

def good_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr(":authority", "h"), hdr("accept", "*/*")])

def upper_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr("X-Test", "1")])

def pseudo_unknown_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr(":foo", "1")])

def status_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr(":status", "200")])

def no_scheme_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":path", "/")])

def dup_method_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/")])

def conn_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr("connection", "close")])

def te_bad_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr("te", "gzip")])

def te_ok_block() -> List<&2, U32>:
  HTTP2.x_block([hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/"), hdr("te", "trailers")])

def order_block() -> List<&2, U32>:
  HTTP2.x_block([hdr("accept", "*/*"), hdr(":method", "GET"), hdr(":scheme", "https"), hdr(":path", "/")])

# The Fail code of a decode, 0 when it succeeds.
def dec_code_go(dec: Result<&1, &1, U32 & String, HTTP.ReqHead & HTTP.Tab>) -> U32:
  match dec:
    case Fail{(+c, +m)}:
      c
    case Done{(+h, +t)}:
      0

def dec_code(block: List<&2, U32>) -> U32:
  dec_code_go(HTTP2.x_req.decode(block, HTTP2.x_tab.empty()))

def run() -> U32:
  +s0 : U32 = point(ACT_PROTOCOL(), act(0, 0, 0, 0, nil(), LAST(), False{}, False{}))
  +s1 : U32 = point(ACT_PROTOCOL(), act(0, 0, 2, 0, nil(), LAST(), False{}, False{}))
  +s2 : U32 = point(ACT_PROTOCOL(), act(0, 0, 3, 0, nil(), LAST(), False{}, False{}))
  +s3 : U32 = point(ACT_STREAM(), act(0, 1, 1, 0, nil(), LAST(), False{}, False{}))
  +s4 : U32 = point(ACT_STREAM(), act(0, 0, 1, 0, nil(), LAST(), False{}, True{}))
  +s5 : U32 = point(ACT_PROTOCOL(), act(1, 4, 0, 0, nil(), LAST(), False{}, False{}))
  +s6 : U32 = point(ACT_STREAM(), act(1, 4, 3, 0, nil(), LAST(), False{}, False{}))
  +s7 : U32 = point(ACT_STREAM_CLOSED(), act(1, 4, 1, 0, nil(), LAST(), False{}, False{}))
  +s8 : U32 = point(ACT_STREAM(), act(1, 4, 1, 0, nil(), LAST(), False{}, True{}))
  +s9 : U32 = point(ACT_PROTOCOL(), act(2, 0, 0, 5, prio_pay(0), LAST(), False{}, False{}))
  +s10 : U32 = point(ACT_IGNORE(), act(2, 0, 1, 5, prio_pay(0), LAST(), False{}, False{}))
  +s11 : U32 = point(ACT_PROTOCOL(), act(3, 0, 0, 4, nil(), LAST(), False{}, False{}))
  +s12 : U32 = point(ACT_PROTOCOL(), act(3, 0, 3, 4, nil(), LAST(), False{}, False{}))
  +s13 : U32 = point(ACT_RST(), act(3, 0, 1, 4, nil(), LAST(), False{}, False{}))
  +s14 : U32 = point(ACT_PROTOCOL(), act(4, 0, 1, 0, nil(), LAST(), False{}, False{}))
  +s15 : U32 = point(ACT_ACK(), act(4, 0, 0, 0, nil(), LAST(), False{}, False{}))
  +s16 : U32 = point(ACT_IGNORE(), act(4, 1, 0, 0, nil(), LAST(), False{}, False{}))
  +s17 : U32 = point(ACT_FRAME_SIZE(), act(4, 1, 0, 6, [0, 2, 0, 0, 0, 0], LAST(), False{}, False{}))
  +s18 : U32 = point(ACT_PROTOCOL(), act(4, 0, 0, 6, [0, 2, 0, 0, 0, 2], LAST(), False{}, False{}))
  +s19 : U32 = point(10, act(4, 0, 0, 6, [0, 4, 128, 0, 0, 0], LAST(), False{}, False{}))
  +s20 : U32 = point(ACT_PROTOCOL(), act(4, 0, 0, 6, [0, 5, 0, 0, 63, 255], LAST(), False{}, False{}))
  +s21 : U32 = point(ACT_ACK(), act(4, 0, 0, 6, [0, 5, 0, 0, 64, 0], LAST(), False{}, False{}))
  +s22 : U32 = point(ACT_ACK(), act(4, 0, 0, 6, [0, 9, 0, 0, 0, 1], LAST(), False{}, False{}))
  +s23 : U32 = point(ACT_PROTOCOL(), act(6, 0, 1, 8, nil(), LAST(), False{}, False{}))
  +s24 : U32 = point(ACT_PING(), act(6, 0, 0, 8, nil(), LAST(), False{}, False{}))
  +s25 : U32 = point(ACT_IGNORE(), act(6, 1, 0, 8, nil(), LAST(), False{}, False{}))
  +s26 : U32 = point(ACT_CLOSE(), act(7, 0, 0, 0, nil(), LAST(), False{}, False{}))
  +s27 : U32 = point(ACT_CREDIT(), act(8, 0, 0, 4, [0, 0, 0, 1], LAST(), False{}, False{}))
  +s28 : U32 = point(ACT_PROTOCOL(), act(8, 0, 3, 4, [0, 0, 0, 1], LAST(), False{}, False{}))
  +s29 : U32 = point(ACT_CREDIT(), act(8, 0, 1, 4, [0, 0, 0, 1], LAST(), False{}, False{}))
  +s30 : U32 = point(ACT_PROTOCOL(), act(8, 0, 0, 4, [0, 0, 0, 0], LAST(), False{}, False{}))
  +s31 : U32 = point(ACT_CONT(), act(9, 4, 1, 0, nil(), LAST(), False{}, False{}))
  +s32 : U32 = point(ACT_IGNORE(), act(10, 0, 0, 0, nil(), LAST(), False{}, False{}))
  +s33 : U32 = point(ACT_PROTOCOL(), act(0, 0, 1, 0, nil(), LAST(), True{}, True{}))
  +s34 : U32 = point(ACT_CONT(), act(9, 4, 1, 0, nil(), LAST(), True{}, False{}))
  +s35 : U32 = point(ACT_PROTOCOL(), act(10, 0, 0, 0, nil(), LAST(), True{}, False{}))
  +s36 : U32 = point(3, U32.max(0, 3))
  +s37 : U32 = point(5, U32.max(5, 3))
  +s38 : U32 = point(1, b2u(HTTP2.x_frame.size_ok(2, 5)))
  +s39 : U32 = point(0, b2u(HTTP2.x_frame.size_ok(2, 4)))
  +s40 : U32 = point(1, b2u(HTTP2.x_frame.size_ok(3, 4)))
  +s41 : U32 = point(0, b2u(HTTP2.x_frame.size_ok(6, 7)))
  +s42 : U32 = point(1, b2u(HTTP2.x_frame.size_ok(8, 4)))
  +s43 : U32 = point(1, b2u(HTTP2.x_frame.size_ok(0, 99)))
  +s44 : U32 = point(1, b2u(HTTP2.x_frame.size_ok(4, 12)))
  +s45 : U32 = point(0, b2u(HTTP2.x_frame.size_ok(4, 7)))
  +s46 : U32 = point(1, b2u(HTTP2.x_prio.self(prio_unit(1, 1), 2, 0, 1)))
  +s47 : U32 = point(0, b2u(HTTP2.x_prio.self(prio_unit(1, 3), 2, 0, 1)))
  +s48 : U32 = point(1, b2u(HTTP2.x_prio.self(hdr_padded_unit(1, 1), 1, 40, 1)))
  +s49 : U32 = point(0, b2u(HTTP2.x_prio.self(hdr_padded_unit(1, 3), 1, 40, 1)))
  +s50 : U32 = point(1, is_bad(prio_unit(1, 1)))
  +s51 : U32 = point(0, is_bad(prio_unit(1, 3)))
  +s52 : U32 = point(1, is_bad(hdr_padded_unit(1, 1)))
  +s53 : U32 = point(0, is_bad(hdr_padded_unit(1, 3)))
  +s54 : U32 = point(ACT_PROTOCOL(), act(0, 0, 1, 0, nil(), 3, False{}, False{}))
  +s55 : U32 = point(ACT_PROTOCOL(), act(1, 4, 1, 0, nil(), 3, False{}, False{}))
  +s56 : U32 = point(15, act(8, 0, 1, 4, [127, 255, 255, 255], LAST(), False{}, False{}))
  +s57 : U32 = point(12, HTTP2.server.admit.head_trailer(True{}, 0, 1))
  +s58 : U32 = point(14, HTTP2.server.admit.head_trailer(True{}, 0, 0))
  +s59 : U32 = point(5, HTTP2.server.admit.head_trailer(True{}, 1, 1))
  +s60 : U32 = point(1, dec_ok(good_block()))
  +s61 : U32 = point(0, dec_ok(upper_block()))
  +s62 : U32 = point(0, dec_ok(pseudo_unknown_block()))
  +s63 : U32 = point(0, dec_ok(status_block()))
  +s64 : U32 = point(0, dec_ok(no_scheme_block()))
  +s65 : U32 = point(0, dec_ok(dup_method_block()))
  +s66 : U32 = point(0, dec_ok(conn_block()))
  +s67 : U32 = point(0, dec_ok(te_bad_block()))
  +s68 : U32 = point(1, dec_ok(te_ok_block()))
  +s69 : U32 = point(0, dec_ok(order_block()))
  +s70 : U32 = point(0, b2u(HTTP2.x_cl.body_bad(Some{"4"}, 4)))
  +s71 : U32 = point(1, b2u(HTTP2.x_cl.body_bad(Some{"1"}, 4)))
  +s72 : U32 = point(0, b2u(HTTP2.x_cl.body_bad(None{}, 9)))
  +s73 : U32 = point(1, b2u(HTTP2.x_cl.body_bad(Some{"x"}, 4)))
  +s74 : U32 = point(9, dec_code([130, 32, 0]))
  +s75 : U32 = point(9, act(5, 4, 2, 0, nil(), LAST(), False{}, False{}))
  +s76 : U32 = point(16, HTTP2.server.data_act.buffered(False{}, False{}, 0, False{}))
  +total : U32 = (s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 + s9 + s10 + s11 + s12 + s13 + s14 + s15 + s16 + s17 + s18 + s19 + s20 + s21 + s22 + s23 + s24 + s25 + s26 + s27 + s28 + s29 + s30 + s31 + s32 + s33 + s34 + s35 + s36 + s37 + s38 + s39 + s40 + s41 + s42 + s43 + s44 + s45 + s46 + s47 + s48 + s49 + s50 + s51 + s52 + s53 + s54 + s55 + s56 + s57 + s58 + s59 + s60 + s61 + s62 + s63 + s64 + s65 + s66 + s67 + s68 + s69 + s70 + s71 + s72 + s73 + s74 + s75 + s76 : U32)
  total

def main() -> IO(U32):
  do IO<U32>:
    +total : U32 = run()
    x : Unit <- IO.print(U32.show(total))
    IO.pure(U32, total)

#|77
