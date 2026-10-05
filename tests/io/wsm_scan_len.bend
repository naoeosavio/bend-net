# lib (wsm_scan_len): client_scan_len head-split golden (task-020 phase 0).
# Guards the off-by-3 fix: scan_len must answer the head length including
# the \r\n\r\n terminator, so take/drop split a coalesced 101 + frame
# segment exactly. Golden is the sum of the five checks below.
import Base
import ../../lib/wsm.bend as WSM

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law eq_list:
  for xs: List<&2, U32>
  for ys: List<&2, U32>
  U32

def eq_list(xs, ys):
  match xs:
    case Nil{}:
      match ys:
        case Nil{}:
          1
        case _ <> _:
          0
    case h1 <> t1:
      match ys:
        case Nil{}:
          0
        case h2 <> t2:
          (b2u(U32.is_eq(h1, h2)) * eq_list(t1, t2) : U32)

law short_head:
  List<&2, U32>

def short_head():
  WSM.wsm_utf8_encode("AB\r\n\r\n")

law long_head:
  String

def long_head():
  "GET /chat HTTP/1.1\r\nHost: example.com:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

law frame_bytes:
  List<&2, U32>

def frame_bytes():
  [129, 5, 72, 101, 108, 108, 111]

law chk_short:
  U32

def chk_short():
  b2u(U32.is_eq(WSM.client_scan_len(short_head()), 6))

law chk_long:
  U32

def chk_long():
  b2u(U32.is_eq(WSM.client_scan_len(WSM.wsm_utf8_encode(long_head())), U32.from_nat(String.length(long_head()))))

law chk_take:
  U32

def chk_take():
  +acc = List.append(&2, U32, short_head(), frame_bytes())
  +taken = List.take(&2, U32, acc, U32.to_nat(WSM.client_scan_len(acc)))
  eq_list(taken, short_head())

law chk_drop:
  U32

def chk_drop():
  +acc = List.append(&2, U32, short_head(), frame_bytes())
  +rest = List.drop(&2, U32, acc, U32.to_nat(WSM.client_scan_len(acc)))
  eq_list(rest, frame_bytes())

law mid_bytes:
  List<&2, U32>

def mid_bytes():
  [65, 13, 10, 13, 10, 66]

law chk_mid:
  U32

def chk_mid():
  +bs = mid_bytes()
  +len = WSM.client_scan_len(bs)
  (b2u(U32.is_eq(len, 5)) * eq_list(List.drop(&2, U32, bs, U32.to_nat(len)), [66]) : U32)

law main:
  U32

def main():
  (chk_short() + chk_long() + chk_take() + chk_drop() + chk_mid() : U32)

#|5
