# lib (ws_unmasked): server-frame parse without mask (interop).
# Unmasked text/binary roundtrips, masked frames still accepted,
# 16-bit lengths, and msg classification on top.
import Base
import ../../lib/ws.bend as WS

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

law read_pay:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  List<&2, U32>

def read_pay(r):
  match r:
    case Fail{e}:
      [255]
    case Done{t}:
      (fin, op, pay) = t
      pay

law read_op:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  U32

def read_op(r):
  match r:
    case Fail{e}:
      255
    case Done{t}:
      (fin, op, pay) = t
      op

law read_fin:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  U32

def read_fin(r):
  match r:
    case Fail{e}:
      0
    case Done{t}:
      (fin, op, pay) = t
      b2u(fin)

law msg_text_ok:
  for r: Result<&1, &1, U32 & String, WS.WSMessage>
  U32

def msg_text_ok(r):
  match r:
    case Fail{e}:
      0
    case Done{m}:
      match m:
        case WS.WSText{text}:
          b2u(String.eq(text, "Hi"))
        case WS.WSBin{data}:
          0

law msg_of_res:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  Result<&1, &1, U32 & String, WS.WSMessage>

def msg_of_res(r):
  match r:
    case Fail{e}:
      Fail{e}
    case Done{t}:
      (fin, op, pay) = t
      WS.msg_of_frame(fin, op, pay)

law chk_text:
  U32

def chk_text():
  (eq_list(read_pay(WS.read_frame_unmasked([129, 2, 72, 105])), [72, 105]) + b2u(U32.is_eq(read_op(WS.read_frame_unmasked([129, 2, 72, 105])), 1)) + read_fin(WS.read_frame_unmasked([129, 2, 72, 105])) : U32)

law chk_text_ok:
  U32

def chk_text_ok():
  b2u(U32.is_eq(chk_text(), 3))

law chk_masked:
  U32

def chk_masked():
  eq_list(read_pay(WS.read_frame_unmasked([129, 130, 1, 2, 3, 4, 73, 107])), [72, 105])

law chk_msg:
  U32

def chk_msg():
  msg_text_ok(msg_of_res(WS.read_frame_unmasked([129, 2, 72, 105])))

law unwrap_show:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap_show(r):
  match r:
    case Fail{e}:
      [255]
    case Done{bs}:
      bs

law chk_med:
  U32

def chk_med():
  +big = List.replicate(U32, 130n, 65)
  b2u(Nat.is_eq(List.length(&2, U32, read_pay(WS.read_frame_unmasked(unwrap_show(WS.show_frame(True{}, 2, big))))), 130n))

law main:
  U32

def main():
  (chk_text_ok() + chk_masked() + chk_msg() + chk_med() : U32)

#|4
