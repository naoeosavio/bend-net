# lib (ws_frame): WS frame codec roundtrips plus fail-closed paths.
# Text, binary, continuation, ping/pong/close; len 16/64;wiadomości.
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

law unwrap_show:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap_show(r):
  match r:
    case Fail{e}:
      [255]
    case Done{bs}:
      bs

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

law is_fail400f:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  U32

def is_fail400f(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))
    case Done{t}:
      0

law is_fail413f:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  U32

def is_fail413f(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 413))
    case Done{t}:
      0

law chk_show:
  U32

def chk_show():
  eq_list(unwrap_show(WS.show_frame(True{}, 1, [72, 105])), [129, 2, 72, 105])

law chk_read:
  U32

def chk_read():
  (eq_list(read_pay(WS.read_frame([129, 130, 1, 2, 3, 4, 73, 107])), [72, 105]) + b2u(U32.is_eq(read_op(WS.read_frame([129, 130, 1, 2, 3, 4, 73, 107])), 1)) + read_fin(WS.read_frame([129, 130, 1, 2, 3, 4, 73, 107])) : U32)

law chk_read_ok:
  U32

def chk_read_ok():
  b2u(U32.is_eq(chk_read(), 3))

law chk_unmasked:
  U32

def chk_unmasked():
  is_fail400f(WS.read_frame([129, 2, 72, 105]))

law chk_ctrl_big:
  U32

def chk_ctrl_big():
  is_fail400f(WS.read_frame([137, 254, 0, 126, 1, 2, 3, 4, 5]))

law chk_frag_ctrl:
  U32

def chk_frag_ctrl():
  is_fail400f(WS.read_frame([9, 130, 1, 2, 3, 4, 73, 107]))

law chk_cap:
  U32

def chk_cap():
  is_fail413f(WS.read_frame([130, 255, 0, 0, 0, 0, 0, 16, 0, 1, 1, 2, 3, 4, 5]))

law main:
  U32

def main():
  (chk_show() + chk_read_ok() + chk_unmasked() + chk_ctrl_big() + chk_frag_ctrl() + chk_cap() : U32)

#|6
