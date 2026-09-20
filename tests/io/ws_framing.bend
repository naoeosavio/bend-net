# lib (ws_framing): incremental WS frame split without IO.
# frame_need totals (small/masked/med), glued frames splitting into
# frame plus exact rest, halves rejoining, short inputs asking for
# more, invalid headers refused, and the unmasked client twins.
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

law unwrap:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap(r):
  match r:
    case Fail{e}:
      [255]
    case Done{bs}:
      bs

law need_val:
  for r: Result<&1, &1, U32 & String, U32>
  U32

def need_val(r):
  match r:
    case Fail{e}:
      4294967295
    case Done{n}:
      n

law is_fail400n:
  for r: Result<&1, &1, U32 & String, U32>
  U32

def is_fail400n(r):
  match r:
    case Fail{(c, e)}:
      b2u(U32.is_eq(c, 400))
    case Done{n}:
      0

law split_frame_eq:
  for s: WS.WSFrameSplit
  for want: List<&2, U32>
  U32

def split_frame_eq(s, want):
  match s:
    case WS.NeedMore{missing}:
      0
    case WS.FrameGot{frame, rest}:
      eq_list(frame, want)
    case WS.FrameBad{code, msg}:
      0

law split_rest_eq:
  for s: WS.WSFrameSplit
  for want: List<&2, U32>
  U32

def split_rest_eq(s, want):
  match s:
    case WS.NeedMore{missing}:
      0
    case WS.FrameGot{frame, rest}:
      eq_list(rest, want)
    case WS.FrameBad{code, msg}:
      0

law split_missing_eq:
  for s: WS.WSFrameSplit
  for want: U32
  U32

def split_missing_eq(s, want):
  match s:
    case WS.NeedMore{missing}:
      b2u(U32.is_eq(missing, want))
    case WS.FrameGot{frame, rest}:
      0
    case WS.FrameBad{code, msg}:
      0

law is_bad:
  for s: WS.WSFrameSplit
  U32

def is_bad(s):
  match s:
    case WS.NeedMore{missing}:
      0
    case WS.FrameGot{frame, rest}:
      0
    case WS.FrameBad{code, msg}:
      1

law pay_go:
  for +n: Nat
  for acc: List<&2, U32>
  List<&2, U32>

def pay_go(n, acc):
  match n:
    case 0n:
      acc
    case 1n+p:
      pay_go(p, U32.from_nat(p) <> acc)

law f_small:
  List<&2, U32>

def f_small():
  unwrap(WS.show_frame(True{}, 1, [72, 105]))

law f_m1:
  List<&2, U32>

def f_m1():
  unwrap(WS.show_masked(True{}, 1, [72, 105], 1, 2, 3, 4))

law f_m2:
  List<&2, U32>

def f_m2():
  unwrap(WS.show_masked(True{}, 2, [1, 2, 3], 1, 2, 3, 4))

law f_med:
  List<&2, U32>

def f_med():
  unwrap(WS.show_masked(True{}, 2, pay_go(200n, Nil{}), 1, 2, 3, 4))

law glued:
  List<&2, U32>

def glued():
  List.append(&2, U32, f_m1(), f_m2())

law take3:
  List<&2, U32>

def take3():
  List.take(&2, U32, glued(), 3n)

law drop3:
  List<&2, U32>

def drop3():
  List.drop(&2, U32, glued(), 3n)

law take1:
  List<&2, U32>

def take1():
  List.take(&2, U32, glued(), 1n)

law chk_need_small:
  U32

def chk_need_small():
  b2u(U32.is_eq(need_val(WS.frame_need_unmasked(f_small())), 4))

law chk_need_masked:
  U32

def chk_need_masked():
  b2u(U32.is_eq(need_val(WS.frame_need(f_m1())), 8))

law chk_need_med:
  U32

def chk_need_med():
  b2u(U32.is_eq(need_val(WS.frame_need(f_med())), 208))

law chk_need_reject:
  U32

def chk_need_reject():
  is_fail400n(WS.frame_need(f_small()))

law chk_glued_frame:
  U32

def chk_glued_frame():
  split_frame_eq(WS.frame_split(glued()), f_m1())

law chk_glued_rest:
  U32

def chk_glued_rest():
  split_rest_eq(WS.frame_split(glued()), f_m2())

law chk_half_need:
  U32

def chk_half_need():
  split_missing_eq(WS.frame_split(take3()), 5)

law chk_short_need:
  U32

def chk_short_need():
  split_missing_eq(WS.frame_split(take1()), 1)

law chk_empty_need:
  U32

def chk_empty_need():
  split_missing_eq(WS.frame_split([]), 1)

law chk_rejoin:
  U32

def chk_rejoin():
  +s = WS.frame_split(List.append(&2, U32, take3(), drop3()))
  (split_frame_eq(s, f_m1()) * split_rest_eq(s, f_m2()) : U32)

law chk_bad_ctrl:
  U32

def chk_bad_ctrl():
  is_bad(WS.frame_split([137, 254, 0, 126, 1, 2, 3, 4, 5]))

law chk_bad_unmasked:
  U32

def chk_bad_unmasked():
  is_bad(WS.frame_split([129, 2, 72, 105]))

law chk_client_ok:
  U32

def chk_client_ok():
  +s = WS.frame_split_unmasked([129, 2, 72, 105])
  (split_frame_eq(s, [129, 2, 72, 105]) * split_rest_eq(s, []) : U32)

law main:
  U32

def main():
  (chk_need_small() + chk_need_masked() + chk_need_med() + chk_need_reject() + chk_glued_frame() + chk_glued_rest() + chk_half_need() + chk_short_need() + chk_empty_need() + chk_rejoin() + chk_bad_ctrl() + chk_bad_unmasked() + chk_client_ok() : U32)

#|13
