# lib (wsm_close): close payload validation golden (task-020 phase 1).
# Empty normalizes to 1005, valid codes echo, reserved codes fail 1002,
# short payloads fail 1002, non-UTF-8 reasons fail 1007. Golden is the
# sum of the ten checks below.
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

law ev_close_is:
  for ev: WSM.WSEv
  for +want: List<&2, U32>
  U32

def ev_close_is(ev, want):
  match ev:
    case WSM.EvOpen{}:
      0
    case WSM.EvMsg{msg}:
      0
    case WSM.EvPing{pay}:
      0
    case WSM.EvPong{pay}:
      0
    case WSM.EvClose{pay}:
      eq_list(pay, want)
    case WSM.EvError{code, msg}:
      0

law ev_err_is:
  for ev: WSM.WSEv
  for +code: U32
  U32

def ev_err_is(ev, code):
  match ev:
    case WSM.EvOpen{}:
      0
    case WSM.EvMsg{msg}:
      0
    case WSM.EvPing{pay}:
      0
    case WSM.EvPong{pay}:
      0
    case WSM.EvClose{pay}:
      0
    case WSM.EvError{c, m}:
      b2u(U32.is_eq(c, code))

law chk_empty:
  U32

def chk_empty():
  ev_close_is(WSM.wsm_close_ev([]), [3, 237])

law chk_normal:
  U32

def chk_normal():
  ev_close_is(WSM.wsm_close_ev([3, 232]), [3, 232])

law chk_reason:
  U32

def chk_reason():
  ev_close_is(WSM.wsm_close_ev([3, 232, 72, 105]), [3, 232, 72, 105])

law chk_1005:
  U32

def chk_1005():
  ev_err_is(WSM.wsm_close_ev([3, 237]), 1002)

law chk_1006:
  U32

def chk_1006():
  ev_err_is(WSM.wsm_close_ev([3, 238]), 1002)

law chk_1015:
  U32

def chk_1015():
  ev_err_is(WSM.wsm_close_ev([3, 247]), 1002)

law chk_low:
  U32

def chk_low():
  ev_err_is(WSM.wsm_close_ev([3, 231]), 1002)

law chk_short:
  U32

def chk_short():
  ev_err_is(WSM.wsm_close_ev([3]), 1002)

law chk_bad_utf8:
  U32

def chk_bad_utf8():
  ev_err_is(WSM.wsm_close_ev([3, 232, 255]), 1007)

law chk_high:
  U32

def chk_high():
  ev_close_is(WSM.wsm_close_ev([11, 184]), [11, 184])

law main:
  U32

def main():
  (chk_empty() + chk_normal() + chk_reason() + chk_1005() + chk_1006() + chk_1015() + chk_low() + chk_short() + chk_bad_utf8() + chk_high() : U32)

#|10
