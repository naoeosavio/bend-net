# lib (ws_fragments): fragment reassembly golden (task-020 phase 1).
# Text/binary stitched over 2-3 fragments, ping interleaved mid-message,
# orphan continuation and mixed-opcode rejects, FIN=0 control reject,
# strict UTF-8 reject. Golden is the sum of the nine checks below.
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

# Fold a frame list through the idle accumulator, stopping at the first
# emitted event or error.

type Frame is Data:
  Frame{fin: Bool, op: U32, pay: List<&2, U32>}

law frag_feed2:
  for frames: List<&2, Frame>
  for s: WS.WsStep
  WS.WsStep

def frag_feed2(frames, s):
  match frames:
    case Nil{}:
      s
    case Frame{fin, op, pay} <> t:
      match s:
        case WS.StepFrag{acc}:
          frag_feed2(t, WS.frag_ev(acc, fin, op, pay))
        case WS.StepEv{ev}:
          s
        case WS.StepOut{out}:
          s

law frag_feed:
  for frames: List<&2, Frame>
  WS.WsStep

def frag_feed(frames):
  frag_feed2(frames, WS.StepFrag{WS.FragIdle{}})

# Step inspectors: each answers 1 on its exact shape, 0 otherwise.

law msg_text_is:
  for msg: WS.WSMessage
  for +want: String
  U32

def msg_text_is(msg, want):
  match msg:
    case WS.WSText{text}:
      b2u(String.eq(text, want))
    case WS.WSBin{data}:
      0

law ev_text_is:
  for ev: WS.WSEv
  for +want: String
  U32

def ev_text_is(ev, want):
  match ev:
    case WS.EvOpen{}:
      0
    case WS.EvMsg{msg}:
      msg_text_is(msg, want)
    case WS.EvPing{pay}:
      0
    case WS.EvPong{pay}:
      0
    case WS.EvClose{pay}:
      0
    case WS.EvError{code, msg}:
      0

law step_text_is:
  for s: WS.WsStep
  for +want: String
  U32

def step_text_is(s, want):
  match s:
    case WS.StepFrag{acc}:
      0
    case WS.StepEv{ev}:
      ev_text_is(ev, want)
    case WS.StepOut{out}:
      0

law msg_bin_is:
  for msg: WS.WSMessage
  for +want: List<&2, U32>
  U32

def msg_bin_is(msg, want):
  match msg:
    case WS.WSText{text}:
      0
    case WS.WSBin{data}:
      eq_list(data, want)

law ev_bin_is:
  for ev: WS.WSEv
  for +want: List<&2, U32>
  U32

def ev_bin_is(ev, want):
  match ev:
    case WS.EvOpen{}:
      0
    case WS.EvMsg{msg}:
      msg_bin_is(msg, want)
    case WS.EvPing{pay}:
      0
    case WS.EvPong{pay}:
      0
    case WS.EvClose{pay}:
      0
    case WS.EvError{code, msg}:
      0

law step_bin_is:
  for s: WS.WsStep
  for +want: List<&2, U32>
  U32

def step_bin_is(s, want):
  match s:
    case WS.StepFrag{acc}:
      0
    case WS.StepEv{ev}:
      ev_bin_is(ev, want)
    case WS.StepOut{out}:
      0

law ev_err_is:
  for ev: WS.WSEv
  for +code: U32
  U32

def ev_err_is(ev, code):
  match ev:
    case WS.EvOpen{}:
      0
    case WS.EvMsg{msg}:
      0
    case WS.EvPing{pay}:
      0
    case WS.EvPong{pay}:
      0
    case WS.EvClose{pay}:
      0
    case WS.EvError{c, m}:
      b2u(U32.is_eq(c, code))

law step_err_is:
  for s: WS.WsStep
  for +code: U32
  U32

def step_err_is(s, code):
  match s:
    case WS.StepFrag{acc}:
      0
    case WS.StepEv{ev}:
      ev_err_is(ev, code)
    case WS.StepOut{out}:
      0

law is_frag:
  for s: WS.WsStep
  U32

def is_frag(s):
  match s:
    case WS.StepFrag{acc}:
      1
    case WS.StepEv{ev}:
      0
    case WS.StepOut{out}:
      0

law fail_code_is:
  for r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for +code: U32
  U32

def fail_code_is(r, code):
  match r:
    case Fail{(c, m)}:
      b2u(U32.is_eq(c, code))
    case Done{t}:
      0

law inop_ping_ok:
  for w: WS.WSIn
  U32

def inop_ping_ok(w):
  match w:
    case WS.InMsg{msg}:
      0
    case WS.InOp{fin, op, pay}:
      b2u(Bool.and(fin, Bool.and(U32.is_eq(op, 9), U32.is_eq(eq_list(pay, [1, 2]), 1))))

# The checks.

law chk_text2:
  U32

def chk_text2():
  step_text_is(frag_feed([Frame{False{}, 1, [72, 101]}, Frame{True{}, 0, [108, 108, 111]}]), "Hello")

law chk_bin3:
  U32

def chk_bin3():
  step_bin_is(frag_feed([Frame{False{}, 2, [1, 2]}, Frame{False{}, 0, [3]}, Frame{True{}, 0, [4, 5]}]), [1, 2, 3, 4, 5])

law chk_ping_mid:
  U32

def chk_ping_mid():
  (is_frag(frag_feed([Frame{False{}, 1, [72]}])) * inop_ping_ok(WS.recv_in_of(True{}, 9, [1, 2])) * step_text_is(frag_feed([Frame{False{}, 1, [72]}, Frame{True{}, 0, [105]}]), "Hi") : U32)

law chk_orphan:
  U32

def chk_orphan():
  step_err_is(frag_feed([Frame{True{}, 0, [1]}]), 400)

law chk_mixed:
  U32

def chk_mixed():
  step_err_is(frag_feed([Frame{False{}, 1, [65]}, Frame{False{}, 2, [66]}]), 400)

law chk_ctrl_fin0:
  U32

def chk_ctrl_fin0():
  fail_code_is(WS.read_frame([9, 2, 72, 105]), 400)

law chk_single:
  U32

def chk_single():
  step_text_is(frag_feed([Frame{True{}, 1, [72, 105]}]), "Hi")

law chk_bad_utf8:
  U32

def chk_bad_utf8():
  step_err_is(frag_feed([Frame{True{}, 1, [255]}]), 1007)

law chk_empty_first:
  U32

def chk_empty_first():
  step_text_is(frag_feed([Frame{False{}, 1, []}, Frame{True{}, 0, [72, 105]}]), "Hi")

law main:
  U32

def main():
  (chk_text2() + chk_bin3() + chk_ping_mid() + chk_orphan() + chk_mixed() + chk_ctrl_fin0() + chk_single() + chk_bad_utf8() + chk_empty_first() : U32)

#|9
