# lib (rfc_wsm): RFC conformance over the deployed WebSocket module —
# lib/wsm.bend, imported as WSM (the names the importers call).
#
# Pure only: no socket, no TLS. Every expected value is written
# longhand from the RFC section named next to it, never captured from
# the implementation; call shapes mirror the already-green
# tests/io/wsm_surface.bend, only the asserted values are new. The
# live legs of the same contract are tests/rfc/ws_oracle.js (node and
# bun) and tests/rfc/browser.html.
#
# Groups: section 1.3 key/accept + byte-exact 101 + pinned-accept
# render, client head contains-checks, validate shapes, frame
# render/parse both ways + unmasked-client refusal, message layer,
# close table (section 5.5.1), strict UTF-8 (section 5.6), fragments
# (section 5.4), client 101 check, scan_len and host_port. Golden 1
# iff every check is 1.
#
# The loop-level fixes of TASK-042 phase 1 are IO, not pure (the fold
# here was always correct): the control frame between fragments that
# must keep the accumulator, the coalesced continuation that must not be
# dropped, the 1009 close on the payload cap and the mixed-fragment
# refusal are measured by tests/io/wsm_ctrl_frag.bend,
# tests/io/wsm_frag_coalesce.bend, tests/io/wsm_cap_close.bend and
# tests/io/wsm_frag_mixed.bend.
import Base
import ../../lib/wsm.bend as WSM
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def u32_is(got: U32, want: U32) -> U32:
  b2u(U32.is_eq(got, want))

def same(got: List<&2, U32>, want: List<&2, U32>) -> U32:
  b2u(U32.is_eq(HTTPX.x_eq(got, want), 1))

def text_is.go(r: Result<&1, &1, U32 & String, String>,
  want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.eq(s, want))

def text_fails.go(r: Result<&1, &1, U32 & String, String>,
  code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, msg) = e
      u32_is(c, code)
    case Done{s}:
      0

def head_has.go(r: Result<&1, &1, U32 & String, String>,
  sub: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(String.contains(s, sub))

def head_lacks.go(r: Result<&1, &1, U32 & String, String>,
  sub: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{s}:
      b2u(Bool.not(String.contains(s, sub)))

def bytes_is.go(r: Result<&1, &1, U32 & String, List<&2, U32>>,
  want: List<&2, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{bs}:
      same(bs, want)

def read_op.go(r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>,
  want: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{t}:
      (fin, op, pay) = t
      u32_is(op, want)

def read_pay.go(r: Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>,
  want: List<&2, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{t}:
      (fin, op, pay) = t
      same(pay, want)

def read_fails.go(r: Result<&1, &1, U32 & String,
  Bool & U32 & List<&2, U32>>, code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, msg) = e
      u32_is(c, code)
    case Done{t}:
      0

def msg_text.go(r: Result<&1, &1, U32 & String, WSM.WSMessage>,
  want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{msg}:
      match msg:
        case WSM.WSText{text}:
          b2u(String.eq(text, want))
        case WSM.WSBin{data}:
          0

def msg_fails.go(r: Result<&1, &1, U32 & String, WSM.WSMessage>,
  code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, msg) = e
      u32_is(c, code)
    case Done{msg}:
      0

def close_is.go(r: Result<&1, &1, U32 & String, List<&2, U32>>,
  want: List<&2, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{bs}:
      same(bs, want)

def close_fails.go(r: Result<&1, &1, U32 & String, List<&2, U32>>,
  code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, msg) = e
      u32_is(c, code)
    case Done{bs}:
      0

def step_msg_is(s: WSM.WsStep, want: String) -> U32:
  match s:
    case WSM.StepEv{ev}:
      match ev:
        case WSM.EvMsg{msg}:
          match msg:
            case WSM.WSText{text}:
              b2u(String.eq(text, want))
            case WSM.WSBin{data}:
              0
        case WSM.EvOpen{}:
          0
        case WSM.EvPing{pay}:
          0
        case WSM.EvPong{pay}:
          0
        case WSM.EvClose{pay}:
          0
        case WSM.EvError{code, msg}:
          0
    case WSM.StepFrag{acc}:
      0
    case WSM.StepOut{out}:
      0

def is_frag(s: WSM.WsStep) -> U32:
  match s:
    case WSM.StepFrag{acc}:
      1
    case WSM.StepEv{ev}:
      0
    case WSM.StepOut{out}:
      0

def good_key() -> String:
  "dGhlIHNhbXBsZSBub25jZQ=="

def want_accept() -> String:
  "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

def key_req() -> String:
  "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

def accept_101() -> String:
  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

def upgrade_hs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Upgrade", "websocket"},
    HTTPX.Hdr{"Connection", "Upgrade"},
    HTTPX.Hdr{"Sec-WebSocket-Key", good_key()},
    HTTPX.Hdr{"Sec-WebSocket-Version", "13"}]

def no_upgrade_hs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Connection", "Upgrade"},
    HTTPX.Hdr{"Sec-WebSocket-Key", good_key()},
    HTTPX.Hdr{"Sec-WebSocket-Version", "13"}]

def accept_hs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Sec-WebSocket-Accept", want_accept()}]

# Section 1.3: the key, the byte-exact 101, the two refusals.
def handshake_t() -> U32:
  (b2u(String.eq(WSM.wsm_accept_of(good_key()), want_accept()))
    + text_is.go(WSM.wsm_handshake(key_req()), accept_101())
    + text_is.go(WSM.wsm_show_101(want_accept()), accept_101())
    + text_fails.go(WSM.wsm_validate("POST", upgrade_hs()), 400)
    + text_fails.go(WSM.wsm_validate("GET", no_upgrade_hs()), 400) : U32)

# Client head: Host with port, Upgrade kept, no Content-Length (the
# shape tests/io/wsm_surface.bend pins), plus the CRLF-key refusal.
def client_t() -> U32:
  (head_has.go(WSM.wsm_client_head("s", 8080, "/chat", good_key()),
      "Host: s:8080\r\n")
    + head_has.go(WSM.wsm_client_head("s", 8080, "/chat", good_key()),
      "Connection: Upgrade\r\n")
    + head_lacks.go(WSM.wsm_client_head("s", 8080, "/chat", good_key()),
      "Content-Length")
    + text_fails.go(WSM.wsm_client_head("s", 8080, "/chat", "a\r\nX: y"),
      400) : U32)

# Section 5.7: masked 0x81 0x85 37 fa 21 3d and plain 0x81 0x05.
def masked_hello() -> List<&2, U32>:
  [129, 133, 55, 250, 33, 61, 127, 159, 77, 81, 88]

def frame_t() -> U32:
  (bytes_is.go(WSM.wsm_show_frame(True{}, 1, [72, 101, 108, 108, 111]),
      [129, 5, 72, 101, 108, 108, 111])
    + bytes_is.go(WSM.wsm_show_masked(True{}, 1,
      [72, 101, 108, 108, 111], 55, 250, 33, 61), masked_hello())
    + read_op.go(WSM.wsm_read_frame(masked_hello()), 1)
    + read_pay.go(WSM.wsm_read_frame(masked_hello()),
      [72, 101, 108, 108, 111])
    + read_fails.go(WSM.wsm_read_frame([129, 5, 72, 101, 108, 108,
      111]), 400) : U32)

# Messages: text decodes, control and fragment never do.
def msg_t() -> U32:
  (msg_text.go(WSM.wsm_msg_of_frame(True{}, 1, [72, 105]), "Hi")
    + msg_fails.go(WSM.wsm_msg_of_frame(True{}, 9, [1]), 400)
    + msg_fails.go(WSM.wsm_msg_of_frame(False{}, 1, [72]), 400) : U32)

# Section 5.5.1: empty means 1005, short means 1002.
def close_t() -> U32:
  (close_is.go(WSM.wsm_close_norm(Nil{}), [3, 237])
    + close_is.go(WSM.wsm_close_norm([3, 232]), [3, 232])
    + close_fails.go(WSM.wsm_close_norm([3]), 1002) : U32)

# Section 5.6: ASCII ok, stray continuation, truncated and overlong
# out. This is the real UTF-8 the H1 lane does not have.
def utf8_t() -> U32:
  (b2u(WSM.wsm_utf8_ok([72, 105]))
    + b2u(Bool.not(WSM.wsm_utf8_ok([128])))
    + b2u(Bool.not(WSM.wsm_utf8_ok([195])))
    + b2u(Bool.not(WSM.wsm_utf8_ok([192, 128])))
    + same(WSM.wsm_utf8_encode("é"), [195, 169]) : U32)

# Section 5.4: a whole message emits, an open fragment waits.
def frag_t() -> U32:
  (step_msg_is(WSM.wsm_frag_ev(WSM.FragIdle{}, True{}, 1, [72, 105]),
      "Hi")
    + is_frag(WSM.wsm_frag_ev(WSM.FragIdle{}, False{}, 1, [72])) : U32)

# Client side: status 101 plus the echoed accept; compat helpers.
def client_ok_t() -> U32:
  (b2u(WSM.wsm_client_ok(101, accept_hs(), want_accept()))
    + b2u(Bool.not(WSM.wsm_client_ok(200, accept_hs(), want_accept())))
    + u32_is(WSM.client_scan_len([72, 73, 13, 10, 13, 10]), 6)
    + b2u(String.eq(WSM.ws_host_port("example.com", 8080),
      "example.com:8080")) : U32)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (handshake_t() + client_t() + frame_t() + msg_t()
      + close_t() + utf8_t() + frag_t() + client_ok_t() : U32)
    +want : U32 = (5 + 4 + 5 + 3 + 3 + 5 + 2 + 4 : U32)
    +pass : U32 = u32_is(total, want)
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
