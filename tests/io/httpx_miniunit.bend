# lib (lib_httpx_miniunit): pure roundtrips of the H2 codec in
# lib/http2.bend, and the SETTINGS copy of lib/httpx.bend. No IO, no TLS:
# frame write->parse and HPACK block->request-head must come back
# byte-identical. Golden 1. Runs in under a minute (unlike the TLS
# goldens) so it gates every mini-codec change.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def frame_score_frame(frame: HTTP.Frame, rest: List<&2, U32>) -> U32:
  match frame:
    case HTTP.Frame{typ, flags, sid,+flen, payload}:
      b2u(Bool.and(Bool.and(U32.is_eq(typ, 1), U32.is_eq(flags, 4)),
        Bool.and(U32.is_eq(sid, 1),
          Bool.and(U32.is_eq(HTTP.x_eq(payload, [10, 20]), 1), U32.is_eq(HTTP.x_len32(rest), 0)))))

def frame_score(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Bad{code, msg}:
      0
    case HTTP.NeedMore{missing, rest}:
      0
    case HTTP.Got{+unit, +fin, +rest}:
      frame_score_frame(HTTP2.x_frame_of(unit), rest)
    case HTTP.End{rest}:
      0

def frame_t() -> U32:
  frame_score(HTTP2.x_parse(HTTP2.x_frame_write(1, 4, 1, [10, 20])))

def req_score_head(head: HTTP.ReqHead, ok: Bool) -> U32:
  match head:
    case HTTP.ReqHead{method, path, headers}:
      b2u(Bool.and(ok, Bool.and(String.eq(method, "POST"), String.eq(path, "/echo"))))

# NOTE: +dr : Result<..., HTTP.ReqHead> is rejected through the alias
# (checker quirk: + on Result with an external single arg). decode is
# pure, so call it twice with single-use results instead.
def req_blk() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "POST"}, HTTP.Hdr{":scheme", "https"}, HTTP.Hdr{":path", "/echo"}])

def req_t_go(got: HTTP.ReqHead & Bool & HTTP.Tab) -> U32:
  match got:
    case (+h, +ok, t):
      req_score_head(h, ok)

def req_t() -> U32:
  req_t_go(HTTP2.x_req.got(HTTP2.x_req.decode(req_blk(), HTTP2.x_tab.empty())))

def resp_score_head(head: HTTP.Head, ok: Bool) -> U32:
  match head:
    case HTTP.Head{status, headers}:
      b2u(Bool.and(ok, U32.is_eq(status, 200)))

def resp_blk() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":status", "200"}, HTTP.Hdr{"content-type", "text/plain"}])

def resp_t() -> U32:
  resp_score_head(HTTP2.x_resp.rh(HTTP2.x_resp.decode(resp_blk(), HTTP2.x_tab.empty())), HTTP2.x_resp.ok(HTTP2.x_resp.decode(resp_blk(), HTTP2.x_tab.empty())))

# The bytes every H2 connection opens with: the 24-byte magic and the
# initial SETTINGS frame the dial builds (client.on.preface_bytes). A
# lost byte here breaks the handshake on every lane, so the seam has a
# pure test. The magic is the take of 24; the tail is one SETTINGS frame
# with an empty flag set, sid 0 and the 24-byte payload of four settings
# (ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
# MAX_FRAME_SIZE).
def settings_score(frame: HTTP.Frame, rest: List<&2, U32>) -> U32:
  match frame:
    case HTTP.Frame{typ, flags, sid,+flen, payload}:
      b2u(Bool.and(U32.is_eq(typ, 4),
        Bool.and(U32.is_eq(flags, 0),
          Bool.and(U32.is_eq(sid, 0),
            Bool.and(U32.is_eq(HTTP.x_len32(payload), 24),
              U32.is_eq(HTTP.x_len32(rest), 0))))))

def settings_out(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Bad{code, msg}:
      0
    case HTTP.NeedMore{missing, rest}:
      0
    case HTTP.Got{+unit, +fin, +rest}:
      settings_score(HTTP2.x_frame_of(unit), rest)
    case HTTP.End{rest}:
      0

def magic_t() -> U32:
  HTTP.x_eq(List.take(&2, U32, HTTP2.client.preface.bytes(), 24n), HTTP2.x_preface())

def settings_t() -> U32:
  settings_out(HTTP2.x_parse(HTTP.x_drop32(24, HTTP2.client.preface.bytes())))

# The facade carries its own copy of the initial SETTINGS, with ids 4 and
# 5 only. The frame cap at offset 8 must match lib/http2.bend (16384), so
# a change to one copy cannot leave the other behind.
def facade_t() -> U32:
  +pay : List<&2, U32> = HTTPX.x_settings_initial_pay()
  +cap : U32 = HTTP2.x_be32_rd(HTTP.x_drop32(8, pay))
  b2u(Bool.and(U32.is_eq(HTTP.x_len32(pay), 12), U32.is_eq(cap, 16384)))

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (frame_t() + req_t() + resp_t() + magic_t() + settings_t() + facade_t() : U32)
    +pass : U32 = b2u(U32.is_eq(total, 6))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
