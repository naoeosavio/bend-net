# lib (lib_mux_miniunit): pure roundtrips of the mini-H2 inside httpx.bend.
# No IO, no TLS: frame write->parse and HPACK block->request-head must
# come back byte-identical. Golden 1. Runs in seconds (unlike the
# TLS goldens) so it gates every mini-codec change.
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def frame_score_frame(frame: HTTPX.HttpxFrame, rest: List<&2, U32>) -> U32:
  match frame:
    case HTTPX.HttpxFrame{typ, flags, sid, payload}:
      b2u(Bool.and(Bool.and(U32.is_eq(typ, 1), U32.is_eq(flags, 4)),
        Bool.and(U32.is_eq(sid, 1),
          Bool.and(U32.is_eq(HTTPX.x_eq(payload, [10, 20]), 1), U32.is_eq(HTTPX.x_len32(rest), 0)))))

def frame_score(out: HTTPX.HttpxFrameOut) -> U32:
  match out:
    case HTTPX.HttpxFrameBad{code, msg}:
      0
    case HTTPX.HttpxNeedMore{missing}:
      0
    case HTTPX.HttpxFrameOk{+frame, +rest}:
      frame_score_frame(frame, rest)

def frame_t() -> U32:
  frame_score(HTTPX.x_parse(HTTPX.x_frame_write(1, 4, 1, [10, 20])))

def req_score_head(head: HTTPX.HttpxReqHead, ok: Bool) -> U32:
  match head:
    case HTTPX.HttpxReqHead{method, path, headers}:
      b2u(Bool.and(ok, Bool.and(String.eq(method, "POST"), String.eq(path, "/echo"))))

# NOTE: +dr : Result<..., HTTPX.HttpxReqHead> is rejected through the alias
# (checker quirk: + on Result with an external single arg). decode is
# pure, so call it twice with single-use results instead.
def req_blk() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.HttpxHdr{":method", "POST"}, HTTPX.HttpxHdr{":path", "/echo"}])

def req_t() -> U32:
  req_score_head(HTTPX.x_req.rh(HTTPX.x_req.decode(req_blk(), HTTPX.x_tab.empty())), HTTPX.x_req.ok(HTTPX.x_req.decode(req_blk(), HTTPX.x_tab.empty())))

def resp_score_head(head: HTTPX.HttpxHead, ok: Bool) -> U32:
  match head:
    case HTTPX.HttpxHead{status, headers}:
      b2u(Bool.and(ok, U32.is_eq(status, 200)))

def resp_blk() -> List<&2, U32>:
  HTTPX.x_block([HTTPX.HttpxHdr{":status", "200"}, HTTPX.HttpxHdr{"content-type", "text/plain"}])

def resp_t() -> U32:
  resp_score_head(HTTPX.x_resp.rh(HTTPX.x_resp.decode(resp_blk(), HTTPX.x_tab.empty())), HTTPX.x_resp.ok(HTTPX.x_resp.decode(resp_blk(), HTTPX.x_tab.empty())))

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (frame_t() + req_t() + resp_t() : U32)
    +pass : U32 = b2u(U32.is_eq(total, 3))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
