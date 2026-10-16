# lib (lib_httpx_shrink_dead): coverage gate for TASK-055 Phase 2.
# The 20 dead defs have no caller; this test pins the live neighbours so a
# cut with fallout fails here. Pure, no IO/TLS, runs in seconds.
# Each check returns 1. Golden 10.
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Dead x_static_name / x_static.value: live x_static.go/name/value answer.
def t_static.n(p: String & String) -> U32:
  (n, v) = p
  b2u(String.eq(HTTPX.x_static.name((n, v)), ":method"))

def t_static.v(p: String & String) -> U32:
  (n, v) = p
  b2u(String.eq(v, "GET"))

def t_static() -> U32:
  (t_static.n(HTTPX.x_static.go(2)) * t_static.v(HTTPX.x_static.go(2)) : U32)

# Dead x_huff_lens: the live tables still head the same values.
def t_huff.firsts(h: U32, +firsts: List<&2, U32>) -> U32:
  match firsts:
    case Nil{}:
      0
    case f <> r:
      b2u(Bool.and(U32.is_eq(h, 10), U32.is_eq(f, 0)))

def t_huff.go(+counts: List<&2, U32>, +firsts: List<&2, U32>) -> U32:
  match counts:
    case Nil{}:
      0
    case h <> t:
      t_huff.firsts(h, firsts)

def t_huff() -> U32:
  t_huff.go(HTTPX.x_huff_counts(), HTTPX.x_huff_firsts())

# Dead x_bytes_str.go: the live bytes helper still encodes.
def t_str() -> U32:
  b2u(U32.is_eq(HTTPX.x_len32(HTTPX.x_str_bytes("hi")), 2))

# Dead x_req.phase + x_hdr.lit.mask + x_hdr.indexed.go2: request decode ok.
def t_req() -> U32:
  b2u(HTTPX.x_req.ok(HTTPX.x_req.decode(HTTPX.x_block([HTTPX.Hdr{":method", "POST"}, HTTPX.Hdr{":path", "/echo"}]), HTTPX.x_tab.empty())))

# Live twin of dead httpxc.resp_of stays: response decode ok.
def t_resp() -> U32:
  b2u(HTTPX.x_resp.ok(HTTPX.x_resp.decode(HTTPX.x_block([HTTPX.Hdr{":status", "200"}]), HTTPX.x_tab.empty())))

# Dead x_send_resp_body: DATA frame write->parse roundtrip still holds.
def t_frame.of(frame: HTTPX.Frame) -> U32:
  match frame:
    case HTTPX.Frame{typ, flags, sid, payload}:
      b2u(Bool.and(Bool.and(U32.is_eq(typ, 1), U32.is_eq(sid, 1)), U32.is_eq(HTTPX.x_len32(payload), 2)))

def t_frame.rest(+unit: List<&2, U32>) -> U32:
  t_frame.of(HTTPX.x_frame_of(unit))

def t_frame.got(+unit: List<&2, U32>, +rest: List<&2, U32>) -> U32:
  (b2u(U32.is_eq(HTTPX.x_len32(rest), 0)) * t_frame.rest(unit) : U32)

def t_frame.go(out: HTTPX.UnitOut) -> U32:
  match out:
    case HTTPX.Got{unit, fin, rest}:
      t_frame.got(unit, rest)
    case HTTPX.NeedMore{missing, rest}:
      0
    case HTTPX.End{rest}:
      0
    case HTTPX.Bad{code, msg}:
      0

def t_frame() -> U32:
  t_frame.go(HTTPX.x_parse(HTTPX.x_frame_write(1, 4, 1, [10, 20])))

# Dead httpxs.out_resp/head_out/head_act/data_out/data_act/is_more: the live
# SrvOut readers agree on Continue and on RespondEarly.
def t_srvout.data(cont_status: U32, hstatus: U32, dresp: HTTPX.Response) -> U32:
  match dresp:
    case HTTPX.Response{status, headers, body}:
      b2u(Bool.and(U32.is_eq(cont_status, 0), Bool.and(U32.is_eq(hstatus, 200), U32.is_eq(status, 200))))

def t_srvout.early(hresp: HTTPX.Response) -> U32:
  match hresp:
    case HTTPX.Response{status, headers, body}:
      status

def t_srvout.more(hresp_cont: HTTPX.Response, hresp: HTTPX.Response, dresp: HTTPX.Response) -> U32:
  match hresp_cont:
    case HTTPX.Response{status, headers, body}:
      t_srvout.data(status, t_srvout.early(hresp), dresp)

def t_srvout() -> U32:
  t_srvout.more(HTTPX.httpxs.resp_from_out(HTTPX.Continue{}), HTTPX.httpxs.resp_from_out(HTTPX.RespondEarly{HTTPX.Response{200, Nil{}, Nil{}}}), HTTPX.httpxs.resp_from_out(HTTPX.RespondEarly{HTTPX.Response{200, Nil{}, Nil{}}}))

# Dead httpxn.head_keep: the live go helper keeps old on trailer, new else.
def t_keep.fresh(kept_status: U32, fresh: HTTPX.Head) -> U32:
  match fresh:
    case HTTPX.Head{status, headers}:
      b2u(Bool.and(U32.is_eq(kept_status, 200), U32.is_eq(status, 404)))

def t_keep.go(kept: HTTPX.Head, fresh: HTTPX.Head) -> U32:
  match kept:
    case HTTPX.Head{status, headers}:
      t_keep.fresh(status, fresh)

def t_keep() -> U32:
  t_keep.go(HTTPX.httpxn.head_keep_go(HTTPX.Head{200, Nil{}}, HTTPX.Head{404, Nil{}}, True{}), HTTPX.httpxn.head_keep_go(HTTPX.Head{200, Nil{}}, HTTPX.Head{404, Nil{}}, False{}))

# Dead httpxc.body_of + client.on.st_h2: sid ledger + next sid + has_head.
def t_clst() -> U32:
  st: HTTPX.St = HTTPX.St{None{}, Nil{}, 7}
  b2u(Bool.and(Bool.and(U32.is_eq(HTTPX.httpx.sid_of(st), 7), U32.is_eq(HTTPX.client.on.next_sid(1), 3)), HTTPX.client.on.has_head(HTTPX.Head{200, Nil{}})))

# Dead httpxc.resp_of via live twin client.on.resp_of: status rides through.
def t_respof.go(resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{status, headers, body}:
      b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTPX.x_len32(body), 2)))

def t_respof() -> U32:
  t_respof.go(HTTPX.client.on.resp_of(HTTPX.Head{200, Nil{}}, [1, 2]))

# Dead x_hdr.indexed.go/num: the live indexed route (x_hdr.dec -> dyn.num)
# still answers a static index and a dynamic index (RFC 7541 section 6.1).
def t_indexed.got(r: Result<&1, &1, U32 & String, HTTPX.HdrGot>, wn: String, wv: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{g}:
      match g:
        case HTTPX.HdrGot{name, value, rest, tab}:
          b2u(Bool.and(Bool.and(String.eq(name, wn), String.eq(value, wv)), U32.is_eq(HTTPX.x_len32(rest), 0)))

def t_indexed.static() -> U32:
  t_indexed.got(HTTPX.x_hdr.dec([130], HTTPX.x_tab.empty()), ":method", "GET")

def t_indexed.dyn() -> U32:
  t_indexed.got(HTTPX.x_hdr.dec([190], HTTPX.x_tab.insert(HTTPX.x_tab.empty(), "x-y", "z")), "x-y", "z")

def t_indexed() -> U32:
  (t_indexed.static() * t_indexed.dyn() : U32)

law main:
  U32

def main():
  (t_static() + t_huff() + t_str() + t_req() + t_resp() + t_frame() + t_srvout() + t_keep() + t_clst() + t_respof() + t_indexed() : U32)
#|11
