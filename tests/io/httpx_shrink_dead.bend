# lib (lib_httpx_shrink_dead): coverage gate for TASK-055 Phase 2.
# The 20 dead defs have no caller; this test pins the live neighbours so a
# cut with fallout fails here. Pure, no IO/TLS, runs in seconds.
# Each check returns 1. Golden 11.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Dead x_static_name / x_static.value: live x_static.go/name/value answer.
def t_static.n(p: String & String) -> U32:
  (n, v) = p
  b2u(String.eq(HTTP2.x_static.name((n, v)), ":method"))

def t_static.v(p: String & String) -> U32:
  (n, v) = p
  b2u(String.eq(v, "GET"))

def t_static() -> U32:
  (t_static.n(HTTP2.x_static.go(2)) * t_static.v(HTTP2.x_static.go(2)) : U32)

# Dead x_huff_lens: the live flat table answers the same head.
def t_huff() -> U32:
  b2u(Bool.and(U32.is_eq(HTTP2.x_huff_sym(0), 48), HTTP2.x_huff_hit(0, 5)))

# Dead x_bytes_str.go: the live bytes helper still encodes.
def t_str() -> U32:
  b2u(U32.is_eq(HTTP.x_len32(HTTP.x_str_bytes("hi")), 2))

# Dead x_req.phase + x_hdr.lit.mask + x_hdr.indexed.go2: request decode ok.
def t_req() -> U32:
  b2u(HTTP2.x_req.ok(HTTP2.x_req.decode(HTTP2.x_block([HTTP.Hdr{":method", "POST"}, HTTP.Hdr{":scheme", "https"}, HTTP.Hdr{":path", "/echo"}]), HTTP2.x_tab.empty())))

# Live twin of dead httpxc.resp_of stays: response decode ok.
def t_resp() -> U32:
  b2u(HTTP2.x_resp.ok(HTTP2.x_resp.decode(HTTP2.x_block([HTTP.Hdr{":status", "200"}]), HTTP2.x_tab.empty())))

# Dead x_send_resp_body: DATA frame write->parse roundtrip still holds.
def t_frame.of(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{typ, flags, sid,+flen, payload}:
      b2u(Bool.and(Bool.and(U32.is_eq(typ, 1), U32.is_eq(sid, 1)), U32.is_eq(HTTP.x_len32(payload), 2)))

def t_frame.rest(+unit: List<&2, U32>) -> U32:
  t_frame.of(HTTP2.x_frame_of(unit))

def t_frame.got(+unit: List<&2, U32>, +rest: List<&2, U32>) -> U32:
  (b2u(U32.is_eq(HTTP.x_len32(rest), 0)) * t_frame.rest(unit) : U32)

def t_frame.go(out: HTTP.UnitOut) -> U32:
  match out:
    case HTTP.Got{unit, fin, rest}:
      t_frame.got(unit, rest)
    case HTTP.NeedMore{missing, rest}:
      0
    case HTTP.End{rest}:
      0
    case HTTP.Bad{code, msg}:
      0

def t_frame() -> U32:
  t_frame.go(HTTP2.x_parse(HTTP2.x_frame_write(1, 4, 1, [10, 20])))

# Dead httpxs.out_resp/head_out/head_act/data_out/data_act/is_more: the live
# SrvOut readers agree on Continue and on RespondEarly.
def t_srvout.data(cont_status: U32, hstatus: U32, dresp: HTTP.Response) -> U32:
  match dresp:
    case HTTP.Response{status, headers, body}:
      b2u(Bool.and(U32.is_eq(cont_status, 0), Bool.and(U32.is_eq(hstatus, 200), U32.is_eq(status, 200))))

def t_srvout.early(hresp: HTTP.Response) -> U32:
  match hresp:
    case HTTP.Response{status, headers, body}:
      status

def t_srvout.more(hresp_cont: HTTP.Response, hresp: HTTP.Response, dresp: HTTP.Response) -> U32:
  match hresp_cont:
    case HTTP.Response{status, headers, body}:
      t_srvout.data(status, t_srvout.early(hresp), dresp)

def t_srvout() -> U32:
  t_srvout.more(HTTP2.httpxs.resp_from_out(HTTP.Continue{}), HTTP2.httpxs.resp_from_out(HTTP.RespondEarly{HTTP.Response{200, Nil{}, Nil{}}}), HTTP2.httpxs.resp_from_out(HTTP.RespondEarly{HTTP.Response{200, Nil{}, Nil{}}}))

# Dead httpxn.head_keep: the live go helper keeps old on trailer, new else.
def t_keep.fresh(kept_status: U32, fresh: HTTP.Head) -> U32:
  match fresh:
    case HTTP.Head{status, headers}:
      b2u(Bool.and(U32.is_eq(kept_status, 200), U32.is_eq(status, 404)))

def t_keep.go(kept: HTTP.Head, fresh: HTTP.Head) -> U32:
  match kept:
    case HTTP.Head{status, headers}:
      t_keep.fresh(status, fresh)

def t_keep() -> U32:
  t_keep.go(HTTP2.httpxn.head_keep_go(HTTP.Head{200, Nil{}}, HTTP.Head{404, Nil{}}, True{}), HTTP2.httpxn.head_keep_go(HTTP.Head{200, Nil{}}, HTTP.Head{404, Nil{}}, False{}))

# Dead httpxc.body_of + client.on.st_h2: sid ledger + next sid + has_head.
def t_clst() -> U32:
  st: HTTP.St = HTTP.St{None{}, Nil{}, 7, 0}
  b2u(Bool.and(Bool.and(U32.is_eq(HTTP2.httpx.sid_of(st), 7), U32.is_eq(HTTP2.client.on.next_sid(1), 3)), HTTP2.client.on.has_head(HTTP.Head{200, Nil{}})))

# Dead httpxc.resp_of via live twin client.on.resp_of: status rides through.
def t_respof.go(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{status, headers, body}:
      b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_len32(body), 2)))

def t_respof() -> U32:
  t_respof.go(HTTP2.client.on.resp_of(HTTP.Head{200, Nil{}}, [1, 2]))

# Dead x_hdr.indexed.go/num: the live indexed route (x_hdr.dec -> dyn.num)
# still answers a static index and a dynamic index (RFC 7541 section 6.1).
def t_indexed.got(r: Result<&1, &1, U32 & String, HTTP.HdrGot>, wn: String, wv: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{g}:
      match g:
        case HTTP.HdrGot{name, value, rest, tab}:
          b2u(Bool.and(Bool.and(String.eq(name, wn), String.eq(value, wv)), U32.is_eq(HTTP.x_len32(rest), 0)))

def t_indexed.static() -> U32:
  t_indexed.got(HTTP2.x_hdr.dec([130], HTTP2.x_tab.empty()), ":method", "GET")

def t_indexed.dyn() -> U32:
  t_indexed.got(HTTP2.x_hdr.dec([190], HTTP2.x_tab.insert(HTTP2.x_tab.empty(), "x-y", "z")), "x-y", "z")

def t_indexed() -> U32:
  (t_indexed.static() * t_indexed.dyn() : U32)

law main:
  U32

def main():
  (t_static() + t_huff() + t_str() + t_req() + t_resp() + t_frame() + t_srvout() + t_keep() + t_clst() + t_respof() + t_indexed() : U32)
#|11
