# lib (lib_httpx_shrink_merges): coverage gate for the merges of TASK-055.
# Each phase replaces defs with one shared def. This test pins the live half
# of each merge, so a wrong cut fails here. Pure, no IO/TLS.
# Each check returns 1. Golden 18.
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# x_pick replaces x_flow_min.pick and x_settings.iw_find: both arms.
def t_pick() -> U32:
  (b2u(U32.is_eq(HTTPX.x_pick(True{}, 7, 9), 7)) * b2u(U32.is_eq(HTTPX.x_pick(False{}, 7, 9), 9)) : U32)

# x_h1.hdr_count.go replaces the two count folds: the needle rides a
# parameter, and the name compare stays case-insensitive (x_h1.eq_ci).
def t_count.hdrs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"content-length", "5"}, HTTPX.Hdr{"host", "a"}, HTTPX.Hdr{"CONTENT-LENGTH", "6"}]

def t_count.cl() -> U32:
  b2u(U32.is_eq(HTTPX.x_h1.cl_count(t_count.hdrs()), 2))

def t_count.host() -> U32:
  b2u(U32.is_eq(HTTPX.x_h1.host_count(t_count.hdrs()), 1))

def t_count() -> U32:
  (t_count.cl() * t_count.host() : U32)

# Phase 6a: one header-list fold (x_h1.hdr_any.go) serves five questions.
# Each entry pins the two arms of its own predicate. A fresh list per call
# keeps the linear value legal. The mixed case in the names pins eq_ci.
def t_folds.hs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"host", ""}, HTTPX.Hdr{"connection", "close"}, HTTPX.Hdr{"transfer-encoding", "chunked"}, HTTPX.Hdr{"content-length", "12"}]

def t_folds.bad() -> U32:
  (b2u(Bool.not(HTTPX.x_h1.bad_hdrs(t_folds.hs()))) * b2u(HTTPX.x_h1.bad_hdrs([HTTPX.Hdr{"x", "a\r\nY: 1"}])) : U32)

def t_folds.close() -> U32:
  (b2u(HTTPX.x_h1.conn_close(t_folds.hs())) * b2u(Bool.not(HTTPX.x_h1.conn_close([HTTPX.Hdr{"host", "a"}]))) : U32)

def t_folds.cl() -> U32:
  (b2u(Bool.not(HTTPX.x_h1.cl_bad(t_folds.hs()))) * b2u(HTTPX.x_h1.cl_bad([HTTPX.Hdr{"Content-Length", "1a"}])) : U32)

def t_folds.host() -> U32:
  (b2u(HTTPX.x_h1.host_empty(t_folds.hs())) * b2u(Bool.not(HTTPX.x_h1.host_empty([HTTPX.Hdr{"Host", "a"}]))) : U32)

def t_folds.te() -> U32:
  (b2u(HTTPX.x_h1.te_any(t_folds.hs())) * b2u(Bool.not(HTTPX.x_h1.te_any([HTTPX.Hdr{"host", "a"}]))) : U32)

# httpxs.resp_from_out replaces the head and data projections: the three
# SrvOut arms.
def t_srvout.resp(resp: HTTPX.Response, want: U32) -> U32:
  match resp:
    case HTTPX.Response{status, headers, body}:
      b2u(U32.is_eq(status, want))

def t_srvout.of(out: HTTPX.SrvOut, want: U32) -> U32:
  t_srvout.resp(HTTPX.httpxs.resp_from_out(out), want)

def t_srvout() -> U32:
  (t_srvout.of(HTTPX.Continue{}, 0) * t_srvout.of(HTTPX.RespondEarly{HTTPX.Response{200, Nil{}, Nil{}}}, 200) * t_srvout.of(HTTPX.Cancel{}, 0) : U32)

# x_wu_ok.empty is List.is_empty: 4 bytes pass, any tail byte fails
# (RFC 9113 section 6.9).
def t_wu() -> U32:
  (b2u(HTTPX.x_wu_ok([0, 0, 0, 1])) * b2u(Bool.not(HTTPX.x_wu_ok([0, 0, 0, 1, 0]))) : U32)

# x_cls.set_ack and httpxn.need_go are x_b2u.
def t_b2u() -> U32:
  (b2u(U32.is_eq(HTTPX.x_b2u(True{}), 1)) * b2u(U32.is_eq(HTTPX.x_b2u(False{}), 0)) : U32)

# client.on.valid_host.put4 and client.on.valid_path.put3 are Bool.not:
# the public validators keep their answer.
def t_valid() -> U32:
  (b2u(HTTPX.client.on.valid_host("example.com")) * b2u(Bool.not(HTTPX.client.on.valid_host("bad host"))) * b2u(HTTPX.client.on.valid_path("/a")) * b2u(Bool.not(HTTPX.client.on.valid_path("/a b"))) : U32)

# httpx.seq_open is Bool.not: sid 0 reads closed, and the sequential lane's
# DATA decision (httpxn.decide_data) still reads the same expression.
def t_seq.open(+sid_a: U32, sid2: U32) -> Bool:
  Bool.and(Bool.not(U32.is_eq(sid_a, 0)), U32.is_eq(sid2, sid_a))

def t_seq.zero() -> U32:
  b2u(U32.is_eq(HTTPX.httpxn.decide_data(t_seq.open(0, 4), 0), 4))

def t_seq.open_end() -> U32:
  b2u(U32.is_eq(HTTPX.httpxn.decide_data(t_seq.open(4, 4), 1), 1))

def t_seq() -> U32:
  (t_seq.zero() * t_seq.open_end() : U32)

# x_huff_empty is List.is_empty: an empty bit list still answers entry 1.
def t_huff() -> U32:
  b2u(U32.is_eq(HTTPX.x_huff_entry(Nil{}), 1))

# Phase 4a: one slot type for both engines. The head rides a tag, so a
# fresh list per check keeps the linear value legal.
def t_slot.req() -> HTTPX.St:
  HTTPX.St{Some{HTTPX.SlotReq{HTTPX.ReqHead{"POST", "/x", Nil{}}}}, Nil{}, 3}

def t_slot.resp() -> HTTPX.St:
  HTTPX.St{Some{HTTPX.SlotResp{HTTPX.Head{200, Nil{}}}}, Nil{}, 5}

def t_slot.slots() -> List<&2, HTTPX.St>:
  [HTTPX.St{None{}, Nil{}, 1}, t_slot.req()]

# Phase 4b: the client twins are gone; the httpxn walkers serve both lanes.
def t_slot.has() -> U32:
  (b2u(HTTPX.httpxn.has(t_slot.slots(), 3)) * b2u(Bool.not(HTTPX.httpxn.has(t_slot.slots(), 7))) : U32)

def t_slot.has_some() -> U32:
  (b2u(HTTPX.httpxn.has_some(t_slot.slots(), 1)) * b2u(Bool.not(HTTPX.httpxn.has_some(t_slot.slots(), 3))) : U32)

def t_slot.del_put() -> U32:
  (b2u(Bool.not(HTTPX.httpxn.has(HTTPX.httpxn.del(t_slot.slots(), 1), 1))) * b2u(HTTPX.httpxn.has(HTTPX.httpxn.put(t_slot.slots(), HTTPX.St{None{}, Nil{}, 7}), 7)) : U32)

def t_slot.take_st(p: HTTPX.Taken) -> U32:
  b2u(U32.is_eq(HTTPX.httpx.sid_of(HTTPX.httpxn.taken_st(p)), 3))

def t_slot.take() -> U32:
  (t_slot.take_st(HTTPX.httpxn.take_del(t_slot.slots(), 3)) * b2u(Bool.not(HTTPX.httpxn.has(HTTPX.httpxn.taken_slots(HTTPX.httpxn.take_del(t_slot.slots(), 3)), 3))) : U32)

# The two lane builders read their own tag; a foreign tag answers empty.
def t_slot.reqof(req: HTTPX.Request) -> U32:
  match req:
    case HTTPX.Request{method, path, headers, body}:
      b2u(Bool.and(String.eq(method, "POST"), String.eq(path, "/x")))

def t_slot.respof(resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{status, headers, body}:
      b2u(U32.is_eq(status, 200))

def t_slot.req_empty(req: HTTPX.Request) -> U32:
  match req:
    case HTTPX.Request{method, path, headers, body}:
      b2u(Bool.and(String.is_empty(method), String.is_empty(path)))

def t_slot.build() -> U32:
  (t_slot.reqof(HTTPX.httpx.req_of_st(t_slot.req(), [1])) * t_slot.respof(HTTPX.httpxc.req_of_st(t_slot.resp(), [1])) * t_slot.req_empty(HTTPX.httpx.req_of_st(t_slot.resp(), [1])) : U32)

law main:
  U32

def main():
  (t_pick() + t_count() + t_folds.bad() + t_folds.close() + t_folds.cl() + t_folds.host() + t_folds.te() + t_srvout() + t_wu() + t_b2u() + t_valid() + t_seq() + t_huff() + t_slot.has() + t_slot.has_some() + t_slot.del_put() + t_slot.take() + t_slot.build() : U32)
#|18
