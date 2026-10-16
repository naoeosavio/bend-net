# lib (lib_httpx_shrink_merges): coverage gate for TASK-055 Phase 3.
# Phase 3 replaces 17 defs with 6 and removes 7 Base forks. This test pins
# the live half of each merge, so a wrong cut fails here. Pure, no IO/TLS.
# Each check returns 1. Golden 8.
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

law main:
  U32

def main():
  (t_pick() + t_count() + t_srvout() + t_wu() + t_b2u() + t_valid() + t_seq() + t_huff() : U32)
#|8
