# HPACK dynamic table unit (RFC 7541 section 2.3/section 4, C.3 sizes):
# insert sizing (57, 110), newest-first lookup, eviction to max,
# oversize empties, out-of-bounds fails. Pure layer, no IO.
# Golden 11111111.
import Base
import ../../lib/http2.bend as H2

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

def tab_size(+tab: H2.HpDyn) -> U32:
  match tab:
    case H2.HpDyn{+ents, +size, +max}:
      size

def pair_ok.go(r: Result<&1, &1, U32 & String, H2.H2Hdr>, +wn: String, +wv: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{h}:
      match h:
        case H2.H2Hdr{+n, +v}:
          b2u(Bool.and(String.eq(n, wn), String.eq(v, wv)))

def pair_ok(+tab: H2.HpDyn, +idx: U32, +wn: String, +wv: String) -> U32:
  pair_ok.go(H2.hp_lookup(tab, idx), wn, wv)

def trim_size(+tab: H2.HpDyn, +max: U32) -> U32:
  match tab:
    case H2.HpDyn{+ents, +size, +old}:
      tab_size(H2.hp_insert.trim(ents, size, max))

def over_size(+tab: H2.HpDyn, +name: String, +value: String) -> U32:
  match tab:
    case H2.HpDyn{+ents, +size, +max}:
      tab_size(H2.hp_insert.fit(ents, size, max, name, value, False{}))

def dyn_fail.go(r: Result<&1, &1, U32 & String, H2.H2Hdr>) -> U32:
  match r:
    case Fail{e}:
      1
    case Done{h}:
      0

def bounds_ok(+tab: H2.HpDyn, +idx: U32) -> U32:
  dyn_fail.go(H2.hp_lookup(tab, idx))

law main:
  U32

def main():
  +t1 = H2.hp_insert(H2.hp_empty(), ":authority", "www.example.com")
  +t2 = H2.hp_insert(t1, "cache-control", "no-cache")
  +a = b2u(U32.is_eq(tab_size(t1), 57))
  +b = pair_ok(t1, 0, ":authority", "www.example.com")
  +c = pair_ok(t2, 0, "cache-control", "no-cache")
  +d = b2u(U32.is_eq(tab_size(t2), 110))
  +e = pair_ok(t2, 1, ":authority", "www.example.com")
  +f = b2u(U32.is_eq(trim_size(t2, 60), 53))
  +g = b2u(U32.is_eq(over_size(t2, "x", "y"), 0))
  +h = bounds_ok(t2, 5)
  (a * 10000000 + b * 1000000 + c * 100000 + d * 10000 + e * 1000 + f * 100 + g * 10 + h : U32)

#|11111111
