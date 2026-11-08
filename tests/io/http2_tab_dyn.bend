# lib (lib_httpx_tab_dyn): HPACK dynamic table unit (RFC 7541 section 2.3 and
# section 4, C.3 sizes) over the H2 codec in lib/http2.bend: insert sizing (57,
# 110), newest-first lookup, eviction to max, oversize empties the table,
# out-of-bounds fails 502. Pure layer, no IO, so it gates every change in the
# dyn-table cost function. Ported from hpack_dyntab.bend (same RFC vectors,
# same expectations) when the old H2 codec was retired; golden 1 iff all
# vectors score.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def tab_size(tab: HTTP.Tab) -> U32:
  match tab:
    case HTTP.Tab{ents, size, max}:
      size

def hdr_eq(h: HTTP.Hdr, wn: String, wv: String) -> U32:
  match h:
    case HTTP.Hdr{n, v}:
      b2u(Bool.and(String.eq(n, wn), String.eq(v, wv)))

def lookup_t.go(r: Result<&1, &1, U32 & String, HTTP.Hdr>, wn: String, wv: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{h}:
      hdr_eq(h, wn, wv)

def lookup_t(tab: HTTP.Tab, idx: U32, wn: String, wv: String) -> U32:
  lookup_t.go(HTTP2.x_tab.lookup(tab, idx), wn, wv)

def is_fail_hdr(r: Result<&1, &1, U32 & String, HTTP.Hdr>) -> U32:
  match r:
    case Fail{e}:
      1
    case Done{h}:
      0

# One table with the two RFC 7541 C.3.1 entries, 57 + 53 = 110 bytes.

def two_tab() -> HTTP.Tab:
  HTTP2.x_tab.insert(HTTP2.x_tab.insert(HTTP2.x_tab.empty(), ":authority",
    "www.example.com"), "cache-control", "no-cache")

# RFC 7541 C.3.1: ":authority: www.example.com" costs 32 + 10 + 15 = 57.

def v1_size() -> U32:
  b2u(U32.is_eq(tab_size(HTTP2.x_tab.insert(HTTP2.x_tab.empty(), ":authority",
    "www.example.com")), 57))

def v2_size_of_two() -> U32:
  b2u(U32.is_eq(tab_size(two_tab()), 110))

# Index 0 is the newest entry, 1 the one before it (RFC 7541 section 2.3).

def v3_newest_first() -> U32:
  (lookup_t(two_tab(), 0, "cache-control", "no-cache")
    + lookup_t(two_tab(), 1, ":authority", "www.example.com") : U32)

# Eviction: the oldest entry goes first, so trimming 110 down to 60 keeps the
# newest 53-byte entry and drops the older 57-byte one.

def v4_evict(tab: HTTP.Tab) -> U32:
  match tab:
    case HTTP.Tab{ents, size, tmax}:
      b2u(U32.is_eq(tab_size(HTTP2.x_tab.trim(ents, size, 60)), 53))

# An entry that cannot fit empties the table (RFC 7541 section 4.4), forced
# here through the same predicate x_tab.insert uses.

def v5_oversize(tab: HTTP.Tab) -> U32:
  match tab:
    case HTTP.Tab{ents, size, tmax}:
      tab_size(HTTP2.x_tab.ins_fit(ents, size, tmax, "x", "y", False{},
        HTTP2.x_tab.entry_size("x", "y")))

def v6_bounds() -> U32:
  is_fail_hdr(HTTP2.x_tab.lookup(two_tab(), 5))

# entry_size is the cost function both insert and the peer SETTINGS ledger
# depend on, so it is pinned apart from the table walk.

def v7_entry_size() -> U32:
  b2u(U32.is_eq(HTTP2.x_tab.entry_size(":authority", "www.example.com"), 57))

# A resize below one entry empties the table: the path a peer
# SETTINGS_HEADER_TABLE_SIZE update takes.

def v8_resize(tab: HTTP.Tab) -> U32:
  +small = HTTP2.x_tab.resize(tab, 0)
  (b2u(U32.is_eq(tab_size(small), 0))
    + b2u(U32.is_eq(lookup_t(small, 0, ":authority", "www.example.com"), 0)) : U32)

# Three inserts keep newest-first order across the whole walk.

def v9_order(tab: HTTP.Tab) -> U32:
  +t3 = HTTP2.x_tab.insert(HTTP2.x_tab.insert(tab, "x-a", "1"), "x-b", "2")
  (lookup_t(t3, 0, "x-b", "2") + lookup_t(t3, 1, "x-a", "1")
    + lookup_t(t3, 2, ":authority", "www.example.com") : U32)

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 = (v1_size() + v2_size_of_two() + v3_newest_first()
      + v4_evict(two_tab()) + v5_oversize(two_tab()) + v6_bounds()
      + v7_entry_size() + v8_resize(two_tab())
      + v9_order(HTTP2.x_tab.insert(HTTP2.x_tab.empty(), ":authority",
        "www.example.com")) : U32)
    +pass : U32 = b2u(U32.is_eq(total, 12))
    w : Unit <- IO.print(U32.show(pass))
    z : Unit <- IO.die(Unit, 0, "")
    return pass

#|1
