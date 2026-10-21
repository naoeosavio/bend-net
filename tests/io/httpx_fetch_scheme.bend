# lib (lib_httpx_fetch_scheme): the URL scheme rule of fetch and
# fetch_bytes (task-057 phase 3).
#
# http:// is the plaintext H1 lane, and that lane has no certificate to
# verify. So http:// is only reachable through the insecure entry:
# fetch("http://...") answers 400 "bad scheme" in the URL dispatch, before
# any socket opens. The banner of the fetch block said the opposite until
# phase 3 ("http:// refuses with 400" for both entries), so this test pins
# the live rule.
#
# Pure: the refusal happens before the dial, so the port never answers and
# nothing waits on a peer. Golden 2.
import Base
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The refusal is a 400 whose message names the scheme, never a dial error.
# The port 1 is closed, so a dial would answer another code.
def is_bad_scheme(e: U32 & String) -> U32:
  match e:
    case (+code, msg):
      b2u(Bool.and(U32.is_eq(code, 400), String.eq(msg, "bad scheme")))

def score_text(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      is_bad_scheme(e)
    case Done{_}:
      0

def score_bytes(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      is_bad_scheme(e)
    case Done{_}:
      0

# fetch on an http:// URL answers the scheme refusal.
def chk_fetch() -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch("http://127.0.0.1:1/x")
    IO.pure(U32, score_text(r))

# fetch_bytes answers the same way: one dispatch, two decoders.
def chk_bytes() -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      HTTPX.fetch_bytes("http://127.0.0.1:1/x")
    IO.pure(U32, score_bytes(r))

def main() -> IO(Unit):
  do IO<Unit>:
    +a : U32 <- chk_fetch()
    +b : U32 <- chk_bytes()
    x : Unit <- IO.print(U32.show((a + b : U32)))
    return x

#|2
