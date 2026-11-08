# io (httpx_h2_clist_cw): the sequential exchange stores the window the
# loop has left in the CliSt (task-063 phase 7c).
#
# The send of the next request seeds from `CliSt.cw`. Before this change
# the fold of the loop answer kept the next sid and the HPACK table but
# dropped the window, so every request on a keep-alive connection started
# from 65535 again. A peer whose credit lags then sees the second body
# pass its window.
#
# Checks: the fold keeps the window, advances the sid by two, and a second
# fold keeps working on the answer of the first. Golden 3.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def CW() -> U32:
  12345

def CW1() -> U32:
  (CW() + 100 : U32)

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def st_new() -> HTTP.CliSt:
  HTTP.CliSt{1, HTTP2.x_tab.empty(), True{}, 65535}

def main() -> IO(U32):
  do IO<U32>:
    +st : HTTP.CliSt = st_new()
    +st2 : HTTP.CliSt = HTTP2.client.loop.st_after(st, HTTP2.x_tab.empty(), CW())
    +st3 : HTTP.CliSt = HTTP2.client.loop.st_after(st2, HTTP2.x_tab.empty(), CW1())
    +kept : Bool = U32.is_eq(HTTP2.client.loop.st_cw(st2), CW())
    +sid : Bool = U32.is_eq(HTTP2.client.loop.st_sid(st2), 3)
    +next : Bool = Bool.and(U32.is_eq(HTTP2.client.loop.st_cw(st3), CW1()), U32.is_eq(HTTP2.client.loop.st_sid(st3), 5))
    +score : U32 = U32.add(b2u(kept), U32.add(b2u(sid), b2u(next)))
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    IO.pure(U32, score)

#|3
