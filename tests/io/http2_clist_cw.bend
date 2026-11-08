# io (httpx_h2_clist_cw): the sequential exchange stores the window the
# loop has left and the peer size it read in the CliSt (task-063 phase 7c,
# task-068 phase 7).
#
# The send of the next request seeds from `CliSt.cw`. Before task-063 the
# fold of the loop answer kept the next sid and the HPACK table but dropped
# the window, so every request on a keep-alive connection started from
# 65535 again. A peer whose credit lags then sees the second body pass its
# window. The send also seeds the stream window from `CliSt.piw`, the peer
# INITIAL_WINDOW_SIZE. Before task-068 the fold dropped that value too, so
# every upload started from the RFC default.
#
# Checks: the fold keeps the window, the fold keeps the peer size, the
# sid advances by two, and a second fold keeps working on the answer of
# the first. Golden 5.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def CW() -> U32:
  12345

def CW1() -> U32:
  (CW() + 100 : U32)

def PIW() -> U32:
  1024

def PIW1() -> U32:
  (PIW() + 100 : U32)

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def st_new() -> HTTP.CliSt:
  HTTP.CliSt{1, HTTP2.x_tab.empty(), True{}, 65535, PIW()}

def main() -> IO(U32):
  do IO<U32>:
    +st : HTTP.CliSt = st_new()
    +st2 : HTTP.CliSt = HTTP2.client.loop.st_after(st, HTTP2.x_tab.empty(), CW(), PIW1())
    +st3 : HTTP.CliSt = HTTP2.client.loop.st_after(st2, HTTP2.x_tab.empty(), CW1(), PIW())
    +kept : Bool = U32.is_eq(HTTP2.client.loop.st_cw(st2), CW())
    +peer : Bool = U32.is_eq(HTTP2.client.loop.st_piw(st2), PIW1())
    +sid : Bool = U32.is_eq(HTTP2.client.loop.st_sid(st2), 3)
    +next : Bool = Bool.and(U32.is_eq(HTTP2.client.loop.st_cw(st3), CW1()), U32.is_eq(HTTP2.client.loop.st_sid(st3), 5))
    +back : Bool = U32.is_eq(HTTP2.client.loop.st_piw(st3), PIW())
    +score : U32 = U32.add(b2u(kept), U32.add(b2u(peer), U32.add(b2u(sid), U32.add(b2u(next), b2u(back)))))
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    IO.pure(U32, score)

#|5
