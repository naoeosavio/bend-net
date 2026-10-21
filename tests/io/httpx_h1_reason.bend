# io (httpx_h1_reason): the H1 reason phrase table.
#
# x_h1.reason writes the words of the status line, so the table is wire
# output: "HTTP/1.1 400 Bad Request". task-057 renamed 2000 type and leaf
# names inside lib/httpx.bend with a script, and a blind one would have
# turned "Bad Request" into "HTTP.Bad Request" on every 400 the server
# sends (D24). This file pins the words so a later rename cannot touch
# them again.
#
# Answers: one per status. Golden 12.
import Base
import ../../lib/http1.bend as HTTP1

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

# The phrase the status line carries is exactly this text.
law chk:
  for +st: U32
  for +want: String
  U32

def chk(st, want):
  b2u(String.eq(HTTP1.x_h1.reason(st), want))

# 101 carries the upgrade words.
law chk_101:
  U32

def chk_101():
  chk(101, "Switching Protocols")

# 200 and the three empty-body statuses.
law chk_2xx:
  U32

def chk_2xx():
  (chk(200, "OK") + chk(204, "No Content") + chk(304, "Not Modified") : U32)

# The 4xx family the server answers on the wire.
law chk_4xx:
  U32

def chk_4xx():
  (chk(400, "Bad Request") + chk(404, "Not Found")
    + chk(411, "Length Required") + chk(413, "Content Too Large")
    + chk(431, "Request Header Fields Too Large") : U32)

# The 5xx family.
law chk_5xx:
  U32

def chk_5xx():
  (chk(500, "Internal Error") + chk(502, "Bad Gateway") : U32)

# A status the table does not know answers an empty phrase.
law chk_unknown:
  U32

def chk_unknown():
  (b2u(String.is_empty(HTTP1.x_h1.reason(418)))
    * b2u(String.is_empty(HTTP1.x_h1.reason(0))) : U32)

law main:
  U32

def main():
  (chk_101() + chk_2xx() + chk_4xx() + chk_5xx() + chk_unknown() : U32)

#|12
