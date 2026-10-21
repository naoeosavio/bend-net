# lib (httpx_utf8_frame): UTF-8 text lane + BodyFrame framing carrier
# (task-036 phase 3). Pins the ported x_utf8_* machine (multibyte
# roundtrip, ASCII identity, strict validator) and the x_h1.frame_of
# carrier in its three shapes (length, chunked, absent).
import Base
import ../../lib/http1.bend as HTTP1
import ../../lib/http.bend as HTTP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law eq_bytes:
  for xs: List<&2, U32>
  for ys: List<&2, U32>
  U32

def eq_bytes(xs, ys):
  match xs:
    case Nil{}:
      match ys:
        case Nil{}:
          1
        case _ <> _:
          0
    case h1 <> t1:
      match ys:
        case Nil{}:
          0
        case h2 <> t2:
          (b2u(U32.is_eq(h1, h2)) * eq_bytes(t1, t2) : U32)

# Multibyte encode: é is [195, 169] on the wire.
law chk_encode_multi:
  U32

def chk_encode_multi():
  eq_bytes(HTTP.x_utf8_encode("é"), [195, 169])

# Multibyte decode roundtrips back to é.
law chk_decode_multi:
  U32

def chk_decode_multi():
  b2u(String.eq(HTTP.x_utf8_decode([195, 169]), "é"))

# ASCII is identical through the UTF-8 lane.
law chk_ascii:
  U32

def chk_ascii():
  (b2u(String.eq(HTTP.x_utf8_decode([72, 105]), "Hi"))
    * eq_bytes(HTTP.x_utf8_encode("Hi"), [72, 105]) : U32)

# Strict validator: valid passes, lone continuation and truncation fail.
law chk_ok:
  U32

def chk_ok():
  (b2u(HTTP.x_utf8_ok([72, 105]))
    * b2u(Bool.not(HTTP.x_utf8_ok([128])))
    * b2u(Bool.not(HTTP.x_utf8_ok([195]))) : U32)

law frame_is:
  for f: HTTP.BodyFrame
  for cl: U32
  for ch: Bool
  for nb: Bool
  U32

def frame_is(f, cl, ch, nb):
  match f:
    case HTTP.BodyFrame{c, k, n}:
      (b2u(U32.is_eq(c, cl)) * b2u(Cmp.is_eq(Bool.cmp(k, ch))) * b2u(Cmp.is_eq(Bool.cmp(n, nb))) : U32)

# Length-delimited framing carries the Content-Length.
law chk_frame_cl:
  U32

def chk_frame_cl():
  frame_is(HTTP1.x_h1.frame_of([HTTP.Hdr{"Content-Length", "5"}], "GET", 200), 5, False{}, False{})

# Chunked framing carries the flag, no length.
law chk_frame_chunked:
  U32

def chk_frame_chunked():
  frame_is(HTTP1.x_h1.frame_of([HTTP.Hdr{"Transfer-Encoding", "chunked"}], "POST", 200), 0, True{}, False{})

# HEAD and 204 carry no body at all.
law chk_frame_nobody:
  U32

def chk_frame_nobody():
  (frame_is(HTTP1.x_h1.frame_of(Nil{}, "HEAD", 200), 0, False{}, True{})
    * frame_is(HTTP1.x_h1.frame_of(Nil{}, "GET", 204), 0, False{}, True{}) : U32)

law main:
  U32

def main():
  (chk_encode_multi() + chk_decode_multi() + chk_ascii() + chk_ok() + chk_frame_cl() + chk_frame_chunked() + chk_frame_nobody() : U32)

#|7
