# io (http2_seed_pad): o seed do pump mantem o PADDED de DATA.
#
# DATA guarda o padding no payload. O credito usa o comprimento
# declarado. O seed gravava os flags sem o bit PADDED. O leitor via um
# corpo com padding. O seed agora mantem o bit para o tipo 0. HEADERS
# continua sem o bit, porque o payload ja sai sem padding.
#
# Pontos: o bit no seed de DATA, o tamanho do corpo, o corpo, HEADERS
# sem o bit, x_f_seed nos dois tipos. Golden 6.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Corpo de 3 octetos com 2 de padding: o octeto de comprimento, o corpo,
# depois o padding.
def pad_pay() -> List<&2, U32>:
  [2, 1, 2, 3, 0, 0]

def got_unit(out: HTTP.UnitOut) -> List<&2, U32>:
  match out:
    case HTTP.Got{+unit, fin, +rest}:
      unit
    case HTTP.Bad{+code, +msg}:
      Nil{}
    case HTTP.NeedMore{+missing, +rest}:
      Nil{}
    case HTTP.End{+rest}:
      Nil{}

def frame_flags(f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      flags

def frame_pay(f: HTTP.Frame) -> List<&2, U32>:
  match f:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      payload

def main() -> IO(U32):
  do IO<U32>:
    +seed : List<&2, U32> = HTTP2.x_flow.seed_add(Nil{}, 0, 8, 3, pad_pay(), Nil{})
    +fr : HTTP.Frame = HTTP2.x_frame_of(got_unit(HTTP2.x_parse(seed)))
    +fl : U32 = frame_flags(fr)
    +body : List<&2, U32> = HTTP2.x_data_body(frame_pay(fr), fl)
    +hseed : List<&2, U32> = HTTP2.x_flow.seed_add(Nil{}, 1, 8, 3, [7], Nil{})
    +hfl : U32 = frame_flags(HTTP2.x_frame_of(got_unit(HTTP2.x_parse(hseed))))
    a : U32 = b2u(U32.is_eq(U32.and(fl, 8), 8))
    b : U32 = b2u(U32.is_eq(HTTP.x_len32(body), 3))
    c : U32 = b2u(U32.is_eq(HTTP.x_eq(body, [1, 2, 3]), 1))
    d : U32 = b2u(U32.is_eq(hfl, 0))
    e : U32 = b2u(U32.is_eq(HTTP2.x_f_seed(0, 8), 8))
    f : U32 = b2u(U32.is_eq(HTTP2.x_f_seed(1, 8), 0))
    +total : U32 = (a + b + c + d + e + f : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|6
