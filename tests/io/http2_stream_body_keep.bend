# lib (httpx_h2_stream_body_keep): the stream form keeps no request body
# (task-066 phase 3).
#
# The shared DATA act 0 appended every chunk to the slot for both forms,
# so the "flat" stream lane held the whole body: a 16 MiB upload to the
# stream form measured 407 MB of RSS before the fix. The act now calls
# server.data_slots, which gates the append on the form: the buffered
# form keeps the reversed body and its byte count, and the stream form
# keeps the head only. The four points are the two form halves: the
# buffered body after one frame, the buffered count after two frames, the
# empty stream body and the zero stream count.
#
# Golden 4.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def CHUNK() -> List<&2, U32>:
  [1, 2, 3, 4]

def LEN() -> U32:
  4

def SID() -> U32:
  1

def slots0() -> List<&2, HTTP.St>:
  [HTTP.St{Some{HTTP.SlotReq{HTTP.ReqHead{"POST", "/x", Nil{}}}}, Nil{}, SID(), 0}]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def body_len(slots: List<&2, HTTP.St>) -> U32:
  HTTP.x_len32(HTTP2.httpx.body_of(HTTP2.ledger.taken_st(HTTP2.ledger.take_del(slots, SID()))))

# The buffered form: one frame keeps its bytes and counts them, the
# second adds both.
def buffered_bits() -> U32:
  +s1 : List<&2, HTTP.St> = HTTP2.server.data_slots(0, slots0(), SID(), CHUNK(), LEN())
  +s2 : List<&2, HTTP.St> = HTTP2.server.data_slots(0, s1, SID(), CHUNK(), LEN())
  +len1 : U32 = HTTP.x_len32(HTTP2.httpx.body_of(HTTP2.ledger.taken_st(HTTP2.ledger.take_del(s1, SID()))))
  +n2 : U32 = HTTP2.ledger.n_of(s2, SID())
  U32.add(weigh(U32.is_eq(len1, LEN()), 1), weigh(U32.is_eq(n2, U32.mul(2, LEN())), 1))

# The stream form: no bytes and no count reach the slot.
def stream_bits() -> U32:
  +t1 : List<&2, HTTP.St> = HTTP2.server.data_slots(1, slots0(), SID(), CHUNK(), LEN())
  +len1 : U32 = body_len(t1)
  +n1 : U32 = HTTP2.ledger.n_of(t1, SID())
  U32.add(weigh(U32.is_eq(len1, 0), 1), weigh(U32.is_eq(n1, 0), 1))

def main() -> IO(U32):
  do IO<U32>:
    +score : U32 = U32.add(buffered_bits(), stream_bits())
    x : Unit <- IO.print(U32.show(score))
    IO.pure(U32, score)

#|4
