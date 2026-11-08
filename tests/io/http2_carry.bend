# io (httpx_h2_carry): the sender routes and the Got-carried read buffer,
# pure checks (task-042 phase 2e).
#
# The flow sender's read seed (TASK-042 phase 2b/2e) is delivered to the
# server loops inside the Got: httpx.sent_seed puts `buf ++ seed` in the
# synthetic Got and phase 0 reads through httpx.carry. The rule that makes
# it safe is subtle and easy to break: a Got that carries no bytes must
# fall back to the loop's own leftover (the ack/ping leaves answer with an
# empty Got, and the leftover there can hold a request HEADERS already
# received), while a Got that carries bytes wins (the stash from a
# response send, which came later on the wire). x_flow.route picks between
# stopping the send, stashing the frame and handling it in place.
#
# Score: one point per check, golden 8.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def list_ok(got: List<&2, U32>, +want: List<&2, U32>) -> U32:
  b2u(U32.is_eq(HTTP.x_eq(got, want), 1))

# The synthetic Got the response sender builds: no frame, bytes in buf.
def synth(+b: List<&2, U32>) -> HTTP.Got:
  HTTP.GotOk{HTTP.Frame{0, 0, 0, 0, Nil{}}, b}

def route_ok(+typ: U32, +sid29: U32, +sid: U32, +cls: U32, +want: U32) -> U32:
  b2u(U32.is_eq(HTTP2.x_flow.route(typ, sid29, sid, cls), want))

def main() -> IO(U32):
  do IO<U32>:
    # 1. a Got that carries bytes wins (the stash of a response send).
    a : U32 = list_ok(HTTP2.httpx.carry(synth([9, 8]), [1, 2]), [9, 8])
    # 2. an empty Got leaves the loop's leftover authoritative (ack/ping).
    b : U32 = list_ok(HTTP2.httpx.carry(synth(Nil{}), [1, 2]), [1, 2])
    # 3. an error Got leaves it too.
    c : U32 = list_ok(HTTP2.httpx.carry(HTTP.GotErr{0, "next"}, [1, 2]), [1, 2])
    # 4. own-stream HEADERS: the send stops (the answer arrived).
    d : U32 = route_ok(1, 5, 5, 0, 13)
    # 5. another stream's HEADERS: stash and keep sending.
    e : U32 = route_ok(1, 5, 7, 0, 14)
    # 6. another stream's DATA: stash too.
    f : U32 = route_ok(0, 5, 7, 0, 14)
    # 7. WINDOW_UPDATE: the sender handles it, nothing to hand back.
    g : U32 = route_ok(8, 0, 7, 2, 12)
    # 8. the seed keeps wire order: accumulated, then the frame, then the
    #    rest of the recv. The count of credited DATA frames travels beside
    #    the seed, so the bytes carry no marker (TASK-068).
    h : U32 = list_ok(HTTP2.x_flow.seed_add([1], 0, 0, 3, [7], [9]), [1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 7, 9])
    # 9. the RST_STREAM of the stream being sent stops it (typed error).
    i : U32 = route_ok(3, 7, 7, 3, 12)
    # 10. a sibling's RST_STREAM is stashed like any foreign frame: the
    #     drain filters it by sid (client.on.stream_cls), the sender must
    #     not fail the upload it is still feeding.
    j : U32 = route_ok(3, 5, 7, 3, 14)
    # 11. GOAWAY is connection-level, never kept.
    k : U32 = route_ok(7, 0, 7, 5, 12)
    +total : U32 = (a + b + c + d + e + f + g + h + i + j + k : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|11
