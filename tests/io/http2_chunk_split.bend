# io (httpx_h2_chunk_split): the sender split of a body into DATA
# chunks, pure checks (task-063 phase 4).
#
# x_chunks must hold the body bytes once, in order, in chunks of
# x_max_send() bytes, with the last chunk holding the remainder. The
# flow sender pops one chunk per turn and keeps it whole when the peer
# window covers it, so a wrong boundary or a lost byte corrupts the
# upload silently. The window rule of x_chunk_of is the other half: the
# chunk is the smallest of the two windows and the chunk length.
#
# A split is a batch of `left` chunks: the rest of the body then rides in
# one last chunk, and the pump splits it again when it reaches it. The
# batch keeps the chunk spine at one MiB, so a big body is not copied
# whole (task-063 phase 12). The last cases pin that shape.
#
# Score: one point per check, golden 52.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# A body of n bytes with distinct content, so a reorder or a lost byte
# changes the compared list.
def build_go(+n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      build_go(p, (i + 1 : U32), U32.and(i, 255) <> acc)

def build(+n: U32) -> List<&2, U32>:
  build_go(U32.to_nat(n), 0, Nil{})

def total_go(+chunks: List<&2, List<&2, U32>>, acc: U32) -> U32:
  match chunks:
    case Nil{}:
      acc
    case +h <> t:
      total_go(t, (acc + HTTP.x_len32(h) : U32))

def total(+chunks: List<&2, List<&2, U32>>) -> U32:
  total_go(chunks, 0)

# Every chunk but the last has the cap; the last one holds 1 to cap bytes.
def sizes_go(+chunks: List<&2, List<&2, U32>>) -> Bool:
  match chunks:
    case Nil{}:
      True{}
    case +h <> t:
      match t:
        case Nil{}:
          Bool.and(U32.is_gt(HTTP.x_len32(h), 0), U32.is_le(HTTP.x_len32(h), HTTP2.x_max_send()))
        case _:
          Bool.and(U32.is_eq(HTTP.x_len32(h), HTTP2.x_max_send()), sizes_go(t))

# The chunks a body of n bytes must produce: the ceiling of n over the cap.
def want_chunks(+n: U32) -> Nat:
  Nat.div(Nat.add(U32.to_nat(n), Nat.sub(U32.to_nat(HTTP2.x_max_send()), 1n)), U32.to_nat(HTTP2.x_max_send()))

def case_ok(+n: U32) -> U32:
  +body : List<&2, U32> = build(n)
  +chunks : List<&2, List<&2, U32>> = HTTP2.x_chunks(HTTP2.x_split_all(), body)
  +count : Bool = Nat.is_eq(List.length(&2, List<&2, U32>, chunks), want_chunks(n))
  +bytes : Bool = U32.is_eq(total(chunks), n)
  +order : Bool = U32.is_eq(HTTP.x_eq(List.concat(&2, U32, chunks), body), 1)
  U32.add(b2u(count), U32.add(b2u(bytes), U32.add(b2u(order), b2u(sizes_go(chunks)))))

# The first `left` chunks of a batch are full: a short one there would
# leave a frame on the wire without its bytes.
def head_full_go(+chunks: List<&2, List<&2, U32>>, left: Nat) -> Bool:
  match chunks left:
    case Nil{} _:
      True{}
    case _ 0n:
      True{}
    case +h <> t 1n+p:
      Bool.and(U32.is_eq(HTTP.x_len32(h), HTTP2.x_max_send()), head_full_go(t, p))

# The chunk bytes at their place in the body. A batch rest chunk is longer
# than one frame, and List.concat recurses once per element of its first
# list: a 67232-byte rest chunk died with a machine stack overflow, so the
# compare walks the body with take32/drop32 instead.
def order_go(+chunks: List<&2, List<&2, U32>>, +rest: List<&2, U32>) -> Bool:
  match chunks:
    case Nil{}:
      True{}
    case +h <> t:
      +n : U32 = HTTP.x_len32(h)
      Bool.and(U32.is_eq(HTTP.x_eq(h, HTTP.x_take32(n, rest)), 1), order_go(t, HTTP.x_drop32(n, rest)))

# One batch case: the count, the bytes, the order and the full heads.
def batch_ok(+n: U32, +left: Nat, +want: Nat) -> U32:
  +body : List<&2, U32> = build(n)
  +chunks : List<&2, List<&2, U32>> = HTTP2.x_chunks(left, body)
  +count : Bool = Nat.is_eq(List.length(&2, List<&2, U32>, chunks), want)
  +bytes : Bool = U32.is_eq(total(chunks), n)
  +order : Bool = order_go(chunks, body)
  +head : Bool = head_full_go(chunks, left)
  U32.add(b2u(count), U32.add(b2u(bytes), U32.add(b2u(order), b2u(head))))

# The chunk of one turn: the smallest of the two windows and the length.
def chunk_ok(+cw: U32, +sw: U32, +blen: U32, +want: U32) -> U32:
  b2u(U32.is_eq(HTTP2.x_chunk_of(cw, sw, blen), want))

def main() -> IO(U32):
  do IO<U32>:
    # 1-4. an empty body has no chunk: no DATA frame to send.
    e : U32 = case_ok(0)
    # 5-8. one byte.
    a : U32 = case_ok(1)
    # 9-12. exactly one cap: one full chunk, not two.
    b : U32 = case_ok(HTTP2.x_max_send())
    # 13-16. one cap plus one byte: a cap chunk and a one-byte last chunk.
    c : U32 = case_ok((HTTP2.x_max_send() + 1 : U32))
    # 17-20. two caps: two full chunks, so the last chunk may equal the cap.
    d : U32 = case_ok((HTTP2.x_max_send() * 2 : U32))
    # 21-24. six caps plus 1696 bytes: a short last chunk in a long body.
    f : U32 = case_ok(100000)
    # 25. the stream window caps the chunk.
    g : U32 = chunk_ok(65535, 100, HTTP2.x_max_send(), 100)
    # 26. the connection window caps it too.
    h : U32 = chunk_ok(50, 65535, HTTP2.x_max_send(), 50)
    # 27. a short last chunk goes whole.
    i : U32 = chunk_ok(65535, 65535, 1000, 1000)
    # 28. a full chunk goes whole.
    j : U32 = chunk_ok(65535, 65535, HTTP2.x_max_send(), HTTP2.x_max_send())
    # 29-32. a two-chunk batch of a seven-chunk body: two full heads and
    # the 67232-byte rest as one chunk.
    k : U32 = batch_ok(100000, 2n, 3n)
    # 33-36. no batch at all: the whole body rides as one chunk.
    l : U32 = batch_ok(100000, 0n, 1n)
    # 37-40. the batch ends on a chunk boundary: no rest chunk.
    m : U32 = batch_ok(HTTP2.x_max_send(), 1n, 1n)
    # 41-44. one byte past the batch: a one-byte rest chunk.
    n : U32 = batch_ok((HTTP2.x_max_send() + 1 : U32), 1n, 2n)
    # 45-48. an empty body has no chunk, whatever the batch.
    o : U32 = batch_ok(0, 5n, 0n)
    # 49-52. a batch that ends on the body: three full chunks, no rest.
    p : U32 = batch_ok((HTTP2.x_max_send() * 3 : U32), 3n, 3n)
    +total : U32 = (e + a + b + c + d + f + g + h + i + j + k + l + m + n + o + p : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|52
