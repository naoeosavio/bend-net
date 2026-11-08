# Micro-bench of the hot list walks of lib/http2.bend, on the test.bend
# shape: 5 runs, average with min/max spread, checksum per variant.
#   bend examples/httpx/bench_h2.bend [elements]
# Elements default to 1 MiB; use 262144 for a quick run.
# Every sender variant builds the same DATA frames, so the checksum is
# n bytes plus the 9-byte header of each frame.
#   send_take_drop   today: take32 + drop32 per 16 KiB turn, then write
#   send_chunks      HTTP2.x_chunks split outside the timer, then pop
#   send_chunks_e2e  HTTP2.x_chunks split inside the timer, then pop
#   send_chunks_td   take32/drop32 split inside the timer (loses, kept)
#   strip_eager      x_data_body today: x_len32(payload) even when unpadded
#   strip_lazy       branch on the PADDED flag first, no length walk
#   wu_each          receive credit before 6b: a pair of frames per DATA frame
#   wu_batch         shipped credit: one step per frame, flush at the half
#   probe_all        the single-frame question before phase 8: x_len32
#   probe_cap        shipped: x_len_upto stops at x_max_send + 1
import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as HTTP2

def RUNS() -> Nat:
  5n

def SIZE() -> U32:
  1048576

def MAX_SEND() -> U32:
  16384

# Bytes a DATA frame adds in front of the payload.
def FRAME_HDR() -> U32:
  9

# The payload of one DATA frame of the credit rows.
def FLEN() -> U32:
  16384

def CHECK_WIDTH() -> Nat:
  22n

def dots(n: Nat) -> String:
  match n:
    case 0n:
      ""
    case 1n+p:
      String.append(".", dots(p))

def pad_name(+name: String) -> String:
  String.append(name, dots(Nat.sub(CHECK_WIDTH(), String.length(name))))

def show_check(name: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(pad_name(name) ++ " ok")
    case False{}:
      IO.print(pad_name(name) ++ " FAIL")

@unsafe
def build_flat(n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      build_flat((n - 1 : U32), 97 <> acc)

def min2_go(le: Bool, +a: U32, +b: U32) -> U32:
  match le:
    case True{}:
      a
    case False{}:
      b

def min2(+a: U32, +b: U32) -> U32:
  min2_go(U32.is_le(a, b), a, b)

def refill_go(eq: Bool, +cw: U32, +chunk: U32) -> U32:
  match eq:
    case True{}:
      MAX_SEND()
    case False{}:
      (cw - chunk : U32)

def refill(+cw: U32, +chunk: U32) -> U32:
  refill_go(U32.is_eq(cw, chunk), cw, chunk)

# DATA frames a body of n bytes needs: one per x_max_send() slice.
def nchunks(+n: U32) -> U32:
  U32.div(U32.add(n, (MAX_SEND() - 1 : U32)), MAX_SEND())

# Checksum of one sender run: the payload bytes plus one header per frame,
# plus the head walk each chunk pays twice (one per frame, one to cap it).
def want_send(+n: U32) -> U32:
  U32.mul(U32.add(U32.add(n, n), U32.mul(FRAME_HDR(), nchunks(n))), U32.from_nat(RUNS()))

# --- sender: take/drop per turn, then write (reference) --------------

@unsafe
def send_td(+cw: U32, +body: List<&2, U32>, +sent: U32) -> U32:
  match body:
    case Nil{}:
      sent
    case _:
      +chunk = min2(cw, HTTP.x_len_upto(MAX_SEND(), body))
      +frame = HTTP2.x_frame_write(0, 0, 0, HTTP.x_take32(chunk, body))
      send_td(refill(cw, chunk), HTTP.x_drop32(chunk, body), (sent + HTTP.x_len32(frame) + chunk : U32))

# --- sender: chunks built once, then pop one and write ---------------
# The pump measures the head to cap the chunk, so the walk is part of the
# shape: one run sums the frame bytes plus one head walk per chunk.

@unsafe
def send_ch(+chunks: List<&2, List<&2, U32>>, +sent: U32) -> U32:
  match chunks:
    case Nil{}:
      sent
    case +h <> t:
      +blen = HTTP.x_len32(h)
      +frame = HTTP2.x_frame_write(0, 0, 0, h)
      send_ch(t, (sent + HTTP.x_len32(frame) + blen : U32))

@unsafe
def send_chunks_e2e(+body: List<&2, U32>, +sent: U32) -> U32:
  send_ch(HTTP2.x_chunks(body), sent)

# --- sender: take32/drop32 split, timed like the shipped one --------
# Four passes per chunk: length, copy, reverse, drop. Kept for the
# comparison with HTTP2.x_chunks.

@unsafe
def split_td_go(+body: List<&2, U32>, acc: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match body:
    case Nil{}:
      List.reverse(&2, List<&2, U32>, acc)
    case _:
      +n = HTTP.x_len_upto(MAX_SEND(), body)
      split_td_go(HTTP.x_drop32(n, body), HTTP.x_take32(n, body) <> acc)

@unsafe
def send_chunks_td(+body: List<&2, U32>, +sent: U32) -> U32:
  send_ch(split_td_go(body, Nil{}), sent)

# --- receiver: x_data_body eager vs lazy -----------------------------

def strip_eager(+payload: List<&2, U32>) -> List<&2, U32>:
  HTTP2.x_strip_pad(payload, False{}, HTTP.x_len32(payload))

def strip_lazy_go(padded: Bool, +payload: List<&2, U32>) -> List<&2, U32>:
  match padded:
    case False{}:
      payload
    case True{}:
      HTTP2.x_strip_pad(payload, True{}, HTTP.x_len32(payload))

def strip_lazy(+payload: List<&2, U32>) -> List<&2, U32>:
  strip_lazy_go(False{}, payload)

@unsafe
def strip_count_lazy(n: U32, +frame: List<&2, U32>) -> U32:
  match n:
    case 0:
      0
    case _:
      (HTTP.x_len32(strip_lazy(frame)) + strip_count_lazy((n - 1 : U32), frame) : U32)

@unsafe
def strip_count(n: U32, +frame: List<&2, U32>) -> U32:
  match n:
    case 0:
      0
    case _:
      (HTTP.x_len32(strip_eager(frame)) + strip_count((n - 1 : U32), frame) : U32)

# The bytes each credit row writes: the old shape writes 13 bytes twice
# per DATA frame, the batch writes 13 bytes per pair and one frame at the
# end (an even frame count leaves 819 for 64 frames).
def wu_want_each(+n: U32) -> U32:
  U32.mul(U32.mul(2, nchunks(n)), 13)

def wu_want_batch(+n: U32) -> U32:
  U32.mul(U32.sub(nchunks(n), 1), 13)

# --- receive credit: one pair per DATA frame against the batch --------
# The old shape built both frames and wrote them on every DATA frame.
# The shipped shape adds the length to the batch and builds the frames
# only when a window reaches the half.

def wu_each_go(+n: Nat, +sent: U32) -> U32:
  match n:
    case 0n:
      sent
    case 1n+m:
      +b : List<&2, U32> = List.append(&2, U32, HTTP2.x_wu_frame(0, FLEN()), HTTP2.x_wu_frame(1, FLEN()))
      wu_each_go(m, (sent + HTTP.x_len32(b) : U32))

def wu_batch_go(+n: Nat, +cpend: U32, +spend: List<&2, HTTP2.Pnd>, +sent: U32) -> U32:
  match n:
    case 0n:
      (sent + cpend : U32)
    case 1n+m:
      +fin : Bool = Nat.is_eq(m, 0n)
      +b : List<&2, U32> = HTTP2.x_wu.bytes(cpend, spend, 1, FLEN(), fin)
      wu_batch_go(m, HTTP2.x_wu.next_cpend(cpend, FLEN(), fin), HTTP2.x_wu.next_spend(spend, 1, FLEN(), fin), (sent + HTTP.x_len32(b) : U32))

def wu_each(+n: U32) -> U32:
  wu_each_go(U32.to_nat(n), 0)

def wu_batch(+n: U32) -> U32:
  wu_batch_go(U32.to_nat(n), 0, Nil{}, 0)

# The old single-frame question: the whole body for its length.
def probe_all(xs: List<&2, U32>) -> U32:
  HTTP.x_len32(xs)

# The shipped probe: the walk stops at x_send_probe, the smaller of the
# cap and the caller window plus one (task-063 phase 7d and phase 8).
def probe_cap(xs: List<&2, U32>) -> U32:
  HTTP.x_len_upto(HTTP2.x_send_probe(HTTP2.x_init_window()), xs)

@unsafe
def sample(tag: U32, +xs: List<&2, U32>, +chunks: List<&2, List<&2, U32>>, +frame: List<&2, U32>) -> U32:
  match tag:
    case 0:
      send_td(MAX_SEND(), xs, 0)
    case 1:
      send_ch(chunks, 0)
    case 2:
      send_chunks_e2e(xs, 0)
    case 3:
      send_chunks_td(xs, 0)
    case 4:
      strip_count(32, frame)
    case 5:
      strip_count_lazy(32, frame)
    case 6:
      wu_each(nchunks(HTTP.x_len32(xs)))
    case 7:
      wu_batch(nchunks(HTTP.x_len32(xs)))
    case 8:
      probe_all(xs)
    case _:
      probe_cap(xs)

def fold_go(+el: Nat, mn: Nat, rest: Nat & Nat) -> Nat & (Nat & Nat):
  match rest:
    case (mx, tot):
      (Nat.min(el, mn), (Nat.max(el, mx), (el + tot : Nat)))

def fold_el(el: Nat, st: Nat & (Nat & Nat)) -> Nat & (Nat & Nat):
  match st:
    case (mn, rest):
      fold_go(el, mn, rest)

def timed(fuel: Nat, +tag: U32, +xs: List<&2, U32>, +chunks: List<&2, List<&2, U32>>, +frame: List<&2, U32>, msst: Nat & (Nat & Nat), chk: U32) ->
  IO((Nat & (Nat & Nat)) & U32):
  match fuel:
    case 0n:
      IO.pure((Nat & (Nat & Nat)) & U32, (msst, chk))
    case 1n+f:
      do IO<((Nat & (Nat & Nat)) & U32)>:
        t0 : Nat <- IO.now()
        total : U32 = sample(tag, xs, chunks, frame)
        t1 : Nat <- IO.now()
        +el : Nat = Nat.sub(t1, t0)
        timed(f, tag, xs, chunks, frame, fold_el(el, msst), (chk + total : U32))

def show_stats_go(name: String, mn: Nat, rest: Nat & Nat) -> IO(Unit):
  match rest:
    case (mx, tot):
      +avg : Nat = Nat.div(tot, RUNS())
      IO.print(pad_name(name) ++ " avg=" ++ Nat.show(avg) ++ "ms -" ++ Nat.show(Nat.sub(avg, mn)) ++ " +" ++ Nat.show(Nat.sub(mx, avg)))

def show_stats(name: String, st: Nat & (Nat & Nat)) -> IO(Unit):
  match st:
    case (mn, rest):
      show_stats_go(name, mn, rest)

def report(+name: String, want: U32, res: (Nat & (Nat & Nat)) & U32) -> IO(Unit):
  match res:
    case (msst, chk):
      do IO<Unit>:
        show_stats(name, msst)
        show_check(String.append("chk_", name), U32.is_eq(chk, want))

def bench(+n: U32, +xs: List<&2, U32>, +frame: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    +chunks : List<&2, List<&2, U32>> = HTTP2.x_chunks(xs)
    +want : U32 = want_send(n)
    r0 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 0, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r1 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 1, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r2 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 2, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r3 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 3, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r4 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 4, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r5 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 5, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r6 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 6, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r7 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 7, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r8 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 8, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    r9 : (Nat & (Nat & Nat)) & U32 <- timed(RUNS(), 9, xs, chunks, frame, (600000n, (0n, 0n)), 0)
    a : Unit <- report("send_take_drop", want, r0)
    b : Unit <- report("send_chunks", want, r1)
    c : Unit <- report("send_chunks_e2e", want, r2)
    d : Unit <- report("send_chunks_td", want, r3)
    e : Unit <- report("strip_eager", (MAX_SEND() * 32 * U32.from_nat(RUNS()) : U32), r4)
    f : Unit <- report("strip_lazy", (MAX_SEND() * 32 * U32.from_nat(RUNS()) : U32), r5)
    g : Unit <- report("wu_each", (wu_want_each(n) * U32.from_nat(RUNS()) : U32), r6)
    h : Unit <- report("wu_batch", (wu_want_batch(n) * U32.from_nat(RUNS()) : U32), r7)
    i : Unit <- report("probe_all", (n * U32.from_nat(RUNS()) : U32), r8)
    j : Unit <- report("probe_cap", ((MAX_SEND() + 1 : U32) * U32.from_nat(RUNS()) : U32), r9)
    IO.pure(Unit, j)

def u32_go(m: Maybe<&2, U32>, +dflt: U32) -> U32:
  match m:
    case None{}:
      dflt
    case Some{v}:
      v

def size_of(xs: List<String>, +dflt: U32) -> U32:
  match xs:
    case Nil{}:
      dflt
    case +h <> t:
      u32_go(U32.read(h), dflt)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    +n : U32 = size_of(args, SIZE())
    +xs : List<&2, U32> = build_flat(n, Nil{})
    +frame : List<&2, U32> = HTTP.x_take32(MAX_SEND(), xs)
    IO.print("n=" ++ U32.show(n) ++ " runs=" ++ Nat.show(RUNS()))
    bench(n, xs, frame)

# Measured at 1 MiB, 5 runs, on a loaded 8-core box: send_take_drop
# 671-748ms, send_chunks 170-202ms, send_chunks_e2e 364-458ms,
# send_chunks_td 650-852ms, strip_eager 55-177ms, strip_lazy 21-58ms.
# The load moves the absolute number more than the ratio: the shipped
# split sender is 1.6-1.8x the old take/drop sender, and the per-byte
# split is 1.7-1.9x the take32/drop32 split. send_chunks leaves the
# split out of the timer, so it is the floor and not a sender number.
# Each sender row pays one length walk per chunk and one frame write,
# the two passes the pump makes per turn.
