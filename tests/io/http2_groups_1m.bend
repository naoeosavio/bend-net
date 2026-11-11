# io (http2_groups_1m): bench de 1M dos grupos otimizados via test.bend
# (x_huff, x_tab, x_wu, x_flow, x_strip, x_frame, x_block, x_req,
# x_win, x_chunks, x_settings, x_pdc, ledger). Cada grupo constrói a
# entrada fora do relógio e mede uma passada; o total é a soma dos
# checksums e vale de golden. Sem golden por grupo: o relógio varia
# por máquina, o checksum não.
# Golden 12094293.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def B1M() -> Nat:
  1000000n

def B125K() -> Nat:
  125000n

def H1M() -> Nat:
  1000000n

def HBLK() -> Nat:
  200000n

def P99() -> Nat:
  999999n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bytes_go(n: Nat, +v: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      bytes_go(p, v, v <> acc)

def bytes(n: Nat, +v: U32) -> List<&2, U32>:
  bytes_go(n, v, Nil{})

def hdr_go(n: Nat, acc: List<&2, HTTP.Hdr>) -> List<&2, HTTP.Hdr>:
  match n:
    case 0n:
      acc
    case 1n+p:
      hdr_go(p, HTTP.Hdr{"x", "y"} <> acc)

def hdrs(n: Nat) -> List<&2, HTTP.Hdr>:
  hdr_go(n, Nil{})

def hlen_go(xs: List<&2, HTTP.Hdr>, acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case _ <> t:
      hlen_go(t, (acc + 1 : U32))

def hlen(xs: List<&2, HTTP.Hdr>) -> U32:
  hlen_go(xs, 0)

def pnds_go(n: Nat, acc: List<&2, HTTP2.Pnd>) -> List<&2, HTTP2.Pnd>:
  match n:
    case 0n:
      acc
    case 1n+p:
      pnds_go(p, HTTP2.Pnd{0, 1} <> acc)

def pnds(n: Nat) -> List<&2, HTTP2.Pnd>:
  pnds_go(n, Nil{})

def plen_go(xs: List<&2, HTTP2.Pnd>, acc: U32) -> U32:
  match xs:
    case Nil{}:
      acc
    case _ <> t:
      plen_go(t, (acc + 1 : U32))

def plen(xs: List<&2, HTTP2.Pnd>) -> U32:
  plen_go(xs, 0)

def slots_go(n: Nat, acc: List<&2, HTTP.St>) -> List<&2, HTTP.St>:
  match n:
    case 0n:
      acc
    case 1n+p:
      slots_go(p, HTTP.St{None{}, Nil{}, 0, 1} <> acc)

def slots(n: Nat) -> List<&2, HTTP.St>:
  slots_go(n, Nil{})

def slen_go(xs: List<&2, HTTP.St>, acc: Nat) -> Nat:
  match xs:
    case Nil{}:
      acc
    case _ <> t:
      slen_go(t, (1n + acc : Nat))

def slen(xs: List<&2, HTTP.St>) -> Nat:
  slen_go(xs, 0n)

def found_hdr(r: Result<&1, &1, U32 & String, HTTP.Hdr>) -> Bool:
  match r:
    case Fail{e}:
      False{}
    case Done{h}:
      True{}

def lookup_ok(+xs: List<&2, HTTP.Hdr>) -> U32:
  b2u(found_hdr(HTTP2.x_tab.lookup.got(xs, 999999)))

def enc_go(n: Nat, +k: U32, acc: U32) -> U32:
  match n:
    case 0n:
      acc
    case 1n+p:
      +e : List<&2, U32> = HTTP2.x_int.enc(0, k)
      enc_go(p, (k + 1 : U32), (acc + HTTP.x_len32(e) : U32))

def win_go(n: Nat, +w: U32) -> U32:
  match n:
    case 0n:
      w
    case 1n+p:
      win_go(p, HTTP2.x_win_add(w, 1))

def chunks_stat_go(xs: List<&2, List<&2, U32>>, n: U32, sum: U32) -> U32 & U32:
  match xs:
    case Nil{}:
      (n, sum)
    case h <> t:
      chunks_stat_go(t, (n + 1 : U32), (sum + HTTP.x_len32(h) : U32))

def chunks_chk(st: U32 & U32) -> U32:
  match st:
    case (n, s):
      (n + b2u(U32.is_eq(s, 1000000)) : U32)

def frame_ok(f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{typ, flags, sid, len, payload}:
      +a : U32 = b2u(U32.is_eq(HTTP.x_len32(payload), 999991))
      +b : U32 = b2u(U32.is_eq(len, 0))
      (a * b : U32)

def ledger_chk_slots(+xs: List<&2, HTTP.St>) -> U32:
  +a : U32 = b2u(U32.is_eq(HTTP2.ledger.n_of(xs, 0), 1))
  +b : U32 = b2u(Bool.not(HTTP2.ledger.has_some(xs, 1)))
  +c : U32 = b2u(Nat.is_eq(slen(HTTP2.ledger.del(xs, 1)), 1000000n))
  +taken_p : HTTP.Taken = HTTP2.ledger.take_del(xs, 0)
  +taken : List<&2, HTTP.St> = HTTP2.ledger.taken_slots(taken_p)
  +d : U32 = b2u(Nat.is_eq(slen(taken), 999999n))
  (a + b + c + d : U32)

def ledger_chk_fends(+xs: List<&2, U32>) -> U32:
  +a : U32 = b2u(U32.is_eq(HTTP.x_len32(HTTP2.ledger.fdel(xs, 0)), 1000000))
  +p : HTTP.FendTaken = HTTP2.ledger.fdel_flag(xs, 0)
  +l : U32 = HTTP.x_len32(HTTP2.ledger.ftaken_fends(p))
  +f : U32 = HTTP2.ledger.ftaken_flag(p)
  +b : U32 = b2u(Bool.and(U32.is_eq(l, 1000000), U32.is_eq(f, 0)))
  (a + b : U32)

def t_huff_bits() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +xs : List<&2, U32> = bytes(B125K(), 7)
    t0 : Nat <- IO.now()
    +out : List<&2, U32> = HTTP2.x_huff_bits(xs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, HTTP.x_len32(out)))

def t_huff_ones() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +xs : List<&2, U32> = bytes(B1M(), 1)
    t0 : Nat <- IO.now()
    +ok : Bool = HTTP2.x_huff_ones(xs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, b2u(ok)))

def t_int_enc() -> IO(Nat & U32):
  do IO<Nat & U32>:
    t0 : Nat <- IO.now()
    +c : U32 = enc_go(B1M(), 0, 0)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, c))

def t_tab_rev() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +xs : List<&2, HTTP.Hdr> = hdrs(H1M())
    t0 : Nat <- IO.now()
    +ys : List<&2, HTTP.Hdr> = HTTP2.x_tab.rev(xs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, hlen(ys)))

def t_tab_lookup() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +xs : List<&2, HTTP.Hdr> = hdrs(H1M())
    t0 : Nat <- IO.now()
    +c : U32 = lookup_ok(xs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, c))

def t_wu() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +xs1 : List<&2, HTTP2.Pnd> = pnds(H1M())
    +xs2 : List<&2, HTTP2.Pnd> = pnds(H1M())
    t0 : Nat <- IO.now()
    +a : U32 = HTTP2.x_wu.of(xs1, 0)
    +ys : List<&2, HTTP2.Pnd> = HTTP2.x_wu.del(xs2, 1)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, (a + b2u(U32.is_eq(plen(ys), 1000000)) : U32)))

def t_flow_join() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +a : List<&2, U32> = bytes(500000n, 1)
    +b : List<&2, U32> = bytes(500000n, 2)
    t0 : Nat <- IO.now()
    +out : List<&2, U32> = HTTP2.x_flow_join(a, b)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, HTTP.x_len32(out)))

def t_strip() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +pay : List<&2, U32> = bytes(B1M(), 0)
    t0 : Nat <- IO.now()
    +out : List<&2, U32> = HTTP2.x_strip_pad(pay, True{}, 1000000)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, HTTP.x_len32(out)))

def t_frame() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +unit : List<&2, U32> = bytes(B1M(), 0)
    t0 : Nat <- IO.now()
    +f : HTTP.Frame = HTTP2.x_frame_of(unit)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, frame_ok(f)))

def t_block() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +hs : List<&2, HTTP.Hdr> = hdrs(HBLK())
    t0 : Nat <- IO.now()
    +out : List<&2, U32> = HTTP2.x_block(hs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, HTTP.x_len32(out)))

def t_req_strip() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +hs : List<&2, HTTP.Hdr> = hdrs(H1M())
    t0 : Nat <- IO.now()
    +out : List<&2, HTTP.Hdr> = HTTP2.x_req.strip(hs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, hlen(out)))

def t_req_check() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +hs : List<&2, HTTP.Hdr> = hdrs(H1M())
    t0 : Nat <- IO.now()
    +bad : Bool = HTTP2.x_req.check(hs, "GET")
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, b2u(bad)))

def t_req_nof() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +hs : List<&2, HTTP.Hdr> = hdrs(H1M())
    t0 : Nat <- IO.now()
    +n : U32 = HTTP2.x_req.n_of("x", hs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, n))

def t_win() -> IO(Nat & U32):
  do IO<Nat & U32>:
    t0 : Nat <- IO.now()
    +w : U32 = win_go(B1M(), 0)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, w))

def t_chunks() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +body : List<&2, U32> = bytes(B1M(), 0)
    t0 : Nat <- IO.now()
    +xs : List<&2, List<&2, U32>> = HTTP2.x_chunks(62n, body)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    +chk : U32 = chunks_chk(chunks_stat_go(xs, 0, 0))
    IO.pure(Nat & U32, (ms, chk))

def t_settings() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +pay : List<&2, U32> = bytes(B1M(), 0)
    t0 : Nat <- IO.now()
    +b : U32 = HTTP2.x_settings.bad(pay)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, b2u(U32.is_eq(b, 0))))

def t_pdc() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +pay : List<&2, U32> = bytes(P99(), 0)
    t0 : Nat <- IO.now()
    +c : U32 = HTTP2.x_pdc.count(pay)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, c))

def t_ledger() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +ss : List<&2, HTTP.St> = slots(H1M())
    +fs : List<&2, U32> = bytes(H1M(), 9)
    t0 : Nat <- IO.now()
    +c1 : U32 = ledger_chk_slots(ss)
    +c2 : U32 = ledger_chk_fends(fs)
    t1 : Nat <- IO.now()
    ms : Nat = Nat.sub(t1, t0)
    IO.pure(Nat & U32, (ms, (c1 + c2 : U32)))

def show(name: String, p: Nat & U32) -> IO(U32):
  match p:
    case (+ms, +chk):
      do IO<U32>:
        x : Unit <- IO.print(name ++ " ms=" ++ Nat.show(ms) ++ " chk=" ++ U32.show(chk))
        IO.pure(U32, chk)

def main() -> IO(U32):
  do IO<U32>:
    p01 : Nat & U32 <- t_huff_bits()
    c01 : U32 <- show("huff_bits", p01)
    p02 : Nat & U32 <- t_huff_ones()
    c02 : U32 <- show("huff_ones", p02)
    p03 : Nat & U32 <- t_int_enc()
    c03 : U32 <- show("int_enc", p03)
    p04 : Nat & U32 <- t_tab_rev()
    c04 : U32 <- show("tab_rev", p04)
    p05 : Nat & U32 <- t_tab_lookup()
    c05 : U32 <- show("tab_lookup", p05)
    p06 : Nat & U32 <- t_wu()
    c06 : U32 <- show("wu", p06)
    p07 : Nat & U32 <- t_flow_join()
    c07 : U32 <- show("flow_join", p07)
    p08 : Nat & U32 <- t_strip()
    c08 : U32 <- show("strip", p08)
    p09 : Nat & U32 <- t_frame()
    c09 : U32 <- show("frame", p09)
    p10 : Nat & U32 <- t_block()
    c10 : U32 <- show("block", p10)
    p11 : Nat & U32 <- t_req_strip()
    c11 : U32 <- show("req_strip", p11)
    p12 : Nat & U32 <- t_req_check()
    c12 : U32 <- show("req_check", p12)
    p13 : Nat & U32 <- t_req_nof()
    c13 : U32 <- show("req_nof", p13)
    p14 : Nat & U32 <- t_win()
    c14 : U32 <- show("win", p14)
    p15 : Nat & U32 <- t_chunks()
    c15 : U32 <- show("chunks", p15)
    p16 : Nat & U32 <- t_settings()
    c16 : U32 <- show("settings", p16)
    p17 : Nat & U32 <- t_pdc()
    c17 : U32 <- show("pdc", p17)
    p18 : Nat & U32 <- t_ledger()
    c18 : U32 <- show("ledger", p18)
    +total : U32 = (c01 + c02 + c03 + c04 + c05 + c06 + c07 + c08 + c09 + c10 + c11 + c12 + c13 + c14 + c15 + c16 + c17 + c18 : U32)
    y : Unit <- IO.print(U32.show(total))
    IO.pure(U32, total)

#|12094293
