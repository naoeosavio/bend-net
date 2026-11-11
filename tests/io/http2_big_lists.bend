# io (http2_big_lists): as listas sem teto do H2 com 1M de elementos.
# O teste cobre slots, fends, SETTINGS, seed de frames e chunks.
# Cada laço é de cauda: o teste não pode estourar a pilha.
# Golden 14.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def build_go(n: Nat, +v: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      build_go(p, v, v <> acc)

def build(n: Nat, +v: U32) -> List<&2, U32>:
  build_go(n, v, Nil{})

def st_len_go(xs: List<&2, HTTP.St>, acc: Nat) -> Nat:
  match xs:
    case Nil{}:
      acc
    case _ <> t:
      st_len_go(t, (1n + acc : Nat))

def st_len(xs: List<&2, HTTP.St>) -> Nat:
  st_len_go(xs, 0n)

# Esta função constrói 1M de slots com n = 1 e sid = 0.
def slots_go(n: Nat, acc: List<&2, HTTP.St>) -> List<&2, HTTP.St>:
  match n:
    case 0n:
      acc
    case 1n+p:
      slots_go(p, HTTP.St{None{}, Nil{}, 0, 1} <> acc)

def slots() -> List<&2, HTTP.St>:
  slots_go(1000000n, Nil{})

# Esta função confere os quatro laços de slots.
def check_slots() -> U32:
  +xs : List<&2, HTTP.St> = slots()
  +a : U32 = b2u(U32.is_eq(HTTP2.ledger.n_of(xs, 0), 1))
  +b : U32 = b2u(Bool.not(HTTP2.ledger.has_some(xs, 1)))
  +c : U32 = b2u(Nat.is_eq(st_len(HTTP2.ledger.del(xs, 1)), 1000000n))
  +taken_p : HTTP.Taken = HTTP2.ledger.take_del(xs, 0)
  +taken : List<&2, HTTP.St> = HTTP2.ledger.taken_slots(taken_p)
  +d : U32 = b2u(Nat.is_eq(st_len(taken), 999999n))
  (a + b + c + d : U32)

# Esta função confere os dois laços de fends.
def check_fends() -> U32:
  +xs : List<&2, U32> = build(1000000n, 1)
  +a : U32 = b2u(U32.is_eq(HTTP.x_len32(HTTP2.ledger.fdel(xs, 0)), 1000000))
  +p : HTTP.FendTaken = HTTP2.ledger.fdel_flag(xs, 0)
  +l : U32 = HTTP.x_len32(HTTP2.ledger.ftaken_fends(p))
  +f : U32 = HTTP2.ledger.ftaken_flag(p)
  +b : U32 = b2u(Bool.and(U32.is_eq(l, 1000000), U32.is_eq(f, 0)))
  (a + b : U32)

# Esta função confere o laço de SETTINGS com 1M de octetos.
def check_settings() -> U32:
  +xs : List<&2, U32> = build(1000000n, 0)
  b2u(U32.is_eq(HTTP2.x_settings.bad(xs), 0))

# Esta função confere o laço de frames do seed com 111111 frames.
def check_pdc() -> U32:
  +xs : List<&2, U32> = build(999999n, 0)
  b2u(U32.is_eq(HTTP2.x_pdc.count(xs), 111111))

# Esta função soma e conta os chunks de 1M de octetos.
def chunks_go(chunks: List<&2, List<&2, U32>>, n: Nat, sum: Nat) -> Nat & Nat:
  match chunks:
    case Nil{}:
      (n, sum)
    case h <> t:
      chunks_go(t, (1n + n : Nat), Nat.add(sum, U32.to_nat(HTTP.x_len32(h))))

def chunks_ok(p: Nat & Nat) -> U32:
  match p:
    case (n, sum):
      (b2u(Nat.is_eq(n, 62n)) + b2u(Nat.is_eq(sum, 1000000n)) : U32)

def check_chunks() -> U32:
  +body : List<&2, U32> = build(1000000n, 0)
  p : Nat & Nat = chunks_go(HTTP2.x_chunks(62n, body), 0n, 0n)
  chunks_ok(p)

def pnd_len_go(xs: List<&2, HTTP2.Pnd>, acc: Nat) -> Nat:
  match xs:
    case Nil{}:
      acc
    case _ <> t:
      pnd_len_go(t, (1n + acc : Nat))

def pnd_len(xs: List<&2, HTTP2.Pnd>) -> Nat:
  pnd_len_go(xs, 0n)

def wu_go(n: Nat, acc: List<&2, HTTP2.Pnd>) -> List<&2, HTTP2.Pnd>:
  match n:
    case 0n:
      acc
    case 1n+p:
      wu_go(p, HTTP2.Pnd{0, 1} <> acc)

# Esta função confere os dois laços de WINDOW_UPDATE.
def check_wu() -> U32:
  +xs : List<&2, HTTP2.Pnd> = wu_go(1000000n, Nil{})
  +a : U32 = b2u(U32.is_eq(HTTP2.x_wu.of(xs, 0), 1))
  +b : U32 = b2u(Nat.is_eq(pnd_len(HTTP2.x_wu.del(xs, 1)), 1000000n))
  (a + b : U32)

# Esta função confere o strip de 1M de octetos com padding.
def check_strip() -> U32:
  +pay : List<&2, U32> = build(1000000n, 0)
  b2u(U32.is_eq(HTTP.x_len32(HTTP2.x_strip_pad(pay, True{}, 1000000)), 999999))

def frame_ok(f: HTTP.Frame) -> U32:
  match f:
    case HTTP.Frame{typ, flags, sid, len, payload}:
      +a : U32 = b2u(U32.is_eq(HTTP.x_len32(payload), 999991))
      +b : U32 = b2u(U32.is_eq(len, 0))
      (a * b : U32)

# Esta função confere o parse de um frame de 1M de octetos.
def check_frame() -> U32:
  +unit : List<&2, U32> = build(1000000n, 0)
  frame_ok(HTTP2.x_frame_of(unit))

def main() -> IO(U32):
  do IO<U32>:
    +a : U32 = check_slots()
    +b : U32 = check_fends()
    +c : U32 = check_settings()
    +d : U32 = check_pdc()
    +e : U32 = check_chunks()
    +f : U32 = check_wu()
    +g : U32 = check_strip()
    +h : U32 = check_frame()
    +total : U32 = (a + b + c + d + e + f + g + h : U32)
    u : Unit <- IO.print(U32.show(total))
    IO.pure(U32, total)

#|14
