# io (http2_huff_big): bloco grande de Huffman e cauda de enchimento.
# O bloco de 3500 octetos zero decodifica para 5600 símbolos `48`.
# A medida cobre a regressão quadrática do `x_huff_pad` (TASK-074).
# O teste cronometra uma decodificação. O teste exige menos de 1500 ms.
# Sete vetores cobrem o enchimento curto e longo. Golden 11.
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Esta função constrói uma lista uniforme com cauda.
def build_go(n: Nat, +v: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      build_go(p, v, v <> acc)

# Esta função retorna uma lista com n cópias de v.
def build(n: Nat, +v: U32) -> List<&2, U32>:
  build_go(n, v, Nil{})

# Esta função retorna o primeiro octeto ou zero.
def first_go(+xs: List<&2, U32>) -> U32:
  match xs:
    case Nil{}:
      0
    case b <> t:
      b

# Esta função confere o bloco: 5600 octetos `0` e o comprimento.
def big_len_go(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+bs}:
      +want : String = String.repeat("0", 5600n)
      +n : U32 = HTTP.x_len32(bs)
      +s : String = HTTP.x_bytes_str(bs)
      +ok : Bool = Bool.and(U32.is_eq(n, 5600), String.eq(s, want))
      (b2u(ok) * 5600 : U32)

# Esta função decodifica o bloco grande com o fio H2.
def big_len() -> U32:
  big_len_go(HTTP2.x_huff_decode(build(3500n, 0)))

# Esta função decodifica o bloco grande com a fachada.
def big_len_x() -> U32:
  big_len_go(HTTPX.x_huff_decode(build(3500n, 0)))

# Esta função retorna o primeiro símbolo do resultado.
def big_first_go(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{bs}:
      first_go(bs)

# Esta função lê o primeiro símbolo com o fio H2.
def big_first() -> U32:
  big_first_go(HTTP2.x_huff_decode(build(3500n, 0)))

# Esta função verifica o enchimento curto com uns.
def pad_short_ok() -> U32:
  b2u(HTTP2.x_huff_pad([1, 1, 1]))

# Esta função rejeita a cauda curta sem uns.
def pad_short_bad() -> U32:
  b2u(Bool.not(HTTP2.x_huff_pad([1, 0])))

# Esta função aceita sete uns como enchimento.
def pad_seven() -> U32:
  b2u(HTTP2.x_huff_pad([1, 1, 1, 1, 1, 1, 1]))

# Esta função rejeita oito uns como enchimento.
def pad_eight() -> U32:
  b2u(Bool.not(HTTP2.x_huff_pad([1, 1, 1, 1, 1, 1, 1, 1])))

# Esta função rejeita a cauda longa como enchimento.
def pad_long() -> U32:
  b2u(Bool.not(HTTP2.x_huff_pad(build(100n, 0))))

# Esta função confere o símbolo e o enchimento.
def pad_after_go(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{bs}:
      b2u(String.eq(HTTP.x_bytes_str(bs), "0"))

# Esta função decodifica um símbolo com três uns de enchimento.
def pad_after() -> U32:
  pad_after_go(HTTP2.x_huff_decode([7]))

# Esta função rejeita três zeros como enchimento.
def pad_zero_go(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      1
    case Done{bs}:
      0

# Esta função decodifica um símbolo com três zeros de cauda.
def pad_zero() -> U32:
  pad_zero_go(HTTP2.x_huff_decode([0]))

# Esta função soma os vetores puros do bloco e do enchimento.
def pure_total() -> U32:
  (pad_short_ok() + pad_short_bad() + pad_seven() + pad_eight() + pad_long()
    + pad_after() + pad_zero()
    + b2u(U32.is_eq(big_len(), 5600)) + b2u(U32.is_eq(big_first(), 48))
    + b2u(U32.is_eq(big_len_x(), 5600)) : U32)

# Esta função cronometra uma decodificação do bloco grande.
def timed() -> IO(Nat & U32):
  do IO<Nat & U32>:
    +xs : List<&2, U32> = build(3500n, 0)
    t0 : Nat <- IO.now()
    +n : U32 = big_len_go(HTTP2.x_huff_decode(xs))
    t1 : Nat <- IO.now()
    IO.pure(Nat & U32, (Nat.sub(t1, t0), n))

# Esta função verifica o tempo e o comprimento juntos.
def timed_ok(p: Nat & U32) -> U32:
  match p:
    case (ms, n):
      (b2u(Bool.and(U32.is_eq(n, 5600), Nat.is_le(ms, 1500n))) : U32)

def main() -> IO(U32):
  do IO<U32>:
    +pure : U32 = pure_total()
    p : Nat & U32 <- timed()
    +total : U32 = (pure + timed_ok(p) : U32)
    u : Unit <- IO.print(U32.show(total))
    IO.pure(U32, total)

#|11
