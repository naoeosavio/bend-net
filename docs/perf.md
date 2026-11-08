# Orçamento de desempenho do H2

Data: 2026-11-07. Box: AMD Ryzen 7 5800H, 8 núcleos, Linux. Compilador:
`bend` 2.0.27. Os números são a média de 5 execuções no mesmo box, em ms
por MiB, com o mínimo e o máximo medidos ao lado.

O orçamento é um teto, não uma meta. Ele fica em 2x `recv_turn` (169) e
2x `send_chunks` (173): 338 e 346 ms por MiB. O teste
`tests/io/http2_perf.bend` mede as formas `recv` e `send` e falha quando
uma passa do teto. Um box mais lento falha o teste de propósito: o portão
mostra o número novo em vez de esconder uma regressão.

## Os artefatos

Cada linha nomeia o artefato que a produziu. Sem isso o número não vale.

| Linha | Artefato | Medida |
|---|---|---|
| `send_take_drop` | `bend examples/httpx/bench_h2.bend` | 671 ms/MiB, -174 +229 |
| `send_chunks` | o mesmo | 173 ms/MiB, -41 +84 |
| `send_chunks_td` | o mesmo | 761 ms/MiB, -196 +169 |
| `strip_eager` | o mesmo | 57 ms/MiB, -12 +12 |
| `strip_lazy` | o mesmo | 22 ms/MiB, -1 +1 |
| `wu_each` | o mesmo | 0 ms/MiB |
| `wu_batch` | o mesmo | 0 ms/MiB |
| `probe_all` | o mesmo | 95 ms/MiB, -4 +4 |
| `probe_cap` | o mesmo | 2 ms/MiB |
| `write_walk` | o mesmo | 133 ms/MiB, -34 +42 |
| `write_len` | o mesmo | 44 ms/MiB, -3 +10 |
| `write_framed` | o mesmo | 68 ms/MiB, -25 +54 |
| `recv_turn` | o mesmo | 169 ms/MiB, -41 +38 |
| `recv` | `bend tests/io/http2_perf.bend` | 206 ms/MiB |
| `send` | o mesmo | 199 ms/MiB |

O `bench_h2` constrói o corpo fora do relógio e mede uma passada. O
`http2_perf` constrói o corpo fora do relógio e mede 64 `turn`s de 16384
bytes, ou um `x_chunks` de 64 pedaços. A diferença de cerca de 20% entre
`recv_turn` e `recv` é o laço e a soma de controle do teste.

## O que cada linha mede

- `send_take_drop`: `x_take32` mais `x_drop32` por virada de 16 KiB, o
  envio antes da task-067.
- `send_chunks`: o `x_chunks` entregue hoje, com o corte fora do relógio.
- `send_chunks_td`: o mesmo corte com `take32`/`drop32` dentro do relógio.
  Perdeu; fica como registro.
- `strip_eager`: `x_data_body` antes da task-068, com `x_len32` em todo
  payload.
- `strip_lazy`: o `x_data_body` entregue hoje, que só anda o payload
  quando o bit PADDED está ligado.
- `wu_each`: o crédito de recepção antes da task-063 fase 6b, dois frames
  por frame de DATA.
- `wu_batch`: o crédito entregue hoje, um passo por frame com descarga na
  metade da janela.
- `probe_all`: a pergunta de quadro único antes da task-068 fase 8.
- `probe_cap`: `x_len_upto` para em `x_max_send() + 1`.
- `write_walk`, `write_len`, `write_framed`: as três formas de escrever um
  frame de DATA.
- `recv_turn`: uma virada de recepção de um frame de DATA: montar, ler,
  fatiar, tirar o padding e rotear.
- `recv` e `send`: as duas formas que o teste do portão mede, com a soma
  de controle dentro do relógio.

## O uso

O H2 deste módulo é plano de controle, não CDN. Ele serve cabeçalhos,
streams curtos, negociação e caminhos de controle com dezenas de KB. Um
corpo grande passa pelo lane de stream, que segura um pedaço por vez.
Para corpo grande o node é cerca de 10x mais rápido, e a task-063 mede
isso.

O número que importa para o porteiro é a virada de recepção e o corte do
envio, porque os dois rodam por frame. Um frame de 16384 bytes custa 169 /
64 = 2,6 ms por MiB dividido em 16 KiB. Um pedido de controle de 4 KiB
custa menos de 1 ms.
