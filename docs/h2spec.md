# h2spec: a conformidade externa do H2

Data: 2026-11-07. Ferramenta: o binário oficial do `h2spec` 2.6.0 (commit
70ac2294). Cliente: `curl` 8.5.0 com nghttp2 1.59.0. Compilador: `bend`
2.0.27 nas duas passagens. Servidor:
`examples/httpx/stress_h2.bend` no modo `ok`, um binário nativo na porta
18960, com o certificado de teste `tests/io/tls_test_cert.pem`.

## Como repetir

```sh
bash tests/conformance/h2spec.sh
```

O script constrói o servidor, o sobe, roda o `h2spec` e compara a lista de
falhas com `tests/conformance/h2spec.expected`. Ele sai 0 quando nenhuma
falha nova aparece. Ele sai 1 quando uma falha não está na lista. Ele sai
2 quando o `h2spec` falta, a porta está ocupada, o servidor não sobe ou
o servidor para no meio das três tentativas. A variável `H2SPEC` aponta o
binário do `h2spec`. Use o binário oficial do release 2.6.0: um binário
construído de fonte mostra falhas falsas (ver "A ferramenta certa"). A
construção leva cerca de 8 minutos. Use uma máquina sem outra carga: o
servidor é Bend puro sobre TLS.

Os passos manuais:

```sh
bend examples/httpx/stress_h2.bend -o /tmp/stress_h2
/tmp/stress_h2 ok &
h2spec -h 127.0.0.1 -p 18960 -t -k --timeout 3
```

O modo `ok` responde 200 com um corpo de 8 octetos. O corpo importa: um
corpo vazio fecha o stream no `HEADERS` e esconde o caminho de `DATA` que
quatro provas do `h2spec` medem. O corpo tem 5 octetos ou mais, porque o
`h2spec` pula a prova 6.9.2.2 abaixo desse tamanho.

Use o binário nativo (`-o <arquivo>` sem `.js`) para a medida de
referência. O lane JS serve as provas desde a correção de task-074. O
`x_huff_pad` varria a cauda de bits a cada símbolo, e o custo era
quadrático. A correção lê a cauda só com menos de 8 bits, e a resposta do
fio não muda.

A medida de 2026-11-10 usou `--timeout 3`. O `.js` deu 146 provas em
1,39 s e 1,51 s. O interpretado deu 146 provas em 1,49 s e 3,30 s. O
grupo `http2/6.10` deu 6 de 6: 0,66 s no `.js` e 0,84 s no interpretado.
A sonda `http2/3.5` passou depois das duas passagens em cada lane.

A tabela plana de task-075 troca as listas canônicas por um `match` e
não muda o fio. O `.js` deu 146 provas em 0,55 s, 0,67 s e 0,56 s. O
grupo `http2/6.10` deu 6 de 6 em 0,084 s.

Em 2026-11-10, 30 passagens completas no servidor da porta 18960 deram
146 de 146. A prova 6.10.5 sozinha deu 1 de 1 em cerca de 0,2 s.

Se a prova 6.10.5 falhar com `Timeout` e a conexão seguinte falhar no
handshake, a máquina estava carregada. O servidor de uma linha não aceita
conexões durante a decodificação. Repita `http2/6.10/5` sozinho. Se a
prova passar em menos de 1 s, o código está correto e a falha foi carga.

## Resultado

A passagem de referência, com o servidor de task-070 (corpo de 2 octetos),
deu 143 provas aprovadas, 1 pulada e 2 falhas. O binário oficial do
`h2spec` 2.6.0 reproduz este número nesta máquina. A prova pulada é a
6.9.2.2 (`Sends a SETTINGS frame for window size to be negative`). O
`h2spec` a pula quando o corpo da resposta tem menos de 5 octetos.

A passagem de task-071 (corpo de 8 octetos) roda a prova 6.9.2.2 e a
aprova. A passagem completa deu 144 provas aprovadas, 0 puladas e 2
falhas. As duas falhas são os desvios aceitos abaixo.

| Servidor | Corpo | Resultado | Falhas |
|---|---|---|---|
| antes da correção | 2 octetos | 143 aprovadas, 1 pulada, 2 falhas | 4.2.3, 5.1.2.1 |
| antes da correção | 8 octetos | 143 aprovadas, 0 puladas, 3 falhas | 4.2.3, 5.1.2.1, 6.9.2.2 |
| com a correção de task-071 | 8 octetos | 144 aprovadas, 0 puladas, 2 falhas | 4.2.3, 5.1.2.1 |
| com a fila de task-072 | 8 octetos | 145 aprovadas, 0 puladas, 1 falha | 4.2.3 |
| com `MAX_FRAME_SIZE` 16384 (task-072 fase 4) | 8 octetos | 146 provas, 0 falhas, grupo a grupo | — |
| com a correção de task-073 | 8 octetos | 146 provas, 0 falhas, duas passagens | — |
| lane JS `.js` (task-074) | 8 octetos | 146 provas, 0 falhas, duas passagens | — |
| lane JS interpretado (task-074) | 8 octetos | 146 provas, 0 falhas, duas passagens | — |
| lane JS com a tabela plana (task-075) | 8 octetos | 146 provas, 0 falhas, três passagens | — |
| leitura única do cabeçalho (task-079) | 8 octetos | 146 provas, 0 falhas | — |

A passagem de 2026-11-11 repetiu o portão depois de task-079. O script
saiu 0 e a lista de desvios continua vazia. A leitura única do cabeçalho
não mudou o fio: o servidor do modo `ok` respondeu as mesmas provas.

As duas falhas da primeira linha e da terceira linha são as mesmas: 4.2.3
e 5.1.2.1. A linha do meio tem uma falha a mais, a 6.9.2.2. Com o corpo de
8 octetos o `h2spec` não pula a prova, e o código sem a correção falha
nela. O corpo de 2 octetos escondia a prova.

Com a fila de task-072 a prova 5.1.2.1 passa. Com o `MAX_FRAME_SIZE`
16384 da fase 4, a prova 4.2.3 passa também. A lista de desvios fica
vazia, e `tests/conformance/h2spec.expected` não tem linha.

A passagem única fecha nesta máquina desde task-073. O defeito do
servidor está fechado (abaixo). A passagem dá 146 provas, 0 falhas.
Duas passagens no mesmo servidor dão o mesmo número, e a sonda
`http2/3.5` passa depois de cada uma. O script da conformidade sai 0.
O lane JS também fecha desde task-074, com `--timeout 3`.

Para comparação, o node v22.23.2 com o mesmo corpo de 8 octetos deu 135
aprovadas, 1 pulada e 10 falhas. O node passa a 4.2.3 e pula a 5.1.2.1.
Nós passamos a 4.2.3 desde a fase 4, passamos a 5.1.2.1 desde a fase 2 e
passamos as 10 falhas do node.

### A prova 6.9.2.2 antes e depois

```text
antes  (corpo de 2 octetos): 3 provas, 2 aprovadas, 1 pulada
depois (corpo de 8 octetos): 3 provas, 3 aprovadas, 0 puladas
```

A pulada escondia um defeito. Com o modo `big 1` (corpo de 1 MiB) a prova
rodava e falhava: `Expected SETTINGS ACK, Actual Timeout`. O lane não
respondia o SETTINGS enquanto um envio esperava crédito. Ele guardava o
frame na semente e só respondia o ACK quando o envio terminava. O node
responde o ACK no caminho de leitura da sessão. O lane agora segue o node.
O teste `tests/io/http2_settings_ack.bend` fixa o fio.

As duas falhas restantes eram desvios aceitos. Cada uma tinha a razão
escrita e um teste que fixa o limite real do módulo. A lista está vazia
desde a fase 4 de task-072.

## A ferramenta certa

Use o binário oficial do release 2.6.0. Um binário construído do mesmo
commit (70ac2294) com Go 1.22 mostra 7 falhas a mais: 6.9.1.1, 6.9.1.2,
6.9.1.3, 6.9.2.1, 6.9.2.2, 6.10.1 e 7.2. O servidor é o mesmo nas duas
medidas. Medido em 2026-11-07 com o servidor de task-070:

| Cliente | Resultado |
|---|---|
| release 2.6.0 | 143 aprovadas, 1 pulada, 2 falhas |
| fonte, Go 1.22 | 137 aprovadas, 0 puladas, 9 falhas |

O portão usa o `h2spec` do `PATH` ou o caminho de `H2SPEC`. A cópia em
`.scratch/h2spec-bin` é o release oficial nesta máquina. task-073 registra
a medida e o motivo.

## O servidor para depois de uma passagem (task-073, fechada)

Um servidor novo servia uma passagem completa. O mesmo servidor não
servia a segunda: as conexões novas recebiam o fechamento antes do
SETTINGS inicial. A prova 3.5.1 falhava com `Connection closed`.

A prova 6.9.1.1 sozinha já deixava o servidor neste estado. A prova
deixa 7 octetos do corpo parados no pump de envio quando o par fecha.

O código C do TLS deixa um erro do OpenSSL na fila da linha de execução
quando o envio falha e o `tls_close` chama `SSL_shutdown`. A fila fica
suja, e o código não a limpa.

O `SSL_get_error` lê a fila antes do estado de espera (OpenSSL 3.0.13,
`ssl/ssl_lib.c`). A leitura seguinte, de uma conexão nova, espera
`WANT_READ` e recebe `SSL_ERROR_SSL` (1). O servidor fecha a conexão
com o código 616 antes do SETTINGS. O `h2spec` mostra
`Connection closed`.

A correção limpa a fila antes de cada `SSL_read`, `SSL_write` e
`SSL_accept`. O portão `tests/conformance/h2spec.sh` fixa o fio: a sonda
`http2/3.5` depois da passagem falhava antes da correção e passa agora.

A prova vive no portão, não em `tests/io`. O twin C do TLS só entra no
binário nativo (`bend file -o`), e um teste de `tests/io` roda no lane
JS, que não tem a fila do OpenSSL.

Medido em 2026-11-09 com o código corrigido: duas passagens completas
no mesmo servidor, 146 provas e 0 falhas em cada uma, e a sonda
`http2/3.5` passa depois das duas.

Antes da correção, a passagem parava no meio em todas as medidas, e a
contagem de falhas variava de 27 a 36. A suíte passava grupo a grupo,
com um servidor novo por grupo: 49 grupos, 0 falhas.

### 4.2.3 Tamanho de HEADERS acima de SETTINGS_MAX_FRAME_SIZE (fechada por task-072 fase 4)

O `h2spec` envia um bloco de cerca de 20 KiB e espera `GOAWAY` 6. O teste
supõe o tamanho padrão de 16384 octetos. O módulo anunciava 65535, então
um frame de 20 KiB era legal e ele respondia.

Desde a fase 4 o módulo anuncia `MAX_FRAME_SIZE` 16384 (`x_max_frame()`)
e recusa o frame com `GOAWAY` 6. A prova passou: `h2spec http2/4.2` deu 3
de 3.

O node v22.23.2 passa esta prova porque anuncia `MAX_FRAME_SIZE` 16384.
Nós anunciamos o mesmo valor e recusamos o frame de 20 KiB.

O teste local é `tests/io/http2_frame_over.bend`: um frame de 16385
octetos responde `GOAWAY` 6. O frame de 16384 octetos ainda passa, e
`tests/io/http2_frame_big.bend` cobre o maior frame aceito.

### 5.1.2.1 Limite de streams simultâneos (fechada por task-072)

O `h2spec` abre `MAX_CONCURRENT_STREAMS` + 1 streams com `END_STREAM` e
com `INITIAL_WINDOW_SIZE` 0, e espera `RST_STREAM` 7 no 129º. O servidor
em buffer respondia e fechava cada stream antes de ler o próximo
`HEADERS`, então nunca havia dois streams abertos ao mesmo tempo.

Desde task-072 o servidor em buffer lê um bloco, admite todos os frames do
bloco antes de responder um, e segura o stream na fila enquanto a resposta
espera. O `INITIAL_WINDOW_SIZE` 0 impede o primeiro envio, então o lote
inteiro chega à admissão e o 129º recebe `RST_STREAM` 7. A prova passou:
`h2spec http2/5.1.2` deu 1 de 1.

O `WINDOW_UPDATE` de stream que chega com a resposta na fila soma na
entrada da fila. Sem isso a prova `generic/2` do `h2spec` falhava: o laço
consumia o `WINDOW_UPDATE`, e o pump de envio não o lia mais.

A prova local é `tests/io/http2_pq_batch.bend`: o lote numa escrita, a
janela zero, o stream cancelado e a concessão de janela.

O node v22.23.2 pula esta prova porque não anuncia
`MAX_CONCURRENT_STREAMS` quando o cap é o padrão. Com
`settings: { maxConcurrentStreams: 100 }` ele passa a prova.

## Falhas corrigidas nesta fase

| Grupo | Falhas | Causa | Correção | Teste |
|---|---|---|---|---|
| generic | 3 | corpo vazio escondia `DATA`; trailer fechava a conexão | modo `ok`; bloco de trailer decodifica e responde | `http2_req_trailers` |
| 4.3, 5.5, 6.2 | 5 | frame fora do bloco de cabeçalho era ignorado | `ledger.st_block` + ato 9 | `http2_dispatch` |
| 5.1, 6.1, 6.2, 6.3, 6.4 | 13 | frame em stream 0, ímpar, ocioso ou fechado era ignorado | tabela `server.cls_*` com `last` | `http2_dispatch` |
| 4.2, 6.3, 6.4, 6.7, 6.9 | 6 | tamanho fixo de PRIORITY, RST_STREAM, PING e WINDOW_UPDATE não era conferido | `x_frame.size_ok` | `http2_dispatch` |
| 5.3.1 | 2 | dependência própria de prioridade era aceita | `x_prio.self` no leitor | `http2_dispatch` |
| 5.4.1 | 1 | PING de tamanho errado era aceito | `x_frame.size_ok` | `http2_settings_size` |
| 6.5.2 | 4 | valor de SETTINGS não era conferido | `x_settings.bad` | `http2_dispatch` |
| 8.1.1, 8.1.2 | 12 | campo de cabeçalho malformado era servido | `x_req.check` | `http2_dispatch` |
| 8.1.2.6 | 3 | `content-length` não era conferido | `x_cl.body_bad` | `http2_req_trailers` |
| 8.1.2 (trailer) | 2 | trailer sem `END_STREAM` era ignorado | ato 14 | `http2_req_trailers` |
| 6.5 (PUSH_PROMISE) | 1 | frame de push era ignorado | ato 9 | `http2_dispatch` |
| 4.3 (HPACK) | 1 | atualização de tabela no fim do bloco era aceita | `x_req.late` | `http2_dispatch` |
| 6.9.1 | 1 | `WINDOW_UPDATE` de stream acima de 2^31-1 era ignorado | `x_win_fits` + ato 15 | `http2_dispatch` |
| 6.9.2.2 (task-071) | 1 | SETTINGS sem ACK durante a espera de crédito | ACK no pump, bit `x_f_settled`, ato 20 | `http2_settings_ack` |
| 5.1.2.1 (task-072) | 1 | resposta fechava o stream antes do próximo `HEADERS` | fila de respostas, leitura em bloco, portão de crédito | `http2_pq_batch` |
| 4.2.3 (task-072 fase 4) | 1 | o anúncio de `MAX_FRAME_SIZE` era 65535, então um frame de 20 KiB era legal | `x_max_frame()` 16384 no anúncio id 5 e no teto de leitura | `http2_frame_over` |

A primeira passagem, antes de qualquer correção, deu 38 falhas em 100
provas; a suíte parava no meio porque um par que fecha depois do
handshake travava o accept (`tests/io/http2_pre_eof.bend`).

## Saída completa (passagem de referência de task-070, bend 2.0.27)

Esta saída é a primeira passagem de referência. Ela mostra as duas falhas
que a lista de desvios tinha antes de task-072. O resultado da passagem de
task-072 está na tabela acima.

```text
Generic tests for HTTP/2 server
  1. Starting HTTP/2
      1: Sends a client connection preface
    ✔ 1: Sends a client connection preface

  2. Streams and Multiplexing
      1: Sends a PRIORITY frame on idle stream
    ✔ 1: Sends a PRIORITY frame on idle stream
      2: Sends a WINDOW_UPDATE frame on half-closed (remote) stream
    ✔ 2: Sends a WINDOW_UPDATE frame on half-closed (remote) stream
      3: Sends a PRIORITY frame on half-closed (remote) stream
    ✔ 3: Sends a PRIORITY frame on half-closed (remote) stream
      4: Sends a RST_STREAM frame on half-closed (remote) stream
    ✔ 4: Sends a RST_STREAM frame on half-closed (remote) stream
      5: Sends a PRIORITY frame on closed stream
    ✔ 5: Sends a PRIORITY frame on closed stream

  3. Frame Definitions
    3.1. DATA
        1: Sends a DATA frame
      ✔ 1: Sends a DATA frame
        2: Sends multiple DATA frames
      ✔ 2: Sends multiple DATA frames
        3: Sends a DATA frame with padding
      ✔ 3: Sends a DATA frame with padding

    3.2. HEADERS
        1: Sends a HEADERS frame
      ✔ 1: Sends a HEADERS frame
        2: Sends a HEADERS frame with padding
      ✔ 2: Sends a HEADERS frame with padding
        3: Sends a HEADERS frame with priority
      ✔ 3: Sends a HEADERS frame with priority

    3.3. PRIORITY
        1: Sends a PRIORITY frame with priority 1
      ✔ 1: Sends a PRIORITY frame with priority 1
        2: Sends a PRIORITY frame with priority 256
      ✔ 2: Sends a PRIORITY frame with priority 256
        3: Sends a PRIORITY frame with stream dependency
      ✔ 3: Sends a PRIORITY frame with stream dependency
        4: Sends a PRIORITY frame with exclusive
      ✔ 4: Sends a PRIORITY frame with exclusive
        5: Sends a PRIORITY frame for an idle stream, then send a HEADER frame for a lower stream ID
      ✔ 5: Sends a PRIORITY frame for an idle stream, then send a HEADER frame for a lower stream ID

    3.4. RST_STREAM
        1: Sends a RST_STREAM frame
      ✔ 1: Sends a RST_STREAM frame

    3.5. SETTINGS
        1: Sends a SETTINGS frame
      ✔ 1: Sends a SETTINGS frame

    3.7. PING
        1: Sends a PING frame
      ✔ 1: Sends a PING frame

    3.8. GOAWAY
        1: Sends a GOAWAY frame
      ✔ 1: Sends a GOAWAY frame

    3.9. WINDOW_UPDATE
        1: Sends a WINDOW_UPDATE frame with stream ID 0
      ✔ 1: Sends a WINDOW_UPDATE frame with stream ID 0
        2: Sends a WINDOW_UPDATE frame with stream ID 1
      ✔ 2: Sends a WINDOW_UPDATE frame with stream ID 1

    3.10. CONTINUATION
        1: Sends a CONTINUATION frame
      ✔ 1: Sends a CONTINUATION frame
        2: Sends multiple CONTINUATION frames
      ✔ 2: Sends multiple CONTINUATION frames

  4. HTTP Message Exchanges
      1: Sends a GET request
    ✔ 1: Sends a GET request
      2: Sends a HEAD request
    ✔ 2: Sends a HEAD request
      3: Sends a POST request
    ✔ 3: Sends a POST request
      4: Sends a POST request with trailers
    ✔ 4: Sends a POST request with trailers

  5. HPACK
      1: Sends a indexed header field representation
    ✔ 1: Sends a indexed header field representation
      2: Sends a literal header field with incremental indexing - indexed name
    ✔ 2: Sends a literal header field with incremental indexing - indexed name
      3: Sends a literal header field with incremental indexing - indexed name (with Huffman coding)
    ✔ 3: Sends a literal header field with incremental indexing - indexed name (with Huffman coding)
      4: Sends a literal header field with incremental indexing - new name
    ✔ 4: Sends a literal header field with incremental indexing - new name
      5: Sends a literal header field with incremental indexing - new name (with Huffman coding)
    ✔ 5: Sends a literal header field with incremental indexing - new name (with Huffman coding)
      6: Sends a literal header field without indexing - indexed name
    ✔ 6: Sends a literal header field without indexing - indexed name
      7: Sends a literal header field without indexing - indexed name (with Huffman coding)
    ✔ 7: Sends a literal header field without indexing - indexed name (with Huffman coding)
      8: Sends a literal header field without indexing - new name
    ✔ 8: Sends a literal header field without indexing - new name
      9: Sends a literal header field without indexing - new name (huffman encoded)
    ✔ 9: Sends a literal header field without indexing - new name (huffman encoded)
      10: Sends a literal header field never indexed - indexed name
    ✔ 10: Sends a literal header field never indexed - indexed name
      11: Sends a literal header field never indexed - indexed name (huffman encoded)
    ✔ 11: Sends a literal header field never indexed - indexed name (huffman encoded)
      12: Sends a literal header field never indexed - new name
    ✔ 12: Sends a literal header field never indexed - new name
      13: Sends a literal header field never indexed - new name (huffman encoded)
    ✔ 13: Sends a literal header field never indexed - new name (huffman encoded)
      14: Sends a dynamic table size update
    ✔ 14: Sends a dynamic table size update
      15: Sends multiple dynamic table size update
    ✔ 15: Sends multiple dynamic table size update

Hypertext Transfer Protocol Version 2 (HTTP/2)
  3. Starting HTTP/2
    3.5. HTTP/2 Connection Preface
        1: Sends client connection preface
      ✔ 1: Sends client connection preface
        2: Sends invalid connection preface
      ✔ 2: Sends invalid connection preface

  4. HTTP Frames
    4.1. Frame Format
        1: Sends a frame with unknown type
      ✔ 1: Sends a frame with unknown type
        2: Sends a frame with undefined flag
      ✔ 2: Sends a frame with undefined flag
        3: Sends a frame with reserved field bit
      ✔ 3: Sends a frame with reserved field bit

    4.2. Frame Size
        1: Sends a DATA frame with 2^14 octets in length
      ✔ 1: Sends a DATA frame with 2^14 octets in length
        2: Sends a large size DATA frame that exceeds the SETTINGS_MAX_FRAME_SIZE
      ✔ 2: Sends a large size DATA frame that exceeds the SETTINGS_MAX_FRAME_SIZE
        3: Sends a large size HEADERS frame that exceeds the SETTINGS_MAX_FRAME_SIZE
      using source address 127.0.0.1:34282
      × 3: Sends a large size HEADERS frame that exceeds the SETTINGS_MAX_FRAME_SIZE
        -> The endpoint MUST respond with a connection error of type FRAME_SIZE_ERROR.
           Expected: GOAWAY Frame (Error Code: FRAME_SIZE_ERROR)
                     Connection closed
             Actual: DATA Frame (length:2, flags:0x01, stream_id:1)

    4.3. Header Compression and Decompression
        1: Sends invalid header block fragment
      ✔ 1: Sends invalid header block fragment
        2: Sends a PRIORITY frame while sending the header blocks
      ✔ 2: Sends a PRIORITY frame while sending the header blocks
        3: Sends a HEADERS frame to another stream while sending the header blocks
      ✔ 3: Sends a HEADERS frame to another stream while sending the header blocks

  5. Streams and Multiplexing
    5.1. Stream States
        1: idle: Sends a DATA frame
      ✔ 1: idle: Sends a DATA frame
        2: idle: Sends a RST_STREAM frame
      ✔ 2: idle: Sends a RST_STREAM frame
        3: idle: Sends a WINDOW_UPDATE frame
      ✔ 3: idle: Sends a WINDOW_UPDATE frame
        4: idle: Sends a CONTINUATION frame
      ✔ 4: idle: Sends a CONTINUATION frame
        5: half closed (remote): Sends a DATA frame
      ✔ 5: half closed (remote): Sends a DATA frame
        6: half closed (remote): Sends a HEADERS frame
      ✔ 6: half closed (remote): Sends a HEADERS frame
        7: half closed (remote): Sends a CONTINUATION frame
      ✔ 7: half closed (remote): Sends a CONTINUATION frame
        8: closed: Sends a DATA frame after sending RST_STREAM frame
      ✔ 8: closed: Sends a DATA frame after sending RST_STREAM frame
        9: closed: Sends a HEADERS frame after sending RST_STREAM frame
      ✔ 9: closed: Sends a HEADERS frame after sending RST_STREAM frame
        10: closed: Sends a CONTINUATION frame after sending RST_STREAM frame
      ✔ 10: closed: Sends a CONTINUATION frame after sending RST_STREAM frame
        11: closed: Sends a DATA frame
      ✔ 11: closed: Sends a DATA frame
        12: closed: Sends a HEADERS frame
      ✔ 12: closed: Sends a HEADERS frame
        13: closed: Sends a CONTINUATION frame
      ✔ 13: closed: Sends a CONTINUATION frame

      5.1.1. Stream Identifiers
          1: Sends even-numbered stream identifier
        ✔ 1: Sends even-numbered stream identifier
          2: Sends stream identifier that is numerically smaller than previous
        ✔ 2: Sends stream identifier that is numerically smaller than previous

      5.1.2. Stream Concurrency
          1: Sends HEADERS frames that causes their advertised concurrent stream limit to be exceeded
        using source address 127.0.0.1:41988
        × 1: Sends HEADERS frames that causes their advertised concurrent stream limit to be exceeded
          -> The endpoint MUST treat this as a stream error of type PROTOCOL_ERROR or REFUSED_STREAM.
             Expected: GOAWAY Frame (Error Code: PROTOCOL_ERROR)
                       RST_STREAM Frame (Error Code: PROTOCOL_ERROR)
                       GOAWAY Frame (Error Code: REFUSED_STREAM)
                       RST_STREAM Frame (Error Code: REFUSED_STREAM)
                       Connection closed
               Actual: HEADERS Frame (length:13, flags:0x04, stream_id:1)

    5.3. Stream Priority
      5.3.1. Stream Dependencies
          1: Sends HEADERS frame that depends on itself
        ✔ 1: Sends HEADERS frame that depends on itself
          2: Sends PRIORITY frame that depend on itself
        ✔ 2: Sends PRIORITY frame that depend on itself

    5.4. Error Handling
      5.4.1. Connection Error Handling
          1: Sends an invalid PING frame for connection close
        ✔ 1: Sends an invalid PING frame for connection close

    5.5. Extending HTTP/2
        1: Sends an unknown extension frame
      ✔ 1: Sends an unknown extension frame
        2: Sends an unknown extension frame in the middle of a header block
      ✔ 2: Sends an unknown extension frame in the middle of a header block

  6. Frame Definitions
    6.1. DATA
        1: Sends a DATA frame with 0x0 stream identifier
      ✔ 1: Sends a DATA frame with 0x0 stream identifier
        2: Sends a DATA frame on the stream that is not in "open" or "half-closed (local)" state
      ✔ 2: Sends a DATA frame on the stream that is not in "open" or "half-closed (local)" state
        3: Sends a DATA frame with invalid pad length
      ✔ 3: Sends a DATA frame with invalid pad length

    6.2. HEADERS
        1: Sends a HEADERS frame without the END_HEADERS flag, and a PRIORITY frame
      ✔ 1: Sends a HEADERS frame without the END_HEADERS flag, and a PRIORITY frame
        2: Sends a HEADERS frame to another stream while sending a HEADERS frame
      ✔ 2: Sends a HEADERS frame to another stream while sending a HEADERS frame
        3: Sends a HEADERS frame with 0x0 stream identifier
      ✔ 3: Sends a HEADERS frame with 0x0 stream identifier
        4: Sends a HEADERS frame with invalid pad length
      ✔ 4: Sends a HEADERS frame with invalid pad length

    6.3. PRIORITY
        1: Sends a PRIORITY frame with 0x0 stream identifier
      ✔ 1: Sends a PRIORITY frame with 0x0 stream identifier
        2: Sends a PRIORITY frame with a length other than 5 octets
      ✔ 2: Sends a PRIORITY frame with a length other than 5 octets

    6.4. RST_STREAM
        1: Sends a RST_STREAM frame with 0x0 stream identifier
      ✔ 1: Sends a RST_STREAM frame with 0x0 stream identifier
        2: Sends a RST_STREAM frame on a idle stream
      ✔ 2: Sends a RST_STREAM frame on a idle stream
        3: Sends a RST_STREAM frame with a length other than 4 octets
      ✔ 3: Sends a RST_STREAM frame with a length other than 4 octets

    6.5. SETTINGS
        1: Sends a SETTINGS frame with ACK flag and payload
      ✔ 1: Sends a SETTINGS frame with ACK flag and payload
        2: Sends a SETTINGS frame with a stream identifier other than 0x0
      ✔ 2: Sends a SETTINGS frame with a stream identifier other than 0x0
        3: Sends a SETTINGS frame with a length other than a multiple of 6 octets
      ✔ 3: Sends a SETTINGS frame with a length other than a multiple of 6 octets

      6.5.2. Defined SETTINGS Parameters
          1: SETTINGS_ENABLE_PUSH (0x2): Sends the value other than 0 or 1
        ✔ 1: SETTINGS_ENABLE_PUSH (0x2): Sends the value other than 0 or 1
          2: SETTINGS_INITIAL_WINDOW_SIZE (0x4): Sends the value above the maximum flow control window size
        ✔ 2: SETTINGS_INITIAL_WINDOW_SIZE (0x4): Sends the value above the maximum flow control window size
          3: SETTINGS_MAX_FRAME_SIZE (0x5): Sends the value below the initial value
        ✔ 3: SETTINGS_MAX_FRAME_SIZE (0x5): Sends the value below the initial value
          4: SETTINGS_MAX_FRAME_SIZE (0x5): Sends the value above the maximum allowed frame size
        ✔ 4: SETTINGS_MAX_FRAME_SIZE (0x5): Sends the value above the maximum allowed frame size
          5: Sends a SETTINGS frame with unknown identifier
        ✔ 5: Sends a SETTINGS frame with unknown identifier

      6.5.3. Settings Synchronization
          1: Sends multiple values of SETTINGS_INITIAL_WINDOW_SIZE
        ✔ 1: Sends multiple values of SETTINGS_INITIAL_WINDOW_SIZE
          2: Sends a SETTINGS frame without ACK flag
        ✔ 2: Sends a SETTINGS frame without ACK flag

    6.7. PING
        1: Sends a PING frame
      ✔ 1: Sends a PING frame
        2: Sends a PING frame with ACK
      ✔ 2: Sends a PING frame with ACK
        3: Sends a PING frame with a stream identifier field value other than 0x0
      ✔ 3: Sends a PING frame with a stream identifier field value other than 0x0
        4: Sends a PING frame with a length field value other than 8
      ✔ 4: Sends a PING frame with a length field value other than 8

    6.8. GOAWAY
        1: Sends a GOAWAY frame with a stream identifier other than 0x0
      ✔ 1: Sends a GOAWAY frame with a stream identifier other than 0x0

    6.9. WINDOW_UPDATE
        1: Sends a WINDOW_UPDATE frame with a flow control window increment of 0
      ✔ 1: Sends a WINDOW_UPDATE frame with a flow control window increment of 0
        2: Sends a WINDOW_UPDATE frame with a flow control window increment of 0 on a stream
      ✔ 2: Sends a WINDOW_UPDATE frame with a flow control window increment of 0 on a stream
        3: Sends a WINDOW_UPDATE frame with a length other than 4 octets
      ✔ 3: Sends a WINDOW_UPDATE frame with a length other than 4 octets

      6.9.1. The Flow-Control Window
          1: Sends SETTINGS frame to set the initial window size to 1 and sends HEADERS frame
        ✔ 1: Sends SETTINGS frame to set the initial window size to 1 and sends HEADERS frame
          2: Sends multiple WINDOW_UPDATE frames increasing the flow control window to above 2^31-1
        ✔ 2: Sends multiple WINDOW_UPDATE frames increasing the flow control window to above 2^31-1
          3: Sends multiple WINDOW_UPDATE frames increasing the flow control window to above 2^31-1 on a stream
        ✔ 3: Sends multiple WINDOW_UPDATE frames increasing the flow control window to above 2^31-1 on a stream

      6.9.2. Initial Flow-Control Window Size
          1: Changes SETTINGS_INITIAL_WINDOW_SIZE after sending HEADERS frame
        ✔ 1: Changes SETTINGS_INITIAL_WINDOW_SIZE after sending HEADERS frame
          2: Sends a SETTINGS frame for window size to be negative
        2: Sends a SETTINGS frame for window size to be negative
          3: Sends a SETTINGS_INITIAL_WINDOW_SIZE settings with an exceeded maximum window size value
        ✔ 3: Sends a SETTINGS_INITIAL_WINDOW_SIZE settings with an exceeded maximum window size value

    6.10. CONTINUATION
        1: Sends multiple CONTINUATION frames preceded by a HEADERS frame
      ✔ 1: Sends multiple CONTINUATION frames preceded by a HEADERS frame
        2: Sends a CONTINUATION frame followed by any frame other than CONTINUATION
      ✔ 2: Sends a CONTINUATION frame followed by any frame other than CONTINUATION
        3: Sends a CONTINUATION frame with 0x0 stream identifier
      ✔ 3: Sends a CONTINUATION frame with 0x0 stream identifier
        4: Sends a CONTINUATION frame preceded by a HEADERS frame with END_HEADERS flag
      ✔ 4: Sends a CONTINUATION frame preceded by a HEADERS frame with END_HEADERS flag
        5: Sends a CONTINUATION frame preceded by a CONTINUATION frame with END_HEADERS flag
      ✔ 5: Sends a CONTINUATION frame preceded by a CONTINUATION frame with END_HEADERS flag
        6: Sends a CONTINUATION frame preceded by a DATA frame
      ✔ 6: Sends a CONTINUATION frame preceded by a DATA frame

  7. Error Codes
      1: Sends a GOAWAY frame with unknown error code
    ✔ 1: Sends a GOAWAY frame with unknown error code
      2: Sends a RST_STREAM frame with unknown error code
    ✔ 2: Sends a RST_STREAM frame with unknown error code

  8. HTTP Message Exchanges
    8.1. HTTP Request/Response Exchange
        1: Sends a second HEADERS frame without the END_STREAM flag
      ✔ 1: Sends a second HEADERS frame without the END_STREAM flag

      8.1.2. HTTP Header Fields
          1: Sends a HEADERS frame that contains the header field name in uppercase letters
        ✔ 1: Sends a HEADERS frame that contains the header field name in uppercase letters

        8.1.2.1. Pseudo-Header Fields
            1: Sends a HEADERS frame that contains a unknown pseudo-header field
          ✔ 1: Sends a HEADERS frame that contains a unknown pseudo-header field
            2: Sends a HEADERS frame that contains the pseudo-header field defined for response
          ✔ 2: Sends a HEADERS frame that contains the pseudo-header field defined for response
            3: Sends a HEADERS frame that contains a pseudo-header field as trailers
          ✔ 3: Sends a HEADERS frame that contains a pseudo-header field as trailers
            4: Sends a HEADERS frame that contains a pseudo-header field that appears in a header block after a regular header field
          ✔ 4: Sends a HEADERS frame that contains a pseudo-header field that appears in a header block after a regular header field

        8.1.2.2. Connection-Specific Header Fields
            1: Sends a HEADERS frame that contains the connection-specific header field
          ✔ 1: Sends a HEADERS frame that contains the connection-specific header field
            2: Sends a HEADERS frame that contains the TE header field with any value other than "trailers"
          ✔ 2: Sends a HEADERS frame that contains the TE header field with any value other than "trailers"

        8.1.2.3. Request Pseudo-Header Fields
            1: Sends a HEADERS frame with empty ":path" pseudo-header field
          ✔ 1: Sends a HEADERS frame with empty ":path" pseudo-header field
            2: Sends a HEADERS frame that omits ":method" pseudo-header field
          ✔ 2: Sends a HEADERS frame that omits ":method" pseudo-header field
            3: Sends a HEADERS frame that omits ":scheme" pseudo-header field
          ✔ 3: Sends a HEADERS frame that omits ":scheme" pseudo-header field
            4: Sends a HEADERS frame that omits ":path" pseudo-header field
          ✔ 4: Sends a HEADERS frame that omits ":path" pseudo-header field
            5: Sends a HEADERS frame with duplicated ":method" pseudo-header field
          ✔ 5: Sends a HEADERS frame with duplicated ":method" pseudo-header field
            6: Sends a HEADERS frame with duplicated ":scheme" pseudo-header field
          ✔ 6: Sends a HEADERS frame with duplicated ":scheme" pseudo-header field
            7: Sends a HEADERS frame with duplicated ":path" pseudo-header field
          ✔ 7: Sends a HEADERS frame with duplicated ":path" pseudo-header field

        8.1.2.6. Malformed Requests and Responses
            1: Sends a HEADERS frame with the "content-length" header field which does not equal the DATA frame payload length
          ✔ 1: Sends a HEADERS frame with the "content-length" header field which does not equal the DATA frame payload length
            2: Sends a HEADERS frame with the "content-length" header field which does not equal the sum of the multiple DATA frames payload length
          ✔ 2: Sends a HEADERS frame with the "content-length" header field which does not equal the sum of the multiple DATA frames payload length

    8.2. Server Push
        1: Sends a PUSH_PROMISE frame
      ✔ 1: Sends a PUSH_PROMISE frame

HPACK: Header Compression for HTTP/2
  2. Compression Process Overview
    2.3. Indexing Tables
      2.3.3. Index Address Space
          1: Sends a indexed header field representation with invalid index
        ✔ 1: Sends a indexed header field representation with invalid index
          2: Sends a literal header field representation with invalid index
        ✔ 2: Sends a literal header field representation with invalid index

  4. Dynamic Table Management
    4.2. Maximum Table Size
        1: Sends a dynamic table size update at the end of header block
      ✔ 1: Sends a dynamic table size update at the end of header block

  5. Primitive Type Representations
    5.2. String Literal Representation
        1: Sends a Huffman-encoded string literal representation with padding longer than 7 bits
      ✔ 1: Sends a Huffman-encoded string literal representation with padding longer than 7 bits
        2: Sends a Huffman-encoded string literal representation padded by zero
      ✔ 2: Sends a Huffman-encoded string literal representation padded by zero
        3: Sends a Huffman-encoded string literal representation containing the EOS symbol
      ✔ 3: Sends a Huffman-encoded string literal representation containing the EOS symbol

  6. Binary Format
    6.1. Indexed Header Field Representation
        1: Sends a indexed header field representation with index 0
      ✔ 1: Sends a indexed header field representation with index 0

    6.3. Dynamic Table Size Update
        1: Sends a dynamic table size update larger than the value of SETTINGS_HEADER_TABLE_SIZE
      ✔ 1: Sends a dynamic table size update larger than the value of SETTINGS_HEADER_TABLE_SIZE

Failures: 

Hypertext Transfer Protocol Version 2 (HTTP/2)
  4. HTTP Frames
    4.2. Frame Size
      using source address 127.0.0.1:34282
      × 3: Sends a large size HEADERS frame that exceeds the SETTINGS_MAX_FRAME_SIZE
        -> The endpoint MUST respond with a connection error of type FRAME_SIZE_ERROR.
           Expected: GOAWAY Frame (Error Code: FRAME_SIZE_ERROR)
                     Connection closed
             Actual: DATA Frame (length:2, flags:0x01, stream_id:1)

  5. Streams and Multiplexing
    5.1. Stream States
      5.1.2. Stream Concurrency
        using source address 127.0.0.1:41988
        × 1: Sends HEADERS frames that causes their advertised concurrent stream limit to be exceeded
          -> The endpoint MUST treat this as a stream error of type PROTOCOL_ERROR or REFUSED_STREAM.
             Expected: GOAWAY Frame (Error Code: PROTOCOL_ERROR)
                       RST_STREAM Frame (Error Code: PROTOCOL_ERROR)
                       GOAWAY Frame (Error Code: REFUSED_STREAM)
                       RST_STREAM Frame (Error Code: REFUSED_STREAM)
                       Connection closed
               Actual: HEADERS Frame (length:13, flags:0x04, stream_id:1)

Finished in 9.4383 seconds
146 tests, 143 passed, 1 skipped, 2 failed
```
