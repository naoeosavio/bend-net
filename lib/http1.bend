# HTTP1: the HTTP/1.1 module. It owns the wire: the request render, the
# head and body parsers, the reason-phrase table and the chunked codec.
# Four loops carry the lanes (TASK-081). loop.server serves the two
# server forms: stream events and buffered keep-alive. loop.client reads
# the two client forms: the collect flag picks the fold or the events.
# The 101 lanes ride the loops. On the server side, loop.pre.open feeds
# server.open. On the client side, the client.open.exch ladder answers.
#
# It owns its transports on the named entries (TASK-081 Phase 3, user
# decision). The client dials: client.connect is the TCP dial,
# client.connect_secure the verified-TLS dial and
# client.connect_insecure the no-verify-TLS dial. The server accepts:
# server.accept is the TCP accept and server.accept_secure the TLS
# accept with the certificate and key it serves. Every entry owns a
# _secure twin, and the client owns the _insecure twins; the server
# has none, because it serves a certificate and verifies no chain.
# The .conn arms keep the three templates plus the dialed or accepted
# socket, so a caller that owns its transport drives the same core.
# The core (./http.bend) owns the types and the shared leaves.
#
# Callee above caller; match scrutinees are params or pattern-bound vars;
# self-recursion only, and @unsafe keeps the fuel-bounded loops.
#
# Import as: import ./http1.bend as HTTP1 (from lib).
import Base
import ./http.bend as HTTP
import ./tcp.bend as TCP
import ./tls.bend as TLS

# H1 lane, ported patterns (Phase 11): the old lib/http.bend was the base
# that worked, so its shapes came over verbatim (window scan, recurse-in-args
# with match-result-as-param, fuel loops) — but speaking Request/Response/Hdr
# natively, so no pairs converters and no encode/decode layer are needed.
# Subset, fail-closed: client and server decode Transfer-Encoding: chunked
# since TASK-033 (x_h1.chunk_step below); a malformed chunked body is 400 on
# both ends, and everything the decoder refuses stays refused. The client
# still requires Content-Length when the head is not chunked (missing →502,
# never hangs on keep-alive); the server treats a missing CL as an empty
# body. Keep-alive on both ends since TASK-027: the server answers
# and loops back to read (loop.server phase 8), the client reuses the
# socket for N requests in order (client.on over loop.client).
# Closing is by "connection: close", EOF, or a terminal 413/502/400; no
# Connection header is ever emitted, so the one-shot bytes are unchanged.
# ---------------------------------------------------------------------

def x_h1.eq_ci(a: String, b: String) -> Bool:
  String.eq(String.to_lower(a), String.to_lower(b))

def x_h1.bad_char(+s: String) -> Bool:
  Bool.or(HTTP.has_crlf(s), HTTP.has_nul(s))

# Render safety of a header FIELD (TASK-030): render_hs.go writes
# "name: value\r\n" verbatim, so a CR/LF/NUL inside either half ends the
# field early and the rest is read as headers the caller never asked for —
# request splitting on the client render, response splitting on the server
# render, one predicate for both. bad_char is the same check the request
# line already applied to method/path/host. Note the parser cannot be the
# source: it cuts the head on CRLF, so a parsed value never carries one —
# the source is text the app built itself (a decoded query/path echoed
# into a response header is the classic case).
def x_h1.bad_hdr(+h: HTTP.Hdr) -> Bool:
  match h:
    case HTTP.Hdr{+n, +v}:
      Bool.or(x_h1.bad_char(n), x_h1.bad_char(v))

def x_h1.bad_hdrs.go(+hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case h <> t:
      x_h1.bad_hdrs.go(t, Bool.or(acc, x_h1.bad_hdr(h)))

def x_h1.bad_hdrs(hs: List<&2, HTTP.Hdr>) -> Bool:
  x_h1.bad_hdrs.go(hs, False{})

# Everything the request line and the header block render, in one place:
# the same expression was copied inline in x_h1.render_req and
# client.open.fit, and neither copy looked at hs.
def x_h1.bad_req(+method: String, +path: String, +host: String, hs: List<&2, HTTP.Hdr>) ->
  Bool:
  Bool.or(x_h1.bad_char(method),
    Bool.or(x_h1.bad_char(path),
      Bool.or(x_h1.bad_char(host), x_h1.bad_hdrs(hs))))

def x_h1.forbidden(+name: String) -> Bool:
  Bool.or(String.starts_with(name, ":"),
    Bool.or(x_h1.eq_ci(name, "host"),
      Bool.or(x_h1.eq_ci(name, "connection"),
        Bool.or(x_h1.eq_ci(name, "content-length"),
          Bool.or(x_h1.eq_ci(name, "transfer-encoding"),
            Bool.or(x_h1.eq_ci(name, "upgrade"), x_h1.eq_ci(name, "keep-alive")))))))

# Keep-alive policy: the H1 server closes only when the request says so.
# "connection: close" is the one signal — HTTP/1.1 keeps the connection
# alive by default, and the client codec never renders the header
# (x_h1.forbidden skips it), so a peer that sends it means it.
def x_h1.conn_close.go(hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.conn_close.go(t, Bool.or(acc, Bool.and(x_h1.eq_ci(n, "connection"), x_h1.eq_ci(v, "close"))))

def x_h1.conn_close(hs: List<&2, HTTP.Hdr>) -> Bool:
  x_h1.conn_close.go(hs, False{})

# The render walk is the concat_th shape of the bench: each header's
# bytes drain onto the reversed accumulator in one pass, and the
# caller finishes with a single x_cat. Base's List.append here was
# quadratic (it re-walked the accumulated head per header) and not
# tail-recursive -- it faulted near 32k cells, so a handler answering
# ~40 KB of headers killed the server on its own answer.
def x_h1.render_hs.skip(+n: String, +v: String, rev: List<&2, U32>, skip: Bool) -> List<&2, U32>:
  match skip:
    case True{}:
      rev
    case False{}:
      HTTP.x_rev_push(HTTP.x_str_bytes(n ++ ": " ++ v ++ "\r\n"), rev)

# Upgrade renders keep `connection`/`upgrade` (the handshake's own headers):
# forbidden() still drops the rest. Case-insensitive like the parse side.
def x_h1.render_hs.keep(upgrade: Bool, +n: String) -> Bool:
  match upgrade:
    case True{}:
      Bool.or(x_h1.eq_ci(n, "connection"), x_h1.eq_ci(n, "upgrade"))
    case False{}:
      False{}

# The rev answer: the seed first, then each header, so one x_cat gives
# the seed followed by the headers in order.
def x_h1.render_hs.go(hs: List<&2, HTTP.Hdr>, rev: List<&2, U32>, +upgrade: Bool) -> List<&2, U32>:
  match hs:
    case Nil{}:
      rev
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.render_hs.go(t, x_h1.render_hs.skip(n, v, rev, Bool.and(x_h1.forbidden(n), Bool.not(x_h1.render_hs.keep(upgrade, n)))), upgrade)

# An upgrade handshake carries no body framing: with upgrade=True an empty
# body renders no Content-Length at all (a 101 must not claim one); any
# non-empty body still counts exactly as before.
def x_h1.render_cl.empty(upgrade: Bool) -> String:
  match upgrade:
    case True{}:
      ""
    case False{}:
      "Content-Length: 0\r\n"

def x_h1.render_cl(+body: List<&2, U32>, upgrade: Bool) -> String:
  match body:
    case Nil{}:
      x_h1.render_cl.empty(upgrade)
    case _ <> _:
      "Content-Length: " ++ U32.show(HTTP.x_len32(body)) ++ "\r\n"

def x_h1.render_req.go(+upgrade: Bool, bad: Bool, +method: String, +path: String, +host: String, +port: U32, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  match bad:
    case True{}:
      Fail{(400, "bad request")}
    case False{}:
      Done{HTTP.x_cat(HTTP.x_rev_push(body, HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), x_h1.render_hs.go(hs, HTTP.x_rev_push(HTTP.x_str_bytes(method ++ " " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ ":" ++ U32.show(port) ++ "\r\n" ++ x_h1.render_cl(body, upgrade)), Nil{}), upgrade))))}

# hs is + here (and only here): the header block is read twice, once by
# bad_req and once by the render below.
def x_h1.render_req(+method: String, +path: String, +host: String, +port: U32, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  x_h1.render_req.go(False{}, x_h1.bad_req(method, path, host, hs), method, path, host, port, hs, body)

def x_h1.reason(st: U32) -> String:
  match st:
    case 101:
      "Switching Protocols"
    case 200:
      "OK"
    case 204:
      "No Content"
    case 304:
      "Not Modified"
    case 400:
      "Bad Request"
    case 404:
      "Not Found"
    case 411:
      "Length Required"
    case 413:
      "Content Too Large"
    case 431:
      "Request Header Fields Too Large"
    case 500:
      "Internal Error"
    case 502:
      "Bad Gateway"
    case _:
      SNil{}

# Responses render with upgrade=False: a normal answer drops the
# connection/upgrade fields the codec forbids. The 101 head keeps them
# (show_resp_head below).
def x_h1.show_resp(+status: U32, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> List<&2, U32>:
  HTTP.x_cat(HTTP.x_rev_push(body, HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), x_h1.render_hs.go(hs, HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 " ++ U32.show(status) ++ " " ++ x_h1.reason(status) ++ "\r\nContent-Length: " ++ U32.show(HTTP.x_len32(body)) ++ "\r\n"), Nil{}), False{}))))

# The 101 head: status line + the handler's headers (Upgrade/Connection
# kept via upgrade=True) + blank line. No Content-Length, no body — a 101
# carries neither by definition, and show_resp would inject Length: 0.
def x_h1.show_resp_head(+status: U32, hs: List<&2, HTTP.Hdr>) -> List<&2, U32>:
  HTTP.x_cat(HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), x_h1.render_hs.go(hs, HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 " ++ U32.show(status) ++ " " ++ x_h1.reason(status) ++ "\r\n"), Nil{}), True{})))

# Blank-line cut over bytes (window 218762506 = \r\n\r\n, the window the
# retired H1 module's bs_head used; the discriminant rides a param, never
# a match on computed). Triple (head, rest, found) with thin projections.
# ---------------------------------------------------------------------

def x_h1.split.go(+bs: List<&2, U32>, found: Bool, +w: U32, acc: List<&2, U32>) -> List<&2, U32> & List<&2, U32> & Bool:
  match bs:
    case Nil{}:
      # found is carried out of the Nil arm: the boundary can land exactly
      # at the end of the buffer (a GET with no body, a bodyless response),
      # and dropping the flag here made the H1 head loop read forever
      # (TASK-026 Phase 7b, found by tests/io/httpx_plain_h1).
      (List.reverse(&2, U32, acc), Nil{}, found)
    case +b <> t:
      match found:
        case True{}:
          (List.reverse(&2, U32, acc), b <> t, True{})
        case False{}:
          +w2 = (w * 256 + b : U32)
          x_h1.split.go(t, U32.is_eq(w2, 218762506), w2, b <> acc)

def x_h1.split(+bs: List<&2, U32>) -> List<&2, U32> & List<&2, U32> & Bool:
  x_h1.split.go(bs, False{}, 0, Nil{})

def x_h1.split_head(p: List<&2, U32> & List<&2, U32> & Bool) -> List<&2, U32>:
  match p:
    case (h, r, f):
      h

def x_h1.split_rest(p: List<&2, U32> & List<&2, U32> & Bool) -> List<&2, U32>:
  match p:
    case (h, r, f):
      r

def x_h1.split_found(p: List<&2, U32> & List<&2, U32> & Bool) -> Bool:
  match p:
    case (h, r, f):
      f

# Boundary probe without the rebuild (TASK-040, from test.bend's finding
# that the pair costs nothing and the rebuild costs everything): the head
# loops only ask whether the blank line arrived, and x_h1.split answers
# that at the price of building the reversed head on the way. Same walk
# and same window as split.go, so x_h1.split.test(bs) equals
# x_h1.split_found(x_h1.split(bs)) on every input.
def x_h1.split.test.go(+bs: List<&2, U32>, found: Bool, +w: U32) -> Bool:
  match bs:
    case Nil{}:
      found
    case +b <> t:
      match found:
        case True{}:
          True{}
        case False{}:
          +w2 = (w * 256 + b : U32)
          x_h1.split.test.go(t, U32.is_eq(w2, 218762506), w2)

def x_h1.split.test(bs: List<&2, U32>) -> Bool:
  x_h1.split.test.go(bs, False{}, 0)

# The line split of a head as one tail walk over the bytes (TASK-081
# Phase 4.5): Base's String.split is not tail-recursive and its depth
# is the length of the string, so a 64 KiB head would fault inside
# String.lines. Same list on every input: the bytes are one char each,
# and a line ends at byte 10.
def x_h1.head_lines.cut(line_rev: String, rev: List<&2, String>) -> List<&2, String>:
  String.reverse(line_rev) <> rev

def x_h1.head_lines.turn(cut: Bool, +b: U32, line_rev: String, rev: List<&2, String>) -> String & List<&2, String>:
  match cut:
    case True{}:
      (SNil{}, x_h1.head_lines.cut(line_rev, rev))
    case False{}:
      (SCon{Chr{b}, line_rev}, rev)

def x_h1.head_lines.go(+bs: List<&2, U32>, carry: String & List<&2, String>) -> List<&2, String>:
  match bs:
    case Nil{}:
      match carry:
        case (line_rev, rev):
          List.reverse(&2, String, x_h1.head_lines.cut(line_rev, rev))
    case +b <> t:
      match carry:
        case (line_rev, rev):
          x_h1.head_lines.go(t, x_h1.head_lines.turn(U32.is_eq(b, 10), b, line_rev, rev))

def x_h1.head_lines(+head: List<&2, U32>) -> List<&2, String>:
  x_h1.head_lines.go(head, (SNil{}, Nil{}))

def x_h1.first_line(lines: List<&2, String>) -> String:
  match lines:
    case Nil{}:
      SNil{}
    case h <> t:
      h

def x_h1.rest_lines(lines: List<&2, String>) -> List<&2, String>:
  match lines:
    case Nil{}:
      Nil{}
    case h <> t:
      t

def x_h1.strip_cr.go(h: Char, t: String, is_cr: Bool) -> String:
  match is_cr:
    case True{}:
      t
    case False{}:
      SCon{h, t}

def x_h1.strip_cr(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+h, t}:
      x_h1.strip_cr.go(h, t, Char.is_eq(h, Chr{13}))

# Request line: exactly 3 tokens; validity folds version + target +
# bad chars into one Bool carried as param (head_act discipline).
# ---------------------------------------------------------------------

def x_h1.req_valid(+m: String, +p: String, +v: String) -> Bool:
  Bool.and(String.starts_with(v, "HTTP/1."),
    Bool.and(String.starts_with(p, "/"),
      Bool.and(Bool.not(x_h1.bad_char(m)), Bool.not(x_h1.bad_char(p)))))

def x_h1.req_tok(parts: List<&2, String>) -> Result<&1, &1, U32 & String, String & String & String & Bool>:
  match parts:
    case +m <> r1:
      match r1:
        case +p <> r2:
          match r2:
            case +v <> Nil{}:
              Done{(m, p, v, x_h1.req_valid(m, p, v))}
            case Nil{}:
              Fail{(400, "bad request line")}
            case +v <> r3:
              Fail{(400, "bad request line")}
        case Nil{}:
          Fail{(400, "bad request line")}
    case Nil{}:
      Fail{(400, "bad request line")}

# The request line as the server needs it: the ReqHead the handler sees
# plus the HTTP/1.1 flag the Host rule keys on (RFC 9112 section 3.2 asks
# for 400 on a missing Host for HTTP/1.1 requests only). Same tokenizer,
# same validation; only the version, which the parse used to drop, rides
# out beside the head. The version token still carries the CR of its line
# (String.lines cuts on \n only; x_h1.parse_hs trims it off every header
# line for the same reason), so String.trim runs before the compare:
# without it the flag is False for every peer and the Host rule never
# fires.
def x_h1.req_head(r: Result<&1, &1, U32 & String, String & String & String & Bool>) -> Result<&1, &1, U32 & String, HTTP.H1Head>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{q}:
      match q:
        case (m, p, v, ok):
          match ok:
            case True{}:
              Done{HTTP.H1Head{HTTP.ReqHead{m, p, Nil{}}, String.eq(String.trim(v), "HTTP/1.1")}}
            case False{}:
              Fail{(400, "bad request")}

def x_h1.req_join.hs(+m: String, +p: String, +is_11: Bool, hs: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>) ->
  Result<&1, &1, U32 & String, HTTP.H1Head>:
  match hs:
    case Fail{e}:
      Fail{e}
    case Done{+headers}:
      Done{HTTP.H1Head{HTTP.ReqHead{m, p, headers}, is_11}}

def x_h1.req_join(tok: Result<&1, &1, U32 & String, HTTP.H1Head>, hs: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>) ->
  Result<&1, &1, U32 & String, HTTP.H1Head>:
  match tok:
    case Fail{e}:
      Fail{e}
    case Done{+rh}:
      match rh:
        case HTTP.H1Head{head, is_11}:
          match head:
            case HTTP.ReqHead{+m, +p, +hs0}:
              x_h1.req_join.hs(m, p, is_11, hs)

# Status line: version + numeric code (Maybe.default; no partial line
# escapes).
# ---------------------------------------------------------------------

def x_h1.res_valid(+v: String, +c: String) -> Bool:
  Bool.and(String.starts_with(v, "HTTP/1."),
    Bool.not(U32.is_eq(Maybe.default(&2, U32, U32.read(c), 0), 0)))

def x_h1.res_tok(parts: List<&2, String>) -> Result<&1, &1, U32 & String, U32 & Bool>:
  match parts:
    case v <> r1:
      match r1:
        case +c <> r2:
          Done{(Maybe.default(&2, U32, U32.read(c), 0), x_h1.res_valid(v, c))}
        case Nil{}:
          Fail{(400, "bad status")}
    case Nil{}:
      Fail{(400, "bad status")}

def x_h1.res_head(q: U32 & Bool) -> Result<&1, &1, U32 & String, U32>:
  match q:
    case (code, ok):
      match ok:
        case True{}:
          Done{code}
        case False{}:
          Fail{(400, "bad status")}

def x_h1.res_lift(r: Result<&1, &1, U32 & String, U32 & Bool>) -> Result<&1, &1, U32 & String, U32>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{q}:
      x_h1.res_head(q)

# Header lines: blank (\r, post-lines-split) ends; colon-less fails.
# The fold is the fdel_go shape: the combiner never recurses.
# ---------------------------------------------------------------------

def x_h1.is_blank(+l: String) -> Bool:
  Bool.or(String.is_empty(l), String.eq(l, "\r"))

def x_h1.hdr_val(+line: String, +nlen: Nat) -> String:
  String.trim(String.drop(line, (nlen + 1n : Nat)))

# parse_hs as a tail fold with a combiner (TASK-081 Phase 4.5, the
# fdel_go shape): the recursion used to ride the parse_hdr argument,
# depth = the number of lines, and a 64 KiB head may carry twenty
# thousand of them. The combiner is a leaf that never recurses; it
# folds one line into the phase pair -- 0 still folding, 1 blank
# stopped, 2 failed -- and the final leaf turns the pair into the same
# answers as the parse_hdr chain: a blank line ends the fold and the
# headers before it survive (the old Done{Nil} was the base of the
# wrapping arms, not a discard), a line without a colon fails with
# the same (400, "bad header"), the good lines keep their order.
def x_h1.parse_hs.line(blank: Bool, parts: List<&2, String>, +l1: String, rev: List<&2, HTTP.Hdr>) -> U32 & List<&2, HTTP.Hdr>:
  match blank:
    case True{}:
      (1, rev)
    case False{}:
      match parts:
        case Nil{}:
          (2, rev)
        case +n <> vs:
          match vs:
            case Nil{}:
              (2, rev)
            case +v <> vvs:
              (0, HTTP.Hdr{n, x_h1.hdr_val(l1, String.length(n))} <> rev)

def x_h1.parse_hs.comb(ph: U32, +h: String, rev: List<&2, HTTP.Hdr>) -> U32 & List<&2, HTTP.Hdr>:
  match ph:
    case 0:
      +l1 = String.trim(x_h1.strip_cr(h))
      x_h1.parse_hs.line(x_h1.is_blank(h), String.split(l1, ':'), l1, rev)
    case _:
      (ph, rev)

def x_h1.parse_hs.fin.pick(ph: U32, rev: List<&2, HTTP.Hdr>) ->
  Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>:
  match ph:
    case 0:
      Done{List.reverse(&2, HTTP.Hdr, rev)}
    case 1:
      Done{List.reverse(&2, HTTP.Hdr, rev)}
    case _:
      Fail{(400, "bad header")}

def x_h1.parse_hs.fin(acc: U32 & List<&2, HTTP.Hdr>) ->
  Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>:
  match acc:
    case (ph, rev):
      x_h1.parse_hs.fin.pick(ph, rev)

def x_h1.parse_hs.go(lines: List<&2, String>, acc: U32 & List<&2, HTTP.Hdr>) ->
  Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>:
  match lines:
    case Nil{}:
      x_h1.parse_hs.fin(acc)
    case +h <> t:
      match acc:
        case (ph, rev):
          x_h1.parse_hs.go(t, x_h1.parse_hs.comb(ph, h, rev))

def x_h1.parse_hs(lines: List<&2, String>) ->
  Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>:
  x_h1.parse_hs.go(lines, (0, Nil{}))

# Framing queries (folds with combiner, fdel_go shape) + no_body.
# ---------------------------------------------------------------------

def x_h1.cl_at(is_cl: Bool, +v: String, +acc: U32) -> U32:
  match is_cl:
    case True{}:
      Maybe.default(&2, U32, U32.read(v), 0)
    case False{}:
      acc

def x_h1.cl_of.go(hs: List<&2, HTTP.Hdr>, +acc: U32) -> U32:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{n, v} <> t:
      x_h1.cl_of.go(t, x_h1.cl_at(x_h1.eq_ci(n, "content-length"), v, acc))

def x_h1.cl_of(hs: List<&2, HTTP.Hdr>) -> U32:
  x_h1.cl_of.go(hs, 0)

def x_h1.te_at(is_te: Bool, +v: String, acc: Bool) -> Bool:
  match is_te:
    case True{}:
      Bool.or(acc, String.contains(String.to_lower(v), "chunked"))
    case False{}:
      acc

def x_h1.te_go(hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{n, v} <> t:
      x_h1.te_go(t, x_h1.te_at(x_h1.eq_ci(n, "transfer-encoding"), v, acc))

def x_h1.is_chunked(hs: List<&2, HTTP.Hdr>) -> Bool:
  x_h1.te_go(hs, False{})

# Request-head validation (RFC 9112 sections 3.2 and 6.3, TASK-042 phase 6)
# ------------------------------------------------------------------------
# What the H1 server refuses with a 400 before it reads a single body byte.
# The framing pair is the request-smuggling shape: a Transfer-Encoding next
# to a Content-Length (a proxy in front may pick the other framing and the
# two peers disagree on where the body ends), two Content-Length fields,
# and a Content-Length that is not a plain decimal ("-1", "5x", "" all read
# as 0 through U32.read, which is a body of a different length than the
# sender meant). The Host rules are the RFC 9112 section 3.2 ones: more than
# one Host field or an empty one is 400 for any version, and a missing Host
# is 400 for an HTTP/1.1 request only (a 1.0 request may omit it).
def x_h1.count_if(is_hit: Bool, +acc: U32) -> U32:
  match is_hit:
    case True{}:
      (acc + 1 : U32)
    case False{}:
      acc

def x_h1.hdr_count.go(+hs: List<&2, HTTP.Hdr>, +needle: String, +acc: U32) -> U32:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.hdr_count.go(t, needle, x_h1.count_if(x_h1.eq_ci(n, needle), acc))

def x_h1.cl_count(hs: List<&2, HTTP.Hdr>) -> U32:
  x_h1.hdr_count.go(hs, "content-length", 0)

def x_h1.cl_bad_at(is_cl: Bool, +v: String) -> Bool:
  match is_cl:
    case True{}:
      Bool.or(String.is_empty(v), Bool.not(HTTP.all_digits(v)))
    case False{}:
      False{}

def x_h1.cl_bad.go(+hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.cl_bad.go(t, Bool.or(acc, x_h1.cl_bad_at(x_h1.eq_ci(n, "content-length"), v)))

def x_h1.cl_bad(hs: List<&2, HTTP.Hdr>) -> Bool:
  x_h1.cl_bad.go(hs, False{})

def x_h1.host_count(hs: List<&2, HTTP.Hdr>) -> U32:
  x_h1.hdr_count.go(hs, "host", 0)

def x_h1.host_empty_at(is_host: Bool, +v: String) -> Bool:
  match is_host:
    case True{}:
      String.is_empty(v)
    case False{}:
      False{}

def x_h1.host_empty.go(+hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.host_empty.go(t, Bool.or(acc, x_h1.host_empty_at(x_h1.eq_ci(n, "host"), v)))

def x_h1.host_empty(hs: List<&2, HTTP.Hdr>) -> Bool:
  x_h1.host_empty.go(hs, False{})

# A Transfer-Encoding the server cannot frame (anything but chunked): RFC
# 9112 section 6.3 says the body length cannot be determined reliably, so
# the answer is 400 and the connection ends.
def x_h1.te_any.go(+hs: List<&2, HTTP.Hdr>, acc: Bool) -> Bool:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.te_any.go(t, Bool.or(acc, x_h1.eq_ci(n, "transfer-encoding")))

def x_h1.te_any(hs: List<&2, HTTP.Hdr>) -> Bool:
  x_h1.te_any.go(hs, False{})

def x_h1.te_bad(+hs: List<&2, HTTP.Hdr>) -> Bool:
  Bool.and(x_h1.te_any(hs), Bool.not(x_h1.is_chunked(hs)))

# The head validation code: 400 for a head the server must not serve
# (RFC 9112 sections 3.2/6.3), 0 when it is clean. The first rule that fires
# wins, so a request with two problems reports the framing one. The bools
# ride in as parameters because a match cannot scrutinize a call.
def server.head_err_go(cl_bad: Bool, cl_dup: Bool, te_bad: Bool, te_cl: Bool, h_dup: Bool, h_none: Bool, h_empty: Bool, is_11: Bool) -> U32:
  match cl_bad cl_dup te_bad te_cl h_dup h_none h_empty is_11:
    case True{} _ _ _ _ _ _ _:
      400
    case _ True{} _ _ _ _ _ _:
      400
    case _ _ True{} _ _ _ _ _:
      400
    case _ _ _ True{} _ _ _ _:
      400
    case _ _ _ _ True{} _ _ _:
      400
    case _ _ _ _ _ True{} _ True{}:
      400
    case _ _ _ _ _ _ True{} _:
      400
    case _ _ _ _ _ _ _ _:
      0

def server.head_err(+hs: List<&2, HTTP.Hdr>, is_11: Bool) -> U32:
  server.head_err_go(x_h1.cl_bad(hs), U32.is_gt(x_h1.cl_count(hs), 1), x_h1.te_bad(hs), Bool.and(x_h1.te_any(hs), U32.is_gt(x_h1.cl_count(hs), 0)), U32.is_gt(x_h1.host_count(hs), 1), U32.is_eq(x_h1.host_count(hs), 0), x_h1.host_empty(hs), is_11)

# A terminal code the peer must see before the connection ends: 400..599 is
# a status this server renders, 0 ("close") and the 6xx transport codes
# (TLS/DNS) are not. One rule for the three H1 server lanes.
def server.is_status(+code: U32) -> Bool:
  Bool.and(U32.is_ge(code, 400), U32.is_lt(code, 600))

# The server's head cap: 16384 bytes, the default node uses
# (--max-http-header-size) and the value tests/io/httpx_h1_hardening.bend
# pins. The read fuel (64 turns) stays as the slow-drip backstop; both
# answer 431.
def x_h1.head_max() -> U32:
  16384

def x_h1.head_cap() -> U32:
  431

def x_h1.head_over(+n: U32) -> Bool:
  U32.is_gt(n, x_h1.head_max())

# The two values the accumulate step feeds the next turn when the head is
# past the cap: phase 0 (whose fuel floor answers 431) with no fuel left.
def x_h1.fuel_cap(fuel: Nat, over: Bool) -> Nat:
  match over:
    case True{}:
      0n
    case False{}:
      fuel

def x_h1.head_phase(over: Bool) -> U32:
  match over:
    case True{}:
      0
    case False{}:
      2

# The client's head budget (TASK-081 Phase 4.5): 64 KiB, the block
# budget the H2 module already enforces on its own client. The RFC sets
# no predefined limit (RFC 9110 section 5.4); the defaults around the
# field: node 16 KiB on both ends, Chrome 256 KiB on responses, the
# CDN fronts 8 KiB. The read accumulates tail-safe, so the budget is a
# policy choice, not a stack margin; the per-line gate below keeps
# every Base walk on one line under the machine-stack ceiling.
def x_h1.cli_head_max() -> U32:
  65536

def x_h1.cli_head_over(+n: U32) -> Bool:
  U32.is_gt(n, x_h1.cli_head_max())

# The per-line gate (TASK-081 Phase 4.5): Base's String.length is not
# tail-recursive either, and one long line would fault every Base walk
# on it (String.split on ':' or ' ', the length of the name). Each
# line keeps the 16 KiB house budget -- nginx and Apache cap a line at
# 8 KiB, so no mainstream server sends one near it -- while the whole
# head may be 64 KiB. A line past the budget fails closed with 400.
def x_h1.line_len.go(+s: String, +n: U32) -> U32:
  match s:
    case SNil{}:
      n
    case SCon{h, t}:
      x_h1.line_len.go(t, (n + 1 : U32))

def x_h1.line_len(+s: String) -> U32:
  x_h1.line_len.go(s, 0)

def x_h1.line_gate.go(hl: List<&2, String>, ok: Bool) -> Bool:
  match hl:
    case Nil{}:
      ok
    case +h <> t:
      x_h1.line_gate.go(t, Bool.and(ok, U32.is_le(x_h1.line_len(h), x_h1.head_max())))

def x_h1.line_gate.fin(ok: Bool, hl: List<&2, String>) -> Result<&1, &1, U32 & String, List<&2, String>>:
  match ok:
    case True{}:
      Done{hl}
    case False{}:
      Fail{(400, "line too long")}

def x_h1.line_gate(+hl: List<&2, String>) -> Result<&1, &1, U32 & String, List<&2, String>>:
  x_h1.line_gate.fin(x_h1.line_gate.go(hl, True{}), hl)

def x_h1.no_body.go(head: Bool, +status: U32) -> Bool:
  match head:
    case True{}:
      True{}
    case False{}:
      match status:
        case 204:
          True{}
        case 304:
          True{}
        case _:
          U32.is_lt(status, 200)

def x_h1.no_body(+method: String, +status: U32) -> Bool:
  x_h1.no_body.go(String.eq(method, "HEAD"), status)

# One carrier for the three framing answers above (same shape as
# CT.BodyFrame): length-delimited, chunked, or absent. Reuse: the folds
# own the rules, so the lanes stop threading three params for one
# decision; the single-pass fold is future work if ever measured.
def x_h1.frame_of(+hs: List<&2, HTTP.Hdr>, +method: String, +status: U32) -> HTTP.BodyFrame:
  HTTP.BodyFrame{x_h1.cl_of(hs), x_h1.is_chunked(hs), x_h1.no_body(method, status)}

# Chunked (RFC 9112 section 7.1.1): one grammar, one machine.
# ----------------------------------------------------------
# x_h1.chunk_step eats whatever the buffer holds and answers this file's
# own UnitOut (Got / NeedMore / End / Bad) beside its ChunkSt, so a body
# can arrive in pieces. Ported from lib/web/http/main.bend's h1_chunk_step
# -- same states, same answers, same two load-bearing arms (a trailing CR
# is NeedMore and never Bad, and it rides back in the outcome's rest
# unconsumed) -- because this file's isolation build may not import that
# module (Base + http.bend only, see the header). What the grammar
# accepts: a hex size line (either case, with an optional chunk
# extension), the CRLF, that many bytes and the CRLF after them, then "0"
# and the trailer-free CRLF. A trailer section is refused with 400, the
# answer lib/web/http/main.bend gives too (tests/http/h1_stream.bend s10
# and f4): a trailer is not chunked data, and reading it as if it were is
# the fail-open shape this lane exists to avoid.
#
# The body is copied in BLOCKS, never byte by byte: the data state takes
# min(rem, len(bs)) bytes with one slice and leaves the tail, so a whole
# 16 KiB recv costs one arm. Measured on a synthetic 1,1 MB body (64
# chunks of 16 KiB, whole-buffer fold, CPU time of one program): 6,3 s
# for this step fold against 6,9 s for the retired byte-at-a-time
# unchunk. The decisive win is not that margin but the shape: the byte
# machine can only answer "the whole body is here" (it has no NeedMore),
# so an IO lane would have to re-decode the growing buffer on every recv,
# while the step resumes from its own state and lets the lanes below
# consume a recv per arm.

# A fresh decoder: at a size line, nothing owed, no size, no partial chunk.
def x_h1.chunk_init() -> HTTP.ChunkSt:
  HTTP.ChunkSt{0, 0n, 0, Nil{}}

# The chunk's bytes out of the fragment stack the data state fills (newest
# read first, each fragment already in order). One fragment -- the whole
# chunk in one buffer, the common case -- comes back as it is, no copy.
def x_h1.chunk_close.go(+frags: List<&2, List<&2, U32>>, +acc: List<&2, U32>) -> List<&2, U32>:
  match frags:
    case Nil{}:
      acc
    case f <> t:
      x_h1.chunk_close.go(t, List.append(&2, U32, f, acc))

def x_h1.chunk_close(+frags: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match frags:
    case Nil{}:
      Nil{}
    case f <> Nil{}:
      f
    case _ <> _:
      x_h1.chunk_close.go(frags, Nil{})

# The two numbers the data state cannot decide by matching -- the state to
# continue in (3 when the read ended exactly on the chunk, 2 when more is
# owed) and what is left of rem -- computed here because a match cannot
# scrutinize a computed value: the decision has to arrive as a field the
# next iteration matches. The subtraction is guarded by the comparison
# that picks the state, so it never underflows.
def x_h1.chunk_st_of(+want: U32, +have: U32) -> U32:
  Bool.pick(U32, U32.is_eq(want, have), 3, 2)

def x_h1.chunk_rem_of(+want: U32, +have: U32) -> Nat:
  U32.to_nat((want - have : U32))

# One step of the grammar. Self-recursive (@unsafe) with one call per arm
# and a buffer that shrinks on each, so a whole body parses in linear time
# with no fuel. A Nil in the middle of a chunk is NeedMore -- the buffer
# ran out, the state comes back untouched and the caller reads more --
# while a byte the grammar does not allow is Bad. acc is Nil at every
# chunk boundary, so the two size states clear it.
@unsafe
def x_h1.chunk_step(st: HTTP.ChunkSt, +bs: List<&2, U32>) -> HTTP.ChunkSt & HTTP.UnitOut:
  match st:
    case HTTP.ChunkSt{st2, rem, size, acc}:
      match st2:
        case 0:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case b <> rest:
              match b:
                case 48:
                  x_h1.chunk_step(HTTP.ChunkSt{0, 0n, 0, Nil{}}, rest)
                case 49:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 1, Nil{}}, rest)
                case 50:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 2, Nil{}}, rest)
                case 51:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 3, Nil{}}, rest)
                case 52:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 4, Nil{}}, rest)
                case 53:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 5, Nil{}}, rest)
                case 54:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 6, Nil{}}, rest)
                case 55:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 7, Nil{}}, rest)
                case 56:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 8, Nil{}}, rest)
                case 57:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 9, Nil{}}, rest)
                case 65:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 10, Nil{}}, rest)
                case 66:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 11, Nil{}}, rest)
                case 67:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 12, Nil{}}, rest)
                case 68:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 13, Nil{}}, rest)
                case 69:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 14, Nil{}}, rest)
                case 70:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 15, Nil{}}, rest)
                case 97:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 10, Nil{}}, rest)
                case 98:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 11, Nil{}}, rest)
                case 99:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 12, Nil{}}, rest)
                case 100:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 13, Nil{}}, rest)
                case 101:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 14, Nil{}}, rest)
                case 102:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, 15, Nil{}}, rest)
                case 59:
                  x_h1.chunk_step(HTTP.ChunkSt{1, 0n, 0, Nil{}}, rest)
                case 13:
                  match rest:
                    case Nil{}:
                      (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, [13]})
                    case 10 <> rest2:
                      x_h1.chunk_step(HTTP.ChunkSt{5, 0n, 0, Nil{}}, rest2)
                    case _:
                      (st, HTTP.Bad{400, "bad chunked"})
                case _:
                  (st, HTTP.Bad{400, "bad chunked"})
        case 7:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case b <> rest:
              match b:
                case 48:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 0 : U32), Nil{}}, rest)
                case 49:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 1 : U32), Nil{}}, rest)
                case 50:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 2 : U32), Nil{}}, rest)
                case 51:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 3 : U32), Nil{}}, rest)
                case 52:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 4 : U32), Nil{}}, rest)
                case 53:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 5 : U32), Nil{}}, rest)
                case 54:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 6 : U32), Nil{}}, rest)
                case 55:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 7 : U32), Nil{}}, rest)
                case 56:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 8 : U32), Nil{}}, rest)
                case 57:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 9 : U32), Nil{}}, rest)
                case 65:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 10 : U32), Nil{}}, rest)
                case 66:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 11 : U32), Nil{}}, rest)
                case 67:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 12 : U32), Nil{}}, rest)
                case 68:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 13 : U32), Nil{}}, rest)
                case 69:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 14 : U32), Nil{}}, rest)
                case 70:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 15 : U32), Nil{}}, rest)
                case 97:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 10 : U32), Nil{}}, rest)
                case 98:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 11 : U32), Nil{}}, rest)
                case 99:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 12 : U32), Nil{}}, rest)
                case 100:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 13 : U32), Nil{}}, rest)
                case 101:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 14 : U32), Nil{}}, rest)
                case 102:
                  x_h1.chunk_step(HTTP.ChunkSt{7, 0n, (size * 16 + 15 : U32), Nil{}}, rest)
                case 59:
                  x_h1.chunk_step(HTTP.ChunkSt{1, 0n, size, Nil{}}, rest)
                case 13:
                  match rest:
                    case Nil{}:
                      (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, [13]})
                    case 10 <> rest2:
                      x_h1.chunk_step(HTTP.ChunkSt{2, U32.to_nat(size), 0, Nil{}}, rest2)
                    case _:
                      (st, HTTP.Bad{400, "bad chunked"})
                case _:
                  (st, HTTP.Bad{400, "bad chunked"})
        case 1:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case b <> rest:
              match b:
                case 13:
                  match rest:
                    case Nil{}:
                      (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, [13]})
                    case 10 <> rest2:
                      x_h1.chunk_step(HTTP.ChunkSt{2, U32.to_nat(size), 0, Nil{}}, rest2)
                    case _:
                      (st, HTTP.Bad{400, "bad chunked"})
                case _:
                  x_h1.chunk_step(HTTP.ChunkSt{1, 0n, size, acc}, rest)
        case 2:
          match rem:
            case 0n:
              x_h1.chunk_step(HTTP.ChunkSt{3, 0n, size, acc}, bs)
            case 1n+c:
              match bs:
                case Nil{}:
                  (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
                case _ <> _:
                  # The data phase in one arm: have is min(rem, len(bs)),
                  # counted only up to rem, so the take is the chunk's own
                  # slice and the read goes onto the fragment stack with
                  # one cons. The decision "was that the whole chunk?"
                  # rides as the STATE NUMBER (3 whole, 2 partial): the
                  # next iteration matches the field, which is what makes
                  # this legal Bend and not a special case. The partial
                  # read's buffer ends at or before the chunk, so its rest
                  # is Nil and state 2 answers NeedMore.
                  +want = U32.from_nat(rem)
                  +have = HTTP.x_len_upto(want, bs)
                  x_h1.chunk_step(HTTP.ChunkSt{x_h1.chunk_st_of(want, have), x_h1.chunk_rem_of(want, have), size,
                    HTTP.x_take32(have, bs) <> acc}, HTTP.x_drop32(have, bs))
        case 3:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case 13 <> t:
              x_h1.chunk_step(HTTP.ChunkSt{4, 0n, size, acc}, t)
            case _:
              (st, HTTP.Bad{400, "bad chunked"})
        case 4:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case 10 <> t:
              x_h1.chunk_step(HTTP.ChunkSt{8, 0n, size, acc}, t)
            case _:
              (st, HTTP.Bad{400, "bad chunked"})
        case 8:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case 48 <> t:
              (x_h1.chunk_init(), HTTP.Got{x_h1.chunk_close(acc), True{}, bs})
            case 13 <> t:
              (x_h1.chunk_init(), HTTP.Got{x_h1.chunk_close(acc), True{}, bs})
            case _ <> t:
              (x_h1.chunk_init(), HTTP.Got{x_h1.chunk_close(acc), False{}, bs})
        case 5:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case 13 <> t:
              x_h1.chunk_step(HTTP.ChunkSt{6, 0n, size, acc}, t)
            case _:
              (st, HTTP.Bad{400, "bad chunked"})
        case 6:
          match bs:
            case Nil{}:
              (HTTP.ChunkSt{st2, rem, size, acc}, HTTP.NeedMore{1, Nil{}})
            case 10 <> t:
              match t:
                case Nil{}:
                  (st, HTTP.End{Nil{}})
                case _ <> t2:
                  (st, HTTP.Bad{400, "bad chunked"})
            case _:
              (st, HTTP.Bad{400, "bad chunked"})
        case _:
          (st, HTTP.Bad{400, "bad chunked"})

# The client's chunked body reader: the same phase+fuel shape as
# client.bd, except the length is not known up front -- the step decides.
# Got adds the chunk to a reversed body and keeps stepping, NeedMore spends
# one recv (fuel), Bad is 400 and End is the answer. The lookahead's fin is
# NOT the finish line: only End is, so "1\r\nA\r\n\r\n" (a bare empty line
# standing in for the last-chunk, which the lookahead reads as "last")
# stays 400 here, exactly like both whole-buffer decoders. The bare codes
# are the lane's own: 413 is the fuel floor client.bd uses, 400 on EOF is
# its "eof" too.
#
# Phase 1 exists for the same reason client.bd has one: the recv result is
# a computed pair and a match cannot scrutinize a computed value, so it
# travels here as a parameter. The pending state rides in the pair parameter
# as well -- phase 0 hands it chunk_step(st2, Nil{}), which always answers
# NeedMore and consumes no byte -- because that state is all phase 1 needs
# once the new bytes are appended to the buffer.
@unsafe
def client.chunk(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, r: HTTP.ChunkSt & HTTP.UnitOut, fuel: Nat, rev: List<&2, U32>, buf: List<&2, U32>, +code: U32, hs: List<&2, HTTP.Hdr>, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match phase:
    case 0:
      match r:
        case (st2, out):
          match out:
            case HTTP.Got{+chunk, fin, +rest}:
              (sock, _r0) = got
              client.chunk(~recv, ~send, ~close, 0, x_h1.chunk_step(st2, rest), fuel, HTTP.x_rev_push(chunk, rev), rest, code, hs, (sock, Done{Nil{}}))
            case HTTP.NeedMore{missing, +rest}:
              match fuel:
                case 0n:
                  (sock2, _r1) = got
                  IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock2, Fail{(413, "response too long")}))
                case 1n+f:
                  (sock3, _r2) = got
                  do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
                    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(sock3, 16384)
                    client.chunk(~recv, ~send, ~close, 1, x_h1.chunk_step(st2, Nil{}), f, rev, rest, code, hs, r1)
            case HTTP.End{rest}:
              (sock4, _r3) = got
              IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock4, Done{(HTTP.Response{code, hs, HTTP.x_cat(rev)}, Nil{})}))
            case HTTP.Bad{code2, msg}:
              (sock5, _r4) = got
              IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock5, Fail{(code2, msg)}))
    case 1:
      match r:
        case (st2, out):
          match got:
            case (sock, r1):
              match r1:
                case Fail{e}:
                  IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
                case Done{+part}:
                  match part:
                    case Nil{}:
                      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{(400, "eof")}))
                    case h <> t:
                      +buf2 = List.append(&2, U32, buf, part)
                      client.chunk(~recv, ~send, ~close, 0, x_h1.chunk_step(st2, buf2), fuel, rev, buf2, code, hs, (sock, Done{Nil{}}))
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

# H1 client exchange (fallback lane): render, send, head/body fuel loops.
# The one-shot close wrapper lives in the fold over loop.client now
# (TASK-081 Phase 3); the send ladder and the read chain below stay,
# because the open lane (Phase 4) and the direct tests drive them.
# Matches go forward in param order per branch (checker rule).
# Transport is three templates (~recv/~send/~close), instantiated per
# lane at the public entries: TLS (tls_recv/send_bytes + tls_close) or
# TCP (TCP.recv/send_bytes + Socket.close). The grammar is identical —
# that is what let the x_h1p.* mirror die in Phase 1.
#
# The content-length body rides REVERSED (x_rev_push), like the chunked
# lane below: per recv the work stays O(chunk) and the un-reverse happens
# once with x_cat at the answer. Appending each part onto a growing body
# (List.append(rest, part) + x_has_at_least) was O(n) per recv AND
# linear-recursive, which overflowed the interp machine stack past ~48 KB
# (same hazard x_rev_push's header documents for the H2 lane). `need` is
# the count still missing, so the completion test is a match on a U32
# param instead of a re-walk of the buffer.
# ---------------------------------------------------------------------

@unsafe
def client.bd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, fuel: Nat, +need: U32, +code: U32, +hs: List<&2, HTTP.Hdr>, +rev: List<&2, U32>, +cl: U32) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          match need:
            case 0:
              IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s0, Done{(HTTP.Response{code, hs, HTTP.x_take32(cl, HTTP.x_cat(rev))}, Nil{})}))
            case _:
              do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
                client.bd(~recv, ~send, ~close, 1, r, f, need, code, hs, rev, cl)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s1, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s1, Fail{(400, "eof")}))
            case h <> t:
              +need2 = U32.sub(need, HTTP.x_len_upto(need, part))
              client.bd(~recv, ~send, ~close, 0, (s1, Done{Nil{}}), fuel, need2, code, hs, HTTP.x_rev_push(part, rev), cl)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

# The nbody=False arm of hd2: a body to read, or the 502 of an upgrade
# without 101. The decision needs its own def, because Bend refuses a match
# inside two match arms.
def client.body_go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, +hs: List<&2, HTTP.Hdr>, upg: Bool, chunked: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match upg:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{(502, "upgrade without 101")}))
    case False{}:
      match chunked:
        case True{}:
          client.chunk(~recv, ~send, ~close, 0, x_h1.chunk_step(x_h1.chunk_init(), rest), fuel, Nil{}, rest, code, hs, (sock, Done{Nil{}}))
        case False{}:
          +clc = x_h1.cl_of(hs)
          +need0 = U32.sub(clc, HTTP.x_len_upto(clc, rest))
          client.bd(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), fuel, need0, code, hs, HTTP.x_cat(rest), clc)

# The chain serves the plain lane and the upgrade lane. The flag upg turns
# the nbody=False arm into Fail 502 "upgrade without 101" (fail-closed:
# a 101 carries no body by definition). The plain entries drop the rest of
# the triple, the upgrade entries keep it (client.open; the wsm calls
# client.open.exch, TASK-082 migrated the name).

def client.hd2(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, +hs: List<&2, HTTP.Hdr>, nbody: Bool, chunked: Bool, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match nbody:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Done{(HTTP.Response{code, hs, Nil{}}, rest)}))
    case False{}:
      client.body_go(~recv, ~send, ~close, sock, rest, fuel, code, hs, upg, chunked)

# The nbody=False arm of hd2: a body to read, or the 502 of an upgrade
# without 101. The decision needs its own def, because Bend refuses a match
# inside two match arms.
def client.hd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>, nbody: Bool, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match hsres:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+hs}:
      client.hd2(~recv, ~send, ~close, sock, rest, fuel, code, hs, nbody, x_h1.is_chunked(hs), upg)

def client.coded(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +method: String, +rest: List<&2, U32>, fuel: Nat, coderes: Result<&1, &1, U32 & String, U32>, hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match coderes:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+code}:
      client.hd(~recv, ~send, ~close, sock, rest, fuel, code, hsres, x_h1.no_body(method, code), upg)

# got B (TASK-040): the split triple arrives as a parameter — a computed
# triple cannot be scrutinized (E1), a parameter can (E2) — so head-lines
# and rest come out of ONE x_h1.split traversal. Was split_head(split(acc2))
# plus split_rest(split(acc2)): two walks and two reverses per head.
# The line gate answers before any Base walk on a line: a too-long
# line fails closed here, the same 400 on both client lanes.
def client.parsed.lines(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s1: Socket, +rest: List<&2, U32>, fuel: Nat, +method: String, upg: Bool, g: Result<&1, &1, U32 & String, List<&2, String>>) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match g:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s1, Fail{e}))
    case Done{+hl}:
      client.coded(~recv, ~send, ~close, s1, method, rest, fuel, x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl)), upg)

def client.parsed.got(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), p: List<&2, U32> & List<&2, U32> & Bool, s1: Socket, fuel: Nat, +method: String, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match p:
    case (head, rest, found):
      client.parsed.lines(~recv, ~send, ~close, s1, rest, fuel, method, upg, x_h1.line_gate(x_h1.head_lines(head)))

def client.parsed(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s1: Socket, +acc2: List<&2, U32>, fuel: Nat, +method: String, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  client.parsed.got(~recv, ~send, ~close, x_h1.split(acc2), s1, fuel, method, upg)

# Status code of the head sitting in acc (0 when the status line does not
# parse). The 1xx check runs before the head is turned into a response, so
# it reads the code out of the same split/parse the answer path uses
# (TASK-042 phase 4).
def client.code_of_got(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+code}:
      code

# The interim check reads only the status line. A head the line gate
# refuses answers 0 (not interim); the parse of the same head then
# answers the 400 of the gate.
def x_h1.status_of.got(g: Result<&1, &1, U32 & String, List<&2, String>>) -> U32:
  match g:
    case Fail{e}:
      0
    case Done{+hl}:
      client.code_of_got(x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))))

def x_h1.status_of(+acc: List<&2, U32>) -> U32:
  x_h1.status_of.got(x_h1.line_gate(x_h1.head_lines(x_h1.split_head(x_h1.split(acc)))))

# 1xx is an interim status (RFC 9110 section 15.2): any number of them may
# precede the final response — 100 Continue (Expect), 103 Early Hints
# (node's writeEarlyHints, CDNs) — so the head is discarded and the next
# one parsed out of the bytes already read. 101 Switching Protocols is the
# upgrade answer: a final head for the caller, never interim here.
def x_h1.is_info(+code: U32) -> Bool:
  Bool.and(Bool.and(U32.is_lt(99, code), U32.is_lt(code, 200)), U32.is_ne(code, 101))

@unsafe
def client.head(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, +method: String, found: Bool, info: Bool, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            client.head(~recv, ~send, ~close, 1, r, acc, f, method, False{}, False{}, upg)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s1, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s1, Fail{(400, "eof")}))
            case h <> t:
              # TASK-081 Phase 4.5: the turn builds the in-order buffer
              # with the three tail passes of the core (x_cat, x_rev_push,
              # x_cat). Base's List.append is not tail-recursive and
              # faults near 32k cells, and the client head may be 64 KiB
              # now. Past the budget the read routes to the empty-fuel
              # arm, whose 413 is the client's ceiling code; the client
              # never answers 431.
              +acc2 = HTTP.x_cat(HTTP.x_rev_push(part, HTTP.x_cat(acc)))
              +over = x_h1.cli_head_over(HTTP.x_len32(acc2))
              client.head(~recv, ~send, ~close, x_h1.head_phase(over), (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), method, x_h1.split.test(acc2), False{}, upg)
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          client.head(~recv, ~send, ~close, 0, (s2, Done{Nil{}}), acc, fuel, method, False{}, False{}, upg)
        case True{}:
          client.head(~recv, ~send, ~close, 4, (s2, Done{Nil{}}), acc, fuel, method, False{}, x_h1.is_info(x_h1.status_of(acc)), upg)
    case 4:
      (s4, r4) = got
      match info:
        case True{}:
          +rest = x_h1.split_rest(x_h1.split(acc))
          client.head(~recv, ~send, ~close, 2, (s4, Done{Nil{}}), rest, fuel, method, x_h1.split.test(rest), False{}, upg)
        case False{}:
          client.parsed(~recv, ~send, ~close, s4, acc, fuel, method, upg)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

def client.open.sent(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{u}:
      client.head(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), Nil{}, 64n, method, False{}, False{}, True{})

def client.open.send(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match rendered:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+bytes}:
      do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        client.open.sent(~recv, ~send, ~close, sent, method)

# The handshake exchange: the same 400/413 gates as the plain lane (the
# render refuses a bad request before any byte leaves) but rendered with
# upgrade=True and answered by the client.open
# ladder, so the socket comes back live with the bytes past the head. Not
# closing is the caller's job — that is the whole point of the triple.
# hs is + for the same reason as x_h1.render_req: bad_req and the render
# both read the header block.
def client.open.fit(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          client.open.send(~recv, ~send, ~close, sock, x_h1.render_req.go(True{}, x_h1.bad_req(method, path, host, hs), method, path, host, port, hs, body), method)
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>,
            (sock, Fail{(413, "req too large")}))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>,
        (sock, Fail{(400, "bad request")}))

# The exchange of the open family: the handshake on a socket the caller
# owns. The wsm dials itself and reaches this core through the alias
# below; the named vectors dial and wrap it.
def client.open.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  client.open.fit(~recv, ~send, ~close, sock, host, port, method, path, hs, body, HTTP.client.on.valid.go(host, port, path), HTTP.client.on.body_ok(body))

# H1 client body framing (Phase 6; TASK-081 Phase 3 rides it): the
# StreamEv/StreamOut lane of the client, the H1 sibling of the H2 sdrop
# lane in ./http2.bend. The H1 answer to Cancel is Fail (8, "cancelled")
# plus the entry's close — there is no RST_STREAM on this lane. The
# counts (total bytes, chunks delivered) are the same pair shape the H2
# lane reports as (total, fins). The framing cut below is shared with
# the upload lane (frame.next), so both sides cut one body one
# way.
# ---------------------------------------------------------------------

# Field projections: Bend has no field access, so a loop carrying a
# BodyFrame reads the three framing answers back through these.
def frame.cl(+fr: HTTP.BodyFrame) -> U32:
  match fr:
    case HTTP.BodyFrame{+cl, chunked, no_body}:
      cl

def frame.chunked(+fr: HTTP.BodyFrame) -> Bool:
  match fr:
    case HTTP.BodyFrame{cl, +chunked, no_body}:
      chunked

def frame.nbody(+fr: HTTP.BodyFrame) -> Bool:
  match fr:
    case HTTP.BodyFrame{cl, chunked, +no_body}:
      no_body

# Length-delimited cut answering this file's own UnitOut, the same
# vocabulary the chunked step speaks: Got carries the next piece with
# its last-chunk flag and what is left, NeedMore carries the buffer back
# for one more read, End is unused here (a spent length is a caller bug),
# Bad is the overspent length the whole-buffer lane refuses too.
def frame.cl_go(+pending: List<&2, U32>, +cl: U32, +seen: U32, +chunk: List<&2, U32>, fin: Bool, empty: Bool) -> HTTP.UnitOut:
  match empty:
    case True{}:
      HTTP.NeedMore{(cl - seen : U32), pending}
    case False{}:
      HTTP.Got{chunk, fin, HTTP.x_drop32(HTTP.x_len32(chunk), pending)}

def frame.cl_next(+pending: List<&2, U32>, +cl: U32, +seen: U32, ok: Bool) -> HTTP.UnitOut:
  match ok:
    case True{}:
      +chunk = HTTP.x_take32((cl - seen : U32), pending)
      frame.cl_go(pending, cl, seen, chunk, U32.is_eq((seen + HTTP.x_len32(chunk) : U32), cl), List.is_empty(&2, U32, chunk))
    case False{}:
      HTTP.Bad{400, "eof"}

# The next chunk, whichever framing the head declared. One call so the
# loops never match the framing and the answer at once: a chunked body
# goes to the incremental step (which keeps its own state across reads)
# and a length-delimited one to the cut above (whose state is the seen
# count the caller already carries).
def frame.next(+chunked: Bool, +cst: HTTP.ChunkSt, +pending: List<&2, U32>, +cl: U32, +seen: U32) -> HTTP.ChunkSt & HTTP.UnitOut:
  match chunked:
    case True{}:
      x_h1.chunk_step(cst, pending)
    case False{}:
      (x_h1.chunk_init(), frame.cl_next(pending, cl, seen, Bool.not(U32.is_gt(seen, cl))))

# What the head answer means to this loop: 0 go read the body, 2 report
# what was counted and close, 3 close and report (8, "cancelled").
# Asking for more on a message with no body is a finish, not a close:
# the client has nothing left to read.
def client.stream.head_go(nbody: Bool) -> U32:
  match nbody:
    case True{}:
      2
    case False{}:
      0

def client.stream.head_act(+out: HTTP.StreamOut, nbody: Bool) -> U32:
  match out:
    case HTTP.StreamContinue{}:
      client.stream.head_go(nbody)
    case HTTP.StreamCancel{}:
      3

# What one body chunk answer means: 0 keep going, 2 done and report,
# 3 cancelled. Continue past the last chunk is done — there is no next
# chunk.
def client.stream.data_act(+out: HTTP.StreamOut, +fin: Bool) -> U32:
  match out:
    case HTTP.StreamContinue{}:
      match fin:
        case True{}:
          2
        case False{}:
          0
    case HTTP.StreamCancel{}:
      3

# Close and report. Every exit goes through close, so no path leaks.
def client.stream.close(~close: Socket -> IO(Unit), s: Socket, r: Result<&1, &1, U32 & String, U32 & U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    x : Unit <- close(s)
    IO.pure(Result<&1, &1, U32 & String, U32 & U32>, r)

# The response head, parsed. The bytes that arrived with the head seed
# the pending buffer in phase 3, the same way the one-shot lane does.
def client.stream.headers(hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>, +code: U32) -> Result<&1, &1, U32 & String, HTTP.Head>:
  match hsres:
    case Fail{e}:
      Fail{e}
    case Done{+hs}:
      Done{HTTP.Head{code, hs}}

def client.stream.built(coderes: Result<&1, &1, U32 & String, U32>, hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>) -> Result<&1, &1, U32 & String, HTTP.Head>:
  match coderes:
    case Fail{e}:
      Fail{e}
    case Done{+code}:
      client.stream.headers(hsres, code)

# The line gate answers before any Base walk on a line (the stream
# lane's parse): a too-long line fails closed with the same 400.
def client.stream.parsed.got(g: Result<&1, &1, U32 & String, List<&2, String>>) -> Result<&1, &1, U32 & String, HTTP.Head>:
  match g:
    case Fail{e}:
      Fail{e}
    case Done{+hl}:
      client.stream.built(x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl)))

def client.stream.parsed(+acc: List<&2, U32>) -> Result<&1, &1, U32 & String, HTTP.Head>:
  client.stream.parsed.got(x_h1.line_gate(x_h1.head_lines(x_h1.split_head(x_h1.split(acc)))))

def client.stream.no_head() -> Result<&1, &1, U32 & String, HTTP.Head>:
  Fail{(400, "bad status")}

# The buffered form's branches of the client loop (the client sibling
# of server.fold.*): one table per routing point, so the deep loop arms
# never match the form past the arms the checker allows.
# ---------------------------------------------------------------------

# The head answer of one form: the buffered fold answers a bodiless
# message at once (1) and reads the body otherwise; the stream form asks
# the handler about the head event.
def client.fold.ans_of(~H: HTTP.StreamEv -> HTTP.StreamOut, +hd: HTTP.Head, collect: Bool, nb: Bool) -> U32:
  match collect:
    case True{}:
      match nb:
        case True{}:
          1
        case False{}:
          0
    case False{}:
      client.stream.head_act(H(HTTP.StreamHead{hd}), nb)

# The buffered route of one body chunk: the chunked body runs to the
# terminator whatever the lookahead flag says (only End ends it), the
# length-delimited body ends at its exact count.
def client.fold.got_route(chunked: Bool, fin: Bool) -> U32:
  match chunked:
    case True{}:
      0
    case False{}:
      match fin:
        case True{}:
          1
        case False{}:
          0

# The answer of one body chunk: the buffered fold routes on its own
# table, the stream form asks the handler about the data event.
def client.fold.got_ans(~H: HTTP.StreamEv -> HTTP.StreamOut, +chunk: List<&2, U32>, +fin: Bool, chunked: Bool, collect: Bool) -> U32:
  match collect:
    case True{}:
      client.fold.got_route(chunked, fin)
    case False{}:
      client.stream.data_act(H(HTTP.StreamData{chunk, fin}), fin)

# The next phase after one body chunk: the buffered fold routes through
# the answer table (phase 5), the stream form routes the data event
# (phase 7).
def client.fold.got_phase(collect: Bool) -> U32:
  match collect:
    case True{}:
      5
    case False{}:
      7

# The body accumulator of one form: the buffered fold pushes the chunk
# onto the reversed body, the stream form holds nothing.
def client.fold.got_rev(+chunk: List<&2, U32>, rev: List<&2, U32>, collect: Bool) -> List<&2, U32>:
  match collect:
    case True{}:
      HTTP.x_rev_push(chunk, rev)
    case False{}:
      rev

# The buffered answer: the folded body under the threaded head, with
# the unread bytes beside it. The bodiless case rides the same arm: the
# loop seeds the accumulator empty, so the un-reverse answers empty.
def client.fold.answer(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, hres: Result<&1, &1, U32 & String, HTTP.Head>, rev: List<&2, U32>, +total: U32, +chunks: U32, +rest: List<&2, U32>) -> Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>:
  (s, _r) = got
  match hres:
    case Fail{e}:
      (s, Fail{e})
    case Done{+hd}:
      match hd:
        case HTTP.Head{+code, +hs}:
          (s, Done{((total, chunks), HTTP.Response{code, hs, HTTP.x_cat(rev)}, rest)})

# The fail answer of one loop exit: the socket plus the error. The
# entries close; the loop only reports.
def client.err_out(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, e: U32 & String) -> Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>:
  (s, _r) = got
  (s, Fail{e})

# The counts answer: the stream form's (total, chunks) plus the unread
# bytes; the response half stays the dummy the buffered form owns.
def client.counts_out(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +total: U32, +chunks: U32, +rest: List<&2, U32>) -> Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>:
  (s, _r) = got
  (s, Done{((total, chunks), HTTP.Response{0, Nil{}, Nil{}}, rest)})

# The client loop, phase by phase: 0/1/2 read the head (16KB a turn, 64
# turns, the blank-line cut, and the 64 KiB budget of Phase 4.5: the
# accumulation is tail-safe, and past the budget the read routes to the
# empty-fuel arm, which answers the 413 of the floor -- the client
# never answered 431 and keeps not answering it); 3 parses, frames through
# x_h1.frame_of and hands the head over; 4 drops an interim 1xx and
# re-seeds, or routes the head answer; 5 routes that answer (the
# buffered form answers a bodiless or finished body at once); 6 asks
# the framing for the next chunk; 7 delivers it and acts; 9 reads more
# body and 10 takes the read back (a peer that closes mid-body is 400
# "eof"); 13 routes the chunked terminator. act rides the last answer
# decoded to a code.
#
# The two forms share every read phase; collect only picks the answer.
# collect=True folds each chunk onto the reversed body and answers one
# Response (the client sibling of the buffered server fold);
# collect=False hands each chunk to the pure handler and answers the
# counts (total bytes, chunks delivered). The body reads keep the fuel
# floor of the chain the fold replaces for collect=True only: the
# stream machine the loop absorbed read its body without one. Every
# post-head arm threads the real fuel for that floor -- the absorbed
# machine passed 0n there because it never read the value, and a 0n
# seed would fire the floor at the first body read.
#
# The entries close the socket, not the loop: the on entries need the
# socket and the unread bytes back to send the next request, so the
# loop answers counts, response and leftover in one triple. The
# buffered answers carry the real leftover, which the read chain the
# fold replaces always dropped -- the on entries re-seed the next head
# read with those bytes, so a peer that pipelines the next answer
# loses none.
@unsafe
def loop.client(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~H: HTTP.StreamEv -> HTTP.StreamOut, phase: U32, +collect: Bool, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool, +method: String, +nbody: Bool, +chunked: Bool, +cl: U32, +pending: List<&2, U32>, +seen: U32, +cst: HTTP.ChunkSt, act: U32, out: HTTP.ChunkSt & HTTP.UnitOut, +total: U32, +chunks: U32, hres: Result<&1, &1, U32 & String, HTTP.Head>, rev: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          do IO<Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            loop.client(~recv, ~H, 1, collect, r, acc, f, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (s1, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (s1, Fail{(400, "eof")}))
            case h <> t:
              # The accumulation and the budget of client.head, the
              # same wiring (TASK-081 Phase 4.5).
              +acc2 = HTTP.x_cat(HTTP.x_rev_push(part, HTTP.x_cat(acc)))
              +over = x_h1.cli_head_over(HTTP.x_len32(acc2))
              loop.client(~recv, ~H, x_h1.head_phase(over), collect, (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), x_h1.split.test(acc2), method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
    case 2:
      match found:
        case True{}:
          loop.client(~recv, ~H, 3, collect, got, acc, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, client.stream.parsed(acc), rev)
        case False{}:
          loop.client(~recv, ~H, 0, collect, got, acc, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
    case 3:
      match hres:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, e))
        case Done{+hd}:
          match hd:
            case HTTP.Head{+code, +hs}:
              # `found` carries the interim flag into phase 4 (the slot is
              # free after phase 2): a 1xx head is dropped without ever
              # reaching the handler (TASK-042 phase 4b).
              loop.client(~recv, ~H, 4, collect, got, acc, fuel, x_h1.is_info(code), method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
    case 4:
      match found:
        case True{}:
          +rest = x_h1.split_rest(x_h1.split(acc))
          loop.client(~recv, ~H, 2, collect, got, rest, fuel, x_h1.split.test(rest), method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
        case False{}:
          match hres:
            case Fail{e}:
              IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, e))
            case Done{+hd}:
              match hd:
                case HTTP.Head{+code, +hs}:
                  +fr = x_h1.frame_of(hs, method, code)
                  +nb = frame.nbody(fr)
                  loop.client(~recv, ~H, 5, collect, got, Nil{}, fuel, False{}, method, nb, frame.chunked(fr), frame.cl(fr), x_h1.split_rest(x_h1.split(acc)), 0, x_h1.chunk_init(), client.fold.ans_of(~H, hd, collect, nb), (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres, Nil{})
    case 5:
      match act:
        case 0:
          loop.client(~recv, ~H, 6, collect, got, Nil{}, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, 4, frame.next(chunked, cst, pending, cl, seen), total, chunks, hres, rev)
        case 1:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.fold.answer(got, hres, rev, total, chunks, pending))
        case 3:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, (8, "cancelled")))
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.counts_out(got, total, chunks, pending))
    case 6:
      match out:
        case (st2, o):
          match o:
            case HTTP.Got{+chunk, +fin, +rest}:
              +seen2 = (seen + HTTP.x_len32(chunk) : U32)
              loop.client(~recv, ~H, client.fold.got_phase(collect), collect, got, Nil{}, fuel, False{}, method, nbody, chunked, cl, rest, seen2, st2, client.fold.got_ans(~H, chunk, fin, chunked, collect), (x_h1.chunk_init(), HTTP.End{Nil{}}), (total + HTTP.x_len32(chunk) : U32), (chunks + 1 : U32), hres, client.fold.got_rev(chunk, rev, collect))
            case HTTP.NeedMore{missing, +rest}:
              loop.client(~recv, ~H, 9, collect, got, Nil{}, fuel, False{}, method, nbody, chunked, cl, rest, seen, st2, act, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres, rev)
            case HTTP.End{+rest}:
              loop.client(~recv, ~H, 13, collect, got, Nil{}, fuel, False{}, method, nbody, chunked, cl, rest, seen, cst, act, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres, rev)
            case HTTP.Bad{code, msg}:
              IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, (400, "bad chunked")))
    case 7:
      match act:
        case 0:
          loop.client(~recv, ~H, 5, collect, got, Nil{}, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, 0, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres, rev)
        case 3:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, (8, "cancelled")))
        case _:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.counts_out(got, total, chunks, pending))
    case 9:
      match collect:
        case True{}:
          (s9, _r9) = got
          match fuel:
            case 0n:
              IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, (413, "response too long")))
            case 1n+f:
              do IO<Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s9, 16384)
                loop.client(~recv, ~H, 10, collect, r, acc, f, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
        case False{}:
          (s9b, _r9b) = got
          do IO<Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s9b, 16384)
            loop.client(~recv, ~H, 10, collect, r, acc, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres, rev)
    case 10:
      (s10, r10) = got
      match r10:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (s10, Fail{e}))
        case Done{+part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (s10, Fail{(400, "eof")}))
            case h <> t:
              +pend2 = List.append(&2, U32, pending, part)
              loop.client(~recv, ~H, 5, collect, (s10, Done{Nil{}}), Nil{}, fuel, False{}, method, nbody, chunked, cl, pend2, seen, cst, 0, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres, rev)
    case 13:
      match collect:
        case True{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.fold.answer(got, hres, rev, total, chunks, pending))
        case False{}:
          loop.client(~recv, ~H, 7, collect, got, Nil{}, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, client.stream.data_act(H(HTTP.StreamData{Nil{}, True{}}), True{}), (x_h1.chunk_init(), HTTP.End{Nil{}}), total, (chunks + 1 : U32), hres, rev)
    case _:
      IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, client.err_out(got, (502, "bad phase")))

# The stream form's dummy handler: the buffered fold never emits an
# event, and the loop needs some handler to carry.
def client.no_event(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  HTTP.StreamContinue{}

# The read start after one send: a failed send reports, a sent socket
# enters the loop at the head-routing phase with the seed. The socket
# arrives dialed -- the entries name no transport and no dial.
def client.sent(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~H: HTTP.StreamEv -> HTTP.StreamOut, collect: Bool, sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String, +seed: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{u}:
      loop.client(~recv, ~H, 2, collect, (sock, Done{Nil{}}), seed, 64n, x_h1.split.test(seed), method, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), 4, (x_h1.chunk_init(), HTTP.End{Nil{}}), 0, 0, client.stream.no_head(), Nil{})

# One exchange over the loop: render, send, read. The seed is the
# leftover of the previous answer on the same connection, so a re-seeded
# entry never loses pipelined bytes.
def client.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~H: HTTP.StreamEv -> HTTP.StreamOut, collect: Bool, sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String, +seed: List<&2, U32>) -> IO(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>):
  match rendered:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+bytes}:
      do IO<Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        client.sent(~recv, ~H, collect, sent, method, seed)

# Closes the socket and answers the collected response.
def client.once.close(~close: Socket -> IO(Unit), s: Socket, r: Result<&1, &1, U32 & String, HTTP.Response>) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
    x : Unit <- close(s)
    IO.pure(Result<&1, &1, U32 & String, HTTP.Response>, r)

# Closes the socket and answers the collected responses.
def client.on.close(~close: Socket -> IO(Unit), s: Socket, r: Result<&1, &1, U32 & String, List<&2, HTTP.Response>>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    x : Unit <- close(s)
    IO.pure(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>, r)

# Closes the socket and answers the counts of one streamed exchange.
def client.stream.fin(~close: Socket -> IO(Unit), out: Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, r) = out
  match r:
    case Fail{e}:
      client.stream.close(~close, s, Fail{e})
    case Done{ans}:
      match ans:
        case ((t, c), resp, rest):
          client.stream.close(~close, s, Done{(t, c)})

# Closes the socket and answers the collected response.
def client.once.fin(~close: Socket -> IO(Unit), out: Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  (s, r) = out
  match r:
    case Fail{e}:
      client.once.close(~close, s, Fail{e})
    case Done{ans}:
      match ans:
        case ((t, c), resp, rest):
          client.once.close(~close, s, Done{resp})

# The client dials (TASK-081 Phase 3, user decision): the module names
# its own transports on the client side. The plain dial speaks TCP by
# address; resolve the name first when the host is not an address. The
# secure dial verifies the chain and the insecure dial does not
# (_insecure is the house word for a loopback or self-signed cert);
# both offer no ALPN, so the H1 lane owns the protocol. Every entry
# has a _secure and an _insecure twin over these dials.
def client.connect(+host: String, +port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  TCP.connect(host, port)

def client.connect_secure(+host: String, +port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  TLS.tls_connect_noalpn(host, port)

def client.connect_insecure(+host: String, +port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  TLS.tls_connect_noalpn_insecure(host, port)

# The close-and-report leaf of the dialed vectors: a failed handshake
# closes the socket and answers Fail; a done one answers the socket,
# the response and the rest in one triple, so the caller owns the
# transport after the 101.
def client.open.rewrap(~close: Socket -> IO(Unit), out: Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>):
  (s, r) = out
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, Fail{e})
    case Done{pr}:
      (resp, rest) = pr
      IO.pure(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, Done{(s, resp, rest)})

# The conn arm of the open family: a failed dial owns no socket, so its
# Fail goes out with no close; a done dial runs the exchange and the
# rewrap closes on a failed handshake.
def client.open.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- client.open.exch(~recv, ~send, ~close, sock, host, port, method, path, hs, body)
        client.open.rewrap(~close, out)

# The open handshake over TCP: dial, run the exchange, answer the
# socket, the response and the rest.
def client.open(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect(host, port)
    client.open.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, conn, host, port, method, path, hs, body)

# The open handshake over verified TLS.
def client.open_secure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_secure(host, port)
    client.open.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, method, path, hs, body)

# The open handshake over TLS without chain verify.
def client.open_insecure(+host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>):
  do IO<Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_insecure(host, port)
    client.open.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, method, path, hs, body)

# The conn arm of one streamed request: a dialed socket, the body
# events to the handler, close. The templates stay open, so a caller
# that dials itself drives the same core.
def client.stream.once.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        out : Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>> <- client.exch(~recv, ~send, ~H, False{}, sock, x_h1.render_req(method, path, host, port, hs, body), method, Nil{})
        client.stream.fin(~close, out)

# One streamed request over TCP: dial, count the body events, close.
# The render gate answers 400 before any byte leaves, the code the
# deleted one-shot wrapper answered.
def client.stream.once(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect(host, port)
    client.stream.once.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, conn, host, port, method, path, hs, body)

# One streamed request over verified TLS.
def client.stream.once_secure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_secure(host, port)
    client.stream.once.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, conn, host, port, method, path, hs, body)

# One streamed request over TLS without chain verify.
def client.stream.once_insecure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_insecure(host, port)
    client.stream.once.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, conn, host, port, method, path, hs, body)

# The conn arm of one buffered request: a dialed socket, one folded
# exchange, close. The request rides one HTTP.Request, the signature of
# the H2 client.once twin.
def client.once.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, req: HTTP.Request) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, HTTP.Response>, Fail{e})
    case Done{sock}:
      match req:
        case HTTP.Request{+method, +path, +hs, +body}:
          do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
            out : Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>> <- client.exch(~recv, ~send, ~client.no_event, True{}, sock, x_h1.render_req(method, path, host, port, hs, body), method, Nil{})
            client.once.fin(~close, out)

# One buffered request over TCP: dial, fold the whole answer into one
# Response, close.
def client.once(+host: String, +port: U32, req: HTTP.Request) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect(host, port)
    client.once.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, conn, host, port, req)

# One buffered request over verified TLS.
def client.once_secure(+host: String, +port: U32, req: HTTP.Request) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_secure(host, port)
    client.once.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, req)

# One buffered request over TLS without chain verify.
def client.once_insecure(+host: String, +port: U32, req: HTTP.Request) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_insecure(host, port)
    client.once.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, req)

# The keep-alive batch of streamed requests: each answer's leftover
# seeds the next read on the same socket, the counts add up, the close
# runs once at the end. The recursion rides the request list.
def client.stream.on.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, rest: List<&2, HTTP.Request>, +host: String, +port: U32, +tot: U32, +chks: U32, got: Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  match rest:
    case Nil{}:
      (s, r) = got
      match r:
        case Fail{e}:
          client.stream.close(~close, s, Fail{e})
        case Done{ans}:
          match ans:
            case ((t, c), resp, left):
              client.stream.close(~close, s, Done{((tot + t : U32), (chks + c : U32))})
    case HTTP.Request{+method, +path, +hs, +body} <> t:
      (s2, r2) = got
      match r2:
        case Fail{e}:
          client.stream.close(~close, s2, Fail{e})
        case Done{ans}:
          match ans:
            case ((t2, c2), resp, left):
              do IO<Result<&1, &1, U32 & String, U32 & U32>>:
                out : Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>> <- client.exch(~recv, ~send, ~H, False{}, s2, x_h1.render_req(method, path, host, port, hs, body), method, left)
                client.stream.on.go(~recv, ~send, ~close, ~H, t, host, port, (tot + t2 : U32), (chks + c2 : U32), out)

# The conn arm of the streamed batch: N requests in order on one dialed
# socket, the counts add up, close once.
def client.stream.on.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, U32 & U32>, Fail{e})
    case Done{sock}:
      match reqs:
        case Nil{}:
          client.stream.close(~close, sock, Done{(0, 0)})
        case HTTP.Request{+method, +path, +hs, +body} <> t:
          do IO<Result<&1, &1, U32 & String, U32 & U32>>:
            out : Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>> <- client.exch(~recv, ~send, ~H, False{}, sock, x_h1.render_req(method, path, host, port, hs, body), method, Nil{})
            client.stream.on.go(~recv, ~send, ~close, ~H, t, host, port, 0, 0, out)

# N streamed requests in order over TCP: the sequential reuse the
# server loop owns, counted.
def client.stream.on(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect(host, port)
    client.stream.on.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, conn, host, port, reqs)

# N streamed requests in order over verified TLS.
def client.stream.on_secure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_secure(host, port)
    client.stream.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, conn, host, port, reqs)

# N streamed requests in order over TLS without chain verify.
def client.stream.on_insecure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_insecure(host, port)
    client.stream.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, conn, host, port, reqs)

# The keep-alive batch of buffered requests: the responses collect in
# request order, each leftover seeds the next read, the close runs once
# at the end. The recursion rides the request list.
def client.on.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), rest: List<&2, HTTP.Request>, +host: String, +port: U32, acc: List<&2, HTTP.Response>, got: Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  match rest:
    case Nil{}:
      (s, r) = got
      match r:
        case Fail{e}:
          client.on.close(~close, s, Fail{e})
        case Done{ans}:
          match ans:
            case ((t, c), resp, left):
              client.on.close(~close, s, Done{List.reverse(&2, HTTP.Response, resp <> acc)})
    case HTTP.Request{+method, +path, +hs, +body} <> t:
      (s2, r2) = got
      match r2:
        case Fail{e}:
          client.on.close(~close, s2, Fail{e})
        case Done{ans}:
          match ans:
            case ((t2, c2), resp, left):
              do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
                out : Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>> <- client.exch(~recv, ~send, ~client.no_event, True{}, s2, x_h1.render_req(method, path, host, port, hs, body), method, left)
                client.on.go(~recv, ~send, ~close, t, host, port, resp <> acc, out)

# The conn arm of the buffered batch: N requests in order on one dialed
# socket, the whole responses in request order, close once.
def client.on.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), conn: Result<&1, &1, U32 & String, Socket>, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  match conn:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>, Fail{e})
    case Done{sock}:
      match reqs:
        case Nil{}:
          client.on.close(~close, sock, Done{Nil{}})
        case HTTP.Request{+method, +path, +hs, +body} <> t:
          do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
            out : Socket & Result<&1, &1, U32 & String, (U32 & U32) & HTTP.Response & List<&2, U32>> <- client.exch(~recv, ~send, ~client.no_event, True{}, sock, x_h1.render_req(method, path, host, port, hs, body), method, Nil{})
            client.on.go(~recv, ~send, ~close, t, host, port, Nil{}, out)

# N buffered requests in order over TCP.
def client.on(+host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect(host, port)
    client.on.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, conn, host, port, reqs)

# N buffered requests in order over verified TLS.
def client.on_secure(+host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_secure(host, port)
    client.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, reqs)

# N buffered requests in order over TLS without chain verify.
def client.on_insecure(+host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  do IO<Result<&1, &1, U32 & String, List<&2, HTTP.Response>>>:
    conn : Result<&1, &1, U32 & String, Socket> <- client.connect_insecure(host, port)
    client.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, conn, host, port, reqs)

# H1 streaming upload (Phase 6): the H1 leg of server.stream, speaking
# SrvEv/SrvOut like the H2 httpx_stream lane in ./http2.bend. One request
# per connection, then close: no keep-alive, no pipelining. Backpressure
# is the read itself — at most one recv per chunk, so a handler that stops
# saying Continue stops the reads. Slot is 1: H1 has no stream ids, and
# 1 is also the sid the H2 client opens with. Cancel closes without a
# response (the answer the tree's CT.Cancel gives); RespondEarly renders
# and closes. A malformed chunked body is 400, the code the one-shot H1
# server answers. Transport is three templates like every server lane.
# ---------------------------------------------------------------------

# What the head answer means: 0 go read the body, 1 respond now,
# 2 close without responding. Asking for more on a message with no
# body is a close — there is no chunk coming.
def server.stream.head_body(nbody: Bool, +resp: HTTP.Response) -> U32 & HTTP.Response:
  match nbody:
    case True{}:
      (2, resp)
    case False{}:
      (0, resp)

def server.stream.head_act(+out: HTTP.SrvOut, nbody: Bool) -> U32 & HTTP.Response:
  match out:
    case HTTP.Continue{}:
      server.stream.head_body(nbody, HTTP.Response{0, Nil{}, Nil{}})
    case HTTP.RespondEarly{+resp}:
      (1, resp)
    case HTTP.Cancel{}:
      (2, HTTP.Response{0, Nil{}, Nil{}})

# What one body chunk answer means. Continue past the last chunk is a
# close — there is nothing left to hand over.
def server.stream.data_act(+out: HTTP.SrvOut, +fin: Bool) -> U32 & HTTP.Response:
  match out:
    case HTTP.Continue{}:
      match fin:
        case True{}:
          (2, HTTP.Response{0, Nil{}, Nil{}})
        case False{}:
          (0, HTTP.Response{0, Nil{}, Nil{}})
    case HTTP.RespondEarly{+resp}:
      (1, resp)
    case HTTP.Cancel{}:
      (2, HTTP.Response{0, Nil{}, Nil{}})

# The answer path always closes: one request per connection on this
# lane, so there is no keep-alive decision to make.
def server.stream.sent_close(~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = sent
  close(s)

# Renderability gate for a handler response (TASK-030). x_h1.show_resp and
# x_h1.show_resp_head render the handler's headers through the same
# x_h1.render_hs.go the client uses, verbatim, so a CR/LF/NUL in a name or
# value would end the field early and ship the rest as response headers
# nobody asked for — response splitting, and the classic way to get one is
# a decoded query/path echoed into Location or Set-Cookie.
#
# The whole response is replaced by a bare 500 rather than dropping the
# offending field: rendering it at all IS the injection, and silently
# shipping a narrower response than the handler asked for hides the bug
# that produced it. A 101 with bad headers falls into the same 500, so the
# upgrade is refused instead of half-negotiated.
#
# TASK-081 moved the gate above the stream answer: every handler answer
# rides it now. The stream RespondEarly path used to render verbatim, so
# a pure handler shipped the split the buffered lane refused.
def server.safe_resp.go(+status: U32, +headers: List<&2, HTTP.Hdr>, +body: List<&2, U32>, bad: Bool) ->
  HTTP.Response:
  match bad:
    case True{}:
      HTTP.Response{500, Nil{}, Nil{}}
    case False{}:
      HTTP.Response{status, headers, body}

def server.safe_resp(resp: HTTP.Response) -> HTTP.Response:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      server.safe_resp.go(status, headers, body, x_h1.bad_hdrs(headers))

# The rendered half of the stream answer, matched on the checked response:
# a computed match is illegal, so the gate's answer rides a parameter.
def server.stream.respond.go(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, +resp: HTTP.Response) -> IO(Unit):
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(s, x_h1.show_resp(status, headers, body))
        server.stream.sent_close(~close, sent)

def server.stream.respond(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +resp: HTTP.Response) -> IO(Unit):
  (s, r) = got
  server.stream.respond.go(~send, ~close, s, server.safe_resp(resp))

def server.stream.closed(~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = got
  close(s)

def server.stream.bad(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  server.stream.respond(~send, ~close, got, HTTP.Response{400, Nil{}, Nil{}})

# A terminal code the peer must see before the connection ends: the same
# rule the keep-alive machine uses (400..599 is a status this server
# renders; 0 "close" and the 6xx transport codes are not).
def server.stream.told_go(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +code: U32, told: Bool) -> IO(Unit):
  match told:
    case True{}:
      server.stream.respond(~send, ~close, got, HTTP.Response{code, Nil{}, Nil{}})
    case False{}:
      server.stream.closed(~close, got)

def server.stream.told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +code: U32) -> IO(Unit):
  server.stream.told_go(~send, ~close, got, code, server.is_status(code))

# The terminal code of a failed head read: 400/413/431/502 ride out as a
# response, 0 "close" and the transport codes do not.
def server.stream.stop_told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, e: U32 & String) -> IO(Unit):
  (code, msg) = e
  server.stream.told(~send, ~close, got, code)

# The head answer slot for a validated head: the handler's head event when
# the head is clean, the refusal code when it is not (the handler never
# sees a refused request). The code rides in the slot's first half and the
# loop routes on it with server.stream.err_phase, so a match never has to
# scrutinize a computed value.
def server.stream.head_ans(~H: HTTP.SrvEv -> HTTP.SrvOut, +code: U32, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, nb: Bool) -> U32 & HTTP.Response:
  match code:
    case 0:
      server.stream.head_act(H(HTTP.SrvReqHead{1, HTTP.ReqHead{m, p, hs}}), nb)
    case _:
      (code, HTTP.Response{0, Nil{}, Nil{}})

def server.stream.err_phase(+code: U32) -> U32:
  match code:
    case 0:
      5
    case _:
      4

def server.stream.no_ans() -> U32 & HTTP.Response:
  (0, HTTP.Response{0, Nil{}, Nil{}})

def server.stream.no_head() -> Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>:
  (Fail{(400, "bad request")}, Nil{})

# got B (TASK-040): one x_h1.split traversal for head-lines and rest,
# where the pair rides in as a parameter (E1 rejects a computed variant).
def server.stream.parsed.got(p: List<&2, U32> & List<&2, U32> & Bool) -> Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>:
  match p:
    case (head, rest, found):
      +hl = x_h1.head_lines(head)
      (x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))), rest)

# The request head, parsed. The bytes that arrived with the head seed
# the pending buffer — a request that arrives whole in one packet must
# not lose its body.
def server.stream.parsed(+acc: List<&2, U32>) -> Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>:
  server.stream.parsed.got(x_h1.split(acc))

# The answer ladder the buffered form owns: needs_body and sock_of are
# shared leaves, then the read_next/stop pair every answer returns
# through, the told family (a terminal code the peer must see), and the
# respond/answer pair the fold and the open lane both call. The keep-alive
# decision lives in loop.server's phase 8, fed by this ladder.
# ---------------------------------------------------------------------

def server.needs_body(+m: String) -> Bool:
  Bool.not(Bool.or(String.eq(m, "GET"), String.eq(m, "HEAD")))

def server.sock_of(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> Socket:
  (s, r) = got
  s

# The answer path never closes the socket: it hands it back to the server
# loop in the very pair type the read phases use, so the loop's re-entry
# phase is the single place that decides reuse vs close.
#   read_next(s, rest) -> Done{rest}: the answer is out, read the next
#     request, seeded with the bytes already read past this one.
#   stop(s, e)         -> Fail{e}: this connection ends here. e is the
#     send/read error, or (413/502, ...) for a terminal answer, or
#     (0, "close") for a peer that asked for close.
# Fail already means "stop" in the read phases, so no second outcome type
# is invented. The loop cannot be a mutual recursion (respond -> loop ->
# fold -> ... -> respond): Bend only sees defs already defined, so
# loop.server is the one def allowed to loop and the answer path ends by
# returning to it.
def server.read_next(s: Socket, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
    (s, Done{rest}))

def server.stop(s: Socket, e: U32 & String) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (code, msg) = e
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
    (s, Fail{(code, msg)}))

# A terminal code the peer must see before the connection ends: 400..599 is
# a status this server renders (the parse errors, the 413 caps, the 431
# head cap), 0 ("close") and the 6xx transport codes (TLS/DNS) are not, and
# a send that already failed is not retried.
def server.told_sent(~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, r2) = sent
  close(s2)

def server.told_go(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, +code: U32, told: Bool) -> IO(Unit):
  match told:
    case True{}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(s, x_h1.show_resp(code, Nil{}, Nil{}))
        server.told_sent(~close, sent)
    case False{}:
      close(s)

def server.told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, e: U32 & String) -> IO(Unit):
  (+code, msg) = e
  server.told_go(~send, ~close, s, code, server.is_status(code))

def server.cap_told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket) -> IO(Unit):
  server.told(~send, ~close, s, (x_h1.head_cap(), "head too large"))

def server.sent_keep(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s2, r2) = sent
  match r2:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
        (s2, Fail{e}))
    case Done{u}:
      match keep:
        case True{}:
          server.read_next(s2, rest)
        case False{}:
          server.stop(s2, (0, "close"))

def server.respond(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +resp: HTTP.Response, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, x_h1.show_resp(status, headers, body))
        server.sent_keep(~recv, ~send, ~close, sent, keep, rest)

def server.answer(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +req: HTTP.Request, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s, r) = got
  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
    resp : HTTP.Response <- H(req)
    server.respond(~recv, ~send, ~close, s, server.safe_resp(resp), keep, rest)

def server.recv(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s0, r0) = got
  recv(s0, 16384)

# The four loops (TASK-081 Phase 1): the server lane rides one loop, two
# forms. The stream form answers each event with the pure handler, one
# request per connection. The buffered form collects the whole request,
# calls the IO handler once and keeps the connection alive. The machines
# the loop replaced are gone (bd, cl, chunk, go, checked, ruled, parsed,
# head, serve_start, h1_spawn, h1_conn, stream.go, stream.start,
# stream.spawn, stream.conn); what remains serves the open lane and the
# client lanes. Phase 2 split the open head reader off, the server.pre
# shape of the H2 module: loop.pre.open feeds server.open, the 101
# machine of the server namespace (the loop name belongs to the fuel
# machines only). The buffered reader stays here, in phases 0/1/2: the
# keep-alive re-seed (phase 8) re-enters it every request, and Bend
# forbids the mutual recursion a split would create.
# Phase 3 added the client loop: loop.client reads one answer in the
# two forms, collect=True folds the whole response (client.once,
# client.on) and collect=False counts the events (client.stream.once,
# client.stream.on). The one-shot wrapper the fold replaced
# (x_h1.exch, x_h1.exch.done) and the stream machine it absorbed
# (x_h1.cli.stream.go and its entries) are gone; the plain read chain
# (client.head through bd/chunk) stays, because the open lane
# (Phase 4) and the direct tests drive it.
# Phase 4 closed the open lane: client.open is the 101 machine of the
# client namespace, the ladder client.open.sent/send/fit feeds it, and
# the wsm calls client.open.exch (the old alias is gone, TASK-082). Both
# client head reads (this loop and client.head) now carry the 16384
# byte cap: past it the empty-fuel arm answers 413, because the raw
# List.append faults near 32k cells and the 64-turn floor could never
# fire first.
# ---------------------------------------------------------------------

# The two forms of the server loop, the names the H2 module already
# owns. The act tables carry the form; the loop only reads it.
def server.form.stream() -> U32:
  1

def server.form.buffered() -> U32:
  0

# The handler a form does not use. The stream form never calls the IO
# one, and the buffered form never calls the event one.
def server.no_event(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  HTTP.Continue{}

def server.no_buffered(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{0, Nil{}, Nil{}})

# The form branches of the deep loop arms. Bend refuses a match on a
# parameter past the third arm, so every branch below matches `form` in
# a def of its own and the arms only route on the answers.
# ---------------------------------------------------------------------

# The buffered fold's head routing: 0 read the body, 1 answer now (the
# method carries no body), 2 refuse with 413 (a Content-Length past the
# 16384 cap). A chunked body answers 0 whatever the length field says,
# like the buffered lane it replaces.
def server.fold.head_go(nbody: Bool, chunked: Bool, +cl: U32) -> U32:
  match nbody:
    case True{}:
      1
    case False{}:
      match chunked:
        case True{}:
          0
        case False{}:
          Bool.pick(U32, U32.is_gt(cl, 16384), 2, 0)

# The head answer of one form: the buffered fold routes on its own
# table, the stream form asks the handler. The parse arm of the loop
# cannot match `form` that deep, so the branch lives here.
def server.fold.ans_of(~H: HTTP.SrvEv -> HTTP.SrvOut, +code: U32, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, nb: Bool, chunked: Bool, +cl: U32, +form: U32) -> U32 & HTTP.Response:
  match form:
    case 0:
      (server.fold.head_go(nb, chunked, cl), HTTP.Response{0, Nil{}, Nil{}})
    case _:
      server.stream.head_ans(~H, code, m, p, hs, nb)

# The next phase after one body chunk: the buffered fold takes it back,
# the stream form routes the data event.
def server.fold.got_phase(+form: U32) -> U32:
  match form:
    case 0:
      11
    case _:
      7

# The buffered fold's chunk routing: 0 keep reading (the length field is
# not the end of a chunked body, the terminator is), 1 the length-
# delimited body is whole, 2 the decoded body passed the 16384 cap.
def server.fold.got_route(over: Bool, chunked: Bool, fin: Bool) -> U32:
  match over:
    case True{}:
      2
    case False{}:
      match chunked:
        case True{}:
          0
        case False{}:
          match fin:
            case True{}:
              1
            case False{}:
              0

# The answer of one body chunk: the buffered fold routes on its own
# table, the stream form asks the handler about the event.
def server.fold.got_ans(~H: HTTP.SrvEv -> HTTP.SrvOut, +chunk: List<&2, U32>, +fin: Bool, chunked: Bool, over: Bool, +form: U32) -> U32 & HTTP.Response:
  match form:
    case 0:
      (server.fold.got_route(over, chunked, fin), HTTP.Response{0, Nil{}, Nil{}})
    case _:
      server.stream.data_act(H(HTTP.SrvReqData{1, chunk, fin}), fin)

# The body accumulator of one form: the buffered fold pushes the chunk,
# the stream form holds nothing.
def server.fold.got_rev(+chunk: List<&2, U32>, rev: List<&2, U32>, +form: U32) -> List<&2, U32>:
  match form:
    case 0:
      HTTP.x_rev_push(chunk, rev)
    case _:
      rev

# The buffered fold's end-of-body: a close mid-body. The buffered form
# answers 400 "eof" like the machine it replaces; the stream form closes
# silently. The branch rides a helper because the loop arm sits too deep
# for a match on `form`.
def server.fold.eof(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +form: U32) -> IO(Unit):
  match form:
    case 0:
      server.told(~send, ~close, server.sock_of(got), (400, "eof"))
    case _:
      server.stream.closed(~close, got)

# The buffered fold's answer: the request from the threaded head pieces
# plus the folded body, through the answer ladder the buffered lane owns
# (the 500 guard, the keep-alive seed, the close).
def server.fold.answer(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~B: HTTP.Request -> IO(HTTP.Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, rev: List<&2, U32>, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  server.answer(~recv, ~send, ~close, ~B, got, HTTP.Request{m, p, hs, HTTP.x_cat(rev)}, Bool.not(x_h1.conn_close(hs)), rest)

# The server loop, phase by phase: 0/1/2 read the head (16 KB a turn,
# 64 turns, answer 431 past either cap); 3 parses, validates and frames
# the head (400 before any body byte) and threads the request pieces; 4
# refuses a bad head; 5 routes the head answer; 6 takes the framing
# answer back; 7 routes the data answer of the stream form; 8 re-seeds
# the keep-alive; 9/10 read more body; 11 takes the buffered body answer
# back (the chunk route rides `ans`); 12 routes the read the framing
# asked for; 13 routes the chunked terminator. The stream form closes
# after one request, its H1 contract. The buffered form answers and
# reads the next head.
#
# The head accumulator keeps `List.append` under the 16384 cap of
# x_h1.head_max, the margin the probes measured (the raw append dies
# between 24577 and 32768 cells). Raise the cap and the append grows past
# that stack limit; swap the accumulator for x_rev_push first, the way
# the body reader already did.
#
# A malformed chunked body is 400 once, then the connection closes. The
# buffered machine it replaces answered 400 twice: the respond ran, then
# the stop carried (400, "bad chunked") into the told path, and the told
# rendered a second status line nobody asked for.
@unsafe
def loop.server(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), phase: U32, +form: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool, +nbody: Bool, +chunked: Bool, +cl: U32, +pending: List<&2, U32>, +seen: U32, +cst: HTTP.ChunkSt, ans: U32 & HTTP.Response, out: HTTP.ChunkSt & HTTP.UnitOut, head: Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>, rev: List<&2, U32>, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          server.stream.told(~send, ~close, got, x_h1.head_cap())
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            loop.server(~recv, ~send, ~close, ~H, ~B, 1, form, r, acc, f, False{}, nbody, chunked, cl, pending, seen, cst, ans, out, head, rev, m, p, hs)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          close(s1)
        case Done{+part}:
          match part:
            case Nil{}:
              close(s1)
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              +over = x_h1.head_over(HTTP.x_len32(acc2))
              loop.server(~recv, ~send, ~close, ~H, ~B, x_h1.head_phase(over), form, (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), x_h1.split.test(acc2), nbody, chunked, cl, pending, seen, cst, ans, out, head, rev, m, p, hs)
    case 2:
      match found:
        case True{}:
          loop.server(~recv, ~send, ~close, ~H, ~B, 3, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, ans, out, server.stream.parsed(acc), rev, m, p, hs)
        case False{}:
          loop.server(~recv, ~send, ~close, ~H, ~B, 0, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, ans, out, head, rev, m, p, hs)
    case 3:
      match head:
        case (h3, p3):
          match h3:
            case Fail{e}:
              server.stream.stop_told(~send, ~close, got, e)
            case Done{+rh}:
              match rh:
                case HTTP.H1Head{head2, is_11}:
                  match head2:
                    case HTTP.ReqHead{+m, +p, +hs}:
                      +code = server.head_err(hs, is_11)
                      +nb = Bool.or(String.eq(m, "GET"), String.eq(m, "HEAD"))
                      +ch2 = x_h1.is_chunked(hs)
                      +cl2 = x_h1.cl_of(hs)
                      loop.server(~recv, ~send, ~close, ~H, ~B, server.stream.err_phase(code), form, got, Nil{}, fuel, False{}, nb, ch2, cl2, p3, 0, x_h1.chunk_init(), server.fold.ans_of(~H, code, m, p, hs, nb, ch2, cl2, form), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, m, p, hs)
    case 4:
      match ans:
        case (a4, resp4):
          server.stream.told(~send, ~close, got, a4)
    case 5:
      match form:
        case 0:
          match ans:
            case (a5, resp5):
              match a5:
                case 0:
                  loop.server(~recv, ~send, ~close, ~H, ~B, 6, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), frame.next(chunked, cst, pending, cl, seen), head, rev, m, p, hs)
                case 1:
                  do IO<Unit>:
                    out5 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.fold.answer(~recv, ~send, ~close, ~B, got, m, p, hs, rev, pending)
                    loop.server(~recv, ~send, ~close, ~H, ~B, 8, form, out5, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, m, p, hs)
                case _:
                  do IO<Unit>:
                    out5b : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, server.sock_of(got), HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
                    loop.server(~recv, ~send, ~close, ~H, ~B, 8, form, out5b, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, Nil{}, m, p, hs)
        case _:
          match ans:
            case (a5, resp5):
              match a5:
                case 0:
                  loop.server(~recv, ~send, ~close, ~H, ~B, 6, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), frame.next(chunked, cst, pending, cl, seen), head, rev, m, p, hs)
                case 1:
                  server.stream.respond(~send, ~close, got, resp5)
                case _:
                  server.stream.closed(~close, got)
    case 6:
      match out:
        case (st2, o):
          match o:
            case HTTP.Got{+chunk, +fin, +rest}:
              +seen2 = (seen + HTTP.x_len32(chunk) : U32)
              loop.server(~recv, ~send, ~close, ~H, ~B, server.fold.got_phase(form), form, got, acc, fuel, False{}, nbody, chunked, cl, rest, seen2, st2, server.fold.got_ans(~H, chunk, fin, chunked, U32.is_gt(seen2, 16384), form), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, server.fold.got_rev(chunk, rev, form), m, p, hs)
            case HTTP.NeedMore{missing, +rest}:
              loop.server(~recv, ~send, ~close, ~H, ~B, 12, form, got, acc, fuel, False{}, nbody, chunked, cl, rest, seen, st2, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, rev, m, p, hs)
            case HTTP.End{+rest}:
              loop.server(~recv, ~send, ~close, ~H, ~B, 13, form, got, acc, fuel, False{}, nbody, chunked, cl, rest, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, rev, m, p, hs)
            case HTTP.Bad{code, msg}:
              server.stream.bad(~send, ~close, got)
    case 7:
      match ans:
        case (a7, resp7):
          match a7:
            case 0:
              loop.server(~recv, ~send, ~close, ~H, ~B, 6, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), frame.next(chunked, cst, pending, cl, seen), head, rev, m, p, hs)
            case 1:
              server.stream.respond(~send, ~close, got, resp7)
            case _:
              server.stream.closed(~close, got)
    case 8:
      (s8, r8) = got
      match r8:
        case Fail{e}:
          server.told(~send, ~close, s8, e)
        case Done{+seed}:
          match seed:
            case Nil{}:
              loop.server(~recv, ~send, ~close, ~H, ~B, 0, form, (s8, Done{Nil{}}), Nil{}, 64n, False{}, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, "", "", Nil{})
            case h <> t:
              loop.server(~recv, ~send, ~close, ~H, ~B, 1, form, (s8, Done{seed}), Nil{}, 64n, False{}, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, "", "", Nil{})
    case 9:
      (s9, r9) = got
      do IO<Unit>:
        r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s9, 16384)
        loop.server(~recv, ~send, ~close, ~H, ~B, 10, form, r, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, rev, m, p, hs)
    case 10:
      (s10, r10) = got
      match r10:
        case Fail{e}:
          close(s10)
        case Done{+part}:
          match part:
            case Nil{}:
              server.fold.eof(~send, ~close, got, form)
            case h <> t:
              +pend2 = List.append(&2, U32, pending, part)
              loop.server(~recv, ~send, ~close, ~H, ~B, 6, form, (s10, Done{Nil{}}), acc, fuel, False{}, nbody, chunked, cl, pend2, seen, cst, server.stream.no_ans(), frame.next(chunked, cst, pend2, cl, seen), head, rev, m, p, hs)
    case 11:
      match ans:
        case (a11, resp11):
          match a11:
            case 2:
              do IO<Unit>:
                out11 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, server.sock_of(got), HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
                loop.server(~recv, ~send, ~close, ~H, ~B, 8, form, out11, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, Nil{}, m, p, hs)
            case 1:
              do IO<Unit>:
                out11b : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.fold.answer(~recv, ~send, ~close, ~B, got, m, p, hs, rev, pending)
                loop.server(~recv, ~send, ~close, ~H, ~B, 8, form, out11b, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, m, p, hs)
            case _:
              loop.server(~recv, ~send, ~close, ~H, ~B, 6, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), frame.next(chunked, cst, pending, cl, seen), head, rev, m, p, hs)
    case 12:
      match form:
        case 0:
          match fuel:
            case 0n:
              do IO<Unit>:
                out12 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, server.sock_of(got), HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
                loop.server(~recv, ~send, ~close, ~H, ~B, 8, form, out12, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, Nil{}, m, p, hs)
            case 1n+f:
              loop.server(~recv, ~send, ~close, ~H, ~B, 9, form, got, acc, f, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, rev, m, p, hs)
        case _:
          loop.server(~recv, ~send, ~close, ~H, ~B, 9, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, rev, m, p, hs)
    case 13:
      match form:
        case 0:
          do IO<Unit>:
            out13 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.fold.answer(~recv, ~send, ~close, ~B, got, m, p, hs, rev, pending)
            loop.server(~recv, ~send, ~close, ~H, ~B, 8, form, out13, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, m, p, hs)
        case _:
          loop.server(~recv, ~send, ~close, ~H, ~B, 7, form, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, server.stream.data_act(H(HTTP.SrvReqData{1, Nil{}, True{}}), True{}), (x_h1.chunk_init(), HTTP.End{Nil{}}), head, rev, m, p, hs)
    case _:
      server.stream.closed(~close, got)

# Per-connection entries over the loop, both forms.
def server.start(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), form: U32, sock: Socket) -> IO(Unit):
  loop.server(~recv, ~send, ~close, ~H, ~B, 0, form, (sock, Done{Nil{}}), Nil{}, 64n, False{}, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, "", "", Nil{})

def server.spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), form: U32, sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, server.start(~recv, ~send, ~close, ~H, ~B, form, sock))
    return l

def server.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, ~B: HTTP.Request -> IO(HTTP.Response), form: U32, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      server.spawn(~recv, ~send, ~close, ~H, ~B, form, sock, l)

# The stream form: the pure handler answers each event.
def server.stream.on.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  server.conn(~recv, ~send, ~close, ~H, ~server.no_buffered, server.form.stream(), m)

# The buffered form: the loop collects the whole request and the IO
# handler answers it once.
def server.buffered.on.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~B: HTTP.Request -> IO(HTTP.Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  server.conn(~recv, ~send, ~close, ~server.no_event, ~B, server.form.buffered(), m)

# The named accepts: the server side of the client dials. server.accept
# is the plain TCP accept; server.accept_secure is the TLS one with the
# certificate and key it serves. The server has no _insecure: it serves
# a certificate and verifies no chain, so there is no verify step to
# skip -- the _insecure word names the client's act.
def server.accept(l: Listener) -> IO(Listener & Result<&1, &1, U32 & String, Socket>):
  TCP.accept(l)

def server.accept_secure(l: Listener, +cert: String, +key: String) -> IO(Listener & Result<&1, &1, U32 & String, Socket>):
  TLS.tls_accept_http1(l, cert, key)

# The accept entries over the two forms, one twin per transport. A
# caller that owns its transport accepts itself and drives the .conn
# arms above. `once` counts connections, not requests.
def server.stream.once(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept(l)
    l2 : Listener <- server.stream.on.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, m)
    return Unit{}

def server.stream.once_secure(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept_secure(l, cert, key)
    l2 : Listener <- server.stream.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, m)
    return Unit{}

# The accept loop never shrinks the listener, so the checker cannot prove
# it ends. @unsafe marks only that loop, like every accept loop the
# facade owns today.
@unsafe
def server.stream.on(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept(l)
    l2 : Listener <- server.stream.on.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, m)
    z : Unit <- server.stream.on(~H, l2)
    return z

@unsafe
def server.stream.on_secure(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept_secure(l, cert, key)
    l2 : Listener <- server.stream.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, m)
    z : Unit <- server.stream.on_secure(~H, l2, cert, key)
    return z

def server.once(~B: HTTP.Request -> IO(HTTP.Response), l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept(l)
    l2 : Listener <- server.buffered.on.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~B, m)
    return Unit{}

def server.once_secure(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept_secure(l, cert, key)
    l2 : Listener <- server.buffered.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~B, m)
    return Unit{}

@unsafe
def server.on(~B: HTTP.Request -> IO(HTTP.Response), l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept(l)
    l2 : Listener <- server.buffered.on.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~B, m)
    z : Unit <- server.on(~B, l2)
    return z

@unsafe
def server.on_secure(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept_secure(l, cert, key)
    l2 : Listener <- server.buffered.on.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~B, m)
    z : Unit <- server.on_secure(~B, l2, cert, key)
    return z

# H1 upgrade lane (101): the answer path that lends the socket out. Unlike
# server.answer (which hands the socket BACK to the server loop's
# re-entry phase as read_next/stop), server.open.answer never returns
# the socket to the loop: on 101 it sends the head and calls ~K(sock,
# rest), and the
# socket stays with ~K until the WS loop closes it. Anything else answers
# through the normal respond and REJOINS loop.server (rejoin = the
# keep-alive re-entry phase with the leftover seed), so a ~H that refuses
# the upgrade reuses or closes exactly like the buffered form. The bytes
# on the wire are unchanged.
# A 101 body is dropped (a 101 carries none); only status and headers
# ride show_resp_head.
# ---------------------------------------------------------------------

def server.open.sent(~close: Socket -> IO(Unit), ~K: Socket -> List<&2, U32> -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +rest: List<&2, U32>) -> IO(Unit):
  (s2, r2) = sent
  match r2:
    case Fail{e}:
      close(s2)
    case Done{u}:
      K(s2, rest)

# The open lane's return to the keep-alive machine: the answer ladder
# came back, so the buffered form re-enters loop.server at its re-seed
# phase with the leftover seed (TASK-081 Phase 1 pulled this off the
# machine the loop replaced).
def server.open.rejoin(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), out: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = out
  match r:
    case Fail{e}:
      close(s)
    case Done{+seed}:
      loop.server(~recv, ~send, ~close, ~server.no_event, ~H, 8, server.form.buffered(), (s, Done{seed}), Nil{}, 64n, False{}, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), server.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), server.stream.no_head(), Nil{}, "", "", Nil{})

def server.open.status(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, +status: U32, +headers: List<&2, HTTP.Hdr>, +body: List<&2, U32>, keep: Bool, +rest: List<&2, U32>, is101: Bool) -> IO(Unit):
  match is101:
    case True{}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, x_h1.show_resp_head(status, headers))
        server.open.sent(~close, ~K, sent, rest)
    case False{}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, sock, HTTP.Response{status, headers, body}, keep, rest)
        server.open.rejoin(~recv, ~send, ~close, ~H, out)

def server.open.reply(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, +resp: HTTP.Response, keep: Bool, +rest: List<&2, U32>) -> IO(Unit):
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      server.open.status(~recv, ~send, ~close, ~H, ~K, sock, status, headers, body, keep, rest, U32.is_eq(status, 101))

def server.open.answer(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +req: HTTP.Request, keep: Bool, +rest: List<&2, U32>) -> IO(Unit):
  (s, r) = got
  do IO<Unit>:
    resp : HTTP.Response <- H(req)
    server.open.reply(~recv, ~send, ~close, ~H, ~K, s, server.safe_resp(resp), keep, rest)

@unsafe
def server.open.bd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +have: List<&2, U32>, fuel: Nat, +cl: U32, enough: Bool) -> IO(Unit):
  match phase:
    case 0:
      match fuel:
        case 0n:
          close(server.sock_of(got))
        case 1n+f:
          match enough:
            case True{}:
              server.open.answer(~recv, ~send, ~close, ~H, ~K, got, HTTP.Request{m, p, hs, HTTP.x_take32(cl, have)}, Bool.not(x_h1.conn_close(hs)), HTTP.x_drop32(cl, have))
            case False{}:
              do IO<Unit>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.recv(~recv, ~send, ~close, got)
                server.open.bd(~recv, ~send, ~close, ~H, ~K, 1, r, m, p, hs, have, f, cl, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          close(s1)
        case Done{+part}:
          match part:
            case Nil{}:
              close(s1)
            case h <> t:
              +have2 = List.append(&2, U32, have, part)
              server.open.bd(~recv, ~send, ~close, ~H, ~K, 0, (s1, Done{Nil{}}), m, p, hs, have2, fuel, cl, HTTP.x_has_at_least(cl, have2))
    case _:
      (s9, r9) = got
      close(s9)

def server.open.cl(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s: Socket, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +rest: List<&2, U32>, fuel: Nat, +cl: U32, big: Bool) -> IO(Unit):
  match big:
    case True{}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, s, HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
        server.open.rejoin(~recv, ~send, ~close, ~H, out)
    case False{}:
      server.open.bd(~recv, ~send, ~close, ~H, ~K, 0, (s, Done{Nil{}}), m, p, hs, rest, fuel, cl, HTTP.x_has_at_least(cl, rest))

# The upgrade lane's copy of the chunked reader: same grammar, same caps,
# different endings. A 413 over the cap is answered and then rejoined
# through server.open.rejoin (the CL path's server.open.cl does the same
# with its 413), a malformed body is answered 400 and the connection ends,
# and fuel exhaustion closes without an answer, which is what
# server.open.bd does. End hands the request to the handler through
# server.open.answer, so a chunked request reaches ~H on this lane too
# instead of the old 502.
@unsafe
def server.open.chunk(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, big: Bool, r: HTTP.ChunkSt & HTTP.UnitOut, fuel: Nat, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, rev: List<&2, U32>, buf: List<&2, U32>, +have: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Unit):
  match phase:
    case 0:
      match big:
        case True{}:
          (sock, _r0) = got
          do IO<Unit>:
            rr : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, sock, HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
            server.open.rejoin(~recv, ~send, ~close, ~H, rr)
        case False{}:
          match r:
            case (st2, out):
              match out:
                case HTTP.Got{+chunk, fin, +rest}:
                  (sock2, _r1) = got
                  +have2 = (have + HTTP.x_len32(chunk) : U32)
                  server.open.chunk(~recv, ~send, ~close, ~H, ~K, 0, U32.is_gt(have2, 16384), x_h1.chunk_step(st2, rest), fuel, m, p, hs, HTTP.x_rev_push(chunk, rev), rest, have2, (sock2, Done{Nil{}}))
                case HTTP.NeedMore{missing, +rest}:
                  match fuel:
                    case 0n:
                      (sock3, _r2) = got
                      close(sock3)
                    case 1n+f:
                      (sock4, _r3) = got
                      do IO<Unit>:
                        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(sock4, 16384)
                        server.open.chunk(~recv, ~send, ~close, ~H, ~K, 1, big, r, f, m, p, hs, rev, rest, have, r1)
                case HTTP.End{rest}:
                  (sock5, _r4) = got
                  server.open.answer(~recv, ~send, ~close, ~H, ~K, (sock5, Done{Nil{}}), HTTP.Request{m, p, hs, HTTP.x_cat(rev)}, Bool.not(x_h1.conn_close(hs)), rest)
                case HTTP.Bad{code2, msg}:
                  (sock6, _r5) = got
                  do IO<Unit>:
                    rr2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- server.respond(~recv, ~send, ~close, sock6, HTTP.Response{400, Nil{}, Nil{}}, False{}, Nil{})
                    server.open.rejoin(~recv, ~send, ~close, ~H, rr2)
    case 1:
      match r:
        case (st2, out):
          match got:
            case (sock, r1):
              match r1:
                case Fail{e}:
                  close(sock)
                case Done{+part}:
                  match part:
                    case Nil{}:
                      close(sock)
                    case h <> t:
                      +buf2 = List.append(&2, U32, buf, part)
                      server.open.chunk(~recv, ~send, ~close, ~H, ~K, 0, big, x_h1.chunk_step(st2, buf2), fuel, m, p, hs, rev, buf2, have, (sock, Done{Nil{}}))
    case _:
      (s9, r9) = got
      close(s9)

def server.open.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s: Socket, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +rest: List<&2, U32>, fuel: Nat, needs: Bool, +cl: U32, chunked: Bool) -> IO(Unit):
  match needs:
    case False{}:
      server.open.answer(~recv, ~send, ~close, ~H, ~K, (s, Done{Nil{}}), HTTP.Request{m, p, hs, Nil{}}, Bool.not(x_h1.conn_close(hs)), rest)
    case True{}:
      match chunked:
        case True{}:
          server.open.chunk(~recv, ~send, ~close, ~H, ~K, 0, False{}, x_h1.chunk_step(x_h1.chunk_init(), rest), fuel, m, p, hs, Nil{}, rest, 0, (s, Done{Nil{}}))
        case False{}:
          server.open.cl(~recv, ~send, ~close, ~H, ~K, s, m, p, hs, rest, fuel, cl, U32.is_gt(cl, 16384))

def server.open.checked(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s1: Socket, +rest: List<&2, U32>, fuel: Nat, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, code: U32) -> IO(Unit):
  match code:
    case 0:
      server.open.go(~recv, ~send, ~close, ~H, ~K, s1, m, p, hs, rest, fuel, server.needs_body(m), x_h1.cl_of(hs), x_h1.is_chunked(hs))
    case _:
      server.told(~send, ~close, s1, (code, "refused"))

def server.open.ruled(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s1: Socket, +rest: List<&2, U32>, fuel: Nat, joinres: Result<&1, &1, U32 & String, HTTP.H1Head>) -> IO(Unit):
  match joinres:
    case Fail{e}:
      server.told(~send, ~close, s1, e)
    case Done{+rh}:
      match rh:
        case HTTP.H1Head{head, is_11}:
          match head:
            case HTTP.ReqHead{+m, +p, +hs}:
              server.open.checked(~recv, ~send, ~close, ~H, ~K, s1, rest, fuel, m, p, hs, server.head_err(hs, is_11))

# The 101 machine from the blank line on (server.open, an auxiliary of
# the server namespace: the loop name belongs to the fuel machines
# only): one x_h1.split traversal for head-lines and rest (the same walk
# the buffered loop's parse phase does), then the request ladder below
# (ruled, checked, go, then bd/cl/chunk) whose endings answer splits:
# a 101 lends the socket plus the rest to ~K, anything else responds and
# rejoins loop.server.
def server.open.got(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, p: List<&2, U32> & List<&2, U32> & Bool, fuel: Nat) -> IO(Unit):
  match p:
    case (head, rest, found):
      +hl = x_h1.head_lines(head)
      server.open.ruled(~recv, ~send, ~close, ~H, ~K, server.sock_of(got), rest, fuel, x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))))

def server.open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat) -> IO(Unit):
  server.open.got(~recv, ~send, ~close, ~H, ~K, got, x_h1.split(acc), fuel)

# The open lane's head reader, loop.pre's twin on the 101 lane: phases
# 0/1 read the head (16 KB a turn, 64 turns; the 16384-byte cap and the
# fuel floor answer 431 through cap_told); phase 2 routes on the blank
# line: found hands the whole buffer to server.open, the 101 machine
# above, with the leftover bytes as its rest.
@unsafe
def loop.pre.open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          server.cap_told(~send, ~close, s0)
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            loop.pre.open(~recv, ~send, ~close, ~H, ~K, 1, r, acc, f, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          close(s1)
        case Done{+part}:
          match part:
            case Nil{}:
              close(s1)
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              +over = x_h1.head_over(HTTP.x_len32(acc2))
              loop.pre.open(~recv, ~send, ~close, ~H, ~K, x_h1.head_phase(over), (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), x_h1.split.test(acc2))
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          loop.pre.open(~recv, ~send, ~close, ~H, ~K, 0, (s2, Done{Nil{}}), acc, fuel, False{})
        case True{}:
          server.open(~recv, ~send, ~close, ~H, ~K, (s2, Done{Nil{}}), acc, fuel)
    case _:
      (s9, r9) = got
      close(s9)

# The open family's runners: the per-socket start, the fork wrapper and
# the conn arm, the same three the other server families own.
def server.open.start(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket) -> IO(Unit):
  loop.pre.open(~recv, ~send, ~close, ~H, ~K, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def server.open.spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, server.open.start(~recv, ~send, ~close, ~H, ~K, sock))
    return l

def server.open.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      server.open.spawn(~recv, ~send, ~close, ~H, ~K, sock, l)

# The open lane's named accepts, one twin per transport: the 101 family
# over the same server.accept/server.accept_secure the other lanes use.
# server.open.conn is the conn arm with the templates; the wsm calls it
# from its own accept loops (TASK-082 migrated the names).
def server.open.once(~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept(l)
    l2 : Listener <- server.open.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, ~K, m)
    return Unit{}

def server.open.once_secure(~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), l: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept_secure(l, cert, key)
    l2 : Listener <- server.open.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, ~K, m)
    return Unit{}

# The accept loop never shrinks the listener, so the checker cannot
# prove it ends. @unsafe marks only that loop.
@unsafe
def server.open.on(~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept(l)
    l2 : Listener <- server.open.conn(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, ~K, m)
    z : Unit <- server.open.on(~H, ~K, l2)
    return z

@unsafe
def server.open.on_secure(~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), l: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- server.accept_secure(l, cert, key)
    l2 : Listener <- server.open.conn(~TLS.tls_recv_bytes, ~TLS.tls_send_bytes, ~TLS.tls_close, ~H, ~K, m)
    z : Unit <- server.open.on_secure(~H, ~K, l2, cert, key)
    return z
