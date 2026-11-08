# HTTP1: the HTTP/1.1 module. It owns the wire: the request render, the
# head and body parsers, the reason-phrase table, the chunked codec, the
# keep-alive connection machine, the streaming upload and download lanes,
# the 101 upgrade machine and the per-connection runners the accept loops
# spawn.
#
# It does not dial, does not accept and does not name a transport. The
# runners take the three templates (~recv/~send/~close, plus ~K on the
# upgrade lane) and the facade (./httpx.bend) instantiates them with TLS or
# TCP. The core (./http.bend) owns the types and the shared leaves.
#
# Callee above caller; match scrutinees are params or pattern-bound vars;
# self-recursion only, and @unsafe keeps the fuel-bounded loops.
#
# Import as: import ./http1.bend as HTTP1 (from lib).
import Base
import ./http.bend as HTTP

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
# and loops back to read (x_h1.srv.head phase 3), the client reuses the
# socket for N requests in order (x_h1.cli.exch / client_seq.h1.keep).
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
# x_h1.cli.exch.open.fit, and neither copy looked at hs.
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

def x_h1.render_hs.skip(+n: String, +v: String, acc: List<&2, U32>, skip: Bool) -> List<&2, U32>:
  match skip:
    case True{}:
      acc
    case False{}:
      List.append(&2, U32, acc, HTTP.x_str_bytes(n ++ ": " ++ v ++ "\r\n"))

# Upgrade renders keep `connection`/`upgrade` (the handshake's own headers):
# forbidden() still drops the rest. Case-insensitive like the parse side.
def x_h1.render_hs.keep(upgrade: Bool, +n: String) -> Bool:
  match upgrade:
    case True{}:
      Bool.or(x_h1.eq_ci(n, "connection"), x_h1.eq_ci(n, "upgrade"))
    case False{}:
      False{}

def x_h1.render_hs.go(hs: List<&2, HTTP.Hdr>, acc: List<&2, U32>, +upgrade: Bool) -> List<&2, U32>:
  match hs:
    case Nil{}:
      acc
    case HTTP.Hdr{+n, +v} <> t:
      x_h1.render_hs.go(t, x_h1.render_hs.skip(n, v, acc, Bool.and(x_h1.forbidden(n), Bool.not(x_h1.render_hs.keep(upgrade, n)))), upgrade)

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
      Done{List.append(&2, U32, List.append(&2, U32, x_h1.render_hs.go(hs, HTTP.x_str_bytes(method ++ " " ++ path ++ " HTTP/1.1\r\nHost: " ++ host ++ ":" ++ U32.show(port) ++ "\r\n" ++ x_h1.render_cl(body, upgrade)), upgrade), HTTP.x_str_bytes("\r\n")), body)}

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

# Responses render with upgrade=False today: no handler emits Upgrade yet.
# Phase 3 (answer_open/show_resp_head) revisits this for the 101 path.
def x_h1.show_resp(+status: U32, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, List.append(&2, U32, x_h1.render_hs.go(hs, HTTP.x_str_bytes("HTTP/1.1 " ++ U32.show(status) ++ " " ++ x_h1.reason(status) ++ "\r\nContent-Length: " ++ U32.show(HTTP.x_len32(body)) ++ "\r\n"), False{}), HTTP.x_str_bytes("\r\n")), body)

# The 101 head: status line + the handler's headers (Upgrade/Connection
# kept via upgrade=True) + blank line. No Content-Length, no body — a 101
# carries neither by definition, and show_resp would inject Length: 0.
def x_h1.show_resp_head(+status: U32, hs: List<&2, HTTP.Hdr>) -> List<&2, U32>:
  List.append(&2, U32, x_h1.render_hs.go(hs, HTTP.x_str_bytes("HTTP/1.1 " ++ U32.show(status) ++ " " ++ x_h1.reason(status) ++ "\r\n"), True{}), HTTP.x_str_bytes("\r\n"))

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

def x_h1.head_lines(+head: List<&2, U32>) -> List<&2, String>:
  String.lines(HTTP.x_bytes_str(head))

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
# Recursion rides args with match-result-as-param (parse_headers shape).
# ---------------------------------------------------------------------

def x_h1.is_blank(+l: String) -> Bool:
  Bool.or(String.is_empty(l), String.eq(l, "\r"))

def x_h1.hdr_val(+line: String, +nlen: Nat) -> String:
  String.trim(String.drop(line, (nlen + 1n : Nat)))

def x_h1.parse_hdr(done: Bool, parts: List<&2, String>, +line: String, rec: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>) ->
  Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>:
  match done:
    case True{}:
      Done{Nil{}}
    case False{}:
      match parts:
        case Nil{}:
          Fail{(400, "bad header")}
        case +n <> vs:
          match vs:
            case Nil{}:
              Fail{(400, "bad header")}
            case +v <> vvs:
              match rec:
                case Fail{e}:
                  Fail{e}
                case Done{+tl}:
                  Done{HTTP.Hdr{n, x_h1.hdr_val(line, String.length(n))} <> tl}

def x_h1.parse_hs(lines: List<&2, String>) ->
  Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>:
  match lines:
    case Nil{}:
      Done{Nil{}}
    case +h <> t:
      +l1 = String.trim(x_h1.strip_cr(h))
      x_h1.parse_hdr(x_h1.is_blank(h), String.split(l1, ':'), l1, x_h1.parse_hs(t))

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
def x_h1.srv.head_err_go(cl_bad: Bool, cl_dup: Bool, te_bad: Bool, te_cl: Bool, h_dup: Bool, h_none: Bool, h_empty: Bool, is_11: Bool) -> U32:
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

def x_h1.srv.head_err(+hs: List<&2, HTTP.Hdr>, is_11: Bool) -> U32:
  x_h1.srv.head_err_go(x_h1.cl_bad(hs), U32.is_gt(x_h1.cl_count(hs), 1), x_h1.te_bad(hs), Bool.and(x_h1.te_any(hs), U32.is_gt(x_h1.cl_count(hs), 0)), U32.is_gt(x_h1.host_count(hs), 1), U32.is_eq(x_h1.host_count(hs), 0), x_h1.host_empty(hs), is_11)

# A terminal code the peer must see before the connection ends: 400..599 is
# a status this server renders, 0 ("close") and the 6xx transport codes
# (TLS/DNS) are not. One rule for the three H1 server lanes.
def x_h1.srv.is_status(+code: U32) -> Bool:
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

# The whole-buffer fold: one body, one Result, the shape every caller above
# already speaks. A starved step answers the failure the byte-at-a-time
# machine gave when its buffer ran out mid-chunk (400 "bad chunked"),
# which is also what keeps a truncated body from reading as an empty one.
@unsafe
def x_h1.unchunk.go(r: HTTP.ChunkSt & HTTP.UnitOut, acc: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  (st2, out) = r
  match out:
    case HTTP.Got{+chunk, fin, +rest}:
      x_h1.unchunk.go(x_h1.chunk_step(st2, rest), HTTP.x_rev_push(chunk, acc))
    case HTTP.NeedMore{missing, rest}:
      Fail{(400, "bad chunked")}
    case HTTP.End{rest}:
      Done{HTTP.x_cat(acc)}
    case HTTP.Bad{code, msg}:
      Fail{(code, msg)}

def x_h1.unchunk(+bs: List<&2, U32>) -> Result<&1, &1, U32 & String, List<&2, U32>>:
  x_h1.unchunk.go(x_h1.chunk_step(x_h1.chunk_init(), bs), Nil{})

# The client's chunked body reader: the same phase+fuel shape as
# x_h1.cli.bd, except the length is not known up front -- the step decides.
# Got adds the chunk to a reversed body and keeps stepping, NeedMore spends
# one recv (fuel), Bad is 400 and End is the answer. The lookahead's fin is
# NOT the finish line: only End is, so "1\r\nA\r\n\r\n" (a bare empty line
# standing in for the last-chunk, which the lookahead reads as "last")
# stays 400 here, exactly like both whole-buffer decoders. The bare codes
# are the lane's own: 413 is the fuel floor x_h1.cli.bd uses, 400 on EOF is
# its "eof" too.
#
# Phase 1 exists for the same reason x_h1.cli.bd has one: the recv result is
# a computed pair and a match cannot scrutinize a computed value, so it
# travels here as a parameter. The pending state rides in the pair parameter
# as well -- phase 0 hands it chunk_step(st2, Nil{}), which always answers
# NeedMore and consumes no byte -- because that state is all phase 1 needs
# once the new bytes are appended to the buffer.
@unsafe
def x_h1.cli.chunk(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, r: HTTP.ChunkSt & HTTP.UnitOut, fuel: Nat, rev: List<&2, U32>, buf: List<&2, U32>, +code: U32, hs: List<&2, HTTP.Hdr>, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match phase:
    case 0:
      match r:
        case (st2, out):
          match out:
            case HTTP.Got{+chunk, fin, +rest}:
              (sock, _r0) = got
              x_h1.cli.chunk(~recv, ~send, ~close, 0, x_h1.chunk_step(st2, rest), fuel, HTTP.x_rev_push(chunk, rev), rest, code, hs, (sock, Done{Nil{}}))
            case HTTP.NeedMore{missing, +rest}:
              match fuel:
                case 0n:
                  (sock2, _r1) = got
                  IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock2, Fail{(413, "response too long")}))
                case 1n+f:
                  (sock3, _r2) = got
                  do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
                    r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(sock3, 16384)
                    x_h1.cli.chunk(~recv, ~send, ~close, 1, x_h1.chunk_step(st2, Nil{}), f, rev, rest, code, hs, r1)
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
                      x_h1.cli.chunk(~recv, ~send, ~close, 0, x_h1.chunk_step(st2, buf2), fuel, rev, buf2, code, hs, (sock, Done{Nil{}}))
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

# H1 client exchange (fallback lane): render, send, head/body fuel loops,
# close. Matches go forward in param order per branch (checker rule).
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
def x_h1.cli.bd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, fuel: Nat, +need: U32, +code: U32, +hs: List<&2, HTTP.Hdr>, +rev: List<&2, U32>, +cl: U32) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
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
                x_h1.cli.bd(~recv, ~send, ~close, 1, r, f, need, code, hs, rev, cl)
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
              x_h1.cli.bd(~recv, ~send, ~close, 0, (s1, Done{Nil{}}), fuel, need2, code, hs, HTTP.x_rev_push(part, rev), cl)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

# The nbody=False arm of hd2: a body to read, or the 502 of an upgrade
# without 101. The decision needs its own def, because Bend refuses a match
# inside two match arms.
def x_h1.cli.body_go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, +hs: List<&2, HTTP.Hdr>, upg: Bool, chunked: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match upg:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{(502, "upgrade without 101")}))
    case False{}:
      match chunked:
        case True{}:
          x_h1.cli.chunk(~recv, ~send, ~close, 0, x_h1.chunk_step(x_h1.chunk_init(), rest), fuel, Nil{}, rest, code, hs, (sock, Done{Nil{}}))
        case False{}:
          +clc = x_h1.cl_of(hs)
          +need0 = U32.sub(clc, HTTP.x_len_upto(clc, rest))
          x_h1.cli.bd(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), fuel, need0, code, hs, HTTP.x_cat(rest), clc)

# The chain serves the plain lane and the upgrade lane. The flag upg turns
# the nbody=False arm into Fail 502 "upgrade without 101" (fail-closed:
# a 101 carries no body by definition). The plain entries drop the rest of
# the triple, the upgrade entries keep it (x_h1.cli.exch.open).

def x_h1.cli.hd2(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, +hs: List<&2, HTTP.Hdr>, nbody: Bool, chunked: Bool, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match nbody:
    case True{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Done{(HTTP.Response{code, hs, Nil{}}, rest)}))
    case False{}:
      x_h1.cli.body_go(~recv, ~send, ~close, sock, rest, fuel, code, hs, upg, chunked)

# The nbody=False arm of hd2: a body to read, or the 502 of an upgrade
# without 101. The decision needs its own def, because Bend refuses a match
# inside two match arms.
def x_h1.cli.hd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +rest: List<&2, U32>, fuel: Nat, +code: U32, hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>, nbody: Bool, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match hsres:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+hs}:
      x_h1.cli.hd2(~recv, ~send, ~close, sock, rest, fuel, code, hs, nbody, x_h1.is_chunked(hs), upg)

def x_h1.cli.coded(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +method: String, +rest: List<&2, U32>, fuel: Nat, coderes: Result<&1, &1, U32 & String, U32>, hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match coderes:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+code}:
      x_h1.cli.hd(~recv, ~send, ~close, sock, rest, fuel, code, hsres, x_h1.no_body(method, code), upg)

# got B (TASK-040): the split triple arrives as a parameter — a computed
# triple cannot be scrutinized (E1), a parameter can (E2) — so head-lines
# and rest come out of ONE x_h1.split traversal. Was split_head(split(acc2))
# plus split_rest(split(acc2)): two walks and two reverses per head.
def x_h1.cli.parsed.got(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), p: List<&2, U32> & List<&2, U32> & Bool, s1: Socket, fuel: Nat, +method: String, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match p:
    case (head, rest, found):
      +hl = x_h1.head_lines(head)
      x_h1.cli.coded(~recv, ~send, ~close, s1, method, rest, fuel, x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl)), upg)

def x_h1.cli.parsed(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s1: Socket, +acc2: List<&2, U32>, fuel: Nat, +method: String, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  x_h1.cli.parsed.got(~recv, ~send, ~close, x_h1.split(acc2), s1, fuel, method, upg)

# Status code of the head sitting in acc (0 when the status line does not
# parse). The 1xx check runs before the head is turned into a response, so
# it reads the code out of the same split/parse the answer path uses
# (TASK-042 phase 4).
def x_h1.cli.code_of_got(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+code}:
      code

def x_h1.status_of(+acc: List<&2, U32>) -> U32:
  +hl = x_h1.head_lines(x_h1.split_head(x_h1.split(acc)))
  x_h1.cli.code_of_got(x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))))

# 1xx is an interim status (RFC 9110 section 15.2): any number of them may
# precede the final response — 100 Continue (Expect), 103 Early Hints
# (node's writeEarlyHints, CDNs) — so the head is discarded and the next
# one parsed out of the bytes already read. 101 Switching Protocols is the
# upgrade answer: a final head for the caller, never interim here.
def x_h1.is_info(+code: U32) -> Bool:
  Bool.and(Bool.and(U32.is_lt(99, code), U32.is_lt(code, 200)), U32.is_ne(code, 101))

@unsafe
def x_h1.cli.head(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, +method: String, found: Bool, info: Bool, upg: Bool) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s0, Fail{(413, "response too long")}))
        case 1n+f:
          do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.cli.head(~recv, ~send, ~close, 1, r, acc, f, method, False{}, False{}, upg)
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
              +acc2 = List.append(&2, U32, acc, part)
              x_h1.cli.head(~recv, ~send, ~close, 2, (s1, Done{Nil{}}), acc2, fuel, method, x_h1.split.test(acc2), False{}, upg)
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          x_h1.cli.head(~recv, ~send, ~close, 0, (s2, Done{Nil{}}), acc, fuel, method, False{}, False{}, upg)
        case True{}:
          x_h1.cli.head(~recv, ~send, ~close, 4, (s2, Done{Nil{}}), acc, fuel, method, False{}, x_h1.is_info(x_h1.status_of(acc)), upg)
    case 4:
      (s4, r4) = got
      match info:
        case True{}:
          +rest = x_h1.split_rest(x_h1.split(acc))
          x_h1.cli.head(~recv, ~send, ~close, 2, (s4, Done{Nil{}}), rest, fuel, method, x_h1.split.test(rest), False{}, upg)
        case False{}:
          x_h1.cli.parsed(~recv, ~send, ~close, s4, acc, fuel, method, upg)
    case _:
      (s9, r9) = got
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (s9, Fail{(502, "bad phase")}))

# The plain lane drops the bytes past the answer; the upgrade lane keeps
# them, because they are the first frame bytes.
def x_h1.cli.rest_drop(out: Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>) ->
  Socket & Result<&1, &1, U32 & String, HTTP.Response>:
  (sock, r) = out
  match r:
    case Fail{e}:
      (sock, Fail{e})
    case Done{p}:
      (res, _rest) = p
      (sock, Done{res})

def x_h1.exch.sent(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response>, (sock, Fail{e}))
    case Done{u}:
      do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response>>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- x_h1.cli.head(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), Nil{}, 64n, method, False{}, False{}, False{})
        IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response>, x_h1.cli.rest_drop(out))

def x_h1.exch.send(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response>):
  match rendered:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response>, (sock, Fail{e}))
    case Done{+bytes}:
      do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        x_h1.exch.sent(~recv, ~send, ~close, sent, method)

def x_h1.exch.done(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), out: Socket & Result<&1, &1, U32 & String, HTTP.Response>) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  (s, r) = out
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, HTTP.Response>, Fail{e})
    case Done{+resp}:
      do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
        x : Unit <- close(s)
        IO.pure(Result<&1, &1, U32 & String, HTTP.Response>, Done{resp})

def x_h1.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Result<&1, &1, U32 & String, HTTP.Response>):
  do IO<Result<&1, &1, U32 & String, HTTP.Response>>:
    out : Socket & Result<&1, &1, U32 & String, HTTP.Response> <- x_h1.exch.send(~recv, ~send, ~close, sock, x_h1.render_req(method, path, host, port, hs, body), method)
    x_h1.exch.done(~recv, ~send, ~close, out)

# The exchange that does NOT close: one request out, one response read
# back, socket handed over. x_h1.exch.send already behaves that way
# (x_h1.exch is the one-shot wrapper that closes at the end); this is the
# named entry for the sequential batch lane, and it validates like the
# H2 keep-alive path (client.on.fit_keep) so both lanes fail with the
# same 400/413 before any byte leaves.
def x_h1.cli.exch.fit(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          x_h1.exch.send(~recv, ~send, ~close, sock, x_h1.render_req(method, path, host, port, hs, body), method)
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response>,
            (sock, Fail{(413, "req too large")}))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response>,
        (sock, Fail{(400, "bad request")}))

def x_h1.cli.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response>):
  x_h1.cli.exch.fit(~recv, ~send, ~close, sock, host, port, method, path, hs, body, HTTP.client.on.valid.go(host, port, path), HTTP.client.on.body_ok(body))

def x_h1.exch.sent_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{u}:
      x_h1.cli.head(~recv, ~send, ~close, 0, (sock, Done{Nil{}}), Nil{}, 64n, method, False{}, False{}, True{})

def x_h1.exch.send_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match rendered:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>, (sock, Fail{e}))
    case Done{+bytes}:
      do IO<Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        x_h1.exch.sent_open(~recv, ~send, ~close, sent, method)

# The handshake exchange: like x_h1.cli.exch (same 400/413 before any byte
# leaves) but rendered with upgrade=True and answered by the _open chain,
# so the socket comes back live with the bytes past the head. Not closing
# is the caller's job — that is the whole point of the triple.
# hs is + for the same reason as x_h1.render_req: bad_req and the render
# both read the header block.
def x_h1.cli.exch.open.fit(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>, fit: Bool, ok: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  match fit:
    case True{}:
      match ok:
        case True{}:
          x_h1.exch.send_open(~recv, ~send, ~close, sock, x_h1.render_req.go(True{}, x_h1.bad_req(method, path, host, hs), method, path, host, port, hs, body), method)
        case False{}:
          IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>,
            (sock, Fail{(413, "req too large")}))
    case False{}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>,
        (sock, Fail{(400, "bad request")}))

def x_h1.cli.exch.open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>):
  x_h1.cli.exch.open.fit(~recv, ~send, ~close, sock, host, port, method, path, hs, body, HTTP.client.on.valid.go(host, port, path), HTTP.client.on.body_ok(body))

# H1 streaming download (Phase 6): the H1 leg of client.stream, speaking
# StreamEv/StreamOut like the H2 sdrop lane in ./http2.bend. One request
# per connection, then close: the H1 answer to Cancel is close + Fail
# (8, "cancelled") — there is no RST_STREAM on this lane. Counts only,
# never buffers: the answer is (total bytes, chunks delivered), the same
# pair shape the H2 lane reports as (total, fins).
# Transport is three templates (~recv/~send/~close) like x_h1.cli.exch,
# instantiated per lane at the entries in ./httpx.bend (TLS for the ALPN
# dispatch in client_stream, TCP for the plaintext entry). The framing cut
# below is shared with the upload lane (x_h1.stream.next), so both lanes
# cut one body one way.
# ---------------------------------------------------------------------

# Field projections: Bend has no field access, so a loop carrying a
# BodyFrame reads the three framing answers back through these.
def x_h1.stream.frame_cl(+fr: HTTP.BodyFrame) -> U32:
  match fr:
    case HTTP.BodyFrame{+cl, chunked, no_body}:
      cl

def x_h1.stream.frame_chunked(+fr: HTTP.BodyFrame) -> Bool:
  match fr:
    case HTTP.BodyFrame{cl, +chunked, no_body}:
      chunked

def x_h1.stream.frame_nbody(+fr: HTTP.BodyFrame) -> Bool:
  match fr:
    case HTTP.BodyFrame{cl, chunked, +no_body}:
      no_body

# Length-delimited cut answering this file's own UnitOut, the same
# vocabulary the chunked step speaks: Got carries the next piece with
# its last-chunk flag and what is left, NeedMore carries the buffer back
# for one more read, End is unused here (a spent length is a caller bug),
# Bad is the overspent length the whole-buffer lane refuses too.
def x_h1.stream.cl_go(+pending: List<&2, U32>, +cl: U32, +seen: U32, +chunk: List<&2, U32>, fin: Bool, empty: Bool) -> HTTP.UnitOut:
  match empty:
    case True{}:
      HTTP.NeedMore{(cl - seen : U32), pending}
    case False{}:
      HTTP.Got{chunk, fin, HTTP.x_drop32(HTTP.x_len32(chunk), pending)}

def x_h1.stream.cl_next(+pending: List<&2, U32>, +cl: U32, +seen: U32, ok: Bool) -> HTTP.UnitOut:
  match ok:
    case True{}:
      +chunk = HTTP.x_take32((cl - seen : U32), pending)
      x_h1.stream.cl_go(pending, cl, seen, chunk, U32.is_eq((seen + HTTP.x_len32(chunk) : U32), cl), List.is_empty(&2, U32, chunk))
    case False{}:
      HTTP.Bad{400, "eof"}

# The next chunk, whichever framing the head declared. One call so the
# loops never match the framing and the answer at once: a chunked body
# goes to the incremental step (which keeps its own state across reads)
# and a length-delimited one to the cut above (whose state is the seen
# count the caller already carries).
def x_h1.stream.next(+chunked: Bool, +cst: HTTP.ChunkSt, +pending: List<&2, U32>, +cl: U32, +seen: U32) -> HTTP.ChunkSt & HTTP.UnitOut:
  match chunked:
    case True{}:
      x_h1.chunk_step(cst, pending)
    case False{}:
      (x_h1.chunk_init(), x_h1.stream.cl_next(pending, cl, seen, Bool.not(U32.is_gt(seen, cl))))

# What the head answer means to this loop: 0 go read the body, 2 report
# what was counted and close, 3 close and report (8, "cancelled").
# Asking for more on a message with no body is a finish, not a close:
# the client has nothing left to read.
def x_h1.cli.stream.head_go(nbody: Bool) -> U32:
  match nbody:
    case True{}:
      2
    case False{}:
      0

def x_h1.cli.stream.head_act(+out: HTTP.StreamOut, nbody: Bool) -> U32:
  match out:
    case HTTP.StreamContinue{}:
      x_h1.cli.stream.head_go(nbody)
    case HTTP.StreamCancel{}:
      3

# What one body chunk answer means: 0 keep going, 2 done and report,
# 3 cancelled. Continue past the last chunk is done — there is no next
# chunk.
def x_h1.cli.stream.data_act(+out: HTTP.StreamOut, +fin: Bool) -> U32:
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
def x_h1.cli.stream.close(~close: Socket -> IO(Unit), s: Socket, r: Result<&1, &1, U32 & String, U32 & U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  do IO<Result<&1, &1, U32 & String, U32 & U32>>:
    x : Unit <- close(s)
    IO.pure(Result<&1, &1, U32 & String, U32 & U32>, r)

def x_h1.cli.stream.done(~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +total: U32, +chunks: U32) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, g) = got
  x_h1.cli.stream.close(~close, s, Done{(total, chunks)})

def x_h1.cli.stream.failed(~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, e: U32 & String) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, g) = got
  x_h1.cli.stream.close(~close, s, Fail{e})

def x_h1.cli.stream.cancelled(~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  (s, g) = got
  x_h1.cli.stream.close(~close, s, Fail{(8, "cancelled")})

# The response head, parsed. The bytes that arrived with the head seed
# the pending buffer in phase 3, the same way the one-shot lane does.
def x_h1.cli.stream.headers(hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>, +code: U32) -> Result<&1, &1, U32 & String, HTTP.Head>:
  match hsres:
    case Fail{e}:
      Fail{e}
    case Done{+hs}:
      Done{HTTP.Head{code, hs}}

def x_h1.cli.stream.built(coderes: Result<&1, &1, U32 & String, U32>, hsres: Result<&1, &1, U32 & String, List<&2, HTTP.Hdr>>) -> Result<&1, &1, U32 & String, HTTP.Head>:
  match coderes:
    case Fail{e}:
      Fail{e}
    case Done{+code}:
      x_h1.cli.stream.headers(hsres, code)

def x_h1.cli.stream.parsed(+acc: List<&2, U32>) -> Result<&1, &1, U32 & String, HTTP.Head>:
  +hl = x_h1.head_lines(x_h1.split_head(x_h1.split(acc)))
  x_h1.cli.stream.built(x_h1.res_lift(x_h1.res_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl)))

def x_h1.cli.stream.no_head() -> Result<&1, &1, U32 & String, HTTP.Head>:
  Fail{(400, "bad status")}

# The loop, phase by phase: 0/1/2 read the head (16KB a turn, 64 turns,
# the blank-line cut); 3 parses, frames through x_h1.frame_of and hands
# the head over; 5 acts on the head answer; 6 asks the framing for the
# next chunk; 7 delivers it and acts; 9 reads more body and 10 takes the
# read back (a peer that closes mid-body is 400 "eof", the code the
# one-shot lane already answers). act rides the last answer decoded to
# a code; the response half the upload lane carries is dead here — the
# client has nobody to hand it to.
@unsafe
def x_h1.cli.stream.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool, +method: String, +nbody: Bool, +chunked: Bool, +cl: U32, +pending: List<&2, U32>, +seen: U32, +cst: HTTP.ChunkSt, act: U32, out: HTTP.ChunkSt & HTTP.UnitOut, +total: U32, +chunks: U32, hres: Result<&1, &1, U32 & String, HTTP.Head>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          x_h1.cli.stream.failed(~close, got, (413, "response too long"))
        case 1n+f:
          do IO<Result<&1, &1, U32 & String, U32 & U32>>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 1, r, acc, f, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          x_h1.cli.stream.close(~close, s1, Fail{e})
        case Done{+part}:
          match part:
            case Nil{}:
              x_h1.cli.stream.close(~close, s1, Fail{(400, "eof")})
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 2, (s1, Done{Nil{}}), acc2, fuel, x_h1.split.test(acc2), method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres)
    case 2:
      match found:
        case True{}:
          x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 3, got, acc, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, x_h1.cli.stream.parsed(acc))
        case False{}:
          x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 0, got, acc, fuel, False{}, method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres)
    case 3:
      match hres:
        case Fail{e}:
          x_h1.cli.stream.failed(~close, got, e)
        case Done{+hd}:
          match hd:
            case HTTP.Head{+code, +hs}:
              # `found` carries the interim flag into phase 4 (the slot is
              # free after phase 2): a 1xx head is dropped without ever
              # reaching the handler (TASK-042 phase 4b).
              x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 4, got, acc, fuel, x_h1.is_info(code), method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres)
    case 4:
      match found:
        case True{}:
          +rest = x_h1.split_rest(x_h1.split(acc))
          x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 2, got, rest, fuel, x_h1.split.test(rest), method, nbody, chunked, cl, pending, seen, cst, act, out, total, chunks, hres)
        case False{}:
          match hres:
            case Fail{e}:
              x_h1.cli.stream.failed(~close, got, e)
            case Done{+hd}:
              match hd:
                case HTTP.Head{+code, +hs}:
                  +fr = x_h1.frame_of(hs, method, code)
                  +nb = x_h1.stream.frame_nbody(fr)
                  x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 5, got, Nil{}, 0n, False{}, method, nb, x_h1.stream.frame_chunked(fr), x_h1.stream.frame_cl(fr), x_h1.split_rest(x_h1.split(acc)), 0, x_h1.chunk_init(), x_h1.cli.stream.head_act(H(HTTP.StreamHead{hd}), nb), (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, x_h1.cli.stream.no_head())
    case 5:
      match act:
        case 0:
          x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 6, got, Nil{}, 0n, False{}, method, nbody, chunked, cl, pending, seen, cst, 4, x_h1.stream.next(chunked, cst, pending, cl, seen), total, chunks, hres)
        case 3:
          x_h1.cli.stream.cancelled(~close, got)
        case _:
          x_h1.cli.stream.done(~close, got, total, chunks)
    case 6:
      match out:
        case (st2, o):
          match o:
            case HTTP.Got{+chunk, +fin, +rest}:
              x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 7, got, Nil{}, 0n, False{}, method, nbody, chunked, cl, rest, (seen + HTTP.x_len32(chunk) : U32), st2, x_h1.cli.stream.data_act(H(HTTP.StreamData{chunk, fin}), fin), (x_h1.chunk_init(), HTTP.End{Nil{}}), (total + HTTP.x_len32(chunk) : U32), (chunks + 1 : U32), hres)
            case HTTP.NeedMore{missing, +rest}:
              x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 9, got, Nil{}, 0n, False{}, method, nbody, chunked, cl, rest, seen, st2, act, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres)
            case HTTP.End{+rest}:
              x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 7, got, Nil{}, 0n, False{}, method, nbody, chunked, cl, rest, seen, cst, x_h1.cli.stream.data_act(H(HTTP.StreamData{Nil{}, True{}}), True{}), (x_h1.chunk_init(), HTTP.End{Nil{}}), total, (chunks + 1 : U32), hres)
            case HTTP.Bad{code, msg}:
              x_h1.cli.stream.failed(~close, got, (400, "bad chunked"))
    case 7:
      match act:
        case 0:
          x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 5, got, Nil{}, 0n, False{}, method, nbody, chunked, cl, pending, seen, cst, 0, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres)
        case 3:
          x_h1.cli.stream.cancelled(~close, got)
        case _:
          x_h1.cli.stream.done(~close, got, total, chunks)
    case 9:
      (s9, r9) = got
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s9, 16384)
        x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 10, r, Nil{}, 0n, False{}, method, nbody, chunked, cl, pending, seen, cst, act, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres)
    case 10:
      (s10, r10) = got
      match r10:
        case Fail{e}:
          x_h1.cli.stream.close(~close, s10, Fail{e})
        case Done{+part}:
          match part:
            case Nil{}:
              x_h1.cli.stream.close(~close, s10, Fail{(400, "eof")})
            case h <> t:
              x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 5, (s10, Done{Nil{}}), Nil{}, 0n, False{}, method, nbody, chunked, cl, List.append(&2, U32, pending, part), seen, cst, 0, (x_h1.chunk_init(), HTTP.End{Nil{}}), total, chunks, hres)
    case _:
      x_h1.cli.stream.failed(~close, got, (502, "bad phase"))

# Entry: render, send, stream, close. The socket arrives dialed — the
# ALPN dispatch in client_stream keeps it for the H1 answer, and the
# plaintext entry in ./httpx.bend dials it.
def x_h1.cli.stream.sent2(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, sent: Socket & Result<&1, &1, U32 & String, Unit>, +method: String) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  (sock, r) = sent
  match r:
    case Fail{e}:
      x_h1.cli.stream.close(~close, sock, Fail{e})
    case Done{u}:
      x_h1.cli.stream.go(~recv, ~send, ~close, ~H, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{}, method, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), 4, (x_h1.chunk_init(), HTTP.End{Nil{}}), 0, 0, x_h1.cli.stream.no_head())

def x_h1.cli.stream.sent(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, rendered: Result<&1, &1, U32 & String, List<&2, U32>>, +method: String) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  match rendered:
    case Fail{e}:
      x_h1.cli.stream.close(~close, sock, Fail{e})
    case Done{+bytes}:
      do IO<Result<&1, &1, U32 & String, U32 & U32>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, bytes)
        x_h1.cli.stream.sent2(~recv, ~send, ~close, ~H, sent, method)

def x_h1.cli.stream.exch(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  x_h1.cli.stream.sent(~recv, ~send, ~close, ~H, sock, x_h1.render_req(method, path, host, port, hs, body), method)

# H1 streaming upload (Phase 6): the H1 leg of server.stream, speaking
# SrvEv/SrvOut like the H2 httpx_stream lane in ./http2.bend. One request
# per connection, then close: no keep-alive, no pipelining. Backpressure
# is the read itself — at most one recv per chunk, so a handler that stops
# saying Continue stops the reads. Slot is 1: H1 has no stream ids, and
# 1 is also the sid the H2 client opens with. Cancel closes without a
# response (the answer the tree's CT.Cancel gives); RespondEarly renders
# and closes. A malformed chunked body is 400, the code the one-shot H1
# server answers. Transport is three templates like x_h1.srv.head.
# ---------------------------------------------------------------------

# What the head answer means: 0 go read the body, 1 respond now,
# 2 close without responding. Asking for more on a message with no
# body is a close — there is no chunk coming.
def x_h1.stream.head_body(nbody: Bool, +resp: HTTP.Response) -> U32 & HTTP.Response:
  match nbody:
    case True{}:
      (2, resp)
    case False{}:
      (0, resp)

def x_h1.stream.head_act(+out: HTTP.SrvOut, nbody: Bool) -> U32 & HTTP.Response:
  match out:
    case HTTP.Continue{}:
      x_h1.stream.head_body(nbody, HTTP.Response{0, Nil{}, Nil{}})
    case HTTP.RespondEarly{+resp}:
      (1, resp)
    case HTTP.Cancel{}:
      (2, HTTP.Response{0, Nil{}, Nil{}})

# What one body chunk answer means. Continue past the last chunk is a
# close — there is nothing left to hand over.
def x_h1.stream.data_act(+out: HTTP.SrvOut, +fin: Bool) -> U32 & HTTP.Response:
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
def x_h1.stream.sent_close(~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = sent
  close(s)

def x_h1.stream.respond(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +resp: HTTP.Response) -> IO(Unit):
  (s, r) = got
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(s, x_h1.show_resp(status, headers, body))
        x_h1.stream.sent_close(~close, sent)

def x_h1.stream.closed(~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = got
  close(s)

def x_h1.stream.bad(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  x_h1.stream.respond(~send, ~close, got, HTTP.Response{400, Nil{}, Nil{}})

# A terminal code the peer must see before the connection ends: the same
# rule the keep-alive machine uses (400..599 is a status this server
# renders; 0 "close" and the 6xx transport codes are not).
def x_h1.stream.told_go(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +code: U32, told: Bool) -> IO(Unit):
  match told:
    case True{}:
      x_h1.stream.respond(~send, ~close, got, HTTP.Response{code, Nil{}, Nil{}})
    case False{}:
      x_h1.stream.closed(~close, got)

def x_h1.stream.told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +code: U32) -> IO(Unit):
  x_h1.stream.told_go(~send, ~close, got, code, x_h1.srv.is_status(code))

# The terminal code of a failed head read: 400/413/431/502 ride out as a
# response, 0 "close" and the transport codes do not.
def x_h1.stream.stop_told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, e: U32 & String) -> IO(Unit):
  (code, msg) = e
  x_h1.stream.told(~send, ~close, got, code)

# The head answer slot for a validated head: the handler's head event when
# the head is clean, the refusal code when it is not (the handler never
# sees a refused request). The code rides in the slot's first half and the
# loop routes on it with x_h1.stream.err_phase, so a match never has to
# scrutinize a computed value.
def x_h1.stream.head_ans(~H: HTTP.SrvEv -> HTTP.SrvOut, +code: U32, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, nb: Bool) -> U32 & HTTP.Response:
  match code:
    case 0:
      x_h1.stream.head_act(H(HTTP.SrvReqHead{1, HTTP.ReqHead{m, p, hs}}), nb)
    case _:
      (code, HTTP.Response{0, Nil{}, Nil{}})

def x_h1.stream.err_phase(+code: U32) -> U32:
  match code:
    case 0:
      5
    case _:
      4

def x_h1.stream.no_ans() -> U32 & HTTP.Response:
  (0, HTTP.Response{0, Nil{}, Nil{}})

def x_h1.stream.no_head() -> Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>:
  (Fail{(400, "bad request")}, Nil{})

# got B (TASK-040): one x_h1.split traversal for head-lines and rest,
# where the pair rides in as a parameter (E1 rejects a computed variant).
def x_h1.stream.parsed.got(p: List<&2, U32> & List<&2, U32> & Bool) -> Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>:
  match p:
    case (head, rest, found):
      +hl = x_h1.head_lines(head)
      (x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))), rest)

# The request head, parsed. The bytes that arrived with the head seed
# the pending buffer — a request that arrives whole in one packet must
# not lose its body.
def x_h1.stream.parsed(+acc: List<&2, U32>) -> Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>:
  x_h1.stream.parsed.got(x_h1.split(acc))

# The loop, phase by phase: 0/1/2 read the head (16KB a turn, 64 turns,
# the blank-line cut, 431 past either cap); 3 parses, validates the head
# (RFC 9112 sections 3.2/6.3, 400) and frames it (GET/HEAD carry no body,
# like the one-shot server); 5 acts on the head answer; 6 asks the framing
# for the next chunk through x_h1.stream.next above; 7 delivers it and
# acts; 9 reads more body and 10 takes the read back. ans rides the last
# answer as code plus the response it chose.
@unsafe
def x_h1.stream.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool, +nbody: Bool, +chunked: Bool, +cl: U32, +pending: List<&2, U32>, +seen: U32, +cst: HTTP.ChunkSt, ans: U32 & HTTP.Response, out: HTTP.ChunkSt & HTTP.UnitOut, head: Result<&1, &1, U32 & String, HTTP.H1Head> & List<&2, U32>) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          x_h1.stream.told(~send, ~close, got, x_h1.head_cap())
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.stream.go(~recv, ~send, ~close, ~H, 1, r, acc, f, False{}, nbody, chunked, cl, pending, seen, cst, ans, out, head)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          x_h1.stream.closed(~close, got)
        case Done{+part}:
          match part:
            case Nil{}:
              x_h1.stream.closed(~close, got)
            case h <> t:
              +acc2 = List.append(&2, U32, acc, part)
              +over = x_h1.head_over(HTTP.x_len32(acc2))
              x_h1.stream.go(~recv, ~send, ~close, ~H, x_h1.head_phase(over), (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), x_h1.split.test(acc2), nbody, chunked, cl, pending, seen, cst, ans, out, head)
    case 2:
      match found:
        case True{}:
          x_h1.stream.go(~recv, ~send, ~close, ~H, 3, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, ans, out, x_h1.stream.parsed(acc))
        case False{}:
          x_h1.stream.go(~recv, ~send, ~close, ~H, 0, got, acc, fuel, False{}, nbody, chunked, cl, pending, seen, cst, ans, out, head)
    case 3:
      match head:
        case (h3, p3):
          match h3:
            case Fail{e}:
              x_h1.stream.stop_told(~send, ~close, got, e)
            case Done{+rh}:
              match rh:
                case HTTP.H1Head{head, is_11}:
                  match head:
                    case HTTP.ReqHead{+m, +p, +hs}:
                      +code = x_h1.srv.head_err(hs, is_11)
                      +nb = Bool.or(String.eq(m, "GET"), String.eq(m, "HEAD"))
                      x_h1.stream.go(~recv, ~send, ~close, ~H, x_h1.stream.err_phase(code), got, Nil{}, 0n, False{}, nb, x_h1.is_chunked(hs), x_h1.cl_of(hs), p3, 0, x_h1.chunk_init(), x_h1.stream.head_ans(~H, code, m, p, hs, nb), (x_h1.chunk_init(), HTTP.End{Nil{}}), x_h1.stream.no_head())
    case 4:
      match ans:
        case (a4, resp4):
          x_h1.stream.told(~send, ~close, got, a4)
    case 5:
      match ans:
        case (a5, resp5):
          match a5:
            case 0:
              x_h1.stream.go(~recv, ~send, ~close, ~H, 6, got, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, x_h1.stream.no_ans(), x_h1.stream.next(chunked, cst, pending, cl, seen), head)
            case 1:
              x_h1.stream.respond(~send, ~close, got, resp5)
            case _:
              x_h1.stream.closed(~close, got)
    case 6:
      match out:
        case (st2, o):
          match o:
            case HTTP.Got{+chunk, +fin, +rest}:
              x_h1.stream.go(~recv, ~send, ~close, ~H, 7, got, Nil{}, 0n, False{}, nbody, chunked, cl, rest, (seen + HTTP.x_len32(chunk) : U32), st2, x_h1.stream.data_act(H(HTTP.SrvReqData{1, chunk, fin}), fin), (x_h1.chunk_init(), HTTP.End{Nil{}}), head)
            case HTTP.NeedMore{missing, +rest}:
              x_h1.stream.go(~recv, ~send, ~close, ~H, 9, got, Nil{}, 0n, False{}, nbody, chunked, cl, rest, seen, st2, ans, (x_h1.chunk_init(), HTTP.End{Nil{}}), head)
            case HTTP.End{+rest}:
              x_h1.stream.go(~recv, ~send, ~close, ~H, 7, got, Nil{}, 0n, False{}, nbody, chunked, cl, rest, seen, cst, x_h1.stream.data_act(H(HTTP.SrvReqData{1, Nil{}, True{}}), True{}), (x_h1.chunk_init(), HTTP.End{Nil{}}), head)
            case HTTP.Bad{code, msg}:
              x_h1.stream.bad(~send, ~close, got)
    case 7:
      match ans:
        case (a7, resp7):
          match a7:
            case 0:
              x_h1.stream.go(~recv, ~send, ~close, ~H, 5, got, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, x_h1.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head)
            case 1:
              x_h1.stream.respond(~send, ~close, got, resp7)
            case _:
              x_h1.stream.closed(~close, got)
    case 9:
      (s9, r9) = got
      do IO<Unit>:
        r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s9, 16384)
        x_h1.stream.go(~recv, ~send, ~close, ~H, 10, r, Nil{}, 0n, False{}, nbody, chunked, cl, pending, seen, cst, ans, (x_h1.chunk_init(), HTTP.End{Nil{}}), head)
    case 10:
      (s10, r10) = got
      match r10:
        case Fail{e}:
          x_h1.stream.closed(~close, got)
        case Done{+part}:
          match part:
            case Nil{}:
              x_h1.stream.closed(~close, got)
            case h <> t:
              x_h1.stream.go(~recv, ~send, ~close, ~H, 5, (s10, Done{Nil{}}), Nil{}, 0n, False{}, nbody, chunked, cl, List.append(&2, U32, pending, part), seen, cst, x_h1.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), head)
    case _:
      x_h1.stream.closed(~close, got)

# Per-connection entry, the two the accept loops spawn.
def x_h1.stream.start(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket) -> IO(Unit):
  x_h1.stream.go(~recv, ~send, ~close, ~H, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{}, False{}, False{}, 0, Nil{}, 0, x_h1.chunk_init(), x_h1.stream.no_ans(), (x_h1.chunk_init(), HTTP.End{Nil{}}), x_h1.stream.no_head())

def x_h1.stream.spawn.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket) -> IO(Unit):
  x_h1.stream.start(~recv, ~send, ~close, ~H, sock)

def x_h1.stream.spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, sock: Socket, l: Listener) -> IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, x_h1.stream.spawn.go(~recv, ~send, ~close, ~H, sock))
    return l

def x_h1.stream.conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.SrvEv -> HTTP.SrvOut, m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      x_h1.stream.spawn(~recv, ~send, ~close, ~H, sock, l)

# H1 serve (Phase 11), keep-alive since TASK-027: the connection lane is
# one state machine (x_h1.srv.head) whose phase 3 decides reuse vs close,
# fed back by the answer path as a (socket, outcome) pair — Bend has no
# forward references, so the loop cannot be a mutual recursion. Closing is
# by "connection: close" (x_h1.conn_close), EOF, or a terminal 413/502.
# Handlers speak Request / Response natively, so server.on_alpn takes ONE
# handler for both lanes.
# ---------------------------------------------------------------------

def x_h1.srv.needs_body(+m: String) -> Bool:
  Bool.not(Bool.or(String.eq(m, "GET"), String.eq(m, "HEAD")))

def x_h1.srv.sock_of(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> Socket:
  (s, r) = got
  s

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
def x_h1.srv.safe_resp.go(+status: U32, +headers: List<&2, HTTP.Hdr>, +body: List<&2, U32>, bad: Bool) ->
  HTTP.Response:
  match bad:
    case True{}:
      HTTP.Response{500, Nil{}, Nil{}}
    case False{}:
      HTTP.Response{status, headers, body}

def x_h1.srv.safe_resp(resp: HTTP.Response) -> HTTP.Response:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      x_h1.srv.safe_resp.go(status, headers, body, x_h1.bad_hdrs(headers))

# The answer path never closes the socket: it hands it back to the head
# machine in the very pair type the read phases use, so phase 3 is the
# single place that decides reuse vs close.
#   read_next(s, rest) -> Done{rest}: the answer is out, read the next
#     request, seeded with the bytes already read past this one.
#   stop(s, e)         -> Fail{e}: this connection ends here. e is the
#     send/read error, or (413/502, ...) for a terminal answer, or
#     (0, "close") for a peer that asked for close.
# Fail already means "stop" in phases 1 and 3, so no second outcome type
# is invented. The loop cannot be a mutual recursion (respond -> head ->
# parsed -> ... -> respond): Bend only sees defs already defined, so the
# head machine is the one def allowed to loop and the answer path ends by
# returning to it.
def x_h1.srv.read_next(s: Socket, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
    (s, Done{rest}))

def x_h1.srv.stop(s: Socket, e: U32 & String) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (code, msg) = e
  IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
    (s, Fail{(code, msg)}))

# A terminal code the peer must see before the connection ends: 400..599 is
# a status this server renders (the parse errors, the 413 caps, the 431
# head cap), 0 ("close") and the 6xx transport codes (TLS/DNS) are not, and
# a send that already failed is not retried.
def x_h1.srv.told_sent(~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, r2) = sent
  close(s2)

def x_h1.srv.told_go(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, +code: U32, told: Bool) -> IO(Unit):
  match told:
    case True{}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(s, x_h1.show_resp(code, Nil{}, Nil{}))
        x_h1.srv.told_sent(~close, sent)
    case False{}:
      close(s)

def x_h1.srv.told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket, e: U32 & String) -> IO(Unit):
  (+code, msg) = e
  x_h1.srv.told_go(~send, ~close, s, code, x_h1.srv.is_status(code))

def x_h1.srv.cap_told(~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), s: Socket) -> IO(Unit):
  x_h1.srv.told(~send, ~close, s, (x_h1.head_cap(), "head too large"))

def x_h1.srv.sent_keep(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s2, r2) = sent
  match r2:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, List<&2, U32>>,
        (s2, Fail{e}))
    case Done{u}:
      match keep:
        case True{}:
          x_h1.srv.read_next(s2, rest)
        case False{}:
          x_h1.srv.stop(s2, (0, "close"))

def x_h1.srv.respond(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), sock: Socket, +resp: HTTP.Response, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, x_h1.show_resp(status, headers, body))
        x_h1.srv.sent_keep(~recv, ~send, ~close, sent, keep, rest)

def x_h1.srv.answer(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +req: HTTP.Request, keep: Bool, +rest: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s, r) = got
  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
    resp : HTTP.Response <- H(req)
    x_h1.srv.respond(~recv, ~send, ~close, s, x_h1.srv.safe_resp(resp), keep, rest)

def x_h1.srv.recv(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  (s0, r0) = got
  recv(s0, 16384)

@unsafe
def x_h1.srv.bd(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +have: List<&2, U32>, fuel: Nat, +cl: U32, enough: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match phase:
    case 0:
      match fuel:
        case 0n:
          x_h1.srv.stop(x_h1.srv.sock_of(got), (413, "request too long"))
        case 1n+f:
          match enough:
            case True{}:
              x_h1.srv.answer(~recv, ~send, ~close, ~H, got, HTTP.Request{m, p, hs, HTTP.x_take32(cl, have)}, Bool.not(x_h1.conn_close(hs)), HTTP.x_drop32(cl, have))
            case False{}:
              do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.recv(~recv, ~send, ~close, got)
                x_h1.srv.bd(~recv, ~send, ~close, ~H, 1, r, m, p, hs, have, f, cl, False{})
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          x_h1.srv.stop(s1, e)
        case Done{+part}:
          match part:
            case Nil{}:
              x_h1.srv.stop(s1, (400, "eof"))
            case h <> t:
              +have2 = List.append(&2, U32, have, part)
              x_h1.srv.bd(~recv, ~send, ~close, ~H, 0, (s1, Done{Nil{}}), m, p, hs, have2, fuel, cl, HTTP.x_has_at_least(cl, have2))
    case _:
      (s9, r9) = got
      x_h1.srv.stop(s9, (502, "bad phase"))

def x_h1.srv.cl(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), s: Socket, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +rest: List<&2, U32>, fuel: Nat, +cl: U32, big: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match big:
    case True{}:
      x_h1.srv.respond(~recv, ~send, ~close, s, HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
    case False{}:
      x_h1.srv.bd(~recv, ~send, ~close, ~H, 0, (s, Done{Nil{}}), m, p, hs, rest, fuel, cl, HTTP.x_has_at_least(cl, rest))

# The server's chunked request reader: the same phase+fuel shape as
# x_h1.srv.bd, with the decoder deciding where the body ends instead of a
# Content-Length. Two caps, both the ones the CL path already has: the
# decoded size (the same 16384 x_h1.srv.cl refuses with a 413 response,
# carried as the big parameter and matched on the next iteration because a
# match cannot scrutinize a computed value) and fuel (one recv per step,
# floor 413 "request too long", which closes without an answer exactly
# like x_h1.srv.bd). A chunk larger than the cap is still read before the
# answer -- the decoder only reports a chunk when it is whole -- so the
# memory bound in that case is the fuel floor, not the cap.
#
# Malformed bytes are answered 400 "bad chunked" and the connection ends:
# task-033's fail-closed rule is that the peer is told, not just dropped
# (the old 502 was a response too). Only End hands the request to the
# handler; the leftover bytes past the terminator ride to x_h1.srv.answer
# as the next request's seed, exactly like the CL path's x_drop32(cl, have).
@unsafe
def x_h1.srv.chunk(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), phase: U32, big: Bool, r: HTTP.ChunkSt & HTTP.UnitOut, fuel: Nat, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, rev: List<&2, U32>, buf: List<&2, U32>, +have: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match phase:
    case 0:
      match big:
        case True{}:
          (sock, _r0) = got
          x_h1.srv.respond(~recv, ~send, ~close, sock, HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
        case False{}:
          match r:
            case (st2, out):
              match out:
                case HTTP.Got{+chunk, fin, +rest}:
                  (sock2, _r1) = got
                  +have2 = (have + HTTP.x_len32(chunk) : U32)
                  x_h1.srv.chunk(~recv, ~send, ~close, ~H, 0, U32.is_gt(have2, 16384), x_h1.chunk_step(st2, rest), fuel, m, p, hs, HTTP.x_rev_push(chunk, rev), rest, have2, (sock2, Done{Nil{}}))
                case HTTP.NeedMore{missing, +rest}:
                  match fuel:
                    case 0n:
                      (sock3, _r2) = got
                      x_h1.srv.stop(sock3, (413, "request too long"))
                    case 1n+f:
                      (sock4, _r3) = got
                      do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
                        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(sock4, 16384)
                        x_h1.srv.chunk(~recv, ~send, ~close, ~H, 1, big, r, f, m, p, hs, rev, rest, have, r1)
                case HTTP.End{rest}:
                  (sock5, _r4) = got
                  x_h1.srv.answer(~recv, ~send, ~close, ~H, (sock5, Done{Nil{}}), HTTP.Request{m, p, hs, HTTP.x_cat(rev)}, Bool.not(x_h1.conn_close(hs)), rest)
                case HTTP.Bad{code2, msg}:
                  (sock6, _r5) = got
                  do IO<Socket & Result<&1, &1, U32 & String, List<&2, U32>>>:
                    rr : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, sock6, HTTP.Response{400, Nil{}, Nil{}}, False{}, Nil{})
                    x_h1.srv.stop(x_h1.srv.sock_of(rr), (400, "bad chunked"))
    case 1:
      match r:
        case (st2, out):
          match got:
            case (sock, r1):
              match r1:
                case Fail{e}:
                  x_h1.srv.stop(sock, e)
                case Done{+part}:
                  match part:
                    case Nil{}:
                      x_h1.srv.stop(sock, (400, "eof"))
                    case h <> t:
                      +buf2 = List.append(&2, U32, buf, part)
                      x_h1.srv.chunk(~recv, ~send, ~close, ~H, 0, big, x_h1.chunk_step(st2, buf2), fuel, m, p, hs, rev, buf2, have, (sock, Done{Nil{}}))
    case _:
      (s9, r9) = got
      x_h1.srv.stop(s9, (502, "bad phase"))

def x_h1.srv.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), s: Socket, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +rest: List<&2, U32>, fuel: Nat, needs: Bool, +cl: U32, chunked: Bool) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match needs:
    case False{}:
      x_h1.srv.answer(~recv, ~send, ~close, ~H, (s, Done{Nil{}}), HTTP.Request{m, p, hs, Nil{}}, Bool.not(x_h1.conn_close(hs)), rest)
    case True{}:
      match chunked:
        case True{}:
          x_h1.srv.chunk(~recv, ~send, ~close, ~H, 0, False{}, x_h1.chunk_step(x_h1.chunk_init(), rest), fuel, m, p, hs, Nil{}, rest, 0, (s, Done{Nil{}}))
        case False{}:
          x_h1.srv.cl(~recv, ~send, ~close, ~H, s, m, p, hs, rest, fuel, cl, U32.is_gt(cl, 16384))

def x_h1.srv.checked(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), s1: Socket, +rest: List<&2, U32>, fuel: Nat, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, code: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match code:
    case 0:
      x_h1.srv.go(~recv, ~send, ~close, ~H, s1, m, p, hs, rest, fuel, x_h1.srv.needs_body(m), x_h1.cl_of(hs), x_h1.is_chunked(hs))
    case _:
      x_h1.srv.stop(s1, (code, "refused"))

def x_h1.srv.ruled(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), s1: Socket, +rest: List<&2, U32>, fuel: Nat, joinres: Result<&1, &1, U32 & String, HTTP.H1Head>) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match joinres:
    case Fail{e}:
      x_h1.srv.stop(s1, e)
    case Done{+rh}:
      match rh:
        case HTTP.H1Head{head, is_11}:
          match head:
            case HTTP.ReqHead{+m, +p, +hs}:
              x_h1.srv.checked(~recv, ~send, ~close, ~H, s1, rest, fuel, m, p, hs, x_h1.srv.head_err(hs, is_11))

# got B (TASK-040): one x_h1.split traversal for head-lines and rest.
def x_h1.srv.parsed.got(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, p: List<&2, U32> & List<&2, U32> & Bool, fuel: Nat) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  match p:
    case (head, rest, found):
      +hl = x_h1.head_lines(head)
      x_h1.srv.ruled(~recv, ~send, ~close, ~H, x_h1.srv.sock_of(got), rest, fuel, x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))))

def x_h1.srv.parsed(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  x_h1.srv.parsed.got(~recv, ~send, ~close, ~H, got, x_h1.split(acc), fuel)

@unsafe
def x_h1.srv.head(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          x_h1.srv.cap_told(~send, ~close, s0)
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.srv.head(~recv, ~send, ~close, ~H, 1, r, acc, f, False{})
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
              x_h1.srv.head(~recv, ~send, ~close, ~H, x_h1.head_phase(over), (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), x_h1.split.test(acc2))
    case 2:
      match found:
        case False{}:
          x_h1.srv.head(~recv, ~send, ~close, ~H, 0, got, acc, fuel, False{})
        case True{}:
          # The answer path hands the socket back: Done{rest} keeps the
          # connection (phase 3 re-seeds from the leftover), Fail{e}
          # stops it (phase 3 closes). acc restarts empty — the bytes
          # just answered are not part of the next request — and the
          # head fuel budget restarts per request, or a long-lived
          # connection would starve after 64 of them.
          do IO<Unit>:
            out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.parsed(~recv, ~send, ~close, ~H, got, acc, fuel)
            x_h1.srv.head(~recv, ~send, ~close, ~H, 3, out, Nil{}, 64n, False{})
    case 3:
      # Keep-alive re-entry: never reads here, only decides. An empty
      # seed (nothing was buffered past the request) goes back to the
      # socket; a non-empty one is the next request's first bytes, so it
      # enters the accumulate phase exactly like a fresh recv would —
      # pipelined requests lose nothing.
      (s3, r3) = got
      match r3:
        case Fail{e}:
          x_h1.srv.told(~send, ~close, s3, e)
        case Done{+seed}:
          match seed:
            case Nil{}:
              x_h1.srv.head(~recv, ~send, ~close, ~H, 0, (s3, Done{Nil{}}), acc, fuel, False{})
            case h <> t:
              x_h1.srv.head(~recv, ~send, ~close, ~H, 1, (s3, Done{seed}), acc, fuel, False{})
    case _:
      (s9, r9) = got
      close(s9)

def x_h1.serve_start(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), sock: Socket) -> IO(Unit):
  x_h1.srv.head(~recv, ~send, ~close, ~H, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def h1_spawn.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), sock: Socket) -> IO(Unit):
  x_h1.serve_start(~recv, ~send, ~close, ~H, sock)

def h1_spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, h1_spawn.go(~recv, ~send, ~close, ~H, sock))
    return l

def h1_conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      h1_spawn(~recv, ~send, ~close, ~H, sock, l)

# H1 upgrade lane (101): the answer path that lends the socket out. Unlike
# x_h1.srv.answer (which hands the socket BACK to the head machine's phase
# 3 as read_next/stop), answer_open never returns the socket to the
# machine: on 101 it sends the head and calls ~K(sock, rest), and the
# socket stays with ~K until the WS loop closes it. Anything else answers
# through the normal respond and REJOINS the machine (rejoin = phase 3
# with the leftover seed), so a ~H that refuses the upgrade reuses or
# closes exactly like the keep-alive lane. The keep-alive machine itself
# is untouched — no signature churn on the hot path, no wire change.
# A 101 body is dropped (a 101 carries none); only status and headers
# ride show_resp_head.
# ---------------------------------------------------------------------

def x_h1.srv.sent_open(~close: Socket -> IO(Unit), ~K: Socket -> List<&2, U32> -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>, +rest: List<&2, U32>) -> IO(Unit):
  (s2, r2) = sent
  match r2:
    case Fail{e}:
      close(s2)
    case Done{u}:
      K(s2, rest)

def x_h1.srv.rejoin(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), out: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = out
  match r:
    case Fail{e}:
      close(s)
    case Done{+seed}:
      x_h1.srv.head(~recv, ~send, ~close, ~H, 3, (s, Done{seed}), Nil{}, 64n, False{})

def x_h1.srv.status_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, +status: U32, +headers: List<&2, HTTP.Hdr>, +body: List<&2, U32>, keep: Bool, +rest: List<&2, U32>, is101: Bool) -> IO(Unit):
  match is101:
    case True{}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- send(sock, x_h1.show_resp_head(status, headers))
        x_h1.srv.sent_open(~close, ~K, sent, rest)
    case False{}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, sock, HTTP.Response{status, headers, body}, keep, rest)
        x_h1.srv.rejoin(~recv, ~send, ~close, ~H, out)

def x_h1.srv.reply_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, +resp: HTTP.Response, keep: Bool, +rest: List<&2, U32>) -> IO(Unit):
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      x_h1.srv.status_open(~recv, ~send, ~close, ~H, ~K, sock, status, headers, body, keep, rest, U32.is_eq(status, 101))

def x_h1.srv.answer_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +req: HTTP.Request, keep: Bool, +rest: List<&2, U32>) -> IO(Unit):
  (s, r) = got
  do IO<Unit>:
    resp : HTTP.Response <- H(req)
    x_h1.srv.reply_open(~recv, ~send, ~close, ~H, ~K, s, x_h1.srv.safe_resp(resp), keep, rest)

@unsafe
def x_h1.srv.bd_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +have: List<&2, U32>, fuel: Nat, +cl: U32, enough: Bool) -> IO(Unit):
  match phase:
    case 0:
      match fuel:
        case 0n:
          close(x_h1.srv.sock_of(got))
        case 1n+f:
          match enough:
            case True{}:
              x_h1.srv.answer_open(~recv, ~send, ~close, ~H, ~K, got, HTTP.Request{m, p, hs, HTTP.x_take32(cl, have)}, Bool.not(x_h1.conn_close(hs)), HTTP.x_drop32(cl, have))
            case False{}:
              do IO<Unit>:
                r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.recv(~recv, ~send, ~close, got)
                x_h1.srv.bd_open(~recv, ~send, ~close, ~H, ~K, 1, r, m, p, hs, have, f, cl, False{})
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
              x_h1.srv.bd_open(~recv, ~send, ~close, ~H, ~K, 0, (s1, Done{Nil{}}), m, p, hs, have2, fuel, cl, HTTP.x_has_at_least(cl, have2))
    case _:
      (s9, r9) = got
      close(s9)

def x_h1.srv.cl_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s: Socket, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +rest: List<&2, U32>, fuel: Nat, +cl: U32, big: Bool) -> IO(Unit):
  match big:
    case True{}:
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, s, HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
        x_h1.srv.rejoin(~recv, ~send, ~close, ~H, out)
    case False{}:
      x_h1.srv.bd_open(~recv, ~send, ~close, ~H, ~K, 0, (s, Done{Nil{}}), m, p, hs, rest, fuel, cl, HTTP.x_has_at_least(cl, rest))

# The upgrade lane's copy of the chunked reader: same grammar, same caps,
# different endings. A 413 over the cap is answered and then rejoined
# through x_h1.srv.rejoin (the CL path's x_h1.srv.cl_open does the same
# with its 413), a malformed body is answered 400 and the connection ends,
# and fuel exhaustion closes without an answer, which is what
# x_h1.srv.bd_open does. End hands the request to the handler through
# x_h1.srv.answer_open, so a chunked request reaches ~H on this lane too
# instead of the old 502.
@unsafe
def x_h1.srv.chunk_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, big: Bool, r: HTTP.ChunkSt & HTTP.UnitOut, fuel: Nat, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, rev: List<&2, U32>, buf: List<&2, U32>, +have: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Unit):
  match phase:
    case 0:
      match big:
        case True{}:
          (sock, _r0) = got
          do IO<Unit>:
            rr : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, sock, HTTP.Response{413, Nil{}, Nil{}}, False{}, Nil{})
            x_h1.srv.rejoin(~recv, ~send, ~close, ~H, rr)
        case False{}:
          match r:
            case (st2, out):
              match out:
                case HTTP.Got{+chunk, fin, +rest}:
                  (sock2, _r1) = got
                  +have2 = (have + HTTP.x_len32(chunk) : U32)
                  x_h1.srv.chunk_open(~recv, ~send, ~close, ~H, ~K, 0, U32.is_gt(have2, 16384), x_h1.chunk_step(st2, rest), fuel, m, p, hs, HTTP.x_rev_push(chunk, rev), rest, have2, (sock2, Done{Nil{}}))
                case HTTP.NeedMore{missing, +rest}:
                  match fuel:
                    case 0n:
                      (sock3, _r2) = got
                      close(sock3)
                    case 1n+f:
                      (sock4, _r3) = got
                      do IO<Unit>:
                        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(sock4, 16384)
                        x_h1.srv.chunk_open(~recv, ~send, ~close, ~H, ~K, 1, big, r, f, m, p, hs, rev, rest, have, r1)
                case HTTP.End{rest}:
                  (sock5, _r4) = got
                  x_h1.srv.answer_open(~recv, ~send, ~close, ~H, ~K, (sock5, Done{Nil{}}), HTTP.Request{m, p, hs, HTTP.x_cat(rev)}, Bool.not(x_h1.conn_close(hs)), rest)
                case HTTP.Bad{code2, msg}:
                  (sock6, _r5) = got
                  do IO<Unit>:
                    rr2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- x_h1.srv.respond(~recv, ~send, ~close, sock6, HTTP.Response{400, Nil{}, Nil{}}, False{}, Nil{})
                    x_h1.srv.rejoin(~recv, ~send, ~close, ~H, rr2)
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
                      x_h1.srv.chunk_open(~recv, ~send, ~close, ~H, ~K, 0, big, x_h1.chunk_step(st2, buf2), fuel, m, p, hs, rev, buf2, have, (sock, Done{Nil{}}))
    case _:
      (s9, r9) = got
      close(s9)

def x_h1.srv.go_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s: Socket, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, +rest: List<&2, U32>, fuel: Nat, needs: Bool, +cl: U32, chunked: Bool) -> IO(Unit):
  match needs:
    case False{}:
      x_h1.srv.answer_open(~recv, ~send, ~close, ~H, ~K, (s, Done{Nil{}}), HTTP.Request{m, p, hs, Nil{}}, Bool.not(x_h1.conn_close(hs)), rest)
    case True{}:
      match chunked:
        case True{}:
          x_h1.srv.chunk_open(~recv, ~send, ~close, ~H, ~K, 0, False{}, x_h1.chunk_step(x_h1.chunk_init(), rest), fuel, m, p, hs, Nil{}, rest, 0, (s, Done{Nil{}}))
        case False{}:
          x_h1.srv.cl_open(~recv, ~send, ~close, ~H, ~K, s, m, p, hs, rest, fuel, cl, U32.is_gt(cl, 16384))

def x_h1.srv.checked_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s1: Socket, +rest: List<&2, U32>, fuel: Nat, +m: String, +p: String, +hs: List<&2, HTTP.Hdr>, code: U32) -> IO(Unit):
  match code:
    case 0:
      x_h1.srv.go_open(~recv, ~send, ~close, ~H, ~K, s1, m, p, hs, rest, fuel, x_h1.srv.needs_body(m), x_h1.cl_of(hs), x_h1.is_chunked(hs))
    case _:
      x_h1.srv.told(~send, ~close, s1, (code, "refused"))

def x_h1.srv.ruled_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), s1: Socket, +rest: List<&2, U32>, fuel: Nat, joinres: Result<&1, &1, U32 & String, HTTP.H1Head>) -> IO(Unit):
  match joinres:
    case Fail{e}:
      x_h1.srv.told(~send, ~close, s1, e)
    case Done{+rh}:
      match rh:
        case HTTP.H1Head{head, is_11}:
          match head:
            case HTTP.ReqHead{+m, +p, +hs}:
              x_h1.srv.checked_open(~recv, ~send, ~close, ~H, ~K, s1, rest, fuel, m, p, hs, x_h1.srv.head_err(hs, is_11))

# got B (TASK-040), open variant: one x_h1.split traversal for head-lines
# and rest (see x_h1.srv.parsed.got).
def x_h1.srv.parsed_open.got(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, p: List<&2, U32> & List<&2, U32> & Bool, fuel: Nat) -> IO(Unit):
  match p:
    case (head, rest, found):
      +hl = x_h1.head_lines(head)
      x_h1.srv.ruled_open(~recv, ~send, ~close, ~H, ~K, x_h1.srv.sock_of(got), rest, fuel, x_h1.req_join(x_h1.req_head(x_h1.req_tok(String.split(x_h1.first_line(hl), ' '))), x_h1.parse_hs(x_h1.rest_lines(hl))))

def x_h1.srv.parsed_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat) -> IO(Unit):
  x_h1.srv.parsed_open.got(~recv, ~send, ~close, ~H, ~K, got, x_h1.split(acc), fuel)

@unsafe
def x_h1.srv.head_open(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool) -> IO(Unit):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          x_h1.srv.cap_told(~send, ~close, s0)
        case 1n+f:
          do IO<Unit>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- recv(s0, 16384)
            x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 1, r, acc, f, False{})
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
              x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, x_h1.head_phase(over), (s1, Done{Nil{}}), acc2, x_h1.fuel_cap(fuel, over), x_h1.split.test(acc2))
    case 2:
      (s2, r2) = got
      match found:
        case False{}:
          x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 0, (s2, Done{Nil{}}), acc, fuel, False{})
        case True{}:
          x_h1.srv.parsed_open(~recv, ~send, ~close, ~H, ~K, (s2, Done{Nil{}}), acc, fuel)
    case _:
      (s9, r9) = got
      close(s9)

def h1_open_spawn.go(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket) -> IO(Unit):
  x_h1.srv.head_open(~recv, ~send, ~close, ~H, ~K, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def h1_open_spawn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), sock: Socket, l: Listener) ->
  IO(Listener):
  do IO<Listener>:
    x : Unit <- IO.spawn(Unit, h1_open_spawn.go(~recv, ~send, ~close, ~H, ~K, sock))
    return l

def h1_open_conn(~recv: Socket -> U32 -> IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>), ~send: Socket -> List<&2, U32> -> IO(Socket & Result<&1, &1, U32 & String, Unit>), ~close: Socket -> IO(Unit), ~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), m: Listener & Result<&1, &1, U32 & String, Socket>) ->
  IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      h1_open_spawn(~recv, ~send, ~close, ~H, ~K, sock, l)
