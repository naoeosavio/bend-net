# Static files pure in Bend (no net, File only).
#
# Import as: import ./static.bend as Static
# Reuses Base and HTTP (has_crlf, has_nul) for validation.
#
# Policy: reject .., absolute paths, empty, CRLF and NUL.
# Content-Type is minimal; missing files are Fail{404}.
# Reads are capped AND fail closed: a file that does not fit the cap is
# Fail{413}, never a truncated body served as a whole one.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
import Base
import ./http1.bend as HTTP

# True when the path is safe to join under a root.

def has_dotdot(+p: String) -> Bool:
  String.contains(p, "..")

def has_bad_start(+p: String) -> Bool:
  Bool.or(String.starts_with(p, "/"), String.starts_with(p, "\\"))

def is_safe.go(empty: Bool, crlf: Bool, nul: Bool, dotdot: Bool, abs: Bool) -> Bool:
  match empty:
    case True{}:
      False{}
    case False{}:
      match crlf:
        case True{}:
          False{}
        case False{}:
          match nul:
            case True{}:
              False{}
            case False{}:
              match dotdot:
                case True{}:
                  False{}
                case False{}:
                  match abs:
                    case True{}:
                      False{}
                    case False{}:
                      True{}

def is_safe(+p: String) -> Bool:
  is_safe.go(String.is_empty(p), HTTP.has_crlf(p), HTTP.has_nul(p), has_dotdot(p), has_bad_start(p))

# Minimal content types (priority json > txt > js > css > html).

def ctype_end(is_html: Bool) -> String:
  match is_html:
    case True{}:
      "text/html"
    case False{}:
      "application/octet-stream"

def ctype_css(is_css: Bool, is_html: Bool) -> String:
  match is_css:
    case True{}:
      "text/css"
    case False{}:
      ctype_end(is_html)

def ctype_js(is_js: Bool, is_css: Bool, is_html: Bool) -> String:
  match is_js:
    case True{}:
      "text/javascript"
    case False{}:
      ctype_css(is_css, is_html)

def ctype_txt(is_txt: Bool, is_js: Bool, is_css: Bool, is_html: Bool) -> String:
  match is_txt:
    case True{}:
      "text/plain"
    case False{}:
      ctype_js(is_js, is_css, is_html)

def ctype_json(is_json: Bool, is_txt: Bool, is_js: Bool, is_css: Bool, is_html: Bool) -> String:
  match is_json:
    case True{}:
      "application/json"
    case False{}:
      ctype_txt(is_txt, is_js, is_css, is_html)

def content_type(+p: String) -> String:
  ctype_json(String.contains(p, ".json"), String.contains(p, ".txt"), String.contains(p, ".js"), String.contains(p, ".css"), Bool.or(String.contains(p, ".html"), String.contains(p, ".htm")))

# File IO: open, size, read, close on every path (mold HTTP.fetch).
# Caps are named, and every read is fail closed.

# Text read cap for safe_read: the historical 8 KB.
def TEXT_CAP() -> U32:
  8192

# Bytes of the file at root ++ path, at most cap. 400 when is_safe
# refuses the path, 404 when it is missing or unreadable, 413 when it
# does not fit cap. The handle is closed on every one of those paths.
def read_bytes.got(read: File & Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  (f, r) = read
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        x : Unit <- File.close(f)
        return Fail{(404, "not found")}
    case Done{bs}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        x : Unit <- File.close(f)
        return Done{bs}

# The cap decision as its own def, so the match inspects a parameter and
# never a computed value.
def read_bytes.fit(f: File, n: U32, is_over: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match is_over:
    case True{}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        x : Unit <- File.close(f)
        return Fail{(413, "file too large")}
    case False{}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        read : File & Result<&1, &1, U32 & String, List<&2, U32>> <-
          File.read_bytes(f, n)
        read_bytes.got(read)

def read_bytes.sized(sized: File & Result<&1, &1, U32 & String, U32>, +cap: U32) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  (f, r) = sized
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        x : Unit <- File.close(f)
        return Fail{(404, "not found")}
    case Done{+n}:
      read_bytes.fit(f, n, U32.is_gt(n, cap))

def read_bytes.open(opened: Result<&1, &1, U32 & String, File>, cap: U32) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match opened:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>,
        Fail{(404, "not found")})
    case Done{f}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        sized : File & Result<&1, &1, U32 & String, U32> <- File.size(f)
        read_bytes.sized(sized, cap)

def read_bytes.go(+root: String, +path: String, cap: U32, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  match ok:
    case True{}:
      do IO<Result<&1, &1, U32 & String, List<&2, U32>>>:
        opened : Result<&1, &1, U32 & String, File> <-
          File.open(root ++ path, "r")
        read_bytes.open(opened, cap)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, List<&2, U32>>,
        Fail{(400, "bad path")})

def read_bytes(+root: String, +path: String, cap: U32) ->
  IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  read_bytes.go(root, path, cap, is_safe(path))

# safe_read: the same read as text, capped at TEXT_CAP. A file past the
# cap is 413, not a truncated String.
def safe_read.decoded(read: Result<&1, &1, U32 & String, List<&2, U32>>) ->
  IO(Result<&1, &1, U32 & String, String>):
  match read:
    case Fail{(code, msg)}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(code, msg)})
    case Done{+bs}:
      IO.pure(Result<&1, &1, U32 & String, String>, Done{HTTP.decode(bs)})

def safe_read(+root: String, +path: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    read : Result<&1, &1, U32 & String, List<&2, U32>> <-
      read_bytes(root, path, TEXT_CAP())
    safe_read.decoded(read)
