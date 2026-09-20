# Static files pure in Bend (no net, File only).
#
# Import as: import ./static.bend as Static
# Reuses Base and HTTP (has_crlf, has_nul) for validation.
#
# Policy: reject .., absolute paths, empty, CRLF and NUL.
# Content-Type is minimal; missing files are Fail{404}.
#
# Discipline (user-land Bend has no Base carve-out):
# - every callee is defined ABOVE its caller; only self-recursion.
# - match scrutinees are params or pattern-bound vars, never computed.
import Base
import ./http.bend as HTTP

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

# File IO: open, read, close on every path (mold HTTP.fetch).

def read_opened(read: File & Result<&1, &1, U32 & String, String>) -> IO(Result<&1, &1, U32 & String, String>) :
  (f, r) = read
  match r:
    case Fail{e}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- File.close(f)
        return Fail{(404, "not found")}
    case Done{body}:
      do IO<Result<&1, &1, U32 & String, String>>:
        x : Unit <- File.close(f)
        return Done{body}

def read_opened2(opened: Result<&1, &1, U32 & String, File>, +full: String) -> IO(Result<&1, &1, U32 & String, String>):
  match opened:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(404, "not found")})
    case Done{f}:
      do IO<Result<&1, &1, U32 & String, String>>:
        read : File & Result<&1, &1, U32 & String, String> <- File.read(f, 8192)
        read_opened(read)

def read_file(+root: String, +path: String) -> IO(Result<&1, &1, U32 & String, String>):
  do IO<Result<&1, &1, U32 & String, String>>:
    opened : Result<&1, &1, U32 & String, File> <- File.open(root ++ path, "r")
    read_opened2(opened, root ++ path)

def safe_read.go(+root: String, +path: String, ok: Bool) -> IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      read_file(root, path)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(400, "bad path")})

def safe_read(+root: String, +path: String) -> IO(Result<&1, &1, U32 & String, String>):
  safe_read.go(root, path, is_safe(path))
