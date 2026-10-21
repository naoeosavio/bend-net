# io (module_contract): the split's documented contract (task-057 phase 4).
#
# The split is only correct when a consumer finds each name in the module
# that holds it, and when the documents name the live modules. This test
# reads the bundle, the README and the two architecture notes and pins:
#
#   * lib/package.bend imports http, http1 and http2 (a hub consumer gets
#     them: the publish is not transitive);
#   * README names the four modules and no retired one;
#   * docs/modes.md names the H2 wire and carries no line anchor;
#   * docs/h1-transport.md names the H1 wire and no retired WebSocket file;
#   * the H1 source, the facade and the URL test carry no line anchor
#     (D30 removed the `httpx.bend:N` anchors, but `http.bend:N` survived
#     until phase 4).
#
# It reuses Static.read_bytes (fail-closed cap) and HTTP.x_utf8_decode, the
# pair tests/io/httpx_site.bend uses for the same job. Paths are relative to
# the repo root, like every golden. Golden 19.
import Base
import ../../lib/http.bend as HTTP
import ../../lib/static.bend as Static

# Every document here is under 130 KB (http1.bend is the widest).
def CAP() -> U32:
  262144

# 1 for True, 0 for False (the match scrutinee is the parameter).
def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# 1 when the needle is in the text, 0 when it is not.
def has(text: String, +needle: String) -> U32:
  b2u(String.contains(text, needle))

# The inverse: 1 when the retired name is gone.
def lacks(text: String, +needle: String) -> U32:
  U32.sub(1, has(text, needle))

# A file that will not read answers the empty String, so its checks fail
# instead of the run dying: the golden is the count of passing checks.
def slurp.text(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> String:
  match r:
    case Fail{e}:
      ""
    case Done{+bs}:
      HTTP.x_utf8_decode(bs)

def slurp(+path: String, cap: U32) -> IO(String):
  do IO<String>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      Static.read_bytes("", path, cap)
    IO.pure(String, slurp.text(r))

def main() -> IO(Unit):
  do IO<Unit>:
    +readme : String <- slurp("README.md", CAP())
    +modes : String <- slurp("docs/modes.md", CAP())
    +h1doc : String <- slurp("docs/h1-transport.md", CAP())
    +pkg : String <- slurp("lib/package.bend", CAP())
    +h1src : String <- slurp("lib/http1.bend", CAP())
    +hxs : String <- slurp("lib/httpx.bend", CAP())
    +urls : String <- slurp("tests/io/httpx_read_url.bend", CAP())
    +total : U32 =
      (has(readme, "lib/http.bend")
        + has(readme, "lib/http1.bend")
        + has(readme, "lib/http2.bend")
        + has(readme, "lib/httpx.bend")
        + lacks(readme, "lib/https.bend")
        + lacks(readme, "lib/https_http1.bend")
        + lacks(readme, "lib/ws.bend")
        + lacks(readme, "lib/wss.bend")
        + has(pkg, "import ./http.bend")
        + has(pkg, "import ./http1.bend")
        + has(pkg, "import ./http2.bend")
        + has(modes, "lib/http2.bend")
        + lacks(modes, " (:")
        + has(h1doc, "lib/http1.bend")
        + lacks(h1doc, "lib/ws.bend")
        + lacks(h1doc, "lib/wss.bend")
        + lacks(h1src, ".bend:")
        + lacks(hxs, ".bend:")
        + lacks(urls, ".bend:") : U32)
    x : Unit <- IO.print(U32.show(total))
    return x

#|19
