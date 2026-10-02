# HTTPX bulk fetch against a real-world HTTPS API (manual only — not in
# check.sh). GETs the Binance spot exchangeInfo feed (~5.8 MB JSON) via
# HTTPX.fetch_bytes (URL string through httpx_url.read_url, secure TLS, H2
# with H1 fallback) and prints the body length in bytes plus the first
# 200 bytes. NOTE: run the compiled binary, NOT interp — interp stack-
# overflows on multi-MB bodies (deep x_len32 walk + O(n^2) drain
# accumulation over ~5.8M list nodes).
# Usage: bend examples/httpx_fetch_bulk.bend -o /tmp/opencode/fetchbulk
#        /tmp/opencode/fetchbulk
import Base
import ../lib/httpx.bend as HTTPX

def report_fail(+c: U32, +e: String) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("FAIL " ++ U32.show(c) ++ " " ++ e)
    IO.die(Unit, 1, "")

def report_body(+body: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("LEN " ++ U32.show(HTTPX.x_len32(body)))
    _ : Unit <- IO.print("HEAD " ++ HTTPX.x_bytes_str(HTTPX.x_take32(200, body)))
    _ : Unit <- IO.print("DONE 2/2")
    IO.die(Unit, 0, "")

def report(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      report_fail(c, e)
    case Done{+body}:
      report_body(body)

def main() -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("STEP fetch api.binance.com exchangeInfo")
    r : Result<&1, &1, U32 & String, List<&2, U32>> <- HTTPX.fetch_bytes("https://api.binance.com/api/v3/exchangeInfo?symbolStatus=TRADING&permissions=SPOT")
    report(r)
