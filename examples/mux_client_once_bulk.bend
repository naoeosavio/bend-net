# HTTPX bulk fetch against a real-world HTTPS API (manual only — not in
# check.sh). GETs the Binance spot exchangeInfo feed (~5.8 MB JSON) via
# HTTPX.client_once (secure TLS, H2 with H1 fallback) and prints the
# status, the body length in bytes, and the first 200 bytes.
# Usage: bend examples/mux_fetch_bulk.bend -o /tmp/opencode/fetchbulk
#        /tmp/opencode/fetchbulk
import Base
import ../lib/httpx.bend as HTTPX

def report_fail(+c: U32, +e: String) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("FAIL " ++ U32.show(c) ++ " " ++ e)
    IO.die(Unit, 1, "")

def report_body(+status: U32, +body: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("STATUS " ++ U32.show(status))
    _ : Unit <- IO.print("LEN " ++ U32.show(HTTPX.x_len32(body)))
    _ : Unit <- IO.print("HEAD " ++ HTTPX.x_bytes_str(HTTPX.x_take32(200, body)))
    _ : Unit <- IO.print("DONE 3/3")
    IO.die(Unit, 0, "")

def report_resp(resp: HTTPX.HttpxResp) -> IO(Unit):
  match resp:
    case HTTPX.HttpxResp{+status, +headers, +body}:
      report_body(status, body)

def report(r: Result<&1, &1, U32 & String, HTTPX.HttpxResp>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      report_fail(c, e)
    case Done{+resp}:
      report_resp(resp)

def main() -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("STEP dial api.binance.com:443")
    r : Result<&1, &1, U32 & String, HTTPX.HttpxResp> <- HTTPX.client_once("api.binance.com", 443, "GET", "/api/v3/exchangeInfo?symbolStatus=TRADING&permissions=SPOT", Nil{}, Nil{})
    report(r)
