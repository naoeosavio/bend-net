# Binance individual-symbol book ticker over WSS (task-017 API, live
# peer). Dials the raw stream endpoint wss://stream.binance.com:9443/ws
# with WSS.client.on (the verified path: TLS cert + hostname checked),
# sends one SUBSCRIBE frame for the <symbol>@bookTicker stream and
# prints the best bid/ask of every update.
#
#   bend examples/wss_binance_bookticker.bend
#   bend examples/wss_binance_bookticker.bend | head -20
#
# Manual only — never in check.sh: it needs the network and a real TLS
# peer, and the feed is real-time (~35 BNBUSDT updates a second measured,
# hence the `head` above). main forks the client, sleeps 15 s and halts,
# so the run always ends on its own.
#
# Server behaviour this handler has to honour: Binance pings every 3
# minutes and drops the socket if no pong comes back within 1 minute, so
# every EvPing is answered with a pong. The raw /ws endpoint takes the
# subscription as a frame (the combined form would put the stream in the
# path: /ws/bnbusdt@bookTicker) and answers the SUBSCRIBE with an ack
# `{"result":null,"id":1}` before the first BOOK line.
#
# The handshake nonce is the RFC 6455 sample key, fixed like every other
# example here; a real client should draw it from the entropy pool.
# There is no JSON parser in the package, so fld pulls a field out of a
# flat object with String.split (no nested objects, no escaped quotes).
import Base
# import ../lib/wsS.bend as WS
import ../lib/wsm.bend as WSS

law sub_frame:
  for +sym: String
  String

def sub_frame(sym):
  "{\"method\":\"SUBSCRIBE\",\"params\":[\"" ++ sym ++ "@bookTicker\"],\"id\":1}"

# Flat-JSON field. Splitting on '"' puts every key on a segment of its
# own, and a string value two segments later with a lone ":" in between:
# {"u":400900217,"s":"BNBUSDT","b":"25.35",...} -> ["{", "u",
# ":400900217,", "s", ":", "BNBUSDT", ..., "b", ":", "25.35", ...].
# So the value is the segment after the ":". "-" when absent. No nested
# objects and no escaped quotes — bookTicker has neither.
law fld.val:
  for xs: List<&2, String>
  String

def fld.val(xs):
  match xs:
    case Nil{}:
      "-"
    case _ <> t:
      match t:
        case Nil{}:
          "-"
        case v <> _:
          v

# Walk the segments carrying the answer in `acc`: "-" until `key` shows
# up, its value from there on, untouched for the rest of the list. The
# found/keep decision lives in fld.pick because a match cannot
# scrutinize a computed value: the call site computes `String.eq(k, key)`
# and hands it over as a parameter.
law fld.pick:
  for +acc: String
  for cand: String
  for is_key: Bool
  String

def fld.pick(acc, cand, is_key):
  match is_key:
    case True{}:
      cand
    case False{}:
      acc

law fld:
  for xs: List<&2, String>
  for +key: String
  for acc: String
  String

def fld(xs, key, acc):
  match xs:
    case Nil{}:
      acc
    case k <> +t:
      fld(t, key, fld.pick(acc, fld.val(t), String.eq(k, key)))

# One update: {"u":400900217,"s":"BNBUSDT","b":"25.35190000",
# "B":"31.21000000","a":"25.36520000","A":"40.66000000"}.
law bk.line:
  for +js: String
  String

def bk.line(js):
  +parts = String.split(js, '"')
  +acc : String = "-"
  +sym = fld(parts, "s", acc)
  +bid = fld(parts, "b", acc)
  +bq = fld(parts, "B", acc)
  +ask = fld(parts, "a", acc)
  +aq = fld(parts, "A", acc)
  "BOOK " ++ sym ++ " bid " ++ bid ++ " x " ++ bq ++ " ask " ++ ask ++ " x " ++ aq

# `is_ack` is a parameter, not a let: a match cannot scrutinize a
# local binder, so the call site computes it.
law h.text:
  for +text: String
  for is_ack: Bool
  IO(WSS.WSOut)

def h.text(text, is_ack):
  match is_ack:
    case True{}:
      do IO<WSS.WSOut>:
        w : Unit <- IO.print("ACK " ++ text)
        return WSS.OutRaw{[]}
    case False{}:
      do IO<WSS.WSOut>:
        w : Unit <- IO.print(bk.line(text))
        return WSS.OutRaw{[]}

law h.btc:
  for ev: WSS.WSEv
  IO(WSS.WSOut)

def h.btc(ev):
  match ev:
    case WSS.EvOpen{}:
      do IO<WSS.WSOut>:
        w : Unit <- IO.print("OPEN stream.binance.com:9443/ws")
        return WSS.OutMsg{WSS.WSText{sub_frame("bnbusdt")}}
    case WSS.EvMsg{msg}:
      match msg:
        case WSS.WSText{text}:
          +t = text
          h.text(t, String.contains(t, "\"result\""))
        case WSS.WSBin{data}:
          do IO<WSS.WSOut>:
            w : Unit <- IO.print("BIN " ++ U32.show(U32.from_nat(List.length(&2, U32, data))))
            return WSS.wsm_out_close([])
    case WSS.EvPing{pay}:
      do IO<WSS.WSOut>:
        w : Unit <- IO.print("PING -> pong")
        return WSS.wsm_out_pong(pay)
    case WSS.EvPong{pay}:
      IO.pure(WSS.WSOut, WSS.OutRaw{[]})
    case WSS.EvClose{pay}:
      do IO<WSS.WSOut>:
        w : Unit <- IO.print("CLOSE " ++ U32.show(U32.from_nat(List.length(&2, U32, pay))))
        return WSS.wsm_out_close([])
    case WSS.EvError{code, msg}:
      do IO<WSS.WSOut>:
        w : Unit <- IO.print("ERR " ++ U32.show(code) ++ " " ++ msg)
        return WSS.wsm_out_close([])

law feed:
  IO(Unit)

def feed():
  do IO<Unit>:
    z : Unit <- WSS.client_on(~h.btc, "stream.binance.com", 9443, "/ws", "dGhlIHNhbXBsZSBub25jZQ==")
    return z

law main:
  IO(U32)

def main():
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, feed())
    w : Unit <- IO.sleep(150000)
    s : Unit <- IO.print("STOP")
    z : Unit <- IO.die(Unit, 0, "")
    return 0
