# DNS resolve: package-local A lookup for the HTTP lib (no Base
# patch). The public lane is resolve: a canonical dotted quad answers
# itself, "localhost" answers 127.0.0.1, and everything else must pass
# the host checks before the effect runs. The effect (dns_lookup) is
# a twin pair like tcp.bend's: C rides getaddrinfo on io_work's
# helper thread (the loop stays free); JS writes one A query over UDP
# to the first nameserver of /etc/resolv.conf, parks on the socket
# with a deadline (one retry), and answers the first A record.
#
# Fail codes are stable numbers, never resolver text: 601 bad host
# (validation), 602 host not found, 603 resolve failed (try again),
# 604 no IPv4 address, 605 resolve error.
#
# Import as: import ./dns.bend as DNS (from lib) or
# import ../../lib/dns.bend as DNS (from tests/io).
# Then DNS.resolve(host) answers IO(Result<&1, &1, U32 & String,
# String>) with a dotted quad on Done.
#
# Discipline (same as lib/http.bend): every callee is defined ABOVE
# its caller; match scrutinees are params or pattern-bound vars,
# never computed; helpers above drivers are leaves.
#
# Invariant: the resolved IP is transport-only — the caller (HTTP
# fetch/send_request) connects by IP but sends the ORIGINAL host in
# the Host header; virtual hosting never changes.
import Base

# The effect: real name resolution only (the pure layer above this
# comment never reaches it with a quad, "localhost" or an invalid
# host). The twins answer a dotted quad, or Fail with the stable
# table in the header comment.
def dns_lookup(host: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./effs/dns_resolve.c"
  import "./effs/dns_resolve.js"

# A canonical dotted quad — the shape Base's TCP.connect itself
# accepts: four octets of 1-3 digits, no leading zero, each 0-255.

def all_digits.put(is_dig: Bool, rest: Bool) -> Bool:
  match is_dig:
    case True{}:
      rest
    case False{}:
      False{}

def all_digits(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+h, +t}:
      all_digits.put(Char.is_digit(h), all_digits(t))

def no_lead0.put(multi: Bool, lead0: Bool) -> Bool:
  match multi:
    case True{}:
      Bool.not(lead0)
    case False{}:
      True{}

def no_lead0(+s: String) -> Bool:
  no_lead0.put(Nat.is_gt(String.length(s), 1n), String.starts_with(s, "0"))

def octet_val(+s: String) -> Bool:
  U32.is_le(Maybe.default(&2, U32, U32.read(s), 256), 255)

def octet_len(+s: String) -> Bool:
  Bool.and(Nat.is_ge(String.length(s), 1n), Nat.is_le(String.length(s), 3n))

def octet_ok(+s: String) -> Bool:
  Bool.and(octet_len(s), Bool.and(all_digits(s), Bool.and(no_lead0(s), octet_val(s))))

def quad_all.put(ok: Bool, rest: Bool) -> Bool:
  match ok:
    case True{}:
      rest
    case False{}:
      False{}

def quad_all(parts: List<&2, String>) -> Bool:
  match parts:
    case Nil{}:
      True{}
    case h <> t:
      quad_all.put(octet_ok(h), quad_all(t))

def quad_n.go(parts: List<&2, String>, acc: Nat) -> Nat:
  match parts:
    case Nil{}:
      acc
    case h <> t:
      quad_n.go(t, 1n+acc)

def quad_n(parts: List<&2, String>) -> Nat:
  quad_n.go(parts, 0n)

def is_quad.put(four: Bool, all_ok: Bool) -> Bool:
  match four:
    case True{}:
      all_ok
    case False{}:
      False{}

def is_quad(+host: String) -> Bool:
  is_quad.put(Nat.is_eq(quad_n(String.split(host, '.')), 4n), quad_all(String.split(host, '.')))

# Host checks before the effect: printable ASCII only (no controls,
# CRLF, NUL or space), 253 bytes at most, and every dot-label 1-63
# bytes — an empty label rejects leading, trailing and double dots.

def char_ok(+c: Char) -> Bool:
  Bool.and(U32.is_ge(Char.to_u32(c), 33), U32.is_le(Char.to_u32(c), 126))

def chars_ok.put(ok: Bool, rest: Bool) -> Bool:
  match ok:
    case True{}:
      rest
    case False{}:
      False{}

def chars_ok(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+h, +t}:
      chars_ok.put(char_ok(h), chars_ok(t))

def label_ok.put(out: Bool) -> Bool:
  match out:
    case True{}:
      False{}
    case False{}:
      True{}

def label_ok(+s: String) -> Bool:
  label_ok.put(Bool.or(Nat.is_lt(String.length(s), 1n), Nat.is_gt(String.length(s), 63n)))

def labels_ok.put(ok: Bool, rest: Bool) -> Bool:
  match ok:
    case True{}:
      rest
    case False{}:
      False{}

def labels_ok(parts: List<&2, String>) -> Bool:
  match parts:
    case Nil{}:
      True{}
    case h <> t:
      labels_ok.put(label_ok(h), labels_ok(t))

def name_len(+host: String) -> Bool:
  Bool.and(Nat.is_gt(String.length(host), 0n), Nat.is_le(String.length(host), 253n))

def valid_name(+host: String) -> Bool:
  Bool.and(name_len(host), Bool.and(chars_ok(host), labels_ok(String.split(host, '.'))))

# resolve: the fast paths answer without the effect, so both lanes
# see only real names. A dotted quad that fails the canonical check
# is a NAME to the resolver ("256.1.1.1" is asked and fails 602/603,
# never connected as if it were an IP).

def resolve.checked(ok: Bool, host: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match ok:
    case True{}:
      dns_lookup(host)
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Fail{(601, "bad host")})

def resolve.named(is_local: Bool, +host: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match is_local:
    case True{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Done{"127.0.0.1"})
    case False{}:
      resolve.checked(valid_name(host), host)

def resolve.put(quad: Bool, +host: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  match quad:
    case True{}:
      IO.pure(Result<&1, &1, U32 & String, String>, Done{host})
    case False{}:
      resolve.named(String.eq(host, "localhost"), host)

def resolve(+host: String) -> IO(Result<&1, &1, U32 & String, String>):
  resolve.put(is_quad(host), host)
