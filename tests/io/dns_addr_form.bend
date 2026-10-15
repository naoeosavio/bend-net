# lib (dns_addr_form): pure address-form vectors for DNS.resolve.
# addr_form is the pre-effect gate task-051 A2 added so both lanes
# refuse the same inputs: a host whose characters are only digits,
# dots and x (plus hex letters behind a 0x prefix) is an address
# form, and a form that is not a canonical quad fails 601 before the
# effect. A real name with hex letters but no 0x prefix (beef1.cafe,
# F4: .cafe is a real TLD) is still a name. Hermetic: addr_form is
# pure, no effect runs here.
import Base
import ../../lib/dns.bend as DNS

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law main:
  IO(U32)

def main():
  do IO<U32>:
    t1 : U32 = b2u(DNS.addr_form("01.2.3.4"))
    t2 : U32 = (b2u(DNS.addr_form("127.1")) * 10 : U32)
    t3 : U32 = (b2u(DNS.addr_form("0x7f.1")) * 100 : U32)
    t4 : U32 = (b2u(DNS.addr_form("256.1.1.1")) * 1000 : U32)
    t5 : U32 = (b2u(DNS.addr_form("127.0.0.1")) * 10000 : U32)
    f1 : U32 = (b2u(Bool.not(DNS.addr_form("beef1.cafe"))) * 100000 : U32)
    f2 : U32 = (b2u(Bool.not(DNS.addr_form("example.com"))) * 1000000 : U32)
    f3 : U32 = (b2u(Bool.not(DNS.addr_form("a..b"))) * 10000000 : U32)
    +total : U32 = (t1 + t2 + t3 + t4 + t5 + f1 + f2 + f3 : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|11111111
