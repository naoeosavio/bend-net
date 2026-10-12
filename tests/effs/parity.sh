#!/usr/bin/env bash
# Effs parity lint: the JS twins under lib/effs/ measured against the
# runtime's own effs (~/.bend/bend2/effs/*.js), which is the reference for
# shape. The runtime's files answer "how does an effect .js look": they
# talk to the runtime through io_sys() and reach the outside with a bare
# module name, so the same file runs wherever the host puts io_sys.
#
# The rule for a twin, in one line: generic, never host-specific.
#   require("fs")        ok    -- bare, both hosts map it
#   require("node:fs")   wrong -- Node spelling
#   require("bun:fs")    wrong -- Bun spelling
#   require("bun:ffi")   wrong -- the Bun spelling of the host itself
# No file, directory or branch named after a host, and no variant per
# host: the .c/.js choice is compile-time, so the branch would have to
# live inside the one file.
#
# Usage:
#   tests/effs/parity.sh            green while every divergence is listed
#                                   in EXCEPTIONS (known, not forgotten)
#   tests/effs/parity.sh --strict   no exception list: everything fails
#
# Checks, per twin:
#   mapping  every `import "./effs/x.js"` in lib/ resolves, every twin is
#            imported by some def, and the file defines the host function
#            named after that def (lowercased, dots to underscores)
#   generic  every require() specifier is a bare name ("fs", "crypto", "tls"); a
#            prefixed one
#            ("node:fs", "bun:ffi") is host-specific; no file or directory
#            named after a host lives under lib/effs/
#   reuse    a top-level helper may be defined in one twin only: each twin
#            becomes its own closure in the emitted bundle, so a repeated
#            definition is duplication, not reuse
#   syntax   node --check on every twin
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

strict=""
[ "${1:-}" = "--strict" ] && strict="1"

pass=0
fail=0
known=0

ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
# A divergence the tree still carries on purpose, with the phase that
# clears it. Only the default mode forgives it.
warn() { known=$((known + 1)); printf 'KNOWN %s\n' "$1"; }

# Known divergences, "file:check" -> why the tree still carries it and who
# pays it. An entry here is a debt with an owner, not a mute button:
# --strict ignores the list, so a phase gate can require the debt paid.
exceptions="
lib/effs/tls_connect.js:generic=declared: OpenSSL por bun:ffi -- nao ha API generica de TLS cru em JS; o require e guardado e o bundle sobrevive
lib/effs/tls_accept.js:generic=declared: OpenSSL por bun:ffi -- nao ha API generica de TLS cru em JS; o require e guardado e o bundle sobrevive
lib/effs/tls_send_bytes.js:generic=declared: OpenSSL por bun:ffi -- nao ha API generica de TLS cru em JS; o require e guardado e o bundle sobrevive
lib/effs/tls_recv_bytes.js:generic=declared: OpenSSL por bun:ffi -- nao ha API generica de TLS cru em JS; o require e guardado e o bundle sobrevive
lib/effs/tls_close.js:generic=declared: OpenSSL por bun:ffi -- nao ha API generica de TLS cru em JS; o require e guardado e o bundle sobrevive
lib/effs/tls_close.js:reuse=declared: os cinco twins ficam separados por decisao (o merge foi revertido); cada um carrega o seu tls_lib()
lib/effs/tls_connect.js:reuse=declared: os cinco twins ficam separados por decisao (o merge foi revertido); cada um carrega o seu tls_lib()
lib/effs/tls_recv_bytes.js:reuse=declared: os cinco twins ficam separados por decisao (o merge foi revertido); cada um carrega o seu tls_lib()
lib/effs/tls_send_bytes.js:reuse=declared: os cinco twins ficam separados por decisao (o merge foi revertido); cada um carrega o seu tls_lib()
"

# Reports one divergence: a debt when the default mode knows it, a failure
# otherwise. $1 is "file:check", $2 the message.
report() {
  local key="$1" msg="$2" line
  if [ -n "$strict" ]; then
    bad "$msg"
    return
  fi
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
      "$key"=*)
        warn "$msg [${line#*=}]"
        return
        ;;
    esac
  done <<<"$exceptions"
  bad "$msg"
}

# Def name -> host function name: lowercased, dots to underscores.
host_name() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr '.' '_'; }

# Every (def, js twin) pair declared in lib/, one "def file" per line.
pairs="$(awk '
  /^def [A-Za-z0-9_.]+\(/ {
    name = $2
    sub(/\(.*/, "", name)
    cur = name
    next
  }
  /^[ \t]*import "\.\/effs\/[^"]+\.js"/ {
    if (cur != "") {
      match($0, /effs\/[^"]+\.js/)
      print cur, substr($0, RSTART + 5, RLENGTH - 5)
    }
  }
' lib/*.bend lib/**/*.bend 2>/dev/null | sort -u)"

# mapping: every declared twin exists and defines its def's host function.
while IFS=' ' read -r def file; do
  [ -z "$def" ] && continue
  if [ ! -f "lib/effs/$file" ]; then
    bad "mapping lib/effs/$file is imported by $def and does not exist"
    continue
  fi
  if grep -qE "^function $(host_name "$def")\(" "lib/effs/$file"; then
    ok "mapping $def -> lib/effs/$file"
  else
    bad "mapping lib/effs/$file has no function $(host_name "$def")()"
  fi
done <<<"$pairs"

# mapping: no orphan twin (a .js no def imports is dead weight in the lane).
for f in lib/effs/*.js; do
  [ -f "$f" ] || continue
  base="${f#lib/effs/}"
  if printf '%s\n' "$pairs" | awk '{print $2}' | grep -qxF "$base"; then
    continue
  fi
  bad "mapping $f is imported by no def"
done

# generic: no file or directory named after a host under lib/effs/.
for d in lib/effs/*/; do
  [ -d "$d" ] || continue
  bad "generic $d is a per-host directory (the branch lives in the .js)"
done
for f in lib/effs/*.node.js lib/effs/*.bun.js lib/effs/*.browser.js; do
  [ -f "$f" ] && bad "generic $f is a per-host file"
done

# generic: a bare require() only -- "fs" is fine, "node:fs" and "bun:fs"
# are host spellings, and "bun:ffi" is the Bun spelling of the host
# itself. Comment lines are skipped: a twin's header explains the rule it
# obeys, and a lint that trips on prose is a lint that gets deleted.
for f in lib/effs/*.js; do
  [ -f "$f" ] || continue
  while IFS=: read -r at text; do
    [ -z "$at" ] && continue
    spec="$(printf '%s' "$text" | sed -n 's/.*require("\([^"]*\)").*/\1/p')"
    [ -z "$spec" ] && continue
    prev="$(sed -n "$((at - 1))p" "$f" | tr -d ' \t')"
    guard="unguarded"
    [ "$prev" = "try{" ] && guard="guarded"
    case "$spec" in
      node:*|bun:*)
        report "$f:generic" "generic $f:$at require($spec) is host-specific ($guard)"
        ;;
      .*|/*)
        report "$f:generic" "generic $f:$at require($spec) is a path, and a relative one does not resolve in any lane"
        ;;
      *)
        ok "generic $f:$at require($spec) is bare"
        ;;
    esac
  done < <(awk '/^[ \t]*\/\// { next } /require\(/ { print NR ":" $0 }' "$f")
done

# reuse: a top-level helper defined in two twins is duplication. Each twin
# is its own closure, so the second copy cannot call the first: the fix is
# one file serving both defs, the way the runtime groups file_read.js.
seen="$(mktemp)"
trap 'rm -f "$seen"' EXIT
for f in lib/effs/*.js; do
  [ -f "$f" ] || continue
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    case "$name" in
      *_need) continue ;;
    esac
    first="$(awk -v n="$name" '$2 == n { print $1; exit }' "$seen")"
    if [ -z "$first" ]; then
      printf '%s %s\n' "$f" "$name" >>"$seen"
    else
      report "$f:reuse" "reuse $name is defined in $first and $f"
    fi
  done < <(grep -oE '^function [a-z_0-9]+' "$f" | awk '{print $2}')
done

# syntax: every twin has to parse as a plain script (the emitted bundle
# wraps it in a closure; the file itself is functions only).
if command -v node >/dev/null 2>&1; then
  for f in lib/effs/*.js; do
    [ -f "$f" ] || continue
    if out="$(node --check "$f" 2>&1)"; then
      ok "syntax $f"
    else
      bad "syntax $f: $(printf '%s' "$out" | tail -n 1)"
    fi
  done
else
  printf 'node not found: skipping the syntax checks\n'
fi

printf '=== %d passed, %d failed, %d known ===\n' "$pass" "$fail" "$known"
[ "$fail" -eq 0 ]
