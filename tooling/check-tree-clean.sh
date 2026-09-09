#!/usr/bin/env bash
# Refuse build output in the tracked tree.
#
#   check-tree-clean.sh
#
# The invariant: the tracked tree contains source, prose and configuration,
# never build output, and no tracked non-text file carries symbols of a
# strong-copyleft crate. Two things are checked: no tracked file lives in a
# build directory, and no tracked non-text file names a crate that
# tooling/check-licences.sh's licence scan classifies as strong-copyleft.
# Source and prose may name any library freely; only non-text files are
# inspected for symbols.
#
# This checks the working tree's index, not history.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

status=0

# --- Build directories -----------------------------------------------------
# Cargo's, and the ones a JS or Lean toolchain leaves behind. A tracked file
# under any of these is build output by construction.
artefacts=$(git ls-files | grep -E '(^|/)(target|node_modules|\.lake|dist|\.astro)/' || true)
if [ -n "$artefacts" ]; then
  count=$(printf '%s\n' "$artefacts" | wc -l | tr -d ' ')
  echo "" >&2
  echo "REFUSING: ${count} tracked file(s) live in a build directory:" >&2
  printf '%s\n' "$artefacts" | head -10 | sed 's/^/  /' >&2
  [ "$count" -gt 10 ] && echo "  ... and $((count - 10)) more" >&2
  echo "" >&2
  echo "Build output does not belong in the tree. Widen .gitignore and" >&2
  echo "'git rm -r --cached' the paths." >&2
  status=1
fi

# --- Object code carrying strong-copyleft symbols --------------------------
# The names to look for are read from the build graph rather than written
# here: every crate whose declared licence is strong-copyleft (the same
# classification tooling/check-licences.sh applies). With none in the graph
# there is nothing to scan for, and the step says so.
pattern=$(cargo metadata --format-version 1 --all-features 2>/dev/null | python3 -c '
import json, sys
m = json.load(sys.stdin)
names = sorted({p["name"] for p in m["packages"]
                if ("AGPL" in (p.get("license") or "").upper() or "GPL" in (p.get("license") or "").upper())
                and " OR " not in (p.get("license") or "")})
print("|".join(n.replace("-", "[-_]") for n in names))
') || {
  echo "check-tree-clean: cargo metadata failed; the dependency graph could not be resolved" >&2
  exit 1
}
suspect=""
if [ -n "$pattern" ]; then
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    mime=$(file -b --mime-type "$f" 2>/dev/null || echo unknown)
    case "$mime" in text/*) continue ;; esac
    # Counted rather than `grep -q`, so the pipeline under `pipefail` reports
    # the match instead of the SIGPIPE a quitting grep hands upstream.
    hits=$(strings -a "$f" 2>/dev/null | grep -ciE "$pattern" || true)
    if [ "${hits:-0}" -ne 0 ]; then
      suspect="${suspect}${f} (${hits} references)
"
    fi
  done < <(git ls-files)
fi
if [ -n "$suspect" ]; then
  echo "" >&2
  echo "REFUSING: tracked non-text file(s) carry strong-copyleft symbols:" >&2
  printf '%s' "$suspect" | sed 's/^/  /' >&2
  echo "" >&2
  echo "The product depends on nothing under the AGPL or GPL, and a non-text" >&2
  echo "file carrying such symbols does not belong in this tree." >&2
  status=1
fi
if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "check-tree-clean: no build output tracked, no strong-copyleft object code tracked"
