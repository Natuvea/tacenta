#!/usr/bin/env bash
# Refuse documentation that contradicts the system it describes.
#
#   check-docs-match.sh
#
# **A note on `|| true`, which is everywhere below.** This script sets
# `pipefail`, and `grep` exits non-zero when it matches nothing -- which here is
# the *good* case, since no matches means no bad claims. Without the guard the
# script would die on a clean tree.
#
# **Why this exists.** Documentation drifts from the code it describes: a claim
# about a dependency, a named module, a path, a pin, a port or a feature can
# outlive the change that made it false. Machine checks already guard the
# dependency graph, the tree and workflow syntax; this guards the mechanically
# checkable claims in prose. It catches
# only the subset that quotes machine-readable facts -- a crate named as a
# dependency, a cited path, pin, port or feature -- and the rest still needs a
# person who updates the prose in the same commit as the code.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

status=0
# A soft signal, distinct from a hard failure: something printed a candidate for
# review (an unresolved cited name) that is not a contradiction. The final line
# must not claim a clean match while these are outstanding.
review_notes=0
note() { printf '  %s\n' "$1"; }
fail() { status=1; printf '\n%s\n' "$1" >&2; }

docs=$(git ls-files '*.md')

# --- 1. Cited paths resolve -------------------------------------------------
# Documents cite files relative to all sorts of roots, so a citation counts as
# resolved if any tracked path ends with it. That tolerates the styles in use
# and still fires when a file is renamed or deleted out from under a document.
echo "== cited paths =="
# Both repositories, because the product's documents legitimately cite
# tacenta-core files -- the two are one system described in two places, and a
# check that only knew about one would report half of them as missing.
tracked=$(git ls-files)
sibling="${OPEN_TACENTA_DIR:-${TACENTA_CORE_DIR:-$(cd .. && pwd)/tacenta-core}}"
if [ -d "$sibling/.git" ]; then
  tracked="$tracked
$(git -C "$sibling" ls-files)"
else
  # **This is not a skip.** Nothing below filters citations by which
  # repository they belong to -- it cannot, without the file list that is
  # missing. An absent sibling therefore means every tacenta-core citation is
  # reported as a path that does not exist. Set TACENTA_CORE_DIR, or clone it
  # beside this repo.
  note "tacenta-core not found beside this repo (set TACENTA_CORE_DIR)."
  note "  Citations into it will be reported as missing -- they are not."
fi
missing_paths=$(
  python3 - "$sibling" <<'PYEOF'
import re, subprocess, sys, pathlib

root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True).stdout.strip()
tracked = set(subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                             cwd=root).stdout.split())
sib = sys.argv[1] if len(sys.argv) > 1 else ""
if sib and pathlib.Path(sib, ".git").exists():
    tracked |= set(subprocess.run(["git", "ls-files"], capture_output=True,
                                  text=True, cwd=sib).stdout.split())

# A citation resolves if any tracked path is it, or ends with it after a slash.
suffixes = set()
for t in tracked:
    parts = t.split("/")
    for i in range(len(parts)):
        suffixes.add("/".join(parts[i:]))

pattern = re.compile(r"`([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+\.(?:rs|toml|sh|yml|yaml|lean))`")
cited = set()
for f in subprocess.run(["git", "ls-files", "*.md"], capture_output=True,
                        text=True, cwd=root).stdout.split():
    cited |= set(pattern.findall(pathlib.Path(root, f).read_text(errors="ignore")))

for c in sorted(cited - suffixes):
    print(c)
PYEOF
)
if [ -n "$missing_paths" ]; then
  fail "Documents cite paths that do not exist:"
  printf '%s\n' "$missing_paths" | sed 's/^/  /' >&2
else
  note "every cited path resolves"
fi

# --- 1b. Cited test names resolve to a function -----------------------------
# A document citing a test as evidence -- "reproduced in `a_forged_..._refused`"
# -- is quoting a fact with one source of truth: a `fn` of that name. When a test
# is renamed, the citation goes stale and the evidence a reviewer would grep for
# is not there.
#
# Heuristic: a backticked all-lowercase snake identifier with four or more
# segments (three or more underscores) is, in these documents, a test or function
# name. It resolves if `fn <name>` appears in any tracked Rust source (either
# repo). This deliberately covers ordinary function citations too -- a stale
# `fn` citation is the same defect.
echo "== cited test names =="
missing_tests=$(
  python3 - "$sibling" <<'PYEOF'
import re, subprocess, sys, pathlib

root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True).stdout.strip()

def ls(repo, glob):
    return subprocess.run(["git", "ls-files", glob], capture_output=True,
                          text=True, cwd=repo).stdout.split()

repos = [root]
sib = sys.argv[1] if len(sys.argv) > 1 else ""
if sib and pathlib.Path(sib, ".git").exists():
    repos.append(sib)

# A cited name resolves to any Rust `fn` OR any Lean declaration -- documents in
# both repositories cite proofs (`decode_stream_loop_spec`) as well as tests, and
# a check that only knew `fn` would flag every legitimate proof citation.
defined = set()
fn_re = re.compile(r"\bfn\s+([a-z][a-z0-9_]*)")
lean_re = re.compile(
    r"\b(?:theorem|lemma|def|abbrev|example|instance|structure|inductive)\s+"
    r"([A-Za-z_][A-Za-z0-9_.']*)")
for repo in repos:
    for f in ls(repo, "*.rs"):
        defined |= set(fn_re.findall(pathlib.Path(repo, f).read_text(errors="ignore")))
    for f in ls(repo, "*.lean"):
        for name in lean_re.findall(pathlib.Path(repo, f).read_text(errors="ignore")):
            # A dotted Lean name resolves under its full form and any prefix, so
            # citing the namespace `extend_from_slice_u8` of
            # `extend_from_slice_u8.step_spec` counts as resolved.
            parts = name.split(".")
            for i in range(1, len(parts) + 1):
                defined.add(".".join(parts[:i]))
    # SQL schema objects too -- documents cite constraint and index names
    # (`users_tenant_email_key`) as the source of a guarantee, and those are
    # defined in migrations, not in Rust.
    sql_re = re.compile(
        r"\b(?:constraint|index|table|type|trigger|sequence)\s+"
        r"(?:if\s+not\s+exists\s+)?\"?([a-z_][a-z0-9_]*)\"?", re.IGNORECASE)
    for f in ls(repo, "*.sql"):
        defined |= set(sql_re.findall(pathlib.Path(repo, f).read_text(errors="ignore")))

# Four or more snake segments: a test-name-shaped identifier.
cite_re = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+){3,})`")
cited = set()
for f in ls(root, "*.md"):
    cited |= set(cite_re.findall(pathlib.Path(root, f).read_text(errors="ignore")))

for c in sorted(cited - defined):
    print(c)
PYEOF
)
if [ -n "$missing_tests" ]; then
  # A **note, not a failure**, on the same reasoning as the quoted-pins check:
  # resolution here is heuristic (a four-segment snake identifier, matched against
  # Rust `fn`, Lean declarations and SQL objects), so a stray config key or a
  # since-removed symbol can surface without being a live defect, and a hard gate
  # with any false-positive rate is one people learn to switch off. A citation
  # used as evidence must resolve, and that is checked with judgment against
  # this list.
  review_notes=1
  note "cited names with no matching fn / Lean decl / SQL object (review before"
  note "citing them as evidence -- a renamed test cited as proof is a stale claim):"
  printf '%s\n' "$missing_tests" | sed 's/^/    /'
else
  note "every cited test/function name resolves"
fi

# --- 2. Quoted dependency pins match the manifest ---------------------------
# A document that quotes the tacenta-core revision is quoting a fact with one
# source of truth, and a stale pin in prose sends a reader to the wrong
# revision.
echo "== quoted pins =="
real_rev=$(grep -oE 'rev = "[0-9a-f]{40}"' Cargo.toml | head -1 | grep -oE '[0-9a-f]{40}')
bad_pins=$(
  { grep -rhoE 'tacenta-core[^\n]{0,80}[0-9a-f]{7,40}' $docs 2>/dev/null || true; } \
    | { grep -oE '[0-9a-f]{7,40}' || true; } | sort -u | while read -r q; do
        if [ "${real_rev:0:${#q}}" != "$q" ]; then echo "$q"; fi
      done
)
if [ -n "$bad_pins" ]; then
  note "quoted revisions that are not the current pin (${real_rev:0:7}):"
  printf '%s\n' "$bad_pins" | sed 's/^/    /'
  note "not a failure: records legitimately cite historical revisions"
else
  note "no quoted revision contradicts the pin"
fi

# --- 3. Documented cargo features exist -------------------------------------
# A feature named in prose but absent from every manifest is a document
# describing a build that cannot be produced.
echo "== documented cargo features =="
declared=$(git ls-files '*/Cargo.toml' 'Cargo.toml' | xargs awk '/^\[features\]/{f=1;next} /^\[/{f=0} f && /=/{print $1}' | sort -u)
missing_features=$(
  { grep -rhoE -- '--features [a-z][a-z0-9-]+' $docs 2>/dev/null || true
    grep -rhoE 'feature = "[a-z][a-z0-9-]+"' $docs 2>/dev/null || true
  } | sed 's/--features //; s/feature = //; s/"//g' | sort -u | while read -r f; do
        printf '%s\n' "$declared" | grep -qx "$f" || echo "$f"
      done
)
if [ -n "$missing_features" ]; then
  fail "Documents name cargo features that no manifest declares:"
  printf '%s\n' "$missing_features" | sed 's/^/  /' >&2
else
  note "every documented feature is declared somewhere"
fi

# --- 4. Named dependencies are actually dependencies -------------------------
# **A crate named in backticks and called a dependency, or described as
# pinned, is a claim about `Cargo.lock`** and can be checked against it.
# Blockquoted lines are excluded: a quotation is not a claim of the document
# that quotes it.
echo "== named dependencies =="
# Lines that deny a dependency are excluded too, by a small vocabulary of
# negation words, since they state the opposite of the claim being checked.
# This is a heuristic and can miss in both directions.
claimed=$(
  { grep -rhE '^[^>]' $docs 2>/dev/null || true; } \
    | { grep -vE 'remov|no longer|gone|dropped|withdraw|used to|gains|instead of' || true; } \
    | { grep -ohE '`[a-z][a-z0-9_-]+` dependency|pinned `[a-z][a-z0-9_-]+`' || true; } \
    | { grep -oE '`[a-z][a-z0-9_-]+`' || true; } | tr -d '`' | sort -u
)
absent=""
for c in $claimed; do
  # A crate counts as present if the lock names it, or if the lock reaches it
  # through a renamed package (the tacenta-core git dependency is aliased
  # `open-tacenta` in Cargo.toml).
  if ! grep -qE "^name = \"$c\"$" Cargo.lock && ! grep -q "$c" Cargo.lock; then
    absent="$absent $c"
  fi
done
if [ -n "$absent" ]; then
  fail "Documents name these as dependencies, and Cargo.lock does not have them:"
  for c in $absent; do printf '  %s\n' "$c" >&2; done
else
  note "every crate called a dependency is one"
fi

echo
if [ "$status" -ne 0 ]; then
  echo "check-docs-match: documentation contradicts the system" >&2
  exit 1
fi
if [ "$review_notes" -ne 0 ]; then
  # Green, but not silent: the hard checks pass, yet a soft note above lists
  # names to review. Saying "everything matches" here would be a stronger
  # claim than the output supports.
  echo "check-docs-match: no contradictions; some cited names need review (see notes above)"
  exit 0
fi
echo "check-docs-match: the checkable claims match the tree"
