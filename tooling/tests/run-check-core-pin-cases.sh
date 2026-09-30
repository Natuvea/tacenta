#!/usr/bin/env bash
# Hold check-core-pin.sh to controls that each end in the outcome they name.
#
#   bash tooling/tests/run-check-core-pin-cases.sh
#
# Three groups, in this order:
#
#   1. Static refusals. A copy of the real Cargo.toml and Cargo.lock with one
#      change each: a short SHA, a branch pin, another repository, a stray git
#      source in the lock, a [patch] section, and so on. The API address is a
#      port nothing listens on, so a refusal that names the API instead of the
#      change means the static check did not catch it.
#   2. API answers. A local stand-in for GitHub's compare endpoint answers the
#      question the script asks, once per status it can give: behind and
#      identical pass; ahead, diverged, a merge base that is not the revision,
#      a 404, a 403, a 500 that never recovers, an answer of the wrong shape,
#      and a port nothing listens on all refuse. It also checks the request
#      path, and that a token is not sent to an address that is not GitHub's.
#   3. Live controls against GitHub. The pin in this tree passes. The head of
#      pull request 207 of Natuvea/tacenta-core, which is in the repository's
#      object store but never was on main, is put into a copy of the tree (in
#      Cargo.toml and in every Cargo.lock entry, so the static checks pass) and
#      must be refused. This is the case the check exists for.
#
# The live group needs the network. If it cannot run, the runner FAILS: a
# control that quietly does not run is not a control. To run only the first two
# groups on purpose (on a machine with no network), set
# CHECK_CORE_PIN_CASES_OFFLINE=1; the runner then says the live group was not
# run. CI does not set it.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
stub_pid=""
cleanup() {
  if [ -n "$stub_pid" ]; then kill "$stub_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

repo="Natuvea/tacenta-core"
pin="$(sed -n 's/^open-tacenta = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' "$root/Cargo.toml")"
if [ -z "$pin" ]; then
  echo "WRONG  setup: could not read the pin from $root/Cargo.toml" >&2
  exit 1
fi

# A tree with the checker, the real Cargo.toml and the real Cargo.lock.
make_case() {
  local dst="$work/$1"
  mkdir -p "$dst/tooling" "$dst/crates/member"
  cp "$root/tooling/check-core-pin.sh" "$dst/tooling/"
  cp "$root/Cargo.toml" "$root/Cargo.lock" "$dst/"
  printf '[package]\nname = "member"\n' > "$dst/crates/member/Cargo.toml"
}

# edit CASE FILE 'python statement using text'; the statement rebinds `text`.
edit() {
  python3 - "$work/$1/$2" "$3" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
exec(sys.argv[2])
path.write_text(text)
PY
}

# Runs the checker in CASE against the API at $3 (default: a dead port).
run_case() {
  local name="$1" api="${3:-http://127.0.0.1:9}"
  CHECK_CORE_PIN_API="$api" CHECK_CORE_PIN_RETRY_DELAY=0 \
    bash "$work/$name/tooling/check-core-pin.sh" 2>&1
}

expect_fail() {
  local name="$1" needle="$2" api="${3:-}" out rc
  set +e
  out="$(run_case "$name" x "$api")"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "WRONG  $name: expected refusal containing '$needle', was accepted" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -qF -- "$needle"; then
    echo "WRONG  $name: refused, but not for '$needle':" >&2
    printf '  %s\n' "$out" >&2
    return 1
  fi
}

expect_pass() {
  local name="$1" api="${2:-}" out rc
  set +e
  out="$(run_case "$name" x "$api")"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "WRONG  $name: expected acceptance, was refused:" >&2
    printf '  %s\n' "$out" >&2
    return 1
  fi
}

# --- 1. Static refusals ----------------------------------------------------
static=0
static_case() {
  local name="$1" needle="$2"
  expect_fail "$name" "$needle"
  # The refusal must be the static one, not the dead API.
  if run_case "$name" | grep -qF 'could not reach'; then
    echo "WRONG  $name: got as far as the API" >&2
    return 1
  fi
  static=$((static + 1))
}

make_case short-rev
edit short-rev Cargo.toml "text = text.replace('$pin', '${pin:0:8}', 1)"
static_case short-rev 'not a full 40-digit lowercase SHA'

make_case uppercase-rev
edit uppercase-rev Cargo.toml "text = text.replace('$pin', '$pin'.upper(), 1)"
static_case uppercase-rev 'not a full 40-digit lowercase SHA'

make_case branch-pin
edit branch-pin Cargo.toml "text = text.replace('rev = \"$pin\"', 'branch = \"main\"', 1)"
static_case branch-pin 'pinned by `rev` alone'

make_case tag-beside-rev
edit tag-beside-rev Cargo.toml "text = text.replace('rev = \"$pin\"', 'rev = \"$pin\", tag = \"v1\"', 1)"
static_case tag-beside-rev 'pinned by `rev` alone'

make_case no-rev
edit no-rev Cargo.toml "text = text.replace('rev = \"$pin\", ', '', 1)"
static_case no-rev 'has no `rev`'

make_case other-repository
edit other-repository Cargo.toml "text = text.replace('Natuvea/tacenta-core', 'someone/tacenta-core', 1)"
static_case other-repository 'must be a git dependency on https://github.com/Natuvea/tacenta-core'

make_case dependency-missing
edit dependency-missing Cargo.toml "text = text.replace('open-tacenta = {', 'core-dependency = {', 1)"
static_case dependency-missing 'exactly once; found 0'

make_case dependency-twice
edit dependency-twice Cargo.toml "text += chr(10) + 'open-tacenta = { git = \"https://github.com/Natuvea/tacenta-core\", rev = \"$pin\" }' + chr(10)"
static_case dependency-twice 'exactly once; found 2'

make_case lock-other-revision
edit lock-other-revision Cargo.lock "text = text.replace('#$pin', '#${pin:0:39}0', 1)"
static_case lock-other-revision 'other than crates.io and the pin'

make_case lock-other-git-source
edit lock-other-git-source Cargo.lock "text += chr(10).join(['[[package]]', 'name = \"extra\"', 'version = \"0.1.0\"', 'source = \"git+https://github.com/someone/extra?rev=$pin#$pin\"', '']) + chr(10)"
static_case lock-other-git-source 'other than crates.io and the pin'

make_case lock-other-registry
edit lock-other-registry Cargo.lock "text += chr(10).join(['[[package]]', 'name = \"extra\"', 'version = \"0.1.0\"', 'source = \"registry+https://registry.example.invalid/index\"', '']) + chr(10)"
static_case lock-other-registry 'other than crates.io and the pin'

make_case lock-without-the-pin
edit lock-without-the-pin Cargo.lock "text = ''.join(l for l in text.splitlines(True) if not l.startswith('source = \"git+'))"
static_case lock-without-the-pin 'has no package from'

make_case patch-section
edit patch-section Cargo.toml "text += chr(10) + '[patch.\"https://github.com/Natuvea/tacenta-core\"]' + chr(10) + 'tacenta-core = { path = \"elsewhere\" }' + chr(10)"
static_case patch-section 'section, which can redirect a dependency'

make_case replace-section
edit replace-section Cargo.toml "text += chr(10) + '[replace]' + chr(10)"
static_case replace-section 'section, which can redirect a dependency'

make_case patch-in-a-member
edit patch-in-a-member crates/member/Cargo.toml "text += chr(10) + '[patch.crates-io]' + chr(10)"
static_case patch-in-a-member 'crates/member/Cargo.toml'

make_case source-replacement
edit source-replacement Cargo.toml "text += chr(10) + '[source.crates-io]' + chr(10)"
static_case source-replacement 'section, which can redirect a dependency'

make_case cargo-config
mkdir -p "$work/cargo-config/.cargo"
printf '[net]\noffline = true\n' > "$work/cargo-config/.cargo/config.toml"
static_case cargo-config 'cargo config can redirect sources'

make_case no-manifest
rm "$work/no-manifest/Cargo.toml"
static_case no-manifest 'cannot read Cargo.toml'

make_case no-lock
rm "$work/no-lock/Cargo.lock"
static_case no-lock 'cannot read Cargo.lock'

# --- 2. API answers --------------------------------------------------------
stub="$work/stub"
mkdir -p "$stub"
python3 - "$stub" <<'PY' &
import http.server, os, sys
d = sys.argv[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(os.path.join(d, "last-request"), "w") as out:
            out.write(self.path + "\n" + str(self.headers))
        with open(os.path.join(d, "code")) as code:
            status = int(code.read().strip())
        with open(os.path.join(d, "body"), "rb") as body:
            payload = body.read()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(os.path.join(d, "port.tmp"), "w") as out:
    out.write(str(server.server_address[1]))
os.rename(os.path.join(d, "port.tmp"), os.path.join(d, "port"))
server.serve_forever()
PY
stub_pid=$!
disown "$stub_pid"
for _ in $(seq 1 50); do
  [ -s "$stub/port" ] && break
  sleep 0.1
done
if [ ! -s "$stub/port" ]; then
  echo "WRONG  setup: the local API stand-in did not start" >&2
  exit 1
fi
api="http://127.0.0.1:$(cat "$stub/port")"

# answer CODE BODY: what the stand-in says to the next request.
answer() {
  printf '%s' "$1" > "$stub/code"
  printf '%s' "$2" > "$stub/body"
}
compare() { # STATUS MERGE_BASE
  printf '{"status":"%s","ahead_by":0,"behind_by":8,"merge_base_commit":{"sha":"%s"}}' "$1" "$2"
}

make_case api
answers=0
api_pass() {
  answer 200 "$2"
  expect_pass api "$api"
  answers=$((answers + 1))
}
api_fail() {
  answer "$2" "$3"
  expect_fail api "$4" "$api"
  answers=$((answers + 1))
}

api_pass behind "$(compare behind "$pin")"
# The script asks the question we think it asks.
expected_path="/repos/$repo/compare/main...$pin?per_page=1"
if [ "$(head -n 1 "$stub/last-request")" != "$expected_path" ]; then
  echo "WRONG  request-path: asked '$(head -n 1 "$stub/last-request")', expected '$expected_path'" >&2
  exit 1
fi
api_pass identical "$(compare identical "$pin")"

other="ffffffffffffffffffffffffffffffffffffffff"
api_fail ahead 200 "$(compare ahead "$pin")" 'compare says ahead'
api_fail diverged 200 "$(compare diverged "$pin")" 'compare says diverged'
api_fail behind-wrong-merge-base 200 "$(compare behind "$other")" 'refusing to pass'
api_fail identical-wrong-merge-base 200 "$(compare identical "$other")" 'refusing to pass'
api_fail unknown-status 200 "$(compare unrecognised "$pin")" 'refusing to pass'
api_fail not-found 404 '{"message":"Not Found"}' 'GitHub has no commit'
api_fail rate-limited 403 '{"message":"API rate limit exceeded"}' 'rate limited'
api_fail server-error 500 '{"message":"boom"}' 'HTTP 500'
api_fail not-json 200 'not json' 'not the shape GitHub documents'
api_fail empty-object 200 '{}' 'not the shape GitHub documents'
api_fail merge-base-null 200 '{"status":"behind","merge_base_commit":null}' 'not the shape GitHub documents'

# Nothing listening: the check must fail, and say why, not pass.
expect_fail api "Connection refused" "http://127.0.0.1:9"
answers=$((answers + 1))

# A token goes to GitHub and nowhere else.
answer 200 "$(compare behind "$pin")"
GITHUB_TOKEN=token-for-github-only GH_TOKEN=token-for-github-only expect_pass api "$api"
if grep -qi 'authorization' "$stub/last-request"; then
  echo "WRONG  token-scope: the token was sent to an address that is not api.github.com" >&2
  exit 1
fi
answers=$((answers + 1))

# --- 3. Live controls against GitHub ----------------------------------------
if [ "${CHECK_CORE_PIN_CASES_OFFLINE:-}" = 1 ]; then
  echo "check-core-pin-cases: $static static refusals and $answers API-answer controls gave the expected result." \
    "The live controls were NOT run (CHECK_CORE_PIN_CASES_OFFLINE=1)."
  exit 0
fi

live_fail() {
  echo "WRONG  live: $*" >&2
  echo "       The live controls need the network; set CHECK_CORE_PIN_CASES_OFFLINE=1 to run the others only." >&2
  exit 1
}

pr_head="$(git ls-remote "https://github.com/$repo" refs/pull/207/head 2>/dev/null | cut -f1)" || true
if ! printf '%s' "$pr_head" | grep -qE '^[0-9a-f]{40}$'; then
  live_fail "could not resolve refs/pull/207/head of $repo with git ls-remote"
fi
if [ "$pr_head" = "$pin" ]; then
  live_fail "the pin is the head of pull request 207; the negative control needs a commit that is not the pin"
fi

make_case live-pin
set +e
out="$(CHECK_CORE_PIN_RETRY_DELAY=1 bash "$work/live-pin/tooling/check-core-pin.sh" 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "WRONG  live-pin: the pin in this tree was refused:" >&2
  printf '  %s\n' "$out" >&2
  exit 1
fi

# The same tree with the pull request head as the pin, everywhere it is written.
make_case live-pull-request-head
edit live-pull-request-head Cargo.toml "text = text.replace('$pin', '$pr_head')"
edit live-pull-request-head Cargo.lock "text = text.replace('$pin', '$pr_head')"
set +e
out="$(CHECK_CORE_PIN_RETRY_DELAY=1 bash "$work/live-pull-request-head/tooling/check-core-pin.sh" 2>&1)"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "WRONG  live-pull-request-head: a commit that is only a pull request head was accepted:" >&2
  printf '  %s\n' "$out" >&2
  exit 1
fi
if ! printf '%s' "$out" | grep -qF "is not on $repo main"; then
  echo "WRONG  live-pull-request-head: refused, but not because it is off main:" >&2
  printf '  %s\n' "$out" >&2
  exit 1
fi

echo "check-core-pin-cases: $static static refusals and $answers API-answer controls gave the expected result;" \
  "the pin in this tree is on $repo main and the head of pull request 207 (${pr_head:0:12}) is refused"
