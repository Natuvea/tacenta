#!/usr/bin/env bash
# Hold tooling/install-elan.sh to its pin: an archive whose digest is not the
# pinned one is never run.
#
#   bash tooling/tests/run-install-elan-cases.sh
#
# The installer downloads a GitHub release archive. Here `curl` is a stand-in
# that serves a small archive of our own (no network), so the cases can show
# what the script does with it:
#
#   - the pinned digest: the archive's installer runs, with the flags the
#     script promises, from the URL that names the pinned release, and the
#     runner's PATH file gets elan's directory;
#   - a different digest pinned, an archive whose contents changed under the
#     pinned digest, or a missing pin: the script refuses and nothing from the
#     archive runs;
#   - an elan of the pinned version already installed: nothing is downloaded.
#
# It also holds the workflows to the change this script made: no workflow pipes
# a download into a shell.
#
# `flock` and `sha256sum` are on the Linux runners the script is for; where a
# machine lacks them (macOS) a stand-in is used so the cases run anywhere.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
installer="$root/tooling/install-elan.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Stand-ins first on PATH.
shims="$work/shims"
mkdir -p "$shims"
cat > "$shims/curl" <<'SH'
#!/bin/sh
# Serves $FAKE_ARCHIVE to whatever `-o FILE` names, and logs the URL.
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "$HOME/curl-log"
cp "$FAKE_ARCHIVE" "$out"
SH
chmod +x "$shims/curl"
if ! command -v flock >/dev/null 2>&1; then
  printf '#!/bin/sh\nexit 0\n' > "$shims/flock"
  chmod +x "$shims/flock"
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  cat > "$shims/sha256sum" <<'SH'
#!/bin/sh
# `sha256sum -c -` on stdin, as the installer uses it.
read -r want file
got=$(shasum -a 256 "$file" | awk '{print $1}')
if [ "$got" = "$want" ]; then echo "$file: OK"; else echo "$file: FAILED"; exit 1; fi
SH
  chmod +x "$shims/sha256sum"
fi

# Two archives: the one whose digest is pinned, and one with other contents.
make_archive() { # OUT MARKER
  local dir="$work/archive-$2"
  mkdir -p "$dir"
  cat > "$dir/elan-init" <<SH
#!/bin/sh
echo "\$@" > "\$HOME/elan-init-ran"
echo "$2" >> "\$HOME/elan-init-ran"
mkdir -p "\$HOME/.elan/bin"
printf '#!/bin/sh\necho "elan 4.2.4 (stand-in)"\n' > "\$HOME/.elan/bin/elan"
chmod +x "\$HOME/.elan/bin/elan"
SH
  chmod +x "$dir/elan-init"
  tar czf "$1" -C "$dir" elan-init
}
make_archive "$work/good.tar.gz" good
make_archive "$work/tampered.tar.gz" tampered
good="$(digest "$work/good.tar.gz")"
if [ "$good" = "$(digest "$work/tampered.tar.gz")" ]; then
  echo "WRONG  setup: the two archives have the same digest" >&2
  exit 1
fi
tag=v4.2.4
url="https://github.com/leanprover/elan/releases/download/$tag/elan-x86_64-unknown-linux-gnu.tar.gz"

# run CASE ARCHIVE [VAR=value ...]: runs the installer in a fresh HOME.
run() {
  local name="$1" archive="$2"
  shift 2
  local home="$work/home-$name"
  mkdir -p "$home"
  : > "$home/github-path"
  set +e
  out="$(env -i PATH="$shims:$PATH" HOME="$home" FAKE_ARCHIVE="$archive" \
    GITHUB_PATH="$home/github-path" "$@" bash "$installer" 2>&1)"
  rc=$?
  set -e
  home_of_last="$home"
}

fail() { echo "WRONG  $*" >&2; printf '  %s\n' "$out" >&2; exit 1; }

run pinned "$work/good.tar.gz" ELAN_VERSION=$tag ELAN_SHA256="$good"
[ "$rc" -eq 0 ] || fail "pinned: the pinned archive was refused"
[ "$(head -n 1 "$work/home-pinned/elan-init-ran")" = "-y --no-modify-path --default-toolchain none" ] ||
  fail "pinned: the archive's installer did not run with the promised flags"
[ "$(cat "$work/home-pinned/curl-log")" = "$url" ] || fail "pinned: fetched '$(cat "$work/home-pinned/curl-log")', expected '$url'"
grep -qxF "$work/home-pinned/.elan/bin" "$work/home-pinned/github-path" || fail "pinned: elan's directory is not on the runner's PATH file"

refusals=0
refused() { # NAME NEEDLE
  [ "$rc" -ne 0 ] || fail "$1: was accepted"
  printf '%s' "$out" | grep -qF -- "$2" || fail "$1: refused, but not for '$2'"
  [ ! -e "$work/home-$1/elan-init-ran" ] || fail "$1: the archive's installer ran"
  [ ! -e "$work/home-$1/.elan" ] || fail "$1: something was installed"
  refusals=$((refusals + 1))
}

# The pinned digest with its first digit changed.
wrong="$(printf '%s' "$good" | awk '{ c = substr($0, 1, 1); printf "%s%s", (c == "0" ? "1" : "0"), substr($0, 2) }')"
run other-digest "$work/good.tar.gz" ELAN_VERSION=$tag ELAN_SHA256="$wrong"
refused other-digest 'did not match ELAN_SHA256'

run tampered-archive "$work/tampered.tar.gz" ELAN_VERSION=$tag ELAN_SHA256="$good"
refused tampered-archive 'did not match ELAN_SHA256'

run no-digest "$work/good.tar.gz" ELAN_VERSION=$tag
refused no-digest 'set ELAN_SHA256'

run no-version "$work/good.tar.gz" ELAN_SHA256="$good"
refused no-version 'set ELAN_VERSION'

# Already installed at the pinned version: nothing is downloaded.
mkdir -p "$work/home-installed/.elan/bin"
printf '#!/bin/sh\necho "elan 4.2.4 (already here)"\n' > "$work/home-installed/.elan/bin/elan"
chmod +x "$work/home-installed/.elan/bin/elan"
run installed "$work/good.tar.gz" ELAN_VERSION=$tag ELAN_SHA256="$good"
[ "$rc" -eq 0 ] || fail "installed: refused"
[ ! -e "$work/home-installed/curl-log" ] || fail "installed: downloaded although elan $tag was installed"
printf '%s' "$out" | grep -qF 'already installed' || fail "installed: did not say so"

# An older elan is replaced by the pinned one.
mkdir -p "$work/home-older/.elan/bin"
printf '#!/bin/sh\necho "elan 4.2.3 (older)"\n' > "$work/home-older/.elan/bin/elan"
chmod +x "$work/home-older/.elan/bin/elan"
run older "$work/good.tar.gz" ELAN_VERSION=$tag ELAN_SHA256="$good"
[ "$rc" -eq 0 ] || fail "older: refused"
[ -e "$work/home-older/elan-init-ran" ] || fail "older: the pinned release was not installed over an older one"

# No workflow pipes a download into a shell.
if grep -nE 'curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh' "$root"/.github/workflows/*.yml; then
  echo "WRONG  a workflow pipes curl into a shell" >&2
  exit 1
fi

echo "install-elan-cases: the pinned archive installs, and $refusals refusals (another digest, a tampered archive, no digest, no version) ran nothing from the archive; nothing is downloaded for the pinned version already present; no workflow pipes curl into a shell"
