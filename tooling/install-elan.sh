#!/usr/bin/env bash
# Install a fixed elan release on a Linux x86_64 runner, checking the archive
# against a pinned sha256 before anything from it runs.
#
#   ELAN_VERSION=v4.2.4 ELAN_SHA256=<hex> bash tooling/install-elan.sh
#
# The usual `curl elan-init.sh | sh` fetches whatever the script's host serves
# today and runs it unread. This downloads one named release archive, compares
# its digest with the one the workflow pins, and only then runs the installer
# inside it. The pin is the release tag and the digest together: bumping one
# without the other fails here rather than installing something else. The
# digest is the sha256 that GitHub lists for the release asset
# (https://github.com/leanprover/elan/releases), and the workflow's `env:`
# block says where it came from.
#
# The toolchain itself is not chosen here. `--default-toolchain none` leaves
# that to the `lean-toolchain` file in each Lake package, which elan reads on
# the first `lake` invocation and installs, so the version the repository
# pins is the version that builds. Elan fetches that toolchain over HTTPS from
# the Lean releases and this repository does not pin its digest; what is
# checked here is the installer, not the toolchain it goes on to install.
#
# CI-only: it assumes a Linux runner with `sha256sum` and `flock`, and writes to
# `$GITHUB_PATH`. A developer installs elan however they like; the README says
# which version of Lean the packages need.
set -euo pipefail

: "${ELAN_VERSION:?set ELAN_VERSION to the elan release tag, e.g. v4.2.4}"
: "${ELAN_SHA256:?set ELAN_SHA256 to the sha256 of the x86_64-unknown-linux-gnu archive}"

mkdir -p "$HOME/.cache"
exec 9> "$HOME/.cache/install-elan.lock"
flock 9

installed="$("$HOME/.elan/bin/elan" --version 2>/dev/null | awk '{print $2}')" || true
if [ "$installed" = "${ELAN_VERSION#v}" ]; then
  echo "install-elan: elan $ELAN_VERSION is already installed in $HOME/.elan"
else
  archive_name="elan-x86_64-unknown-linux-gnu.tar.gz"
  url="https://github.com/leanprover/elan/releases/download/${ELAN_VERSION}/${archive_name}"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  archive="$work/$archive_name"

  echo "install-elan: fetching elan $ELAN_VERSION"
  curl -sSfL --retry 3 -o "$archive" "$url"

  if ! echo "${ELAN_SHA256}  ${archive}" | sha256sum -c -; then
    echo "install-elan: the archive did not match ELAN_SHA256; refusing to run it" >&2
    exit 1
  fi

  tar xzf "$archive" -C "$work"
  "$work/elan-init" -y --no-modify-path --default-toolchain none
  echo "install-elan: elan $ELAN_VERSION installed"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$HOME/.elan/bin" >> "$GITHUB_PATH"
fi
