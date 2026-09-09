#!/usr/bin/env bash
# Detached, ASCII-armoured GPG signatures for release artifacts (decision 0090). Maven Central requires them
# for every file it accepts, and they let anyone check the xcframework zip
# against the key published at tacenta.com/.well-known/ before trusting the
# checksum beside it.
#
# Usage: sign-artifacts.sh <file>...
# Reads TACENTA_SIGNING_KEY (an ASCII-armoured private key, exported with
# `gpg --armor --export-secret-keys <id>`) and TACENTA_SIGNING_PASSPHRASE
# from the environment, imports the key into a throwaway keyring, and writes
# <file>.asc beside each file. Without the key it says so and exits 0, so a
# build that has no signing material still produces its artifacts, unsigned,
# and a release step that requires signatures checks for the .asc files.
set -euo pipefail

if [ -z "${TACENTA_SIGNING_KEY:-}" ]; then
  echo "sign-artifacts: TACENTA_SIGNING_KEY is not set; artifacts are unsigned" >&2
  exit 0
fi
command -v gpg >/dev/null 2>&1 || { echo "sign-artifacts: gpg is not installed" >&2; exit 1; }

home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
chmod 700 "$home"
export GNUPGHOME="$home"
printf '%s\n' "$TACENTA_SIGNING_KEY" | gpg --batch --quiet --import
fingerprint=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="fpr"{print $10; exit}')
[ -n "$fingerprint" ] || { echo "sign-artifacts: no secret key in TACENTA_SIGNING_KEY" >&2; exit 1; }

for f in "$@"; do
  [ -f "$f" ] || { echo "sign-artifacts: $f is not a file" >&2; exit 1; }
  gpg --batch --yes --quiet --pinentry-mode loopback \
    --passphrase "${TACENTA_SIGNING_PASSPHRASE:-}" \
    --local-user "$fingerprint" --armor --detach-sign --output "$f.asc" "$f"
  gpg --batch --quiet --verify "$f.asc" "$f" 2>/dev/null
  echo "sign-artifacts: signed $f (key $fingerprint)"
done
