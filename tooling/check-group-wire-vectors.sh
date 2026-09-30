#!/usr/bin/env bash
# Replay the group wire vectors through the second reader.
#
#   check-group-wire-vectors.sh [path-to-group-wire-v1.json]
#
# The vectors (contracts/vectors/group-wire-v1.json) are written by a Rust test
# from spec/group-wire-formats.md and replayed there against the production
# codecs (decision 0149). This script replays the same file through
# tooling/group_wire_reference.py, a second program that agrees with the vectors,
# so that they are checked by something other than the code they test. That
# program was first written by a separate agent from the page and the vector file
# and then edited, and it is not an independent implementation of the page (see
# section 14 of the page, "What the second reader is, and is not"). It needs
# python3 and nothing else.
#
# A green run means: every valid vector decodes to its fields and re-encodes to
# its bytes, every refusal vector (and every proper prefix of a prefix vector)
# is refused with its reason, every encode-refusal is refused, and each
# commitment equals the SHA-256 of section 13's label and its preimage. It does
# not mean the Rust codecs agree; `cargo test -p tacenta-group --test
# group_wire_vectors` says that.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-group-wire-vectors: python3 not found" >&2
  exit 1
fi

vectors="${1:-contracts/vectors/group-wire-v1.json}"
python3 tooling/check_group_wire_vectors.py "$vectors"
