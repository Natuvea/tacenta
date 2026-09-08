#!/usr/bin/env bash
# The three SDK heads' conformance conversations must say the same thing.
#
# The public transcript at tacenta.com/dl/conformance/<tag>.md is read by
# comparing the heads line for line, so the conversation is written once per
# language (sdk/typescript, bindings/swift, bindings/android) and nothing
# shares code across them. This is what keeps them from drifting: every step
# phrase and every message text must appear in each, and each must log the
# same number of steps. A step added to one head fails here until it is in
# all three (decision 0090).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

files=(
  sdk/typescript/conformance/conversation.mjs
  bindings/swift/conformance/Conversation.swift
  bindings/android/conformance/src/main/kotlin/com/tacenta/conformance/Conversation.kt
)
phrases=(
  'conform-a-'
  'conform-b-'
  'signed up '
  'signed in as '
  'a wrong password was refused as'
  'a second sign-up was refused as'
  'a send to an unregistered address was refused as'
  'accepted'
  'find of a stranger'
  'found '
  'conformance: first contact'
  'received the first message from'
  'conformance: reply'
  'received the reply'
  'conformance: after resume'
  'resumed from '
  'bytes of state and received again'
  'sent while its own receive was pending'
  'conformance: while receiving'
  'conformance: to the pending receive'
  'conformance: through the stream'
  'took the next message from its inbound stream'
)

failed=0
for f in "${files[@]}"; do
  [ -f "$f" ] || { echo "check-conformance-lines: $f is missing" >&2; failed=1; continue; }
  for p in "${phrases[@]}"; do
    grep -qF -- "$p" "$f" || { echo "check-conformance-lines: $f lacks '$p'" >&2; failed=1; }
  done
done

counts=$(for f in "${files[@]}"; do grep -c 'log(' "$f"; done | sort -u | wc -l | tr -d ' ')
if [ "$counts" != 1 ]; then
  echo "check-conformance-lines: the heads log a different number of steps:" >&2
  for f in "${files[@]}"; do echo "  $(grep -c 'log(' "$f")  $f" >&2; done
  failed=1
fi

[ "$failed" = 0 ] || exit 1
echo "check-conformance-lines: the three heads' conversations match (${#phrases[@]} phrases, $(grep -c 'log(' "${files[0]}") steps)"
