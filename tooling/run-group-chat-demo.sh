#!/bin/sh
# Run the bounded, one-device group-chat demonstration against the in-process
# directory, relay, real provider, and durable operation snapshots.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

echo "group demo: invitation, pending observation, authority restart, admission, and removal"
cargo test --locked -p tacenta-client --lib \
  tests::a_pending_invitee_observes_live_successors_without_application_membership \
  -- --exact

echo "group demo: durable authenticated invitation revocation"
cargo test --locked -p tacenta-client --lib \
  tests::a_live_invitation_revocation_uses_a_durable_control_handoff \
  -- --exact
