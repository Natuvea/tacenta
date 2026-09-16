#!/bin/sh
# Run the bounded, one-device group-chat demonstration against the in-process
# directory, relay, real provider, and durable operation snapshots.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

echo "group profile: eight-member and logical-outbox cap-plus-one refusals"
cargo test --locked -p tacenta-group \
  tests::development_member_cap_accepts_eight_and_refuses_ninth \
  -- --exact
cargo test --locked -p tacenta-group \
  send::tests::outbox_applies_live_backpressure_without_discarding_terminal_evidence \
  -- --exact

echo "group profile: deterministic 2/3/8-member checkpoint sizes"
cargo test --locked -p tacenta-group \
  tests::development_profile_reports_checkpoint_sizes_at_two_three_and_eight_members \
  -- --exact --nocapture

echo "group demo: durable group handoff, interleaved DM, and wrong-sender refusal"
cargo test --locked -p tacenta-client --lib \
  tests::a_live_group_handoff_commits_before_group_delivery \
  -- --exact

echo "group demo: invitation, pending observation, authority restart, admission, and removal"
cargo test --locked -p tacenta-client --lib \
  tests::a_pending_invitee_observes_live_successors_without_application_membership \
  -- --exact

echo "group demo: durable authenticated invitation revocation"
cargo test --locked -p tacenta-client --lib \
  tests::a_live_invitation_revocation_uses_a_durable_control_handoff \
  -- --exact
