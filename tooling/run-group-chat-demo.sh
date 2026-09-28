#!/bin/sh
# Run the bounded, one-device group-chat demonstration: the group policy crate's
# limit and negative-control suites, then the client's live traces against the
# in-process directory, relay and real crypto provider.
#
# What the traces persist to: the live client traces use an in-memory store
# (`GroupStore`, whose commit always succeeds); the native file-backed
# operation store is exercised by the "native durable" step and its unit tests,
# with synthetic data. See docs/claims.md for the profile's limits.
#
# Every step must run exactly the tests it names. A step that runs zero tests
# (a renamed or filtered-out test), or a different number than expected, fails
# the script, so a rename or a removal cannot leave it green. The expected
# counts are the second argument of each `step` below; change them with the
# tests they count.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

work=$(mktemp -d "${TMPDIR:-/tmp}/group-demo.XXXXXX")
trap 'rm -rf "$work"' EXIT

steps=0
tests=0

fail() {
  echo "group demo: FAILED: $*" >&2
  exit 1
}

# step TITLE EXPECTED_TESTS COMMAND...
# Runs COMMAND, shows its output, then requires it to have exited 0, to have
# passed exactly EXPECTED_TESTS tests (summed over every test binary it ran),
# and to have failed or ignored none.
step() {
  title=$1
  expected=$2
  shift 2
  echo "$title"
  status=0
  "$@" >"$work/out" 2>"$work/err" || status=$?
  cat "$work/out"
  cat "$work/err" >&2
  [ "$status" -eq 0 ] || fail "step '$title' exited with status $status"
  counts=$(awk '
    /^test result: / {
      for (i = 2; i <= NF; i++) {
        if ($i == "passed;") passed += $(i - 1)
        if ($i == "failed;") failed += $(i - 1)
        if ($i == "ignored;") ignored += $(i - 1)
      }
    }
    END { printf "%d %d %d", passed, failed, ignored }
  ' "$work/out")
  # shellcheck disable=SC2086
  set -- $counts
  passed=$1
  failed=$2
  ignored=$3
  [ "$passed" -gt 0 ] || fail "step '$title' ran zero tests (expected $expected)"
  [ "$failed" -eq 0 ] || fail "step '$title' had $failed failing tests"
  [ "$ignored" -eq 0 ] || fail "step '$title' ignored $ignored tests"
  [ "$passed" -eq "$expected" ] ||
    fail "step '$title' ran $passed tests, expected $expected"
  steps=$((steps + 1))
  tests=$((tests + passed))
}

echo "group profile: eight-member and logical-outbox cap-plus-one refusals"
step "eight members accepted, a ninth refused" 1 \
  cargo test --locked -p tacenta-group --lib \
  tests::development_member_cap_accepts_eight_and_refuses_ninth \
  -- --exact
step "eight live logical sends, a ninth refused" 1 \
  cargo test --locked -p tacenta-group --lib \
  send::tests::outbox_applies_live_backpressure_without_discarding_terminal_evidence \
  -- --exact

echo "group profile: every limit at both edges, by literal"
step "limits" 20 \
  cargo test --locked -p tacenta-group --test limits

echo "group profile: model vectors, decision fixes and negative controls"
step "the Lean model's group-v1 traces replayed against the Rust types" 2 \
  cargo test --locked -p tacenta-group --test model_vectors
step "roster order, invitation admission, stale sends, sequences, terminal receiver state" 22 \
  cargo test --locked -p tacenta-group --test group_fixes
step "cold-read killers" 30 \
  cargo test --locked -p tacenta-group --test cold_read_killers
step "mutation-survivor killers" 8 \
  cargo test --locked -p tacenta-group --test mutation_killers
step "decoder robustness: no panics, bounded allocation, canonical re-encoding" 2 \
  cargo test --locked -p tacenta-group --test codec_robustness

echo "group profile: deterministic 2/3/8-member checkpoint sizes, 32-byte identities"
step "checkpoint sizes" 1 \
  cargo test --locked -p tacenta-group --lib \
  tests::development_profile_reports_checkpoint_sizes_at_two_three_and_eight_members \
  -- --exact --nocapture

# TODO(client-fixes): the steps below name tests in crates/tacenta-client. If
# the client changes rename, add or remove tests here, update the names and
# the expected counts; a stale name fails the script, which is the point.
echo "group profile: native durable group logical-intent transaction"
step "native snapshot" 1 \
  cargo test --locked -p tacenta-client --lib \
  group_operations::tests::native_snapshot_restores_group_send_and_receive_state_together \
  -- --exact --nocapture

echo "group demo: durable group handoff, interleaved DM, and wrong-sender refusal"
step "handoff, DM, wrong sender" 1 \
  cargo test --locked -p tacenta-client --lib \
  tests::a_live_group_handoff_commits_before_group_delivery \
  -- --exact

echo "group demo: roster removal cancels a prepared application handoff"
step "removal" 1 \
  cargo test --locked -p tacenta-client --lib \
  tests::a_live_roster_update_admits_then_removes_a_group_recipient \
  -- --exact

echo "group demo: sender restart and exact recovered group handoff"
step "restart" 1 \
  cargo test --locked -p tacenta-client --lib \
  tests::a_three_client_group_retries_the_committed_ciphertext_after_sender_restart \
  -- --exact --nocapture

echo "group demo: invitation, pending observation, authority restart, admission, and removal"
step "pending observer" 1 \
  cargo test --locked -p tacenta-client --lib \
  tests::a_pending_invitee_observes_live_successors_without_application_membership \
  -- --exact

echo "group demo: durable authenticated invitation revocation"
step "revocation" 1 \
  cargo test --locked -p tacenta-client --lib \
  tests::a_live_invitation_revocation_uses_a_durable_control_handoff \
  -- --exact --nocapture

echo "group demo: $steps steps, $tests tests, all passed"
