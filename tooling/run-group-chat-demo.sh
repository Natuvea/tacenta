#!/bin/sh
# Run the bounded, one-device group-chat demonstration: the group policy crate's
# limit and negative-control suites, then the client's live traces against the
# in-process directory, relay and real crypto provider.
#
# Usage: tooling/run-group-chat-demo.sh [--update-manifest]
#
# What the traces persist to: the older live client traces use an in-memory
# store (`GroupStore`, whose commit always succeeds); the `GroupClient` traces
# use an in-memory store that a test can script to fail or leave a write in
# doubt; the native file-backed operation store is exercised by the "native
# durable" step and its unit tests, with synthetic data, and by the measurement
# probes (tooling/measure-group-chat.sh). See docs/claims.md for the profile's
# limits.
#
# What a green run establishes. Each step runs one `cargo test` command, and
# the script reads the libtest lines `test NAME ... ok` it printed. A step
# passes only if all of these hold:
#   - cargo exited 0, libtest reported no failed and no ignored test, and the
#     step ran at least one test;
#   - no test line says `should panic` (no test in these crates uses
#     #[should_panic]; one that did could turn a failing body into a pass);
#   - the number of `ok` lines equals the passed count libtest reported;
#   - the set of pairs (test binary, test name) that passed equals the set the
#     checked-in manifest, tooling/group-chat-demo-tests.txt, lists for the
#     step, and its size equals the count pinned there. A rename, a deletion,
#     an addition, a macro-generated test, or a deletion paired with an
#     addition changes the set and fails the step; every missing and every
#     unexpected name is printed;
#   - no test is listed for two steps, so the headline, which sums the steps,
#     counts each test once.
# So a green run establishes that, against an unedited manifest, the named
# tests exist, ran and passed. That is all it establishes.
#
# What it does NOT establish, each shown by an attack that ends green (the
# second verification of the second fix round ran 29 of them, and the
# repository's tests do not repeat them):
#   - that a test still checks what its name says. A body that returns early,
#     asserts `true`, asserts inside a task nobody joins or a thread nobody
#     joins, catches its own panic, is empty, or returns under
#     `cfg!(debug_assertions)`, under a name the manifest lists, passes. Only
#     review or mutation testing answers that (tooling/group-mutation does it for
#     the group crate's tests; nothing here does it for the client's);
#   - that the manifest was not edited with the change it checks. A rename, a
#     deletion or an addition made together with the edit of the manifest that
#     lists it passes, and so does a real regression whose only killer test is
#     deleted from the source and from the manifest in one commit. The same
#     holds for a step deleted from both this script and the manifest. The
#     manifest is the reference; a change to it is visible only in review;
#   - that the output is libtest's or that the tests were built from the
#     source in the tree. A test that prints `test NAME ... ok` and a result line
#     itself, a test target with `harness = false` that prints them, a `cargo`
#     earlier on PATH that replays recorded output, and a stale binary (a source
#     file whose modification time is older than the build) all pass. The script
#     trusts the toolchain and the build;
#   - that it survives load. libtest prints a notice for a test that has been
#     running for more than 60 seconds; the script cannot parse that line and
#     fails the step closed, so a slow runner can fail a run with nothing wrong.
#
# A deliberate change to the tests is made in one commit: change the tests, run
# this script with --update-manifest, and review the manifest's diff.
# --update-manifest is the only way the manifest is ever written, and it is
# never implied. It still requires every step to exit 0 and to pass the checks
# above; it only skips the comparison with the old manifest, so its run proves
# nothing about names and counts and it prints that it is not a check.
set -eu

mode=check
case "$#" in
0) ;;
1)
  case "$1" in
  --update-manifest) mode=update ;;
  *)
    echo "usage: $0 [--update-manifest]" >&2
    exit 64
    ;;
  esac
  ;;
*)
  echo "usage: $0 [--update-manifest]" >&2
  exit 64
  ;;
esac

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

manifest=tooling/group-chat-demo-tests.txt

work=$(mktemp -d "${TMPDIR:-/tmp}/group-demo.XXXXXX")
trap 'rm -rf "$work"; rm -f "$manifest.new"' EXIT

# The parser reads cargo's `Running ...` lines and libtest's lines as plain
# text; colour codes would hide them.
CARGO_TERM_COLOR=never
export CARGO_TERM_COLOR

steps=0
tests=0
: >"$work/ran"
: >"$work/new-manifest"

fail() {
  echo "group demo: FAILED: $*" >&2
  exit 1
}

# problem MESSAGE...: reports one failed check of the current step and counts it.
problem() {
  problems=$((problems + 1))
  echo "group demo:   [$id] $*" >&2
}

tab=$(printf '\t')

if [ "$mode" = check ]; then
  [ -f "$manifest" ] ||
    fail "$manifest is missing; restore it from version control (--update-manifest writes a new one after a deliberate test change)"
  # Every line is a comment, a blank, `step ID COUNT` or `test ID TARGET NAME`;
  # a step's count equals its number of test lines; nothing is listed twice.
  awk -v file="$manifest" '
    function err(message) {
      print "group demo: " file ":" NR ": " message | "cat >&2"
      bad = 1
    }
    /^[ \t]*(#|$)/ { next }
    $1 == "step" && NF == 3 && $3 ~ /^[0-9]+$/ && $3 + 0 > 0 {
      if ($2 in pinned) err("step " $2 " is listed twice")
      pinned[$2] = $3 + 0
      steps_listed++
      next
    }
    $1 == "test" && NF == 4 {
      key = $2 " " $3 " " $4
      if (key in seen) err("test " $4 " is listed twice for step " $2)
      seen[key] = 1
      binary_and_name = $3 " " $4
      if ((binary_and_name in owner) && owner[binary_and_name] != $2)
        err("test " $4 " is listed for steps " owner[binary_and_name] " and " $2)
      owner[binary_and_name] = $2
      listed[$2]++
      next
    }
    { err("not a `step ID COUNT` or `test ID TARGET NAME` record: " $0) }
    END {
      for (id in pinned)
        if (listed[id] + 0 != pinned[id])
          err("step " id " pins " pinned[id] " tests but lists " listed[id] + 0)
      for (id in listed)
        if (!(id in pinned)) err("tests are listed for step " id ", which has no step line")
      if (steps_listed == 0) err("no step is listed")
      exit bad
    }
  ' "$manifest" || fail "$manifest is malformed"
fi

# step ID TITLE COMMAND...
# Runs COMMAND, shows its output, then applies every check in the header. In
# check mode the passing set and count must equal the manifest's for ID; in
# update mode they are recorded for the new manifest instead.
step() {
  id=$1
  title=$2
  shift 2
  if grep -qx -- "$id" "$work/ran"; then
    fail "step id '$id' is used twice in this script"
  fi
  echo "$id" >>"$work/ran"
  echo "$title"
  status=0
  # One file for both streams so cargo's `Running ...` lines (stderr) stay in
  # order with libtest's lines (stdout).
  "$@" >"$work/out" 2>&1 || status=$?
  cat "$work/out"
  [ "$status" -eq 0 ] || fail "step '$title' ($id) exited with status $status"

  # Prints, in this order: `test result:` lines, passed, failed, ignored (all
  # summed from those lines), then counts of the `test ...` lines: ok, failed,
  # ignored, "should panic", and lines that are none of those. Passing tests are
  # written to $work/found as `TARGET<TAB>NAME`, where TARGET is the test binary
  # named on the `Running` line before them, minus the path, hash and suffix
  # (`tacenta_group`, `limits`); the offending lines go to $work/bad.
  : >"$work/found"
  : >"$work/bad"
  counts=$(awk -v found="$work/found" -v bad="$work/bad" '
    BEGIN { target = "?" }
    /^ +Running / {
      target = "?"
      if (match($0, /\([^()]*\)$/)) {
        path = substr($0, RSTART + 1, RLENGTH - 2)
        n = split(path, parts, "/")
        target = parts[n]
        sub(/\.exe$/, "", target)
        sub(/-[0-9a-f]+$/, "", target)
      }
      next
    }
    /^test result: / {
      results++
      for (i = 2; i <= NF; i++) {
        if ($i == "passed;") passed += $(i - 1)
        if ($i == "failed;") failed += $(i - 1)
        if ($i == "ignored;") ignored += $(i - 1)
      }
      next
    }
    /^test / {
      if (index($0, "should panic") > 0) {
        panics++
        print $0 > bad
      }
      at = index($0, " ... ")
      if (at == 0) {
        odd++
        print $0 > bad
        next
      }
      name = substr($0, 6, at - 6)
      outcome = substr($0, at + 5)
      if (name ~ /[ \t]/ && index($0, "should panic") == 0) {
        odd++
        print $0 > bad
      }
      if (outcome == "ok") {
        oks++
        printf "%s\t%s\n", target, name > found
      } else if (outcome == "FAILED") {
        fails++
      } else if (outcome ~ /^ignored/) {
        skips++
      } else {
        odd++
        print $0 > bad
      }
    }
    END {
      printf "%d %d %d %d %d %d %d %d %d\n", results, passed, failed, ignored, oks, fails, skips, panics, odd
    }
  ' "$work/out")
  # shellcheck disable=SC2086
  set -- $counts
  results=$1
  passed=$2
  failed=$3
  ignored=$4
  oks=$5
  fails=$6
  skips=$7
  panics=$8
  odd=$9

  problems=0

  [ "$results" -gt 0 ] && [ "$passed" -gt 0 ] || problem "ran zero tests"
  [ "$failed" -eq 0 ] && [ "$fails" -eq 0 ] ||
    problem "$failed failing tests reported, $fails failing test lines"
  [ "$ignored" -eq 0 ] && [ "$skips" -eq 0 ] ||
    problem "ignored $ignored tests reported, $skips ignored test lines"
  [ "$panics" -eq 0 ] || problem "$panics test line(s) say 'should panic': $(tr '\n' '|' <"$work/bad")"
  [ "$odd" -eq 0 ] || problem "$odd test line(s) could not be read: $(tr '\n' '|' <"$work/bad")"
  [ "$oks" -eq "$passed" ] ||
    problem "$oks 'ok' test lines but libtest counted $passed passed"

  LC_ALL=C sort "$work/found" >"$work/found.sorted"
  duplicated=$(LC_ALL=C uniq -d "$work/found.sorted" | tr '\t\n' ' |')
  [ -z "$duplicated" ] || problem "the same test binary and name ran twice: $duplicated"

  if [ "$mode" = check ]; then
    pinned=$(awk -v id="$id" '$1 == "step" && $2 == id { print $3 }' "$manifest")
    if [ -z "$pinned" ]; then
      problem "the manifest has no entry for this step"
    else
      awk -v id="$id" '$1 == "test" && $2 == id { printf "%s\t%s\n", $3, $4 }' "$manifest" |
        LC_ALL=C sort >"$work/want"
      LC_ALL=C comm -23 "$work/want" "$work/found.sorted" >"$work/missing"
      LC_ALL=C comm -13 "$work/want" "$work/found.sorted" >"$work/unexpected"
      while IFS="$tab" read -r bin name; do
        problem "missing from the run, listed in the manifest: [$bin] $name"
      done <"$work/missing"
      while IFS="$tab" read -r bin name; do
        problem "ran but not in the manifest: [$bin] $name"
      done <"$work/unexpected"
      [ "$passed" -eq "$pinned" ] ||
        problem "ran $passed tests, the manifest pins $pinned"
    fi
  else
    {
      echo "step $id $passed"
      awk -F'\t' -v id="$id" '{ print "test " id " " $1 " " $2 }' "$work/found.sorted"
    } >>"$work/new-manifest"
  fi

  [ "$problems" -eq 0 ] || fail "step '$title' ($id) failed $problems check(s)"
  steps=$((steps + 1))
  tests=$((tests + passed))
}

echo "group profile: eight-member and logical-outbox cap-plus-one refusals"
step member-cap "eight members accepted, a ninth refused" \
  cargo test --locked -p tacenta-group --lib \
  tests::development_member_cap_accepts_eight_and_refuses_ninth \
  -- --exact
step live-backpressure "eight live logical sends, a ninth refused" \
  cargo test --locked -p tacenta-group --lib \
  send::tests::outbox_applies_live_backpressure_without_discarding_terminal_evidence \
  -- --exact

echo "group profile: every limit at both edges, by literal"
step limits "limits" \
  cargo test --locked -p tacenta-group --test limits

echo "group profile: model vectors, decision fixes and negative controls"
step model-vectors "the Lean model's group-v1 traces replayed against the Rust types" \
  cargo test --locked -p tacenta-group --test model_vectors
step group-fixes "roster order, invitation admission, stale sends, sequences, terminal receiver state" \
  cargo test --locked -p tacenta-group --test group_fixes
step cold-read-killers "cold-read killers" \
  cargo test --locked -p tacenta-group --test cold_read_killers
step mutation-killers "mutation-survivor killers" \
  cargo test --locked -p tacenta-group --test mutation_killers
step codec-robustness "decoder robustness: no panics, bounded allocation, canonical re-encoding" \
  cargo test --locked -p tacenta-group --test codec_robustness

echo "group profile: the group crate changes the coordinator needs (decision 0135)"
step coordinator-needs "final-attempt acceptance, recovery at the applied revision, source-roster view, public member order" \
  cargo test --locked -p tacenta-group --test coordinator_needs

echo "group profile: deterministic 2/3/8-member checkpoint sizes, 32-byte identities"
step checkpoint-sizes "checkpoint sizes" \
  cargo test --locked -p tacenta-group --lib \
  tests::development_profile_reports_checkpoint_sizes_at_two_three_and_eight_members \
  -- --exact --nocapture

# The steps below name tests in crates/tacenta-client. If the client changes,
# rename, add or remove tests here, run this script with --update-manifest and
# review the manifest's diff; a stale name fails the script, which is the point.
echo "group profile: native durable group logical-intent transaction"
step native-snapshot "native snapshot" \
  cargo test --locked -p tacenta-client --lib \
  group_operations::tests::native_snapshot_restores_group_send_and_receive_state_together \
  -- --exact --nocapture

echo "group demo: durable group handoff, interleaved DM, and wrong-sender refusal"
step handoff-dm-wrong-sender "handoff, DM, wrong sender" \
  cargo test --locked -p tacenta-client --lib \
  tests::a_live_group_handoff_commits_before_group_delivery \
  -- --exact

echo "group demo: roster removal cancels a prepared application handoff"
step removal "removal" \
  cargo test --locked -p tacenta-client --lib \
  tests::a_live_roster_update_admits_then_removes_a_group_recipient \
  -- --exact

echo "group demo: sender restart and exact recovered group handoff"
step restart "restart" \
  cargo test --locked -p tacenta-client --lib \
  tests::a_three_client_group_retries_the_committed_ciphertext_after_sender_restart \
  -- --exact --nocapture

echo "group demo: invitation, pending observation, authority restart, admission, and removal"
step pending-observer "pending observer" \
  cargo test --locked -p tacenta-client --lib \
  tests::a_pending_invitee_observes_live_successors_without_application_membership \
  -- --exact

echo "group demo: durable authenticated invitation revocation"
step revocation "revocation" \
  cargo test --locked -p tacenta-client --lib \
  tests::a_live_invitation_revocation_uses_a_durable_control_handoff \
  -- --exact --nocapture

echo "group client: staged receive, write-through direct messages, latch, bounds, boundaries"
# The measurement probes in the same module (`group_scale_probe`,
# `group_scale_probe_steady_state`) are ignored and are skipped here by name;
# the measurement script runs them.
step group-client-traces "GroupClient live traces and boundary traces" \
  cargo test --locked -p tacenta-client --lib group_client::tests -- --skip group_scale_probe
step group-operations-review "coordinator functions: bounds, latch, validate before encrypt, unknown-write sites" \
  cargo test --locked -p tacenta-client --lib group_operations::review_tests
step review-live "live guards of the preparation and dispatch functions" \
  cargo test --locked -p tacenta-client --lib tests::review_live
step operation-store "operation store: latch, generations, the fence, the native store under contention" \
  cargo test --locked -p tacenta-client --lib operation_store::tests
step deferred-rosters "held roster controls: the queue and its record" \
  cargo test --locked -p tacenta-client --lib group_deferred_rosters::tests

echo "group profile: guards pinned after the mutation reruns"
step group-guards "group crate guards: send recovery, receiver, roster view, invitation rules" \
  cargo test --locked -p tacenta-group --test logical_send_guards --test send_recovery_transcripts \
  --test receiver_guards --test receiver_events_and_removal_guards --test roster_guards \
  --test invitation_rules
step client-guards "client guards: operation store, control outbox, group operations" \
  cargo test --locked -p tacenta-client --lib guard_tests

if [ "$mode" = update ]; then
  # A test that two steps ran would be counted twice; refuse to record it.
  awk '
    $1 == "test" {
      key = $3 " " $4
      if ((key in owner) && owner[key] != $2) {
        print "group demo: test " $4 " ran in steps " owner[key] " and " $2 | "cat >&2"
        bad = 1
      }
      owner[key] = $2
    }
    END { exit bad }
  ' "$work/new-manifest" || fail "a test ran in two steps; narrow the filters of one of them"
  {
    cat <<'EOF'
# The tests each step of tooling/run-group-chat-demo.sh must run, by test binary
# and name, with the number of tests pinned per step. The script fails a step
# whose passing tests differ from these lines in any way (a rename, a removal,
# an addition, a removal paired with an addition), and fails on a step whose
# count differs from the pinned count.
#
# This file lists names. It does not say that a test's body asserts anything.
#
# Do not edit by hand. After a deliberate change to the tests, run
#   tooling/run-group-chat-demo.sh --update-manifest
# and review this file's diff in the same commit as the test change: every added
# line is a test the demo now runs, every removed line a test it no longer runs.
#
# Records, one per line:
#   step ID COUNT           the step named ID must run exactly COUNT tests
#   test ID BINARY NAME     one of them; BINARY is the test binary (the crate's
#                           library target, or the integration test's file name)
EOF
    cat "$work/new-manifest"
  } >"$manifest.new"
  mv "$manifest.new" "$manifest"
  echo "group demo: manifest $manifest written from this run: $steps steps, $tests tests." \
    "This run compared nothing with the old manifest: review 'git diff $manifest' before committing it."
  exit 0
fi

# Every step the manifest lists must have run (a removed step must leave it).
awk '$1 == "step" { print $2 }' "$manifest" | LC_ALL=C sort >"$work/manifest-ids"
LC_ALL=C sort "$work/ran" >"$work/ran-ids"
stale=$(LC_ALL=C comm -23 "$work/manifest-ids" "$work/ran-ids" | tr '\n' ' ')
[ -z "$stale" ] || fail "the manifest lists steps this script did not run: $stale"

echo "group demo: $steps steps, $tests tests, all passed, names and counts match $manifest"
