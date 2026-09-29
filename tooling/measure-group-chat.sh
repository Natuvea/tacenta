#!/bin/sh
# Capture reproducible measurements for the bounded group-chat demonstration.
# Usage: tooling/measure-group-chat.sh OUTPUT_DIR
#
# It records what the numbers were measured on (product revision, the
# tacenta-core revision Cargo.lock resolves, host, toolchain, load), then:
#
#  1. runs the whole demo cold (empty target directory) and warm, under
#     /usr/bin/time, for process-level elapsed, CPU and maximum resident set;
#  2. extracts the deterministic 2/3/8-member roster and receiver-state sizes,
#     which use real 32-byte identities (the policy crate's own test asserts
#     them), and the three-client live figures the client tests print;
#  3. runs the client crate's per-size probe, once per member count in its own
#     process and twice, and records snapshot bytes, commits per logical send,
#     commit latency, restart cost, CPU and maximum resident set for each size.
#     The probe is an ignored client test (`group_client::tests::scale_probe::
#     group_scale_probe`); a missing probe stops the script.
#
# Every extraction is required. A missing line, a missing timing field or a
# missing /usr/bin/time stops the script with a message; nothing is defaulted.
# These are local comparison measurements, not production budgets, and they
# say nothing about 32, 128 or 512 members.
set -eu

fail() {
  echo "measure-group-chat: $*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 64
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$1
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)

[ -x /usr/bin/time ] || fail "/usr/bin/time is required for process-level timing"
case "$(uname -s)" in
Darwin) time_flag=-l ;;
*) time_flag=-v ;;
esac

# The probe's contract: an ignored lib test with this name that reads
# GROUP_SCALE_MEMBERS (2, 3 or 8), builds that many real clients with 32-byte
# identities, has the authority send one 1,000-byte logical message to every
# other member through a GroupClient over a native file store, and prints one
# line
#   group-scale members=N snapshot_bytes=B provider_state_bytes=P
#     logical_send_commits=C logical_send_micros=T restart_recover_micros=R
#     roster_bytes=.. receiver_state_bytes=.. commit_median_micros=..
# (one line; wrapped here only for reading). It is run with --ignored.
probe=group_client::tests::scale_probe::group_scale_probe

core_source=$(awk '
  /^name = "tacenta-core"$/ { found = 1; next }
  found && /^source = "git\+/ { print; exit }
  /^\[\[package\]\]/ { found = 0 }
' "$root/Cargo.lock" | sed 's/^source = "\(.*\)"$/\1/')
[ -n "$core_source" ] || fail "Cargo.lock has no git source for tacenta-core"
core_rev=${core_source##*#}
dirty=$(git -C "$root" status --porcelain | wc -l | tr -d ' ')

{
  echo "product_revision=$(git -C "$root" rev-parse HEAD)"
  echo "product_branch=$(git -C "$root" branch --show-current)"
  echo "product_tree_changes=$dirty"
  echo "tacenta_core_source=$core_source"
  echo "tacenta_core_revision=$core_rev"
  echo "cargo_lock_sha256=$(shasum -a 256 "$root/Cargo.lock" | cut -d' ' -f1)"
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "seeds=none: the policy-crate fixtures are fixed byte patterns; the live traces and the scale probe draw keys from the operating system and are not seeded. Byte sizes repeated exactly between the two passes of each probe size in the recorded runs; timings vary"
  echo "load_average=$(uptime | sed 's/.*load averages*: //')"
  uname -a
  case "$(uname -s)" in
  Darwin)
    echo "cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model)"
    echo "logical_cpus=$(sysctl -n hw.logicalcpu)"
    echo "memory_bytes=$(sysctl -n hw.memsize)"
    ;;
  *)
    echo "cpu=$(sed -n 's/^model name[^:]*: //p' /proc/cpuinfo | head -1)"
    echo "logical_cpus=$(getconf _NPROCESSORS_ONLN)"
    echo "memory_kib=$(sed -n 's/^MemTotal: *\([0-9]*\) kB/\1/p' /proc/meminfo)"
    ;;
  esac
  rustc -Vv
  cargo -V
} >"$output/environment.txt"
[ "$dirty" -eq 0 ] ||
  echo "measure-group-chat: warning: $dirty uncommitted change(s); the recorded revision does not describe this tree" >&2

run() {
  name=$1
  target_dir=$2
  CARGO_TARGET_DIR="$target_dir" /usr/bin/time "$time_flag" \
    "$root/tooling/run-group-chat-demo.sh" >"$output/$name.log" 2>"$output/$name.time" ||
    fail "the $name demo run failed; see $output/$name.log and $output/$name.time"
}

target_dir="$output/cargo-target"
rm -rf "$target_dir"
run cold "$target_dir"
run warm "$target_dir"

# need FILE REGEX: the file must contain a line matching REGEX.
need() {
  grep -q -- "$2" "$1" || fail "$1 has no line matching: $2"
}

# Elapsed, CPU and maximum resident set out of a /usr/bin/time report, as
# `elapsed_s=.. user_s=.. sys_s=.. max_rss_bytes=..`.
timing() {
  file=$1
  if [ "$time_flag" = "-l" ]; then
    line=$(grep -E '^ +[0-9.]+ real +[0-9.]+ user +[0-9.]+ sys' "$file" | tail -1) ||
      fail "$file has no real/user/sys line"
    [ -n "$line" ] || fail "$file has no real/user/sys line"
    rss=$(sed -n 's/^ *\([0-9][0-9]*\)  *maximum resident set size.*/\1/p' "$file" | tail -1)
    [ -n "$rss" ] || fail "$file has no maximum resident set size"
    echo "$line" | awk -v rss="$rss" '{ printf "elapsed_s=%s user_s=%s sys_s=%s max_rss_bytes=%s\n", $1, $3, $5, rss }'
  else
    wall=$(sed -n 's/^.*Elapsed (wall clock) time[^:]*: *//p' "$file" | tail -1)
    user=$(sed -n 's/^.*User time (seconds): *//p' "$file" | tail -1)
    sys=$(sed -n 's/^.*System time (seconds): *//p' "$file" | tail -1)
    kib=$(sed -n 's/^.*Maximum resident set size (kbytes): *//p' "$file" | tail -1)
    [ -n "$wall" ] && [ -n "$user" ] && [ -n "$sys" ] && [ -n "$kib" ] ||
      fail "$file is missing an elapsed, user, system or maximum resident field"
    echo "elapsed=$wall user_s=$user sys_s=$sys max_rss_bytes=$((kib * 1024))"
  fi
}

for members in 2 3 8; do
  need "$output/warm.log" "^group-profile members=$members identity_bytes=32 roster_bytes=[0-9]* receiver_state_bytes=[0-9]*$"
done
need "$output/warm.log" '^group-profile native_logical_intent_commit_micros=[0-9]*$'
need "$output/warm.log" '^group-profile sender_restart_and_outbox_recovery_micros=[0-9]*$'
need "$output/warm.log" '^group-profile authority_operation_snapshot_bytes=[0-9]* target_operation_snapshot_bytes=[0-9]*$'

scale="$output/scale.txt"
: >"$scale"
client_list=$(cargo test --locked -p tacenta-client --lib -- --list 2>/dev/null) ||
  fail "could not list the client tests"
echo "$client_list" | grep -q "^$probe: test\$" ||
  fail "the client crate has no $probe test"
exe=$(cargo test --locked -p tacenta-client --lib --no-run --message-format=json 2>/dev/null |
  sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1)
[ -x "$exe" ] || fail "could not find the client test executable"
for members in 2 3 8; do
  for pass in first second; do
    log="$output/scale-$members-$pass.log"
    GROUP_SCALE_MEMBERS=$members /usr/bin/time "$time_flag" "$exe" "$probe" --ignored --exact --nocapture \
      >"$log" 2>"$output/scale-$members-$pass.time" ||
      fail "the scale probe failed for $members members; see $log"
    need "$log" "^group-scale members=$members snapshot_bytes="
    echo "members=$members run=$pass $(grep "^group-scale members=$members " "$log" | head -1 | cut -d' ' -f3-) $(timing "$output/scale-$members-$pass.time")" >>"$scale"
  done
done

{
  echo "identification"
  grep -E '^(product_revision|product_tree_changes|tacenta_core_revision|seeds|load_average|cpu|logical_cpus)=' "$output/environment.txt"
  echo
  echo "bounded group checkpoint sizes (policy crate, real 32-byte identities)"
  grep -E '^group-profile members=' "$output/warm.log"
  echo
  echo "three-client live figures (client tests)"
  grep -E '^group-profile (native_logical_intent_commit_micros|sender_restart_and_outbox_recovery_micros|authority_operation_snapshot_bytes)' "$output/warm.log"
  echo
  echo "whole-demo process, cold (empty target directory)"
  timing "$output/cold.time"
  echo
  echo "whole-demo process, warm"
  timing "$output/warm.time"
  echo
  echo "per member count (client probe, one process per size and pass)"
  cat "$scale"
} >"$output/summary.txt"

cat >"$output/README.txt" <<'EOF'
Measurements of the bounded group-chat demonstration (tooling/measure-group-chat.sh).

environment.txt records the product revision, the tacenta-core revision that
Cargo.lock resolves, the host, the toolchain and the load average at the start.
The runs are not seeded; see the seeds line.

cold.log/cold.time and warm.log/warm.time are the demo script's output and the
/usr/bin/time report for the whole process: the cold run compiles into an empty
target directory, the warm run reuses it. summary.txt extracts the fields.

The 2/3/8-member roster and receiver-state sizes are deterministic and use
32-byte identities. The native transaction, restart and snapshot figures come
from the three-client client tests and are single measurements on a loaded
machine. scale.txt has one line per member count and pass from the client's
per-size probe (a GroupClient over a native file store, real 32-byte
identities, one 1,000-byte logical send to every other member): snapshot bytes,
provider-state bytes, whole-snapshot commits per logical send, the time of that
send, the median latency of one more commit at the final size, the restart and
recovery time, and the probe process's CPU and maximum resident set. Nothing
here is a production budget or a 32, 128 or 512-member result.
EOF

echo "group-chat measurements written to $output"
