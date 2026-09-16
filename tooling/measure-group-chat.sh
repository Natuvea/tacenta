#!/bin/sh
# Capture reproducible process-level cold and warm measurements for the
# bounded group-chat demo. Usage: tooling/measure-group-chat.sh OUTPUT_DIR
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 64
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$1
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)

{
  echo "revision=$(git -C "$root" rev-parse HEAD)"
  echo "branch=$(git -C "$root" branch --show-current)"
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  uname -a
  rustc -Vv
  cargo -V
} >"$output/environment.txt"

run() {
  name=$1
  target_dir=$2
  log="$output/$name.log"
  timing="$output/$name.time"
  if [ "$(uname -s)" = "Darwin" ]; then
    CARGO_TARGET_DIR="$target_dir" /usr/bin/time -l \
      "$root/tooling/run-group-chat-demo.sh" >"$log" 2>"$timing"
  else
    CARGO_TARGET_DIR="$target_dir" /usr/bin/time -v \
      "$root/tooling/run-group-chat-demo.sh" >"$log" 2>"$timing"
  fi
}

target_dir="$output/cargo-target"
run cold "$target_dir"
run warm "$target_dir"

{
  echo "bounded group checkpoint sizes"
  grep '^group-profile ' "$output/warm.log" || true
  echo
  echo "cold process timing"
  grep -E 'real|user|sys|resident|Elapsed|User time|System time|Maximum resident' \
    "$output/cold.time" || true
  echo
  echo "warm process timing"
  grep -E 'real|user|sys|resident|Elapsed|User time|System time|Maximum resident' \
    "$output/warm.time" || true
} >"$output/summary.txt"

cat >"$output/README.txt" <<'EOF'
These are process-level measurements of the bounded group-chat demonstration.
The cold run uses an empty target directory; the warm run reuses it. The time
output reports elapsed/user/system time and maximum resident set size when the
host's /usr/bin/time supports it. summary.txt extracts those fields and the
the group-profile metrics emitted by its live tests, including deterministic
2/3/8-member checkpoint sizes and sender restart plus outbox recovery. This
runner records evidence for comparison; it does not establish production
performance budgets or synthetic 32/128/512 member results.
EOF

echo "group-chat measurements written to $output"
