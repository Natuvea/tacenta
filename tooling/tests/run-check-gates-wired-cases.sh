#!/usr/bin/env bash
# Hold the wired-gates check to a passing control and to each way a gate script
# can sit in tooling/ without a workflow step behind it.
#
#   bash tooling/tests/run-check-gates-wired-cases.sh
#
# First the real tree, which must pass, and the same tree with the step that
# runs the group-chat demo script taken out, which must be refused: that is the
# gate that was once documented as "CI does not run this script". Then a small
# scratch tree, one change at a time: a gate no step names, one named only in a
# comment or in a step's `name:`, one whose step is allowed to fail or switched
# off (at step or job level), one whose name is only a prefix of a wired one,
# an excuse that has gone stale either way, a missing workflow directory, an
# unparseable workflow, and a machine without PyYAML.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

refusals=0
expect_fail() {
  local dir="$1" expect="$2" out rc
  shift 2
  set +e
  out="$(env "$@" bash "$dir/tooling/check-gates-wired.sh" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "WRONG  $(basename "$dir"): expected refusal ($expect), was accepted" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -qF -- "$expect"; then
    echo "WRONG  $(basename "$dir"): refused, but not for '$expect':" >&2
    printf '  %s\n' "$out" >&2
    return 1
  fi
  refusals=$((refusals + 1))
}

# The real tree.
bash "$root/tooling/check-gates-wired.sh" >/dev/null

# The real gates and workflow, with the demo step replaced by a no-op.
real="$work/real-without-the-demo"
mkdir -p "$real/tooling" "$real/.github/workflows"
cp "$root/tooling/check-gates-wired.sh" "$real/tooling/"
for f in "$root"/tooling/check-* "$root"/tooling/run-*demo* "$root"/tooling/tests; do
  cp -R "$f" "$real/tooling/"
done
python3 - "$root/.github/workflows/ci.yml" "$real/.github/workflows/ci.yml" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
needle = "run: sh tooling/run-group-chat-demo.sh"
assert needle in text, "the real workflow no longer runs the demo script"
pathlib.Path(sys.argv[2]).write_text(text.replace(needle, "run: 'true'"))
PY
expect_fail "$real" 'tooling/run-group-chat-demo.sh is not run by any workflow step'

# A scratch tree: two gates, a demo, a runner, and the two excused scripts, all
# wired by one workflow.
make_tree() {
  local dir="$work/$1"
  mkdir -p "$dir/tooling/tests" "$dir/.github/workflows"
  cp "$root/tooling/check-gates-wired.sh" "$dir/tooling/"
  for f in check-a.sh check-b.py run-a-demo.sh check-docs-match.sh check-surface-bindings.sh tests/run-check-a-cases.sh; do
    : > "$dir/tooling/$f"
  done
  cat > "$dir/.github/workflows/ci.yml" <<'YAML'
name: ci
on: push
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - run: bash tooling/check-gates-wired.sh
      - run: bash ./tooling/check-a.sh
      - run: python3 tooling/check-b.py
      - run: sh tooling/run-a-demo.sh
      - run: bash tooling/tests/run-check-a-cases.sh
YAML
}
workflow() { echo "$work/$1/.github/workflows/ci.yml"; }

make_tree pass
bash "$work/pass/tooling/check-gates-wired.sh" >/dev/null

make_tree unwired-gate
: > "$work/unwired-gate/tooling/check-c.sh"
expect_fail "$work/unwired-gate" 'tooling/check-c.sh is not run by any workflow step'

make_tree unwired-runner
: > "$work/unwired-runner/tooling/tests/run-check-c-cases.sh"
expect_fail "$work/unwired-runner" 'tooling/tests/run-check-c-cases.sh is not run by any workflow step'

make_tree named-in-a-comment
: > "$work/named-in-a-comment/tooling/check-c.sh"
printf '      # bash tooling/check-c.sh\n' >> "$(workflow named-in-a-comment)"
expect_fail "$work/named-in-a-comment" 'tooling/check-c.sh is not run'

make_tree named-in-a-step-name
: > "$work/named-in-a-step-name/tooling/check-c.sh"
printf '      - name: tooling/check-c.sh\n        run: "true"\n' >> "$(workflow named-in-a-step-name)"
expect_fail "$work/named-in-a-step-name" 'tooling/check-c.sh is not run'

make_tree step-may-fail
: > "$work/step-may-fail/tooling/check-c.sh"
printf '      - run: bash tooling/check-c.sh\n        continue-on-error: true\n' >> "$(workflow step-may-fail)"
expect_fail "$work/step-may-fail" 'tooling/check-c.sh is not run'

make_tree step-switched-off
: > "$work/step-switched-off/tooling/check-c.sh"
printf '      - run: bash tooling/check-c.sh\n        if: ${{ false }}\n' >> "$(workflow step-switched-off)"
expect_fail "$work/step-switched-off" 'tooling/check-c.sh is not run'

make_tree step-switched-off-plain
: > "$work/step-switched-off-plain/tooling/check-c.sh"
printf '      - run: bash tooling/check-c.sh\n        if: false\n' >> "$(workflow step-switched-off-plain)"
expect_fail "$work/step-switched-off-plain" 'tooling/check-c.sh is not run'

make_tree job-switched-off
: > "$work/job-switched-off/tooling/check-c.sh"
printf '  other:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash tooling/check-c.sh\n' >> "$(workflow job-switched-off)"
expect_fail "$work/job-switched-off" 'tooling/check-c.sh is not run'

make_tree job-may-fail
: > "$work/job-may-fail/tooling/check-c.sh"
printf '  other:\n    continue-on-error: true\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash tooling/check-c.sh\n' >> "$(workflow job-may-fail)"
expect_fail "$work/job-may-fail" 'tooling/check-c.sh is not run'

# A longer file name or another directory is not the gate.
make_tree name-continues
python3 - "$(workflow name-continues)" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("./tooling/check-a.sh", "./tooling/check-a.sh.disabled"))
PY
expect_fail "$work/name-continues" 'tooling/check-a.sh is not run'

make_tree other-directory
python3 - "$(workflow other-directory)" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("./tooling/check-a.sh", "vendor/tooling/check-a.sh"))
PY
expect_fail "$work/other-directory" 'tooling/check-a.sh is not run'

make_tree stale-excuse-is-wired
printf '      - run: bash tooling/check-docs-match.sh\n' >> "$(workflow stale-excuse-is-wired)"
expect_fail "$work/stale-excuse-is-wired" 'tooling/check-docs-match.sh is excused'

make_tree stale-excuse-is-gone
rm "$work/stale-excuse-is-gone/tooling/check-surface-bindings.sh"
expect_fail "$work/stale-excuse-is-gone" 'tooling/check-surface-bindings.sh is excused but is not a gate script'

make_tree no-workflows
rm -r "$work/no-workflows/.github"
expect_fail "$work/no-workflows" 'no workflow files'

make_tree unparseable-workflow
printf '  bad: [unclosed\n' >> "$(workflow unparseable-workflow)"
expect_fail "$work/unparseable-workflow" 'cannot read'

# A machine without PyYAML must fail, not skip.
make_tree no-pyyaml
mkdir "$work/no-yaml-module"
printf 'raise ImportError("no yaml here")\n' > "$work/no-yaml-module/yaml.py"
expect_fail "$work/no-pyyaml" 'PyYAML is not installed' PYTHONPATH="$work/no-yaml-module"

echo "check-gates-wired-cases: pass controls and $refusals refusal cases (unwired gates and runners, comment and step-name mentions, steps and jobs that may fail or are off, a longer file name, another directory, both stale excuses, no workflows, an unparseable workflow, no PyYAML, the group-chat demo step removed) gave the expected result"
