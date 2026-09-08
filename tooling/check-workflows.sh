#!/usr/bin/env bash
# Reject a workflow file that GitHub cannot parse.
#
# A workflow that does not parse runs nothing: the run fails in zero seconds,
# and neither the run list nor the commit status distinguishes that from a
# real break. A trailing colon in an unquoted YAML scalar is one way to get
# there.
#
# The check cannot live inside the workflow it protects: if the file does not
# parse, nothing in it runs, including this. So it belongs in the pre-push hook,
# where it fails on the machine that wrote the mistake.
#
# Scope is deliberately narrow. This is a parse check and a few invariants, not
# a schema validator. `actionlint` does the fuller job and is worth adding when
# it can be pinned by digest.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

dir=".github/workflows"
[ -d "$dir" ] || { echo "check-workflows: no $dir, nothing to do"; exit 0; }

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-workflows: python3 not found, skipping" >&2
  exit 0
fi

python3 - "$dir" <<'PY'
import re
import sys, os, glob
try:
    import yaml
except ImportError:
    print("check-workflows: pyyaml not installed, skipping", file=sys.stderr)
    sys.exit(0)

bad = 0
files = sorted(glob.glob(os.path.join(sys.argv[1], "*.yml")) +
               glob.glob(os.path.join(sys.argv[1], "*.yaml")))
if not files:
    print("check-workflows: no workflow files found")
    sys.exit(0)

for f in files:
    try:
        doc = yaml.safe_load(open(f))
    except yaml.YAMLError as e:
        print("check-workflows: %s does not parse as YAML" % f, file=sys.stderr)
        print("  %s" % str(e).replace("\n", "\n  "), file=sys.stderr)
        bad = 1
        continue

    if not isinstance(doc, dict):
        print("check-workflows: %s is not a mapping" % f, file=sys.stderr)
        bad = 1
        continue

    # `on:` is the YAML 1.1 boolean True once parsed, which is a trap worth
    # naming rather than rediscovering.
    if True not in doc and "on" not in doc:
        print("check-workflows: %s has no trigger (`on:`)" % f, file=sys.stderr)
        bad = 1

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        print("check-workflows: %s defines no jobs" % f, file=sys.stderr)
        bad = 1
        continue

    for name, job in jobs.items():
        if not isinstance(job, dict):
            print("check-workflows: %s job '%s' is not a mapping" % (f, name), file=sys.stderr)
            bad = 1
            continue
        if "runs-on" not in job and "uses" not in job:
            print("check-workflows: %s job '%s' has neither runs-on nor uses"
                  % (f, name), file=sys.stderr)
            bad = 1

        # Third-party actions must be pinned by commit digest, not by tag.
        # A tag is movable: whoever controls the action repository can change
        # what `@v4` means after review and before the next run, and a
        # workflow runs with credentials. A machine check keeps every
        # workflow at the same standard.
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not isinstance(uses, str) or "@" not in uses:
                continue
            ref = uses.rsplit("@", 1)[1]
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                print("check-workflows: %s job '%s' uses '%s' -- pin by 40-char "
                      "commit digest, with the tag in a trailing comment"
                      % (f, name, uses), file=sys.stderr)
                bad = 1

print("check-workflows: %d workflow file(s) parse" % len(files))
sys.exit(bad)
PY
