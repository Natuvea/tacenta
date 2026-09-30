#!/usr/bin/env bash
# Refuse a gate script that no workflow step runs.
#
#   check-gates-wired.sh
#
# A check that CI does not run is documentation: it can go red on a
# contributor's machine and never anywhere else, and a reader of the repository
# sees a gate where there is none. tooling/run-group-chat-demo.sh was one for a
# long time, and docs/reproduce.md said so in a sentence. This makes the
# absence a failure instead of a sentence.
#
# The gates are every tooling/check-* script, tooling/run-*demo* script and
# tooling/tests/run-*-cases.sh runner. Each must be named in the `run:` of a
# step in a workflow under .github/workflows, where the step
#   - is not marked `continue-on-error`, and is not switched off by an `if:`
#     that is the literal false, and
#   - sits in a job that is not `continue-on-error` and not switched off.
# A gate that CI cannot run is listed in EXCUSED below, with the reason. An
# excuse for a script that does not exist, or for one a workflow does run, is
# also a failure, so the list cannot go stale.
#
# What this does not establish: that the step runs on the events that matter,
# that its result decides anything, or that the script does what its name says.
# It checks that the step exists. It cannot defend against a change that
# removes the step and edits the list here in the same commit.
#
# Fails closed: without python3 and PyYAML it fails, where check-workflows.sh
# skips, because a skipped check here would pass the very case it exists for.
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-gates-wired: python3 not found; refusing to pass without checking" >&2
  exit 1
fi

exec python3 - "$root" <<'PY'
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("check-gates-wired: PyYAML is not installed; refusing to pass without "
          "reading the workflows", file=sys.stderr)
    sys.exit(1)

ROOT = sys.argv[1]

# script (relative to the repository root) -> why no public workflow runs it.
EXCUSED = {
    "tooling/check-docs-match.sh":
        "resolves citations across this tree and a tacenta-core checkout beside "
        "it; the pre-push hook and the release pipeline run it",
    "tooling/check-surface-bindings.sh":
        "reads the Swift and Kotlin the UniFFI generator writes, which only the "
        "release pipeline builds",
}


def literal_false(value):
    return value is False or (
        isinstance(value, str)
        and re.fullmatch(r"\s*(\$\{\{\s*false\s*\}\}|false)\s*", value, re.I)
    )


def off(node):
    """A job or step that is allowed to fail, or is switched off."""
    if not isinstance(node, dict):
        return True
    coe = node.get("continue-on-error")
    if coe is True or (isinstance(coe, str) and coe.strip().lower() in ("true", "${{ true }}")):
        return True
    return "if" in node and literal_false(node["if"])


def gates():
    found = set()
    for pattern in ("tooling/check-*", "tooling/run-*demo*",
                    "tooling/tests/run-*-cases.sh"):
        for path in glob.glob(os.path.join(ROOT, pattern)):
            if os.path.isfile(path):
                found.add(os.path.relpath(path, ROOT))
    return found


def wired_commands():
    """Every `run:` text of a step that is in force."""
    commands = []
    files = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml")) +
                   glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yaml")))
    if not files:
        print("check-gates-wired: no workflow files under .github/workflows",
              file=sys.stderr)
        sys.exit(1)
    for path in files:
        try:
            with open(path, encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError) as error:
            print("check-gates-wired: cannot read %s: %s" % (path, error),
                  file=sys.stderr)
            sys.exit(1)
        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if off(job):
                continue
            for step in job.get("steps") or []:
                if off(step):
                    continue
                run = step.get("run")
                if isinstance(run, str):
                    commands.append(run)
    return commands


def named_in(script, commands):
    """The script's path, as a whole word: not the tail of another path, not the
    head of a longer file name. `./tooling/x` is `tooling/x`."""
    pattern = re.compile(r"(?<![\w./-])" + re.escape(script) + r"(?![\w.-])")
    return any(pattern.search(command.replace("./tooling/", "tooling/"))
               for command in commands)


problems = []
present = gates()
commands = wired_commands()

for script in sorted(present):
    wired = named_in(script, commands)
    if script in EXCUSED:
        if wired:
            problems.append("%s is excused (%s) but a workflow runs it; remove "
                            "the excuse" % (script, EXCUSED[script]))
    elif not wired:
        problems.append("%s is not run by any workflow step; wire it into "
                        ".github/workflows/ci.yml, or excuse it in "
                        "tooling/check-gates-wired.sh with the reason" % script)
for script in sorted(EXCUSED):
    if script not in present:
        problems.append("%s is excused but is not a gate script in the tree; "
                        "remove the excuse" % script)

if problems:
    for problem in problems:
        print("check-gates-wired: " + problem, file=sys.stderr)
    sys.exit(1)

excused = sorted(EXCUSED)
print("check-gates-wired: %d gate script(s), each run by a workflow step%s"
      % (len(present) - len(excused),
         "; not run by a public workflow: " + ", ".join(excused) if excused else ""))
PY
