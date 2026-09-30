#!/usr/bin/env python3
"""Single-change mutation run over the Lean group model.

usage: tooling/group-model-mutation/mutate.py [--workers N] [--only ID,ID,...] [--out DIR] [--replay]

Each mutant in mutants.py replaces one piece of source text of
spec/Tacenta/Group.lean in a private copy of spec/. Two gates are measured on
that copy, separately, so that a kill is credited to what made it:

  BUILD    `lake build` of the whole specification fails: a theorem, an example
           or an axiom pin in Assurance.lean no longer holds. The failing
           theorems are named and the failing examples counted.
  VECTORS  with every theorem and example deleted (the mutated definitions
           only), `lake exe vectors group` no longer reproduces
           contracts/vectors/group-v1.json byte for byte. This is the CI diff
           on its own.

With --replay, a mutant whose vectors differ is also put to the Rust replay
(`cargo test -p tacenta-group --test model_vectors`) against those regenerated
vectors, in a private worktree of HEAD: what a regeneration committed without
review would face. It needs a clean tree for spec/ and the group vectors, and a
Rust toolchain. Set CARGO_TARGET_DIR to reuse a build.

A mutant is KILLED when either gate catches it, SURVIVED when neither does, and
EQUIVALENT when it survives and mutants.py gives a reason why no reachable
state tells it apart. The exit status is 0 only when the unmodified model
passes both gates, every patch applied, and no mutant survived without an
`equivalent` reason.
"""
import argparse
import concurrent.futures
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
).stdout.strip()
SPEC = os.path.join(ROOT, "spec")
VECTORS = os.path.join(ROOT, "contracts/vectors/group-v1.json")
# Everything from the first theorem on is proof or example; what precedes it is the model.
CUT = "theorem genesis_has_only_its_authority"


def load_mutants():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("mutants", os.path.join(here, "mutants.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ids = [m["id"] for m in module.MUTATIONS]
    assert len(ids) == len(set(ids)), "duplicate mutant id"
    return module.MUTATIONS


def sh(cmd, cwd, env=None):
    done = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, env=env)
    return done.returncode, done.stdout, done.stderr


def declaration_at(lines, lineno):
    """The theorem, or `example`, that encloses a 1-based line of Group.lean."""
    for index in range(lineno - 1, -1, -1):
        found = re.match(r"^(?:private )?theorem (\S+)", lines[index])
        if found:
            return found.group(1)
        if lines[index].startswith("example"):
            return "example"
    return "?"


def copy_spec(target):
    if os.path.exists(target):
        shutil.rmtree(target)
    shutil.copytree(SPEC, target, symlinks=True)


def vectors_of(tree):
    """Regenerated group vectors of a spec copy, or None when it does not build."""
    rc, out, _ = sh("lake build Tacenta.Group >/dev/null 2>&1 && lake exe vectors group", tree)
    if rc != 0 or "{" not in out:
        return None
    return out[out.index("{"):]


def run_one(mutant, scratch, committed):
    record = {"id": mutant["id"], "desc": mutant["desc"]}
    full = os.path.join(scratch, "full_" + mutant["id"])
    copy_spec(full)
    path = os.path.join(full, "Tacenta/Group.lean")
    text = open(path).read()
    if text.count(mutant["old"]) != 1:
        record.update(result="PATCH-FAILED", detail=f"old text occurs {text.count(mutant['old'])} times")
        return record
    mutated = text.replace(mutant["old"], mutant["new"])
    open(path, "w").write(mutated)

    rc, out, err = sh("lake build 2>&1", full)
    log = out + err
    lines = mutated.split("\n")
    theorems, examples, other = set(), 0, set()
    for found in re.finditer(r"error: Tacenta/(\w+)\.lean:(\d+):\d+:", log):
        if found.group(1) == "Group":
            name = declaration_at(lines, int(found.group(2)))
            if name == "example":
                examples += 1
            else:
                theorems.add(name)
        else:
            other.add(found.group(1) + ".lean")
    record["build"] = rc != 0 or "declaration uses" in log
    record["theorems"] = sorted(theorems)
    record["examples"] = examples
    record["other"] = sorted(other)

    bare = os.path.join(scratch, "bare_" + mutant["id"])
    copy_spec(bare)
    open(os.path.join(bare, "Tacenta/Group.lean"), "w").write(
        mutated[: mutated.index(CUT)] + "\nend Tacenta.Group\n"
    )
    regenerated = vectors_of(bare)
    record["vectors"] = regenerated is not None and regenerated.strip() != committed.strip()
    record["regenerated"] = regenerated if record["vectors"] else None
    record["model_builds"] = regenerated is not None
    shutil.rmtree(full, ignore_errors=True)
    shutil.rmtree(bare, ignore_errors=True)
    return record


def replay(records, out):
    """Put each mutant whose vectors differ to the Rust replay, in a worktree of HEAD."""
    tree = tempfile.mkdtemp(prefix="group-model-replay-")
    os.rmdir(tree)
    subprocess.run(["git", "worktree", "add", "--detach", "-q", tree, "HEAD"], cwd=ROOT, check=True)
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(tree, "target")
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    test = "cargo test --locked -p tacenta-group --test model_vectors 2>&1"
    vectors = os.path.join(tree, "contracts/vectors/group-v1.json")
    original = open(vectors).read()
    try:
        if original.strip() != open(VECTORS).read().strip():
            print("the working tree's group vectors are not those of HEAD; commit or stash first", file=sys.stderr)
            return False
        rc, log, _ = sh(test, tree, env)
        if rc != 0:
            print("the unmodified replay fails; see the log under", out, file=sys.stderr)
            open(os.path.join(out, "replay-baseline.log"), "w").write(log)
            return False
        for record in records:
            if not record.get("regenerated"):
                continue
            open(vectors, "w").write(record["regenerated"])
            rc, log, _ = sh(test, tree, env)
            record["replay"] = rc != 0
            said = [l.strip() for l in log.splitlines() if "assertion" in l]
            record["replay_says"] = said[0] if said else ""
    finally:
        open(vectors, "w").write(original)
        subprocess.run(["git", "worktree", "remove", "--force", tree], cwd=ROOT, check=False)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--only", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()

    mutants = load_mutants()
    if args.only:
        wanted = set(args.only.split(","))
        mutants = [m for m in mutants if m["id"] in wanted]
    out = args.out or tempfile.mkdtemp(prefix="group-model-mutation-")
    os.makedirs(out, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="group-model-workers-")
    committed = open(VECTORS).read()

    baseline = os.path.join(scratch, "baseline")
    copy_spec(baseline)
    rc, log, err = sh("lake build 2>&1", baseline)
    regenerated = vectors_of(baseline) if rc == 0 else None
    if rc != 0 or "declaration uses" in log or regenerated is None or regenerated.strip() != committed.strip():
        print("the unmodified model fails its own gates (build, or vectors differ from the committed file)", file=sys.stderr)
        open(os.path.join(out, "baseline.log"), "w").write(log + err)
        return 2
    shutil.rmtree(baseline, ignore_errors=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(lambda m: run_one(m, scratch, committed), mutants))
    shutil.rmtree(scratch, ignore_errors=True)
    if args.replay and not replay(records, out):
        return 2

    by_id = {m["id"]: m for m in mutants}
    problems = 0
    for record in records:
        mutant = by_id[record["id"]]
        if record.get("result") == "PATCH-FAILED":
            problems += 1
        elif not record["model_builds"] and not record["build"]:
            record["result"] = "BUILD-ERROR"
            problems += 1
        elif record["build"] or record["vectors"]:
            record["result"] = "KILLED"
        elif mutant.get("equivalent"):
            record["result"] = "EQUIVALENT"
            record["why"] = mutant["equivalent"]
        else:
            record["result"] = "SURVIVED"
            problems += 1
        record.pop("regenerated", None)
    json.dump(records, open(os.path.join(out, "results.json"), "w"), indent=1)

    for record in records:
        gates = []
        if record.get("build"):
            named = ",".join(record["theorems"]) or "-"
            gates.append(f"build (theorems: {named}; examples: {record['examples']})")
        if record.get("vectors"):
            gates.append("vectors")
        if "replay" in record:
            gates.append("replay " + ("fails" if record["replay"] else "passes"))
        print(record["id"], record["result"], "; ".join(gates), "|", record["desc"])
    killed = sum(1 for r in records if r["result"] == "KILLED")
    print(f"{killed} of {len(records)} killed;",
          sum(1 for r in records if r["result"] == "EQUIVALENT"), "equivalent;",
          sum(1 for r in records if r["result"] == "SURVIVED"), "survived;",
          sum(1 for r in records if r["result"] in ("PATCH-FAILED", "BUILD-ERROR")), "failed to patch or build")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
