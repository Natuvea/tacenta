#!/usr/bin/env python3
"""Single-change mutation run over the Lean group model (spec/Tacenta/Group.lean).

usage: tooling/group-mutation/mutate_model.py [--workers N] [--only ID,ID,...]
                                              [--config full|no-theorems|vectors-only]

Each mutant in model_mutants.py replaces one piece of source text in a private
copy of `spec/`. The copy is then checked the way CI checks the model:

  1. `lake build` (the theorems, their axiom pins in Assurance.lean and the
     `example` traces at the end of Group.lean);
  2. `lake exe vectors group`, whose output is compared byte for byte with
     `contracts/vectors/group-v1.json` (the CI vector diff; the Rust replay in
     `crates/tacenta-group/tests/model_vectors.rs` reads that file, so a mutant
     that leaves it unchanged is also invisible to the replay).

A mutant is KILLED-BUILD when step 1 fails, KILLED-VECTORS when step 2 differs,
SURVIVED when both pass and PATCH-FAILED when its old text no longer occurs
exactly once. The unmodified copy must pass first.

--config says what is left in the copy before the mutant is applied, to show
what each layer adds:
  full          the tree as it is (default);
  no-theorems   the four theorems of Group.lean and their pins deleted;
  vectors-only  the theorems, their pins and the `example` traces deleted.

Survivors are reported, not fatal: one of the mutants is equivalent, and a
survivor is the point of the exercise. The exit status is 0 unless the baseline
fails or a mutant does not patch.
"""
import argparse
import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
).stdout.strip()
SPEC = os.path.join(ROOT, "spec")
COMMITTED = os.path.join(ROOT, "contracts", "vectors", "group-v1.json")
THEOREMS_FROM = "theorem genesis_has_only_its_authority"
TRACES_FROM = "/-! ## Fixed profile traces"
TRACES_TO = "end Tacenta.Group"
PINS_FROM = "-- Bounded group policy (decision 0137)"


def load_mutants():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("model_mutants", os.path.join(here, "model_mutants.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ids = [m["id"] for m in module.MODEL_MUTATIONS]
    assert len(ids) == len(set(ids)), "duplicate mutant id"
    return module.MODEL_MUTATIONS


def sh(cmd, cwd, timeout=600):
    done = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout)
    return done.returncode, done.stdout, done.stderr


def prepare(config, dest):
    """Copy spec/ (without build output) and cut it down to the configuration."""
    shutil.copytree(SPEC, dest, symlinks=True, ignore=shutil.ignore_patterns(".lake"))
    if config == "full":
        return
    group = os.path.join(dest, "Tacenta", "Group.lean")
    text = open(group).read()
    start, traces = text.index(THEOREMS_FROM), text.index(TRACES_FROM)
    text = text[:start] + text[traces:]
    if config == "vectors-only":
        traces, end = text.index(TRACES_FROM), text.index(TRACES_TO)
        text = text[:traces] + text[end:]
    open(group, "w").write(text)
    assurance = os.path.join(dest, "Tacenta", "Assurance.lean")
    text = open(assurance).read()
    open(assurance, "w").write(text[: text.index(PINS_FROM)])


def check(tree):
    """None when the tree builds and regenerates the committed vectors, else why not."""
    rc, out, err = sh("lake build", tree)
    if rc != 0:
        lines = [l for l in (out + err).splitlines() if "error" in l.lower()]
        return "KILLED-BUILD", (lines[0] if lines else "lake build failed")[:200]
    rc, out, err = sh("lake exe vectors group", tree)
    if rc != 0:
        return "KILLED-BUILD", "lake exe vectors group failed"
    if out != open(COMMITTED).read():
        return "KILLED-VECTORS", "regenerated group-v1.json differs from the committed file"
    return None, ""


def run_one(config, scratch, mutant):
    record = {"id": mutant["id"], "desc": mutant["desc"], "equivalent": bool(mutant.get("equivalent"))}
    tree = os.path.join(scratch, mutant["id"])
    prepare(config, tree)
    path = os.path.join(tree, "Tacenta", "Group.lean")
    text = open(path).read()
    count = text.count(mutant["old"])
    if count != 1:
        record.update(result="PATCH-FAILED", detail=f"old text occurs {count} times")
        return record
    open(path, "w").write(text.replace(mutant["old"], mutant["new"]))
    result, detail = check(tree)
    record.update(result=result or "SURVIVED", detail=detail)
    shutil.rmtree(tree, ignore_errors=True)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--only", default="")
    parser.add_argument("--config", choices=["full", "no-theorems", "vectors-only"], default="full")
    args = parser.parse_args()

    mutants = load_mutants()
    if args.only:
        wanted = set(args.only.split(","))
        mutants = [m for m in mutants if m["id"] in wanted]
    scratch = tempfile.mkdtemp(prefix="model-mutation-")
    try:
        base = os.path.join(scratch, "baseline")
        prepare(args.config, base)
        failure, detail = check(base)
        if failure:
            print(f"the unmodified {args.config} copy fails ({failure}): {detail}", file=sys.stderr)
            return 2
        shutil.rmtree(base, ignore_errors=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(lambda m: run_one(args.config, scratch, m), mutants))
        for record in results:
            note = " (equivalent)" if record["equivalent"] and record["result"] == "SURVIVED" else ""
            print(f'{record["id"]} {record["result"]}{note} | {record["desc"]}', flush=True)
        totals = {}
        for record in results:
            totals[record["result"]] = totals.get(record["result"], 0) + 1
        print(json.dumps(dict(sorted(totals.items())), sort_keys=True), f"config={args.config}")
        return 1 if any(r["result"] == "PATCH-FAILED" for r in results) else 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
