#!/usr/bin/env python3
"""Single-change mutation run over the tacenta-group guards.

usage: tooling/group-mutation/mutate.py [--workers N] [--only ID,ID,...] [--out DIR]
                                        [--mutants FILE] [--test COMMAND]

`--mutants` names another mutant list in this directory (default mutants.py);
wire_mutants.py holds the mutants of the group wire codecs (decision 0149).

Each mutant in mutants.py replaces one piece of source text in a private
worktree of HEAD, the group crate's tests run, and the tree is restored. A
double mutant (the `also` key) applies partner edits too, to show that two
guards that back each other up are covered as a pair. A
mutant is KILLED when a test fails, SURVIVED when every test passes,
BUILD-ERROR when it does not compile and PATCH-FAILED when its old text no
longer occurs exactly once. The unmodified tree must pass first. The exit
status is 0 only when the baseline passes and no mutant failed to patch or
build; survivors are reported, not fatal, because some are equivalent (each is
justified in the report that accompanies a run).
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
import time

ROOT = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
).stdout.strip()
TEST = "cargo test --locked -p tacenta-group 2>&1"
FAIL = re.compile(r"^test (\S+) \.\.\. FAILED", re.M)


def load_mutants(name="mutants.py"):
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("mutants", os.path.join(here, name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ids = [m["id"] for m in module.MUTATIONS]
    assert len(ids) == len(set(ids)), "duplicate mutant id"
    return module.MUTATIONS


def sh(cmd, cwd, env=None, timeout=900):
    started = time.time()
    try:
        done = subprocess.run(
            cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout, env=env
        )
        return done.returncode, done.stdout + done.stderr, time.time() - started
    except subprocess.TimeoutExpired:
        return 124, "", time.time() - started


def run_one(worker, target, mutant, out, test=TEST):
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    path = os.path.join(worker, mutant["file"])
    subprocess.run("git checkout -- .", cwd=worker, shell=True, check=True, capture_output=True)
    text = open(path).read()
    occurrences = text.count(mutant["old"])
    record = {"id": mutant["id"], "desc": mutant["desc"], "file": mutant["file"]}
    if occurrences != 1:
        record.update(result="PATCH-FAILED", detail=f"old text occurs {occurrences} times")
        return record
    open(path, "w").write(text.replace(mutant["old"], mutant["new"]))
    # A double mutant also applies its partner edits, each to one occurrence.
    for partner_file, partner_old, partner_new in mutant.get("also", []):
        partner_path = os.path.join(worker, partner_file)
        partner_text = open(partner_path).read()
        if partner_text.count(partner_old) != 1:
            record.update(result="PATCH-FAILED", detail="partner text does not occur exactly once")
            return record
        open(partner_path, "w").write(partner_text.replace(partner_old, partner_new))
    rc, log, secs = sh(test, worker, env)
    open(os.path.join(out, mutant["id"] + ".log"), "w").write(log)
    subprocess.run("git checkout -- .", cwd=worker, shell=True, check=True, capture_output=True)
    failed = FAIL.findall(log)
    if rc == 124:
        record.update(result="TIMEOUT", killed_by=[])
    elif rc != 0 and not failed:
        crashed = "error[" not in log and "could not compile" not in log
        record.update(
            result="KILLED" if crashed else "BUILD-ERROR",
            killed_by=["test binary aborted"] if crashed else [],
            detail="" if crashed else "\n".join(l for l in log.splitlines() if l.startswith("error"))[:400],
        )
    elif failed:
        record.update(result="KILLED", killed_by=failed)
    else:
        record.update(result="SURVIVED", killed_by=[])
    record["secs"] = round(secs, 1)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--only", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--mutants", default="mutants.py")
    parser.add_argument(
        "--test",
        default=TEST,
        help="the shell command that runs the tests (default: %(default)s). "
        "`cargo test` stops at the first failing test binary, so a mutant that a "
        "unit test kills never reaches the integration tests; pass "
        "`cargo test --locked -p tacenta-group --no-fail-fast 2>&1` to see every "
        "test that fails",
    )
    args = parser.parse_args()

    mutants = load_mutants(args.mutants)
    if args.only:
        wanted = set(args.only.split(","))
        mutants = [m for m in mutants if m["id"] in wanted]
    out = args.out or tempfile.mkdtemp(prefix="group-mutation-")
    os.makedirs(out, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="group-mutation-workers-")
    workers = []
    for index in range(args.workers):
        tree = os.path.join(scratch, f"w{index}")
        subprocess.run(["git", "worktree", "add", "--detach", "-q", tree, "HEAD"], cwd=ROOT, check=True)
        workers.append((tree, os.path.join(scratch, f"target{index}")))

    try:
        rc, log, _ = sh(args.test, workers[0][0], dict(os.environ, CARGO_TARGET_DIR=workers[0][1]))
        open(os.path.join(out, "baseline.log"), "w").write(log)
        if rc != 0:
            print(
                f"the unmodified tree fails its own tests (exit {rc}); see {out}/baseline.log",
                file=sys.stderr,
            )
            return 2
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(workers)) as pool:
            def task(item):
                position, mutant = item
                worker, target = workers[position % len(workers)]
                return run_one(worker, target, mutant, out, args.test)

            # Partition by index so that each worker tree is used by one thread.
            groups = [[] for _ in workers]
            for position, mutant in enumerate(mutants):
                groups[position % len(workers)].append((position, mutant))
            futures = [
                pool.submit(lambda g=g: [task(item) for item in g]) for g in groups if g
            ]
            for future in futures:
                results.extend(future.result())
        results.sort(key=lambda r: r["id"])
        for record in results:
            print(record["id"], record["result"], record.get("killed_by", [])[:2], flush=True)
        json.dump(results, open(os.path.join(out, "results.json"), "w"), indent=1)
        totals = {}
        for record in results:
            totals[record["result"]] = totals.get(record["result"], 0) + 1
        print(json.dumps(totals), f"results in {out}")
        bad = [r for r in results if r["result"] in ("PATCH-FAILED", "BUILD-ERROR", "TIMEOUT")]
        return 1 if bad else 0
    finally:
        for tree, target in workers:
            subprocess.run(["git", "worktree", "remove", "--force", tree], cwd=ROOT, capture_output=True)
            shutil.rmtree(target, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
