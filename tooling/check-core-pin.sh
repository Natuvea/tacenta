#!/usr/bin/env bash
# Refuse a tacenta-core pin that is not a commit on tacenta-core `main`.
#
#   check-core-pin.sh
#
# The product takes its cryptographic core as a git dependency pinned by
# revision (`open-tacenta` in Cargo.toml), and Cargo.lock repeats that
# revision. Cargo resolves any commit that GitHub will serve for the
# repository, and GitHub serves more than the branches: the head of every pull
# request, open or closed, and any commit in the repository's fork network.
# Nothing in a revision's spelling says which of those it is, so a bare SHA
# proves nothing about where the code came from or whether it was ever merged
# and checked on `main`.
#
# This checks, in order, and stops at the first failure:
#
#   1. Cargo.toml has exactly one `open-tacenta` dependency; its `git` is
#      https://github.com/Natuvea/tacenta-core; it is pinned by `rev`, not by
#      `branch` or `tag`; and the `rev` is a full 40-digit lowercase SHA.
#   2. No manifest carries a `[patch]`, `[replace]` or `[source]` section, and
#      there is no cargo config beyond audit.toml, since each can redirect a
#      dependency to code this check does not look at.
#   3. Every `git+` source in Cargo.lock is exactly that revision of that
#      repository (at least one is present), and every `registry+` source is
#      crates.io. Any other source kind, git repository or registry fails.
#   4. GitHub's compare endpoint says the revision is an ancestor of `main`
#      (status `behind` or `identical`, and the merge base is the revision
#      itself). A commit that exists only as a pull request head, or in a fork,
#      is `ahead` or `diverged`.
#
# Step 4 needs the network. It fails closed: if the API cannot be reached, or
# answers with anything this script does not recognise, the check fails with
# the reason. It never passes on a guess.
#
# Authentication: reading a public repository needs none. In CI the job passes
# `GITHUB_TOKEN` (read-only) so the request is not counted against the runner
# pool's anonymous rate limit; `GH_TOKEN` is read too. The token is sent only
# to https://api.github.com.
#
# A pin bump therefore needs the core change to be on core `main` first. That
# is the rule, not an obstacle to work around: there is no override switch.
#
# What this does not establish: that the commit is good, only that it is on
# the branch core protects. It does not defend against a change that edits this
# script, or the workflow that runs it, in the same change as the pin (see
# docs/reproduce.md, "What these gates cannot defend against").
#
# Environment (for the case runner, tooling/tests/run-check-core-pin-cases.sh):
#   CHECK_CORE_PIN_API          API base URL   (default https://api.github.com)
#   CHECK_CORE_PIN_RETRY_DELAY  seconds between attempts (default 2)
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-core-pin: python3 not found; refusing to pass without checking the pin" >&2
  exit 1
fi

exec python3 - "$root" <<'PY'
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = sys.argv[1]
REPO = "Natuvea/tacenta-core"
URL = "https://github.com/" + REPO
BRANCH = "main"
DEFAULT_API = "https://api.github.com"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
API = os.environ.get("CHECK_CORE_PIN_API", DEFAULT_API).rstrip("/")
RETRY_DELAY = float(os.environ.get("CHECK_CORE_PIN_RETRY_DELAY", "2"))
ATTEMPTS = 3


def fail(message):
    print("check-core-pin: " + message, file=sys.stderr)
    sys.exit(1)


def read(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
            return handle.read()
    except OSError as error:
        fail("cannot read %s: %s" % (path, error))


# 1. The dependency line in Cargo.toml.
manifest = read("Cargo.toml")
lines = [
    line for line in manifest.splitlines()
    if re.match(r"\s*open-tacenta\s*=", line)
]
if len(lines) != 1:
    fail("Cargo.toml must declare `open-tacenta` exactly once; found %d line(s)"
         % len(lines))
line = lines[0]


def field(name):
    match = re.search(r'[{,]\s*%s\s*=\s*"([^"]*)"' % name, line)
    return match.group(1) if match else None


git = field("git")
rev = field("rev")
if git != URL:
    fail("open-tacenta must be a git dependency on %s; Cargo.toml says %r"
         % (URL, git))
for other in ("branch", "tag", "path", "version"):
    if field(other) is not None:
        fail("open-tacenta is pinned by `rev` alone; Cargo.toml also sets `%s`"
             % other)
if rev is None:
    fail("open-tacenta has no `rev`; pin it to a full commit SHA")
if not re.fullmatch(r"[0-9a-f]{40}", rev):
    fail("open-tacenta rev %r is not a full 40-digit lowercase SHA" % rev)

# 2. Anything that can redirect a dependency around the pin.
manifests = []
for base, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs
               if d not in ("target", "node_modules", ".git", ".lake", "dist")]
    if "Cargo.toml" in files:
        manifests.append(os.path.join(base, "Cargo.toml"))
for path in sorted(manifests):
    with open(path, encoding="utf-8") as handle:
        for number, text in enumerate(handle, 1):
            if re.match(r"\s*\[\s*(patch|replace|source)\b", text):
                fail("%s:%d has a %s section, which can redirect a dependency "
                     "around the pin" % (os.path.relpath(path, ROOT), number,
                                         text.strip()))
cargo_config = [
    name for pattern in ("config", "config.toml")
    for name in glob.glob(os.path.join(ROOT, ".cargo", pattern))
]
if cargo_config:
    fail(".cargo/%s exists; cargo config can redirect sources, so this check "
         "does not accept it" % os.path.basename(cargo_config[0]))

# 3. Cargo.lock: one git source, and it is the pin.
expected = "git+%s?rev=%s#%s" % (URL, rev, rev)
lock = read("Cargo.lock")
sources = re.findall(r'^source = "([^"]*)"$', lock, flags=re.M)
pinned = 0
stray = []
for source in sources:
    if source == expected:
        pinned += 1
    elif source != CRATES_IO:
        stray.append(source)
if stray:
    unique = sorted(set(stray))
    fail("Cargo.lock has %d source(s) other than crates.io and the pin, e.g. %s"
         % (len(stray), ", ".join(unique[:3])))
if pinned == 0:
    fail("Cargo.lock has no package from %s at %s; the lock and Cargo.toml "
         "disagree" % (URL, rev))

# 4. The revision is an ancestor of main.
endpoint = "%s/repos/%s/compare/%s...%s?per_page=1" % (API, REPO, BRANCH, rev)
headers = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "tacenta-check-core-pin",
}
token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
if token and API == DEFAULT_API:
    headers["Authorization"] = "Bearer " + token


def unreachable(reason):
    fail("could not reach %s to check %s against %s %s (%s); refusing to pass "
         "without verifying the pin. Re-run when the network is available."
         % (API, rev[:12], REPO, BRANCH, reason))


body = None
last = "no attempt made"
for attempt in range(ATTEMPTS):
    if attempt:
        time.sleep(RETRY_DELAY)
    try:
        request = urllib.request.Request(endpoint, headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
        break
    except urllib.error.HTTPError as error:
        if error.code == 404:
            fail("GitHub has no commit %s in %s or its fork network; the pin "
                 "is not on %s" % (rev, REPO, BRANCH))
        if error.code in (401, 403, 429):
            last = "HTTP %d (rate limited or not authorised; set GITHUB_TOKEN)" % error.code
        else:
            last = "HTTP %d" % error.code
    except (urllib.error.URLError, OSError, ValueError) as error:
        last = str(getattr(error, "reason", error))
if body is None:
    unreachable(last)

try:
    answer = json.loads(body)
    status = answer["status"]
    merge_base = answer["merge_base_commit"]["sha"]
except (ValueError, KeyError, TypeError):
    fail("the compare answer for %s was not the shape GitHub documents; "
         "refusing to pass on it" % rev)

if status in ("behind", "identical") and merge_base == rev:
    print("check-core-pin: open-tacenta rev %s is on %s %s (%s), and "
          "Cargo.lock has %d package(s) at it and no other git source"
          % (rev[:12], REPO, BRANCH, status, pinned))
    sys.exit(0)
if status in ("ahead", "diverged"):
    fail("rev %s is not on %s %s (compare says %s). It is a commit main does "
         "not contain, such as an unmerged pull request head or a fork "
         "commit. Merge the core change first, then pin the merged commit."
         % (rev, REPO, BRANCH, status))
fail("rev %s: compare answered status %r with merge base %r, which is not "
     "'behind'/'identical' at the revision itself; refusing to pass"
     % (rev, status, merge_base))
PY
