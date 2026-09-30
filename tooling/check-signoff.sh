#!/usr/bin/env bash
# Refuse a change whose commits are not signed off by their authors.
#
#   check-signoff.sh [--require-commits] [BASE]   (BASE defaults to origin/main)
#
# CONTRIBUTING.md asks every commit to carry a `Signed-off-by:` trailer under
# the Developer Certificate of Origin 1.1, and says pull requests whose commits
# are not signed off cannot be merged. This is what checks it. It checks the
# commits a change adds, `BASE..HEAD`, and nothing already on BASE: the history
# on main from before this check carries no sign-off on most commits, and is
# not rewritten.
#
# What counts: every commit in the range has a `Signed-off-by:` trailer whose
# value is exactly its author, `Name <email>`. The trailer must be in the
# commit message's final paragraph, where git reads trailers; a line further up
# the message is prose and does not count. Merge commits are commits: one
# needs a trailer too, so a branch should be rebased onto its base rather than
# merged with it.
#
# --require-commits fails when the range is empty. An empty range is a fine
# thing for a person to check locally, but in CI it means the base or the head
# was wrong, and a check that ran over nothing has not passed.
#
# In CI (.github/workflows/ci.yml):
#   - a pull request is checked against its base branch, on the head commit;
#   - a push to main is checked from the commit before the push, which is what
#     makes a squash merge answer for its message. GitHub writes the squash
#     commit's message when the pull request is merged, after the pull request
#     check ran, so the merge message itself must end with the author's
#     `Signed-off-by:` line (CONTRIBUTING.md).
# A missing BASE is a missing prerequisite and fails closed.
#
# Not established: that the person named in a trailer wrote the change. The
# trailer is a statement by the author; this checks that it was made.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

require_commits=0
if [ "${1:-}" = "--require-commits" ]; then
  require_commits=1
  shift
fi

base="${1:-origin/main}"
if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
  echo "check-signoff: required base ${base} is missing; fetch it before checking" >&2
  exit 1
fi

status=0
count=0
while read -r sha; do
  [ -n "$sha" ] || continue
  count=$((count + 1))
  author=$(git show -s --format='%an <%ae>' "$sha")
  if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qxF -- "$author"; then
    printf 'check-signoff: %s is not signed off by its author, %s\n' \
      "$(git log -1 --format='%h %s' "$sha")" "$author" >&2
    status=1
  fi
done < <(git rev-list "${base}..HEAD")

if [ "$count" -eq 0 ] && [ "$require_commits" -eq 1 ]; then
  echo "check-signoff: no commits between ${base} and HEAD; the base or the head is wrong, so nothing was checked" >&2
  exit 1
fi

if [ "$status" -eq 0 ]; then
  echo "check-signoff: ${count} commit(s) on top of ${base}, each signed off by its author"
else
  echo "" >&2
  echo "check-signoff: sign off with 'git commit -s' (CONTRIBUTING.md, Developer Certificate of Origin)." >&2
  echo "  For commits already made: git rebase --signoff ${base}" >&2
  echo "  A squash-merge message needs the line too: end it with 'Signed-off-by: Name <email>'." >&2
fi
exit "$status"
