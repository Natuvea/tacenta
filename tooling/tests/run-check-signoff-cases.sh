#!/usr/bin/env bash
# Hold check-signoff.sh to a passing control and to each way a commit can fail
# to carry its author's sign-off.
#
#   bash tooling/tests/run-check-signoff-cases.sh
#
# A scratch repository with a signed base commit, then one change at a time: a
# signed commit passes; an unsigned commit, an unsigned merge, a trailer that
# names someone else, a "Signed-off-by:" line that is in the message but not in
# its final paragraph, and a squash-style message (a description with no
# trailer) are each refused. An empty range passes unless --require-commits
# says an empty range is an error; a missing base is refused.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
checker="$root/tooling/check-signoff.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
repo="$work/repo"

git init -q -b main "$repo"
git -C "$repo" config user.name 'Control Author'
git -C "$repo" config user.email 'control@example.invalid'
printf 'base\n' > "$repo/file"
git -C "$repo" add file
git -C "$repo" commit -q -s -m base
git -C "$repo" tag base

expect_fail() {
  local name="$1" needle="$2" out rc
  shift 2
  set +e
  out="$(cd "$repo" && bash "$checker" "$@" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -qF -- "$needle"; then
    echo "WRONG  $name: expected refusal containing '$needle'" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
}

expect_pass() {
  local name="$1"
  shift
  local out rc
  set +e
  out="$(cd "$repo" && bash "$checker" "$@" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "WRONG  $name: expected acceptance" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
}

# A signed commit, then an empty range.
printf 'signed\n' >> "$repo/file"
git -C "$repo" commit -q -s -am signed
expect_pass signed-commit base
expect_pass empty-range HEAD
expect_fail empty-range-required 'nothing was checked' --require-commits HEAD
expect_pass require-commits-with-commits --require-commits base
expect_fail missing-base 'required base absent is missing' absent

# An unsigned commit.
printf 'unsigned\n' >> "$repo/file"
git -C "$repo" commit -q -am unsigned
expect_fail unsigned-commit 'is not signed off by its author' base
git -C "$repo" reset -q --hard HEAD^

# A commit signed off by someone other than its author.
printf 'other\n' >> "$repo/file"
git -C "$repo" commit -q -am 'other' -m 'Signed-off-by: Someone Else <else@example.invalid>'
expect_fail signed-by-someone-else 'is not signed off by its author' base
git -C "$repo" reset -q --hard HEAD^

# A sign-off line in the message that is not in the final paragraph is prose,
# not a trailer: git does not read it, and neither does the check.
printf 'prose\n' >> "$repo/file"
git -C "$repo" commit -q -am 'prose' \
  -m 'Signed-off-by: Control Author <control@example.invalid>' \
  -m 'A closing paragraph after the line.'
expect_fail signoff-not-in-final-paragraph 'is not signed off by its author' base
git -C "$repo" reset -q --hard HEAD^

# A trailer of another kind that names the author is not a sign-off.
printf 'coauthor\n' >> "$repo/file"
git -C "$repo" commit -q -am 'coauthor' \
  -m 'Co-authored-by: Control Author <control@example.invalid>'
expect_fail other-trailer-naming-the-author 'is not signed off by its author' base
git -C "$repo" reset -q --hard HEAD^

# A sign-off whose value merely contains the author's name and address is not
# the author's sign-off.
printf 'substring\n' >> "$repo/file"
git -C "$repo" commit -q -am 'substring' \
  -m 'Signed-off-by: Mr Control Author <control@example.invalid>'
expect_fail signoff-containing-the-author 'is not signed off by its author' base
git -C "$repo" reset -q --hard HEAD^

# A squash-merge commit: a title and a description, no trailer, then the same
# message ending with the author's line.
printf 'squash\n' >> "$repo/file"
git -C "$repo" commit -q -am 'Title (#1)' -m 'A description of the change, as a pull request would carry it.'
expect_fail squash-message-without-trailer 'is not signed off by its author' base
git -C "$repo" commit -q --amend -s -m 'Title (#1)' -m 'A description of the change, as a pull request would carry it.'
expect_pass squash-message-with-trailer base
git -C "$repo" reset -q --hard HEAD^

# An unsigned merge of a signed branch.
git -C "$repo" switch -q -c side base
printf 'side\n' > "$repo/side"
git -C "$repo" add side
git -C "$repo" commit -q -s -m side
git -C "$repo" switch -q main
git -C "$repo" merge -q --no-ff side -m 'unsigned merge'
expect_fail unsigned-merge 'is not signed off by its author' base

echo 'check-signoff-cases: pass controls, and refusals of an unsigned commit, a trailer by someone else, a trailer of another kind, a longer name, a line outside the final paragraph, a squash message without the trailer, an unsigned merge, an empty required range and a missing base gave the expected result'
