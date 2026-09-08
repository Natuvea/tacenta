#!/usr/bin/env bash
# One version, everywhere it is declared, and the tag that ships it.
#
# The tree carries the version the next release tag will have: the
# workspace's Cargo.toml (every crate takes it), sdk/typescript/package.json
# and its lockfile, and bindings/android/lib/build.gradle.kts. This refuses a
# tree where they disagree, and with --tag vX.Y.Z (the release workflows on a
# tag push) refuses a tag whose name is not that version or whose section is
# missing from CHANGELOG.md, so a release cannot ship packages that call
# themselves something else (decision 0090). The Swift package has no version of its own: SwiftPM takes the
# git tag.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

want=$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
[ -n "$want" ] || { echo "check-versions: no version under [workspace.package] in Cargo.toml" >&2; exit 1; }

failed=0
say() { echo "check-versions: $*" >&2; failed=1; }

npm=$(python3 -c 'import json; print(json.load(open("sdk/typescript/package.json"))["version"])')
[ "$npm" = "$want" ] || say "sdk/typescript/package.json says $npm, Cargo.toml says $want"
lock=$(python3 -c 'import json; print(json.load(open("sdk/typescript/package-lock.json"))["version"])')
[ "$lock" = "$want" ] || say "sdk/typescript/package-lock.json says $lock, Cargo.toml says $want"
aar=$(sed -n 's/^version = "\(.*\)"/\1/p' bindings/android/lib/build.gradle.kts | head -1)
[ "$aar" = "$want" ] || say "bindings/android/lib/build.gradle.kts says ${aar:-nothing}, Cargo.toml says $want"

if [ "${1:-}" = "--tag" ]; then
  tag=${2:?tag name}
  [ "$tag" = "v$want" ] || say "tag $tag but the tree is version $want; bump the version (and CHANGELOG.md) before tagging"
  grep -q "^## $tag " CHANGELOG.md || say "CHANGELOG.md has no '## $tag ' section"
fi

[ "$failed" = 0 ] || exit 1
echo "check-versions: the tree is version $want everywhere it is declared${2:+, and $2 matches}"
