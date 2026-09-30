#!/usr/bin/env bash
# Hold the vector-floor checker to a passing control and to each way a vector
# file can come to hold nothing, or less than it did.
#
#   bash tooling/tests/run-check-vectors-cases.sh
#
# Each case is a copy of the real checker and the real vector files with one
# change: a zero-byte file, a whitespace-only file, a file cut off mid-way, a
# top-level array, a repeated key, a wrong format name, a missing or empty
# case list, a list cut to one case or below its floor, a case that is not an
# object or lacks a field, a group trace with no steps, a file whose every
# trace is empty, a file that lost every case of one kind, a file whose cases
# were hollowed out, a file with no floor, and a floor with no file.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

make_case() {
  local dst="$work/$1"
  mkdir -p "$dst/tooling" "$dst/contracts/vectors"
  cp "$root/tooling/check-vectors.py" "$dst/tooling/check-vectors.py"
  cp "$root"/contracts/vectors/*.json "$dst/contracts/vectors/"
}

# edit CASE FILE 'python statement'; the statement changes `data`.
edit() {
  python3 - "$work/$1/contracts/vectors/$2" "$3" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
exec(sys.argv[2])
path.write_text(json.dumps(data, indent=1) + "\n")
PY
}

expect_fail() {
  local name="$1" expect="$2" out rc
  set +e
  out="$(python3 "$work/$name/tooling/check-vectors.py" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "WRONG  $name: expected refusal ($expect), was accepted" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -qF -- "$expect"; then
    echo "WRONG  $name: refused, but not for '$expect':" >&2
    printf '  %s\n' "$out" >&2
    return 1
  fi
}

refusals=0
refuse() {
  expect_fail "$1" "$2"
  refusals=$((refusals + 1))
}

make_case pass
python3 "$work/pass/tooling/check-vectors.py" >/dev/null

make_case zero-bytes
: > "$work/zero-bytes/contracts/vectors/envelope-v1.json"
refuse zero-bytes 'envelope-v1.json: the file is empty'

make_case whitespace-only
printf ' \n\n' > "$work/whitespace-only/contracts/vectors/user-v1.json"
refuse whitespace-only 'user-v1.json: the file is empty'

make_case truncated
head -c 200 "$root/contracts/vectors/session-v1.json" > "$work/truncated/contracts/vectors/session-v1.json"
refuse truncated 'session-v1.json: not valid JSON'

make_case top-level-array
edit top-level-array stream-v1.json 'data = [data]'
refuse top-level-array 'stream-v1.json: the top level is not an object'

make_case repeated-key
python3 - "$work/repeated-key/contracts/vectors/envelope-v1.json" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace('"vectors": [', '"vectors": [], "vectors": [', 1))
PY
refuse repeated-key "envelope-v1.json: not valid JSON: repeats the key 'vectors'"

make_case wrong-format
edit wrong-format group-v1.json 'data["format"] = "group-v2"'
refuse wrong-format "group-v1.json: format is 'group-v2'"

make_case list-missing
edit list-missing session-v1.json 'del data["traces"]'
refuse list-missing 'session-v1.json: `traces` is missing or not a list'

make_case list-not-a-list
edit list-not-a-list stream-v1.json 'data["streams"] = {}'
refuse list-not-a-list 'stream-v1.json: `streams` is missing or not a list'

make_case list-empty
edit list-empty envelope-v1.json 'data["vectors"] = []'
refuse list-empty 'envelope-v1.json: 0 case(s) in `vectors`, the floor is 5'

make_case cut-to-one
edit cut-to-one user-v1.json 'data["traces"] = data["traces"][:1]'
refuse cut-to-one 'user-v1.json: 1 case(s) in `traces`, the floor is 4'

make_case one-below-the-floor
edit one-below-the-floor group-v1.json 'data["traces"] = data["traces"][:-1]'
refuse one-below-the-floor 'group-v1.json: 4 case(s) in `traces`, the floor is 5'

make_case case-not-an-object
edit case-not-an-object stream-v1.json 'data["streams"][2] = "aa"'
refuse case-not-an-object 'stream-v1.json: streams[2] is not an object'

make_case case-lacks-a-field
edit case-lacks-a-field envelope-v1.json 'del data["vectors"][0]["encoded"]'
refuse case-lacks-a-field 'envelope-v1.json: vectors[0] lacks encoded'

make_case group-trace-without-steps
edit group-trace-without-steps group-v1.json 'data["traces"][0]["steps"] = []'
refuse group-trace-without-steps 'group-v1.json: traces[0] has an empty `steps`'

make_case every-trace-empty
edit every-trace-empty session-v1.json '
for t in data["traces"]:
    t["ops"] = []'
refuse every-trace-empty 'session-v1.json: no case has a non-empty `ops`'

make_case every-stream-empty
edit every-stream-empty stream-v1.json '
for s in data["streams"]:
    s["envelopes"] = []'
refuse every-stream-empty 'stream-v1.json: no case has a non-empty `envelopes`'

make_case kind-lost
edit kind-lost envelope-v1.json '
for v in data["vectors"]:
    if v["kind"] == "receipt":
        v["kind"] = "dm"'
refuse kind-lost "envelope-v1.json: 0 case(s) of kind 'receipt', the floor is 1"

make_case hollowed-out
edit hollowed-out group-v1.json '
for t in data["traces"]:
    t["steps"] = t["steps"][:1]'
refuse hollowed-out 'group-v1.json: 5 `steps` item(s) in all, the floor is 63'

make_case unlisted-file
cp "$root/contracts/vectors/user-v1.json" "$work/unlisted-file/contracts/vectors/new-v1.json"
refuse unlisted-file 'new-v1.json: no floor in tooling/check-vectors.py'

make_case listed-file-missing
rm "$work/listed-file-missing/contracts/vectors/stream-v1.json"
refuse listed-file-missing 'stream-v1.json: has a floor but the file is not in'

make_case directory-missing
rm -r "$work/directory-missing/contracts"
refuse directory-missing 'cannot list'

echo "check-vectors-cases: pass case and $refusals refusal cases gave the expected result"
