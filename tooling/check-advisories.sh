#!/usr/bin/env bash
# Fail on a known-vulnerable dependency, and keep every exception honest.
#
# A check nobody runs reports whatever the last person to look happened to
# see, so this one runs on every push.
#
# **The exception this file exists to hold.** `cargo audit` reports
# RUSTSEC-2023-0071 against `rsa 0.9.10` -- the Marvin attack, a timing side
# channel, medium severity, with no fixed upgrade available. The reasoning for
# the exception is written down rather than remembered:
#
#   `rsa` is a dependency of `sqlx-mysql`. This workspace takes `sqlx` with
#   `default-features = false` and only the `postgres` driver, so `sqlx-mysql`
#   is never compiled and `rsa` is a Cargo.lock entry rather than shipped code.
#   `cargo audit` reads the lockfile, which lists everything that *could* be
#   enabled, so it sees the crate and cannot see that nothing selects it.
#
# That reasoning is one feature flag away from being false, so it is not left
# as a comment: the check below proves the premise before honouring the
# exception. If anything ever pulls `sqlx-mysql` into the real build graph,
# the ignore stops being justified and this fails.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "advisories: cargo-audit not installed, skipping"
  echo "advisories: install with 'cargo install cargo-audit' -- this check did NOT run"
  exit 0
fi

# --- The premise behind the RUSTSEC-2023-0071 ignore ------------------------
# `cargo tree` resolves what actually builds, unlike the lockfile.
#
# **`--all-features` is load-bearing.** `sqlx` is optional, behind
# tacenta-accounts' `postgres` feature, so a plain `cargo tree -e normal`
# contains no `sqlx` at all and the grep could never match. Under
# `--all-features` the tree carries `sqlx-core` and still no `sqlx-mysql`,
# which is the statement worth making: not "nothing selects the MySQL driver
# today" but "nothing here can select it".
echo "advisories: checking that sqlx-mysql is not in the build graph"
if cargo tree -e normal --all-features 2>/dev/null | grep -q "sqlx-mysql"; then
  echo "" >&2
  echo "ERROR: sqlx-mysql is now in the build graph." >&2
  echo "" >&2
  echo "The ignore of RUSTSEC-2023-0071 in .cargo/audit.toml rests on this" >&2
  echo "crate never being compiled: it is what pulls in \`rsa\`, which carries" >&2
  echo "a key-recovery timing side channel with no fixed upgrade." >&2
  echo "" >&2
  echo "Either drop the MySQL driver again, or remove the ignore and deal with" >&2
  echo "the advisory on its merits. Do not do neither." >&2
  echo "" >&2
  exit 1
fi

echo "advisories: cargo audit"
cargo audit
