#!/usr/bin/env bash
# The surface manifest and its rendered grid stay in step (decision 0090): sdk/SURFACE.md is generated from sdk/surface.json, and this gate
# refuses a tree where one was edited without the other. Each head's own test
# suite is what checks the manifest against the code, and
# check-surface-bindings.sh can check it against the generated Swift and Kotlin.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tooling/surface-grid.py --check
