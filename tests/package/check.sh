#!/usr/bin/env bash
# Build the connectsensors sdist and wheel (the wheel from the sdist, as PyPI users
# get it), install the wheel into a clean Python 3.13 venv, run the smoke test from
# outside the checkout and type-check it against the installed package.
# Usage: tests/package/check.sh [dist dir, new or empty]   (needs uv)
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dist=${1:-$work/dist}
if [ -n "$(ls -A "$dist" 2>/dev/null)" ]; then echo "$dist is not empty" >&2; exit 1; fi
uv build -q --out-dir "$dist" "$repo"
ls "$dist"
uv venv -q --python 3.13 "$work/venv"
uv pip install -q --python "$work/venv/bin/python" "$dist"/connectsensors-*.whl
cd "$work"
"$work/venv/bin/python" -I "$repo/tests/package/smoke_test.py" "$repo"
uv pip install -q --python "$work/venv/bin/python" mypy
"$work/venv/bin/python" -m mypy --strict --no-incremental --cache-dir /dev/null "$repo/tests/package/smoke_test.py"
