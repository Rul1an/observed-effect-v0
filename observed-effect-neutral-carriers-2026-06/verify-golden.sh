#!/usr/bin/env bash
# Golden sync-guard: carriers.json / result.json must not drift from the generator, and the
# independent reproducer must re-derive every address from the bytes alone. Same discipline as the
# sibling observed-effect experiments. Runs cwd-confined.
set -uo pipefail
cd "$(dirname "$0")" || exit 2
status=0

echo "[1/3] carriers.json == fresh emit"
if ! python3 neutral_carriers.py emit | diff -u carriers.json -; then
  echo "  DRIFT: carriers.json differs from a fresh emit" >&2
  status=1
fi

echo "[2/3] result.json == verify(carriers.json)"
if ! python3 neutral_carriers.py verify carriers.json | diff -u result.json -; then
  echo "  DRIFT: result.json differs from verify(carriers.json)" >&2
  status=1
fi

echo "[3/3] independent reproducer re-derives every address from bytes"
if ! python3 independent_recompute.py carriers.json >/dev/null; then
  echo "  REPRODUCER FAILED: addresses do not re-derive from carriers.json" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "OK: goldens in sync — one address per record across four carriers, reproducer agrees"
fi
exit "$status"
