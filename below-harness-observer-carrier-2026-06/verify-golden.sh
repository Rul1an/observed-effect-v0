#!/usr/bin/env bash
# Golden sync-guard: the committed vectors.json / result.json must not drift from the generator, and
# the independent reproducer must re-derive everything from the bytes alone. Same discipline as the
# Evidence Pack goldens. Runs cwd-confined (the generators reject absolute / out-of-tree paths).
set -uo pipefail
cd "$(dirname "$0")" || exit 2
status=0

echo "[1/3] vectors.json == fresh emit"
if ! python3 observer_carrier.py emit | diff -u vectors.json -; then
  echo "  DRIFT: vectors.json differs from a fresh emit" >&2
  status=1
fi

echo "[2/3] result.json == verify(vectors.json)"
if ! python3 observer_carrier.py verify vectors.json | diff -u result.json -; then
  echo "  DRIFT: result.json differs from verify(vectors.json)" >&2
  status=1
fi

echo "[3/3] independent reproducer re-derives from bytes"
if ! python3 independent_consumer.py vectors.json >/dev/null; then
  echo "  REPRODUCER FAILED: digests/verdicts do not re-derive from vectors.json" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "OK: goldens in sync — generator is deterministic and the independent reproducer agrees"
fi
exit "$status"
