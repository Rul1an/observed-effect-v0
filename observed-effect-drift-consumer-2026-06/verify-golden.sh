#!/usr/bin/env bash
# Golden sync-guard: the committed vectors.json / result.json must not drift from the generator, and
# the independent reproducer must re-derive everything from the bytes alone. Same discipline as the
# Evidence Pack goldens. Runs cwd-confined (the generators reject absolute / out-of-tree paths).
set -uo pipefail
cd "$(dirname "$0")" || exit 2
status=0

echo "[1/4] vectors.json == fresh emit"
if ! python3 observed_effect_consumer.py emit | diff -u vectors.json -; then
  echo "  DRIFT: vectors.json differs from a fresh emit" >&2
  status=1
fi

echo "[2/4] result.json == verify(vectors.json)"
if ! python3 observed_effect_consumer.py verify vectors.json | diff -u result.json -; then
  echo "  DRIFT: result.json differs from verify(vectors.json)" >&2
  status=1
fi

echo "[3/4] independent reproducer re-derives from bytes"
if ! python3 independent_consumer.py vectors.json >/dev/null; then
  echo "  REPRODUCER FAILED: digests/verdicts do not re-derive from vectors.json" >&2
  status=1
fi

echo "[4/4] sample-records.json == fresh emit + every sample recomputes"
if ! python3 sample_records.py emit | diff -u sample-records.json -; then
  echo "  DRIFT: sample-records.json differs from a fresh emit" >&2
  status=1
fi
if ! python3 sample_records.py verify sample-records.json >/dev/null; then
  echo "  SAMPLE FAILED: a sample envelope does not recompute against its body" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "OK: goldens in sync — generator is deterministic and the independent reproducer agrees"
fi
exit "$status"
