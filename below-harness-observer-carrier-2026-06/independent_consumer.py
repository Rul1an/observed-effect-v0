#!/usr/bin/env python3
"""Independent reproducer for the below-harness observer-carrier vectors.

Reads vectors.json ALONE and re-derives every carrier digest and verdict with separate code that does
NOT import observer_carrier or tetragon_adapter. Re-implements the canonicalization, the sha256
content address, and the coverage invariant, then checks each against the committed value. Agreement
means the set reproduces from the bytes alone.

Usage: python3 independent_consumer.py [vectors.json]
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

COVERAGE_VALUES = ("observed", "not_observed")
OBSERVER_MODES = ("observe", "enforce")


def _path(arg: str) -> str:
    if not arg or not arg.strip():
        raise SystemExit("refusing an empty vectors path")
    norm = arg.replace("\\", "/")
    if os.path.isabs(arg) or os.path.isabs(norm):
        raise SystemExit(f"refusing an absolute vectors path: {arg!r}")
    if any(p == ".." for p in norm.split("/")):
        raise SystemExit(f"refusing parent traversal: {arg!r}")
    base = os.path.realpath(os.getcwd())
    full = os.path.realpath(os.path.join(base, *[p for p in norm.split("/") if p not in ("", ".")]))
    if full != base and not full.startswith(base + os.sep):
        raise SystemExit(f"refusing a path outside the working directory: {arg!r}")
    if not full.endswith(".json") or not os.path.isfile(full):
        raise SystemExit(f"refusing a non-json or non-file path: {arg!r}")
    return full


def addr(record) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def verdict(record, required) -> dict:
    observer = record.get("observer")
    if not isinstance(observer, dict) or not observer.get("type"):
        return {"verdict": "invalid", "reason": "observer_type_required"}
    if observer.get("mode") and observer["mode"] not in OBSERVER_MODES:
        return {"verdict": "invalid", "reason": f"unknown_observer_mode:{observer.get('mode')}"}
    coverage = record.get("coverage")
    if not isinstance(coverage, dict):
        return {"verdict": "invalid", "reason": "coverage_required"}
    for dim, val in coverage.items():
        if val not in COVERAGE_VALUES:
            return {"verdict": "invalid", "reason": f"unknown_coverage_value:{dim}={val}"}
    for dim in required:
        if coverage.get(dim) != "observed":
            return {"verdict": "incomplete", "reason": f"required_coverage_not_observed:{dim}"}
    if record.get("divergence") or []:
        return {"verdict": "mismatch", "reason": "observed_effect_diverges_from_declared"}
    return {"verdict": "match", "reason": "observed_matched_declared_under_complete_required_coverage"}


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    doc = json.load(open(_path(path), encoding="utf-8"))
    failures = []
    for group in ("observer_coverage_cases", "tetragon_adapter_cases"):
        for c in doc.get(group, []):
            case = c["case"]
            rec = case["record"]
            if rec is None:
                # invalid carriers (e.g. malformed Tetragon) carry no record/digest; only the verdict.
                if case["verdict"]["verdict"] != "invalid":
                    failures.append(f"{c['id']}: null record but verdict {case['verdict']}")
                continue
            d = addr(rec)
            v = verdict(rec, case["required_coverage"])
            if d != case["digest"]:
                failures.append(f"{c['id']}: digest {d} != {case['digest']}")
            if v != case["verdict"]:
                failures.append(f"{c['id']}: verdict {v} != {case['verdict']}")
    print(json.dumps({"reproducer": "independent", "all_reproduced": not failures, "failures": failures},
                     indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
