#!/usr/bin/env python3
"""Independent reproducer for the neutral-carriers golden.

Reads ``carriers.json`` ALONE and re-derives the content address from each of the four carriers with
separate code that does NOT import ``neutral_carriers.py``. It re-implements RFC 8785 JCS and pulls
the observed-effect body out of every carrier its own way (decode the DSSE payload, follow the
SEP-1913 reference slot, decode the SCITT payload), then checks that all four addresses agree with
each other and with the committed ``expected_digest``. Two implementations, no shared runner: if the
addresses agree, the record's identity is carrier-independent by recomputation, not by assertion.

Usage: python3 independent_recompute.py [carriers.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

PREDICATE_TYPE = "https://assay.dev/predicates/observed-effect/v0"


def _path(arg: str) -> str:
    if not arg or not arg.strip():
        raise SystemExit("refusing an empty carriers path")
    norm = arg.replace("\\", "/")
    if os.path.isabs(arg) or os.path.isabs(norm):
        raise SystemExit(f"refusing an absolute path: {arg!r}")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise SystemExit(f"refusing a path with parent traversal: {arg!r}")
    base = os.path.realpath(os.getcwd())
    full = os.path.realpath(os.path.join(base, *parts))
    if full != base and not full.startswith(base + os.sep):
        raise SystemExit(f"refusing a path outside the working directory: {arg!r}")
    if not full.endswith(".json") or not os.path.isfile(full):
        raise SystemExit(f"refusing a non-json or non-file path: {arg!r}")
    return full


# Independent RFC 8785 JCS over the float-free value space these records use.
def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def addr(body) -> str:
    return "sha256:" + hashlib.sha256(canon(body)).hexdigest()


def body_from_standalone(c):
    return c["body"]


def body_from_intoto(c):
    st = json.loads(base64.b64decode(c["dsse"]["payload"]))
    assert st["predicateType"] == PREDICATE_TYPE, "predicateType drift"
    return st["predicate"]


def body_from_sep1913(c):
    ann = c["_meta"]["dev.assay/trust-annotations"]
    ref = ann["evidenceRef"]["ref"]
    return c["resolved_evidence"][ref]


def body_from_scitt(c):
    return json.loads(base64.b64decode(c["payload_b64"]))


PULL = {
    "standalone-jcs": body_from_standalone,
    "in-toto-dsse-statement": body_from_intoto,
    "mcp-sep1913-evidenceRef": body_from_sep1913,
    "scitt-cose-statement": body_from_scitt,
}


def main(argv) -> int:
    path = _path(argv[0]) if argv else _path("carriers.json")
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    failures = 0
    for rec in doc["records"]:
        expected = rec["expected_digest"]
        seen = {}
        for name, carrier in rec["carriers"].items():
            if name not in PULL:
                print(f"  ! {rec['id']}: unknown carrier {name}")
                failures += 1
                continue
            got = addr(PULL[name](carrier))
            seen[name] = got
            if got != expected:
                print(f"  ! {rec['id']} / {name}: {got} != {expected}")
                failures += 1
        if len(set(seen.values())) == 1 and next(iter(seen.values())) == expected:
            print(f"  OK {rec['id']}: 4 carriers -> {expected}")
        else:
            print(f"  ! {rec['id']}: carriers disagree {seen}")
            failures += 1

    if failures:
        print(f"FAIL: {failures} mismatch(es) — the record is NOT carrier-independent")
        return 1
    print(f"OK: {len(doc['records'])} records, every carrier recomputes to the one frozen address")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
