#!/usr/bin/env python3
"""Independent reproducer for the observed-effect-drift vectors.

Reads ``vectors.json`` ALONE and re-derives every committed result with separate code that does
NOT import ``observed_effect_consumer.py``. It re-implements the two canonicalization profiles
(RFC 8785 JCS, RFC 8949 sec 4.2 deterministic CBOR), the fail-closed recompute, and the
monotone-toward-caution merge, then checks each recomputed result against the committed one.
Agreement means the set reproduces from the bytes alone, two implementations and no shared runner.

Usage: python3 independent_consumer.py [vectors.json]
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

PROFILES = ("jcs-json-v1", "cbor-deterministic-v1")
BASIS_OK = ("observed", "not_observed", "unknown")


def _path(arg: str) -> str:
    if not arg or not arg.strip():
        raise SystemExit("refusing an empty vectors path")
    norm = arg.replace("\\", "/")
    if os.path.isabs(arg) or os.path.isabs(norm):
        raise SystemExit(f"refusing an absolute vectors path: {arg!r}")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise SystemExit(f"refusing a vectors path with parent traversal: {arg!r}")
    base = os.path.realpath(os.getcwd())
    full = os.path.realpath(os.path.join(base, *parts))
    if full != base and not full.startswith(base + os.sep):
        raise SystemExit(f"refusing a vectors path outside the working directory: {arg!r}")
    if not full.endswith(".json") or not os.path.isfile(full):
        raise SystemExit(f"refusing a non-json or non-file vectors path: {arg!r}")
    return full


def canon_jcs(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _h(maj: int, n: int) -> bytes:
    if n < 24:
        return bytes([(maj << 5) | n])
    if n < 0x100:
        return bytes([(maj << 5) | 24, n])
    if n < 0x10000:
        return bytes([(maj << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(maj << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(maj << 5) | 27]) + n.to_bytes(8, "big")


def canon_cbor(o) -> bytes:
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if o is None:
        return b"\xf6"
    if isinstance(o, int):
        return _h(0, o) if o >= 0 else _h(1, -1 - o)
    if isinstance(o, str):
        e = o.encode("utf-8")
        return _h(3, len(e)) + e
    if isinstance(o, list):
        return _h(4, len(o)) + b"".join(canon_cbor(x) for x in o)
    if isinstance(o, dict):
        kv = sorted(((canon_cbor(str(k)), canon_cbor(v)) for k, v in o.items()), key=lambda p: p[0])
        return _h(5, len(kv)) + b"".join(k + v for k, v in kv)
    raise TypeError(type(o).__name__)


def addr(body, profile):
    if profile == "jcs-json-v1":
        return "sha256:" + hashlib.sha256(canon_jcs(body)).hexdigest()
    if profile == "cbor-deterministic-v1":
        return "sha256:" + hashlib.sha256(canon_cbor(body)).hexdigest()
    return None


def redacted(v) -> bool:
    return v is None or v == "<redacted>" or (isinstance(v, dict) and v.get("_redacted") is True)


def recompute(ref, store, registry) -> str:
    if not ref.get("digest") or not ref.get("canonicalization"):
        return "malformed_ref"
    canon = ref["canonicalization"]
    loc = ref.get("ref")
    if loc is None:
        return "unresolvable_digest_only"
    if loc not in store:
        return "unresolved_ref"
    body = store[loc]
    if not isinstance(canon, str) or canon not in PROFILES:
        return "unsupported_canonicalization"
    if addr(body, canon) != ref["digest"]:
        for alt in PROFILES:
            if alt != canon and addr(body, alt) == ref["digest"]:
                return "canonicalization_mismatch"
        return "digest_mismatch"
    key = f"{body.get('schema')}/{body.get('schema_version')}"
    spec = registry.get(key)
    if spec is None:
        return "schema_mismatch"
    if any(f not in body or redacted(body[f]) for f in spec["required_fields"]):
        return "incomplete_projection"
    return "recomputed"


def advisory(rec_verdict, body) -> str:
    if rec_verdict != "recomputed" or body is None:
        return "advisory_rejected"
    b = body.get("basis")
    if b not in BASIS_OK or b in ("not_observed", "unknown"):
        return "insufficient_coverage"
    return "divergence_observed" if (body.get("divergence") or []) else "none"


def merge(case, registry) -> dict:
    ref, store = case["ref"], case["body_store"]
    surface = case["surface_verdict"]
    opt_in = case["operator_opt_in"]
    rv = recompute(ref, store, registry)
    body = store.get(ref.get("ref")) if rv == "recomputed" else None
    adv = advisory(rv, body)
    if surface == "surface_drift_block":
        decision = "block"
    elif adv == "divergence_observed":
        decision = "quarantine" if opt_in else "review_required"
    elif adv == "insufficient_coverage":
        decision = "review_required"
    else:
        decision = "allow"
    return {
        "surface_verdict": surface,
        "surface_is_authority": True,
        "recompute_verdict": rv,
        "effect_advisory": adv,
        "effect_can_hard_block": bool(opt_in),
        "decision": decision,
    }


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    with open(_path(path), encoding="utf-8") as fh:
        doc = json.load(fh)
    registry = doc["schema_registry"]
    failures = [
        f"{c['id']}: got {merge(c, registry)}, expected {c['expected']}"
        for c in doc["cases"]
        if merge(c, registry) != c["expected"]
    ]
    print(json.dumps({
        "reproducer": "independent",
        "cases": len(doc["cases"]),
        "all_reproduced": not failures,
        "failures": failures,
    }, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
