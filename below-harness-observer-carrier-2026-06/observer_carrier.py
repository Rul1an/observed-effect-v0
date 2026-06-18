#!/usr/bin/env python3
"""Observer/coverage normalization for the observed-effect carrier.

Append-only extension of ``assay.observed_effect.v0`` (the prior worked example) to
``assay.observed_effect.v1``: it adds an ``observer`` block (which below-harness source produced the
observation, and in what mode) and a per-dimension ``coverage`` map (what that observer actually
watched). The point is honest normalization across heterogeneous below-harness sources — Tetragon,
AgentSight, ActPlane, Kubescape, or a custom probe — so the evidence reads the same regardless of who
produced it.

This is NOT a new runtime-security carrier and NOT an eBPF agent. It is the evidence-contract layer
over whatever the sensor produced: bounded coverage in, recomputable carrier out.

Load-bearing invariant (enforced here, tested in the suite, not just documented):

    missing or not_observed REQUIRED coverage  ->  incomplete, never match

A verdict can only be ``match`` when every coverage dimension the expectation requires was actually
observed. An unobserved network channel cannot clear a "declared no network" expectation: you did not
look. Unknown coverage values fail closed (``invalid``), never silently pass.

Non-claims carried in every record:
  - observation, not runtime truth; bounded to the coverage map
  - the observer is a source of evidence, not a trusted oracle of intent or maliciousness
  - a complete-coverage match verdict means observed matched declared under the stated bounds, nothing
    about what was not observed
  - declared-vs-observed against the tool's own declaration — NOT a learned behavioral baseline

Stdlib only, fail closed. Same canonicalization discipline as the sibling experiments.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = "assay.observed_effect"
SCHEMA_VERSION = "1"  # v1 = v0 + observer + coverage (append-only)
DIGEST_ALG = "sha256"

# The coverage dimensions a below-harness observer can report on. An observer states, per dimension,
# whether it actually watched it. Unknown dimension keys are ignored (they can never be REQUIRED, so
# they can never launder a match verdict); unknown VALUES fail closed.
COVERAGE_DIMENSIONS = (
    "process_exec",
    "network_connect",
    "file_open",
    "payload_content",
)
COVERAGE_VALUES = ("observed", "not_observed")
OBSERVER_MODES = ("observe", "enforce")

NON_CLAIMS = [
    "observation, not runtime truth: bounded to the coverage map; an unobserved dimension is a gap, not a pass",
    "the observer is a source of evidence, not a trusted oracle of intent or maliciousness",
    "a match verdict means observed matched declared under the stated coverage, and says nothing about what was not observed",
    "declared-vs-observed against the tool's own declaration, not a learned behavioral baseline",
    "observer/consumer record, not an issuer: no signature or attestation is asserted here",
]


# ── Canonicalization (JCS over a float-free value space; byte-identical to RFC 8785 here) ──────────


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(record: Dict[str, Any]) -> str:
    return f"{DIGEST_ALG}:{hashlib.sha256(canonical_bytes(record)).hexdigest()}"


# ── Record construction ───────────────────────────────────────────────────────────────────────


def build_record(
    tool: str,
    declared_effect: Dict[str, List[str]],
    observed_effect: Dict[str, List[str]],
    divergence: List[str],
    basis: str,
    scope: str,
    observer: Dict[str, str],
    coverage: Dict[str, str],
) -> Dict[str, Any]:
    """Build the canonical observed-effect v1 record. observer and coverage ride inside the digest,
    so the source and the bounds cannot be stripped while keeping the recompute intact."""
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": str(tool),
        "declared_effect": declared_effect,
        "observed_effect": observed_effect,
        "divergence": [str(d) for d in divergence],
        "basis": str(basis),
        "scope": str(scope),
        "observer": {
            "type": str(observer.get("type") or ""),
            "version": str(observer.get("version") or ""),
            "mode": str(observer.get("mode") or ""),
            "kernel": str(observer.get("kernel") or ""),
        },
        "coverage": {str(k): str(v) for k, v in (coverage or {}).items()},
        "non_claims": list(NON_CLAIMS),
    }


# ── Evaluation: the load-bearing invariant ─────────────────────────────────────────────────────


def evaluate(record: Dict[str, Any], required_coverage: Iterable[str]) -> Dict[str, str]:
    """Render one verdict over a v1 record given which coverage dimensions the expectation requires.

    Verdicts:
      - invalid     : malformed (no observer.type, unknown coverage value) -> fail closed, never match
      - incomplete  : a required coverage dimension was missing or not_observed -> never match
      - mismatch    : required coverage present and observed; observed effect diverges from declared
      - match       : required coverage present and observed; observed matched declared
    """
    observer = record.get("observer")
    if not isinstance(observer, dict) or not observer.get("type"):
        return {"verdict": "invalid", "reason": "observer_type_required"}
    if observer.get("mode") and observer["mode"] not in OBSERVER_MODES:
        return {"verdict": "invalid", "reason": f"unknown_observer_mode:{observer.get('mode')}"}

    coverage = record.get("coverage")
    if not isinstance(coverage, dict):
        return {"verdict": "invalid", "reason": "coverage_required"}
    # Unknown coverage VALUES fail closed. Unknown dimension KEYS are ignored: they can never be
    # required, so they can never produce a match verdict.
    for dim, val in coverage.items():
        if val not in COVERAGE_VALUES:
            return {"verdict": "invalid", "reason": f"unknown_coverage_value:{dim}={val}"}

    # The invariant: every required dimension must be present AND observed.
    for dim in required_coverage:
        if coverage.get(dim) != "observed":
            return {"verdict": "incomplete", "reason": f"required_coverage_not_observed:{dim}"}

    divergence = record.get("divergence") or []
    if divergence:
        return {"verdict": "mismatch", "reason": "observed_effect_diverges_from_declared"}
    return {"verdict": "match", "reason": "observed_matched_declared_under_complete_required_coverage"}


def carrier(record: Dict[str, Any], required_coverage: List[str]) -> Dict[str, Any]:
    """The full carrier: the record, its content address, and the verdict over it."""
    return {
        "record": record,
        "digest": digest(record),
        "required_coverage": list(required_coverage),
        "verdict": evaluate(record, required_coverage),
    }


# ── Observer/coverage vectors ────────────────────────────────────────────────────────────────────────────────


def _observer(otype="tetragon", version="1.4.0", mode="observe", kernel="6.8.0") -> Dict[str, str]:
    return {"type": otype, "version": version, "mode": mode, "kernel": kernel}


def _full_coverage(**overrides) -> Dict[str, str]:
    cov = {d: "observed" for d in COVERAGE_DIMENSIONS}
    cov.update(overrides)
    return cov


def build_observer_coverage_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def add(case_id, kind, record, required):
        cases.append({"id": case_id, "kind": kind, "case": carrier(record, required)})

    declared_none = {"network": [], "filesystem": ["read:/docs"]}
    observed_egress = {"network": ["egress:tcp:203.0.113.7:443"], "filesystem": ["read:/docs"]}

    # match: declared no-network, network_connect observed, no divergence.
    add("match_full_coverage", "match",
        build_record("fetch_doc", declared_none, {"network": [], "filesystem": ["read:/docs"]},
                     [], "observed", "ipv4_tcp_connect", _observer(), _full_coverage()),
        ["network_connect"])

    # mismatch: declared no-network, network_connect observed, egress observed.
    add("mismatch_observed_egress", "mismatch",
        build_record("fetch_doc", declared_none, observed_egress,
                     ["egress"], "observed", "ipv4_tcp_connect",
                     _observer(), _full_coverage()),
        ["network_connect"])

    # incomplete: required network_connect not_observed (observer did not watch network).
    add("incomplete_not_observed", "incomplete",
        build_record("fetch_doc", declared_none, {"filesystem": ["read:/docs"]},
                     [], "not_observed", "ipv4_tcp_connect",
                     _observer(), _full_coverage(network_connect="not_observed")),
        ["network_connect"])

    # incomplete: required dimension absent from the coverage map entirely.
    add("incomplete_missing_dimension", "incomplete",
        build_record("fetch_doc", declared_none, {"filesystem": ["read:/docs"]},
                     [], "not_observed", "ipv4_tcp_connect",
                     _observer(), {"process_exec": "observed", "file_open": "observed"}),
        ["network_connect"])

    # invalid: observer.type missing.
    add("invalid_no_observer_type", "invalid",
        build_record("fetch_doc", declared_none, observed_egress,
                     ["egress"], "observed", "ipv4_tcp_connect",
                     {"type": "", "version": "1.4.0", "mode": "observe", "kernel": "6.8.0"},
                     _full_coverage()),
        ["network_connect"])

    # invalid: unknown coverage value fails closed (must not read as match).
    bad = build_record("fetch_doc", declared_none, {"network": []},
                       [], "observed", "ipv4_tcp_connect", _observer(), _full_coverage())
    bad["coverage"]["network_connect"] = "partial"
    add("invalid_unknown_coverage_value", "invalid", bad, ["network_connect"])

    return cases


# ── Emit / verify ─────────────────────────────────────────────────────────────────────────────


def emit() -> Dict[str, Any]:
    from tetragon_adapter import build_tetragon_adapter_cases  # local import keeps the modules independent

    return {
        "schema": "assay.experiment.below_harness_observer_carrier.v0",
        "carrier_schema": f"{SCHEMA}.v{SCHEMA_VERSION}",
        "coverage_dimensions": list(COVERAGE_DIMENSIONS),
        "invariant": "missing or not_observed required coverage -> incomplete, never match",
        "non_claims": NON_CLAIMS,
        "observer_coverage_cases": build_observer_coverage_cases(),
        "tetragon_adapter_cases": build_tetragon_adapter_cases(),
    }


def verify(path: str) -> int:
    with open(_confined_path(path), encoding="utf-8") as fh:
        doc = json.load(fh)
    failures: List[str] = []
    counts: Dict[str, int] = {}
    for group in ("observer_coverage_cases", "tetragon_adapter_cases"):
        for c in doc.get(group, []):
            case = c["case"]
            v = case["verdict"]["verdict"]
            counts[v] = counts.get(v, 0) + 1
            if case["record"] is None:
                # invalid carriers (e.g. malformed Tetragon) carry no record/digest, only a verdict.
                if v != "invalid":
                    failures.append(f"{c['id']}: null record but verdict {v}")
                continue
            recomputed_digest = digest(case["record"])
            recomputed_verdict = evaluate(case["record"], case["required_coverage"])
            if recomputed_digest != case["digest"]:
                failures.append(f"{c['id']}: digest {recomputed_digest} != {case['digest']}")
            if recomputed_verdict != case["verdict"]:
                failures.append(f"{c['id']}: verdict {recomputed_verdict} != {case['verdict']}")
    invariants = {
        "missing_required_coverage_never_match": all(
            not (c["case"]["verdict"]["verdict"] == "match"
                 and any(c["case"]["record"]["coverage"].get(d) != "observed"
                         for d in c["case"]["required_coverage"]))
            for group in ("observer_coverage_cases", "tetragon_adapter_cases") for c in doc.get(group, [])
        ),
        "unknown_coverage_value_never_match": all(
            not (c["case"]["verdict"]["verdict"] == "match"
                 and any(v not in COVERAGE_VALUES for v in c["case"]["record"]["coverage"].values()))
            for group in ("observer_coverage_cases", "tetragon_adapter_cases") for c in doc.get(group, [])
        ),
    }
    result = {
        "schema": "assay.experiment.below_harness_observer_carrier.v0",
        "all_expected": not failures,
        "all_invariants_hold": all(invariants.values()),
        "invariants": invariants,
        "verdict_counts": counts,
        "failures": failures,
        "non_claims": NON_CLAIMS,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures and all(invariants.values()) else 1


def _confined_path(arg: str) -> str:
    if not arg or not arg.strip():
        raise SystemExit("refusing an empty vectors path")
    normalized = arg.replace("\\", "/")
    if os.path.isabs(arg) or os.path.isabs(normalized):
        raise SystemExit(f"refusing an absolute vectors path: {arg!r}")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise SystemExit(f"refusing a vectors path with parent traversal: {arg!r}")
    base = os.path.realpath(os.getcwd())
    resolved = os.path.realpath(os.path.join(base, *parts))
    if resolved != base and not resolved.startswith(base + os.sep):
        raise SystemExit(f"refusing a vectors path outside the working directory: {arg!r}")
    if not resolved.endswith(".json") or not os.path.isfile(resolved):
        raise SystemExit(f"refusing a non-json or non-file vectors path: {arg!r}")
    return resolved


def main(argv: List[str]) -> int:
    if len(argv) >= 2 and argv[1] == "emit":
        print(json.dumps(emit(), indent=2, sort_keys=True))
        return 0
    if len(argv) >= 2 and argv[1] == "verify":
        return verify(argv[2] if len(argv) > 2 else "vectors.json")
    sys.stderr.write(__doc__ or "")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
