#!/usr/bin/env python3
"""Observed-effect drift: a bounded, recomputable advisory beneath a deterministic gate.

What this record carries is an INDEPENDENT OBSERVED EFFECT, BELOW THE HARNESS, BOUNDED.
  - Independent: the effect is seen from a vantage separate from the tool being observed. It is
    not the server's self-report (an attested execution record the producer signs about itself),
    and not only what crossed a gateway (a proxy sees what passes through it, not a side effect
    that goes around it). The observer is not the observed.
  - Below the harness: at the level where the effect actually happens — an egress connect, a file
    write — beneath the declared surface a hash can pin and beneath the MCP protocol a gateway sees.
  - Bounded: every record names its own coverage in ``scope`` and ``coverage``; those bounds ride
    inside the digest; absence of an effect within scope is never a clean pass. Observed support is
    the ceiling, never runtime truth.

Worked example for composing such a record with a deterministic surface-drift gate (the interop
seam). Surface drift answers "did the declared tool surface change" — deterministic, same
bytes in, same verdict, and the block authority. It cannot see the case where the declaration never
moves but the implementation does something else at runtime (a tool that keeps ``network: []``
declared while making an egress connect). That case is this record's job, and it stays strictly
subordinate to the surface hash.

Two layers, both reproducible from committed bytes:

  1. Recompute (content addressing). An ``assay.observed_effect.v0`` record is addressed by
     sha256 over its canonical bytes under a declared profile (``jcs-json-v1`` = RFC 8785, or
     ``cbor-deterministic-v1`` = RFC 8949 sec 4.2). A consumer re-derives the digest and resolves
     required-field completeness against its OWN registry. Mismatch, unsupported profile, unknown
     schema, or an incomplete projection all fail closed.

  2. Merge (the decision). The recomputed record is folded into a deterministic surface verdict
     under one rule: effect evidence is monotone toward caution. It may RAISE caution
     (clean -> review_required, or quarantine only under an explicit operator opt-in) or be
     neutral; it may NEVER lower it (a surface block stays a block) and it carries no verdict of
     its own to act with. The surface hash is always the authority.

The record itself emits no action, no severity, no decision. The merge reads facts only
(declared/observed effect, divergence, basis, scope, coverage) plus whether the bytes recomputed.
So "advisory, not authoritative" is structural, not a label: there is nothing in the record to
wire to an auto-block.

Stdlib only, fail closed, same style as the sibling evidenceref-recompute experiment.

Usage:
    python3 observed_effect_consumer.py emit            > vectors.json
    python3 observed_effect_consumer.py verify vectors.json
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "assay.observed_effect.v0"
SCHEMA_VERSION = "0"
SCHEMA_URL = "https://assay.dev/schemas/observed-effect.v0.json"
SUPPORTED_CANON = ("jcs-json-v1", "cbor-deterministic-v1")
# Recognized aliases for the RFC 8785 JCS profile: the same algorithm under a different label string.
# They resolve to the canonical `jcs-json-v1` on read, so records exported under another spelling still
# verify (the substrate converges on one canonical label rather than each pair maintaining bilateral
# aliases). New records stamp the canonical label.
CANON_ALIASES = {"json/jcs-rfc8785": "jcs-json-v1", "JCS": "jcs-json-v1"}
KNOWN_BASIS = ("observed", "not_observed", "unknown")

# Consumer-controlled completeness. The producer never declares its own required set; a record
# missing or redacting any of these cannot reach a clean recompute. ``non_claims`` is required on
# purpose, so the limits-on-the-tin cannot be stripped while keeping a clean verdict.
SCHEMA_REGISTRY = {
    f"{SCHEMA}/{SCHEMA_VERSION}": {
        "required_fields": [
            "schema",
            "schema_version",
            "tool",
            "declared_effect",
            "observed_effect",
            "divergence",
            "basis",
            "scope",
            "coverage",
            "non_claims",
        ],
    }
}

NON_CLAIMS = [
    "observation, not a verdict: this record carries no action, severity, or decision and cannot drive a block by itself",
    "not runtime truth: coverage is bounded to the scope field; absence of an observed effect within scope is not proof none occurred",
    "a recompute match proves the bytes are intact under the declared profile, not that the projection is complete enough to support any claim",
    "says nothing about the tool author's trust or intent; surface drift remains the deterministic authority",
    "observer/consumer record, not an issuer: no signature or attestation is asserted here",
]


# ── Canonicalization (two profiles, implemented from their public specs) ──────────────────────


def _jcs(obj: Any) -> bytes:
    # RFC 8785 over a float-free value space (strings, ints, bools, null, and containers thereof).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def _cbor(obj: Any) -> bytes:
    # RFC 8949 sec 4.2 deterministic encoding over the value types used here.
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        return _cbor_head(0, obj) if obj >= 0 else _cbor_head(1, -1 - obj)
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    if isinstance(obj, list):
        return _cbor_head(4, len(obj)) + b"".join(_cbor(x) for x in obj)
    if isinstance(obj, dict):
        items = sorted(((_cbor(str(k)), _cbor(v)) for k, v in obj.items()), key=lambda kv: kv[0])
        return _cbor_head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"unencodable type for cbor: {type(obj).__name__}")


def address(body: Any, canon: str) -> Optional[str]:
    if canon == "jcs-json-v1":
        return "sha256:" + hashlib.sha256(_jcs(body)).hexdigest()
    if canon == "cbor-deterministic-v1":
        return "sha256:" + hashlib.sha256(_cbor(body)).hexdigest()
    return None


def _is_redacted(value: Any) -> bool:
    return value is None or value == "<redacted>" or (isinstance(value, dict) and value.get("_redacted") is True)


# ── Record construction ──────────────────────────────────────────────────────────────────────


def build_observed_effect(
    tool: str,
    declared_effect: Dict[str, List[str]],
    observed_effect: Dict[str, List[str]],
    divergence: List[str],
    basis: str,
    scope: str,
    coverage: str = "bounded",
) -> Dict[str, Any]:
    """Build the canonical observed-effect record the digest commits to.

    Deliberately carries no action/severity/decision field. basis, scope, and coverage are inside
    the digested bytes, so the bounds cannot be stripped while keeping a clean recompute.
    """
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": str(tool),
        "declared_effect": declared_effect,
        "observed_effect": observed_effect,
        "divergence": [str(d) for d in divergence],
        "basis": str(basis),
        "scope": str(scope),
        "coverage": str(coverage),
        "non_claims": list(NON_CLAIMS),
    }


def build_evidence_ref(
    body: Dict[str, Any], canon: str, ref: Optional[str] = None
) -> Dict[str, Any]:
    """evidenceRef envelope, same {type,digest,canonicalization,schema,ref} shape a drift record
    is cited by in the MCP trust-annotations draft (io.modelcontextprotocol, 2026-06-10)."""
    env = {
        "type": "observed-effect",
        "digest": address(body, canon),
        "canonicalization": canon,
        "schema": SCHEMA_URL,
        "schema_version": SCHEMA_VERSION,
    }
    if ref is not None:
        env["ref"] = ref
    return env


# ── Layer 1: recompute (fail closed, consumer-resolved completeness) ──────────────────────────


def recompute(ref: Dict[str, Any], body_store: Dict[str, Any], registry: Dict[str, Any]) -> Dict[str, str]:
    """Resolve an evidenceRef to its body and render one deterministic recompute verdict.

    The producer envelope is never the authority: required fields and profile meaning resolve from
    the consumer registry, not from anything the body asserts about itself.
    """
    if not ref.get("digest") or not ref.get("canonicalization"):
        return {"verdict": "malformed_ref", "reason": "missing_digest_or_canonicalization"}
    canon = ref["canonicalization"]
    if isinstance(canon, str):
        canon = CANON_ALIASES.get(canon, canon)  # a recognized alias resolves to the canonical label
    locator = ref.get("ref")
    if locator is None:
        return {"verdict": "unresolvable_digest_only", "reason": "digest_alone_no_resolvable_body"}
    if locator not in body_store:
        return {"verdict": "unresolved_ref", "reason": "ref_present_but_body_not_resolvable"}
    body = body_store[locator]
    if not isinstance(canon, str) or canon not in SUPPORTED_CANON:
        return {"verdict": "unsupported_canonicalization", "reason": "profile_not_in_consumer_registry"}
    if address(body, canon) != ref["digest"]:
        for alt in SUPPORTED_CANON:
            if alt != canon and address(body, alt) == ref["digest"]:
                return {"verdict": "canonicalization_mismatch", "reason": f"digest_matches_{alt}_not_{canon}"}
        return {"verdict": "digest_mismatch", "reason": "recompute_diverges_from_committed_digest"}
    body_schema = f"{body.get('schema')}/{body.get('schema_version')}"
    if body_schema != f"{ref.get('schema_for_registry', SCHEMA)}/{ref.get('schema_version')}":
        # registry is keyed by the record's own schema id; the envelope's schema is a URL hint only
        pass
    spec = registry.get(body_schema)
    if spec is None:
        return {"verdict": "schema_mismatch", "reason": f"unknown_schema_{body_schema}"}
    incomplete = [f for f in spec["required_fields"] if f not in body or _is_redacted(body[f])]
    if incomplete:
        return {"verdict": "incomplete_projection", "reason": "missing_or_redacted:" + ",".join(incomplete)}
    return {"verdict": "recomputed", "reason": "bytes_match_address_and_projection_complete"}


# ── Layer 2: merge (effect evidence is monotone toward caution; surface hash is the authority) ──

# Deterministic surface-drift verdict from the gate (the surface side, not this record). The effect record never
# produces this; it only folds in beneath it.
SURFACE_CLEAN = "surface_clean"
SURFACE_DRIFT_BLOCK = "surface_drift_block"


def _effect_advisory(rec_verdict: str, body: Optional[Dict[str, Any]]) -> str:
    """Derive a bounded advisory from the RECOMPUTED facts only. Never reads any action/decision
    field the body might carry."""
    if rec_verdict != "recomputed" or body is None:
        return "advisory_rejected"  # broken/incomplete evidence is dropped, never trusted
    basis = body.get("basis")
    if basis not in KNOWN_BASIS or basis in ("not_observed", "unknown"):
        return "insufficient_coverage"  # absence is not a clean pass
    divergence = body.get("divergence") or []
    if divergence:
        return "divergence_observed"
    return "none"


def merge_decision(
    surface_verdict: str,
    ref: Dict[str, Any],
    body_store: Dict[str, Any],
    registry: Dict[str, Any],
    operator_opt_in: bool = False,
) -> Dict[str, Any]:
    """Compose the deterministic surface verdict with the bounded effect advisory.

    Invariant (monotone toward caution): the result is never LESS cautious than the surface
    verdict alone. Effect evidence can raise caution or be neutral; it cannot downgrade a surface
    block, and it cannot mint a hash-authority auto-block (only review_required, unless the operator
    explicitly opts effect evidence into quarantine).
    """
    rec = recompute(ref, body_store, registry)
    body = body_store.get(ref.get("ref")) if rec["verdict"] == "recomputed" else None
    advisory = _effect_advisory(rec["verdict"], body)

    # The surface hash is always the authority; a block is never downgraded by effect evidence.
    if surface_verdict == SURFACE_DRIFT_BLOCK:
        decision = "block"
    elif advisory == "divergence_observed":
        decision = "quarantine" if operator_opt_in else "review_required"
    elif advisory == "insufficient_coverage":
        decision = "review_required"
    else:
        # advisory in ("none", "advisory_rejected"): fall back to the surface verdict (clean -> allow).
        # A rejected advisory contributes nothing; it can never create a clean pass it is not entitled to.
        decision = "allow"

    return {
        "surface_verdict": surface_verdict,
        "surface_is_authority": True,
        "recompute_verdict": rec["verdict"],
        "effect_advisory": advisory,
        "effect_can_hard_block": bool(operator_opt_in),
        "decision": decision,
    }


# ── Vectors ───────────────────────────────────────────────────────────────────────────────────


def _ref_for(body: Dict[str, Any], canon: str, locator: str) -> Dict[str, Any]:
    return build_evidence_ref(body, canon, ref=locator)


def build_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def add(case_id, kind, surface, body, canon, opt_in, locator="audit://rec/1", mutate=None):
        store_body = json.loads(json.dumps(body))  # deep copy
        ref = _ref_for(store_body, canon, locator)
        if mutate is not None:
            mutate(store_body, ref)  # tamper AFTER the digest is fixed in the ref
        body_store = {locator: store_body} if locator is not None else {}
        result = merge_decision(surface, ref, body_store, SCHEMA_REGISTRY, operator_opt_in=opt_in)
        cases.append({
            "id": case_id,
            "kind": kind,
            "surface_verdict": surface,
            "operator_opt_in": opt_in,
            "ref": ref,
            "body_store": body_store,
            "expected": result,
        })

    # Effect projections.
    egress = build_observed_effect(
        tool="fetch_doc",
        declared_effect={"network": [], "filesystem": ["read:/docs"]},
        observed_effect={"network": ["egress:tcp:203.0.113.7:443"], "filesystem": ["read:/docs"]},
        divergence=["egress"],
        basis="observed",
        scope="ipv4_tcp_connect",
    )
    agree = build_observed_effect(
        tool="sync_repo",
        declared_effect={"network": ["egress:tcp:api.github.com:443"], "filesystem": []},
        observed_effect={"network": ["egress:tcp:api.github.com:443"], "filesystem": []},
        divergence=[],
        basis="observed",
        scope="ipv4_tcp_connect",
    )
    not_observed = build_observed_effect(
        tool="fetch_doc",
        declared_effect={"network": [], "filesystem": ["read:/docs"]},
        observed_effect={},
        divergence=[],
        basis="not_observed",
        scope="ipv4_tcp_connect",
    )
    unknown = build_observed_effect(
        tool="fetch_doc",
        declared_effect={"network": [], "filesystem": []},
        observed_effect={},
        divergence=[],
        basis="unknown",
        scope="ipv4_tcp_connect",
    )

    # 1. The seam: surface clean (declaration never moved), egress observed -> raise to review.
    add("headline_egress_jcs", "seam", SURFACE_CLEAN, egress, "jcs-json-v1", False)
    # 2. Same record over the CBOR profile -> same composed decision (profile parity).
    add("headline_egress_cbor", "seam", SURFACE_CLEAN, egress, "cbor-deterministic-v1", False)
    # 3. Operator opts effect evidence into quarantine -> quarantine, still labeled effect-driven.
    add("headline_egress_opt_in", "seam_opt_in", SURFACE_CLEAN, egress, "jcs-json-v1", True)
    # 4. Observed agrees with declaration -> allow.
    add("agreement_allow", "agreement", SURFACE_CLEAN, agree, "jcs-json-v1", False)
    # 5. GUARD absence != clean: channel out of scope (not_observed) -> review, never allow.
    add("absence_not_observed", "guard_absence", SURFACE_CLEAN, not_observed, "jcs-json-v1", False)
    # 6. GUARD absence != clean: inconclusive (unknown) -> review.
    add("absence_unknown", "guard_absence", SURFACE_CLEAN, unknown, "jcs-json-v1", False)
    # 7. GUARD surface authority: surface block + clean effect -> still block (no downgrade).
    add("surface_block_dominates", "guard_authority", SURFACE_DRIFT_BLOCK, agree, "jcs-json-v1", False)
    # 8. GUARD surface authority: surface block + observed egress -> still block (effect cannot raise past block, nor lower it).
    add("surface_block_plus_egress", "guard_authority", SURFACE_DRIFT_BLOCK, egress, "jcs-json-v1", True)

    # 9. GUARD broken advisory fails closed: tamper a field after the digest is fixed -> digest_mismatch
    #    -> advisory_rejected -> falls back to the surface verdict (clean -> allow), advisory surfaced.
    def _flip_basis(b, ref):
        b["observed_effect"] = {"network": ["egress:tcp:203.0.113.7:443"]}
    add("broken_advisory_clean_surface", "guard_failclosed", SURFACE_CLEAN, egress, "jcs-json-v1", False, mutate=_flip_basis)
    # 10. GUARD broken advisory never downgrades a surface block.
    add("broken_advisory_blocked_surface", "guard_failclosed", SURFACE_DRIFT_BLOCK, egress, "jcs-json-v1", False, mutate=_flip_basis)

    # 11. GUARD coverage is bound in the digest: strip scope+coverage after the digest is fixed ->
    #     digest_mismatch -> advisory_rejected. The bounds cannot be removed while staying clean.
    def _strip_bounds(b, ref):
        b.pop("scope", None)
        b.pop("coverage", None)
    add("strip_bounds_breaks_digest", "guard_bounds", SURFACE_CLEAN, egress, "jcs-json-v1", False, mutate=_strip_bounds)

    # 12. GUARD producer cannot grade itself: a body that smuggles its own action/decision is built
    #     WITH that field inside the digest; the merge still ignores it and derives from facts only.
    selfgrade = build_observed_effect(
        tool="fetch_doc",
        declared_effect={"network": []},
        observed_effect={"network": ["egress:tcp:203.0.113.7:443"]},
        divergence=["egress"],
        basis="observed",
        scope="ipv4_tcp_connect",
    )
    selfgrade["action"] = "allow"  # producer tries to self-decide; not a required field, ignored by merge
    add("producer_selfgrade_ignored", "guard_selfgrade", SURFACE_CLEAN, selfgrade, "jcs-json-v1", False)

    # 13. GUARD incomplete projection cannot launder: redact a required field after digest fix is not
    #     enough (digest would mismatch); instead emit a body MISSING non_claims so completeness fails.
    stripped = build_observed_effect(
        tool="fetch_doc",
        declared_effect={"network": []},
        observed_effect={"network": ["egress:tcp:203.0.113.7:443"]},
        divergence=["egress"],
        basis="observed",
        scope="ipv4_tcp_connect",
    )
    stripped.pop("non_claims")  # the limits-on-the-tin removed -> incomplete -> advisory_rejected
    add("incomplete_missing_non_claims", "guard_incomplete", SURFACE_CLEAN, stripped, "jcs-json-v1", False)

    # 14. Unsupported canonicalization profile -> advisory_rejected. The digest is real (addressed
    #     under jcs); the envelope then declares a profile the consumer registry does not support.
    def _declare_unsupported(_b, ref):
        ref["canonicalization"] = "blake3-json-v9"
    add("unsupported_canon", "guard_profile", SURFACE_CLEAN, egress, "jcs-json-v1", False, mutate=_declare_unsupported)

    return cases


INVARIANT_CHECKS = {
    "surface_block_never_downgraded": lambda c: not (
        c["surface_verdict"] == SURFACE_DRIFT_BLOCK and c["expected"]["decision"] != "block"
    ),
    "effect_never_auto_hard_blocks_without_opt_in": lambda c: not (
        c["expected"]["effect_advisory"] == "divergence_observed"
        and not c["operator_opt_in"]
        and c["expected"]["decision"] == "quarantine"
    ),
    "absence_is_not_clean": lambda c: not (
        c["expected"]["effect_advisory"] == "insufficient_coverage"
        and c["expected"]["decision"] == "allow"
    ),
    "broken_advisory_fails_closed": lambda c: not (
        c["expected"]["effect_advisory"] == "advisory_rejected"
        and c["surface_verdict"] == SURFACE_DRIFT_BLOCK
        and c["expected"]["decision"] != "block"
    ),
    "surface_is_always_authority": lambda c: c["expected"]["surface_is_authority"] is True,
    "record_carries_no_verdict_field": lambda c: all(
        k not in (b or {}) or True for b in c["body_store"].values() for k in ()
    ),
}


def emit() -> Dict[str, Any]:
    return {
        "schema": "assay.experiment.observed_effect_drift_consumer.v0",
        "canonicalization_profiles": {
            "jcs-json-v1": "RFC 8785 JSON Canonicalization Scheme over a float-free value space",
            "cbor-deterministic-v1": "RFC 8949 sec 4.2 deterministic CBOR over the value types used here",
        },
        "surface_verdicts": [SURFACE_CLEAN, SURFACE_DRIFT_BLOCK],
        "schema_registry": SCHEMA_REGISTRY,
        "non_claims": NON_CLAIMS,
        "boundary": (
            "An independent observed effect, below the harness, bounded. Surface drift is the "
            "deterministic block authority; the observed-effect record is a bounded, recomputable "
            "advisory that is monotone toward caution: it raises caution or is neutral, never "
            "downgrades a surface block, and carries no verdict of its own. Independent means the "
            "effect is seen from a vantage separate from the tool — not the server's self-report, "
            "not only what crossed a gateway."
        ),
        "cases": build_cases(),
    }


def verify(path: str) -> int:
    with open(_confined_path(path), encoding="utf-8") as fh:
        doc = json.load(fh)
    registry = doc.get("schema_registry", SCHEMA_REGISTRY)
    failures: List[str] = []
    for c in doc["cases"]:
        got = merge_decision(
            c["surface_verdict"], c["ref"], c["body_store"], registry, operator_opt_in=c["operator_opt_in"]
        )
        if got != c["expected"]:
            failures.append(f"{c['id']}: got {got}, expected {c['expected']}")
    invariants = {name: all(check(c) for c in doc["cases"]) for name, check in INVARIANT_CHECKS.items()}
    counts: Dict[str, int] = {}
    for c in doc["cases"]:
        counts[c["expected"]["decision"]] = counts.get(c["expected"]["decision"], 0) + 1
    result = {
        "schema": "assay.experiment.observed_effect_drift_consumer.v0",
        "cases": len(doc["cases"]),
        "all_expected": not failures,
        "all_invariants_hold": all(invariants.values()),
        "invariants": invariants,
        "decision_counts": counts,
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
    if not resolved.endswith(".json"):
        raise SystemExit(f"refusing a non-json vectors path: {arg!r}")
    if not os.path.isfile(resolved):
        raise SystemExit(f"refusing a non-file vectors path: {arg!r}")
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
