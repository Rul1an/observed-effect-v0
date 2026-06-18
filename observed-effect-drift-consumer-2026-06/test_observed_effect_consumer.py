#!/usr/bin/env python3
"""Tests for the observed-effect-drift worked example.

Three things are checked: the recompute/merge matrix reproduces, the false-green guards hold by
construction, and a second implementation that shares no code re-derives every result from the
committed bytes.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys

import pytest

import observed_effect_consumer as oec

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def doc():
    return oec.emit()


def _case(doc, case_id):
    for c in doc["cases"]:
        if c["id"] == case_id:
            return c
    raise KeyError(case_id)


# ── Matrix reproduces ──────────────────────────────────────────────────────────────────────────


def test_every_case_reproduces_under_reference(doc):
    for c in doc["cases"]:
        got = oec.merge_decision(
            c["surface_verdict"], c["ref"], c["body_store"], doc["schema_registry"],
            operator_opt_in=c["operator_opt_in"],
        )
        assert got == c["expected"], c["id"]


def test_dual_profile_parity(doc):
    # The same record over JCS and CBOR yields the same composed decision.
    a = _case(doc, "headline_egress_jcs")["expected"]
    b = _case(doc, "headline_egress_cbor")["expected"]
    assert a["decision"] == b["decision"] == "review_required"


# ── The seam: surface clean, effect catches the runtime divergence ──────────────────────────────


def test_headline_seam_surface_clean_effect_raises(doc):
    c = _case(doc, "headline_egress_jcs")
    # Declaration never moved, so a surface gate alone sees nothing.
    body = c["body_store"][c["ref"]["ref"]]
    assert body["declared_effect"]["network"] == []
    assert body["observed_effect"]["network"]  # an egress was observed
    # The effect advisory raises to review_required (not a hard block).
    assert c["expected"]["effect_advisory"] == "divergence_observed"
    assert c["expected"]["decision"] == "review_required"


def test_opt_in_promotes_to_quarantine_still_labeled(doc):
    c = _case(doc, "headline_egress_opt_in")
    assert c["expected"]["decision"] == "quarantine"
    assert c["expected"]["effect_can_hard_block"] is True


# ── False-green guards, by construction ─────────────────────────────────────────────────────────


def test_guard_absence_is_not_clean(doc):
    for cid in ("absence_not_observed", "absence_unknown"):
        c = _case(doc, cid)
        assert c["expected"]["effect_advisory"] == "insufficient_coverage"
        assert c["expected"]["decision"] == "review_required", cid
        assert c["expected"]["decision"] != "allow", cid


def test_guard_surface_block_never_downgraded(doc):
    for cid in ("surface_block_dominates", "surface_block_plus_egress", "broken_advisory_blocked_surface"):
        c = _case(doc, cid)
        assert c["surface_verdict"] == "surface_drift_block"
        assert c["expected"]["decision"] == "block", cid


def test_guard_effect_never_auto_hard_blocks_without_opt_in(doc):
    c = _case(doc, "headline_egress_jcs")
    assert c["operator_opt_in"] is False
    assert c["expected"]["decision"] != "quarantine"
    assert c["expected"]["decision"] != "block"


def test_guard_broken_advisory_fails_closed_to_surface(doc):
    # Tampered body -> digest mismatch -> advisory rejected -> falls back to the surface verdict,
    # never below it. On a clean surface that is allow; the rejection is surfaced, not swallowed.
    c = _case(doc, "broken_advisory_clean_surface")
    assert c["expected"]["recompute_verdict"] == "digest_mismatch"
    assert c["expected"]["effect_advisory"] == "advisory_rejected"
    assert c["expected"]["decision"] == "allow"
    # A broken advisory can never do better (less cautious) than no advisory at all.


def test_guard_stripping_bounds_breaks_digest(doc):
    c = _case(doc, "strip_bounds_breaks_digest")
    body = c["body_store"][c["ref"]["ref"]]
    assert "scope" not in body and "coverage" not in body  # bounds removed
    assert c["expected"]["recompute_verdict"] == "digest_mismatch"
    assert c["expected"]["effect_advisory"] == "advisory_rejected"


def test_guard_producer_cannot_grade_itself(doc):
    # The body smuggles its own action=allow; the merge derives from facts and ignores it.
    c = _case(doc, "producer_selfgrade_ignored")
    body = c["body_store"][c["ref"]["ref"]]
    assert body.get("action") == "allow"  # the producer tried to self-decide
    assert c["expected"]["recompute_verdict"] == "recomputed"  # extra field still recomputes
    assert c["expected"]["effect_advisory"] == "divergence_observed"  # facts win
    assert c["expected"]["decision"] == "review_required"  # NOT allow


def test_guard_incomplete_projection_cannot_launder(doc):
    # A body missing the required non_claims cannot reach clean; the limits-on-the-tin cannot be
    # stripped while keeping a usable advisory.
    c = _case(doc, "incomplete_missing_non_claims")
    body = c["body_store"][c["ref"]["ref"]]
    assert "non_claims" not in body
    assert c["expected"]["recompute_verdict"] == "incomplete_projection"
    assert c["expected"]["effect_advisory"] == "advisory_rejected"


def test_guard_unsupported_profile_rejected(doc):
    c = _case(doc, "unsupported_canon")
    assert c["expected"]["recompute_verdict"] == "unsupported_canonicalization"
    assert c["expected"]["effect_advisory"] == "advisory_rejected"


def test_canon_alias_resolves_to_canonical():
    # Same RFC 8785 algorithm, different label string: a recognized alias resolves to the canonical
    # `jcs-json-v1` on read, so a record exported under another spelling still recomputes. An
    # unrecognized label stays unsupported (aliases do not open the gate to anything else).
    body = oec.build_observed_effect(
        tool="sync_repo",
        declared_effect={"network": ["egress:tcp:api.github.com:443"]},
        observed_effect={"network": ["egress:tcp:api.github.com:443"]},
        divergence=[],
        basis="observed",
        scope="ipv4_tcp_connect",
    )
    loc = "audit://rec/alias"
    store = {loc: body}
    canonical_ref = oec.build_evidence_ref(body, "jcs-json-v1", ref=loc)
    assert oec.recompute(canonical_ref, store, oec.SCHEMA_REGISTRY)["verdict"] == "recomputed"
    for alias in ("json/jcs-rfc8785", "JCS"):
        aliased = dict(canonical_ref, canonicalization=alias)
        assert oec.recompute(aliased, store, oec.SCHEMA_REGISTRY)["verdict"] == "recomputed", alias
    bogus = dict(canonical_ref, canonicalization="blake3-json-v9")
    assert oec.recompute(bogus, store, oec.SCHEMA_REGISTRY)["verdict"] == "unsupported_canonicalization"


def test_sample_records_all_recompute():
    # The producer-side sample set for a consumer reader: every sample's envelope must recompute against
    # its body (resolve + verify digest), including the one stamped with a recognized alias.
    import sample_records as sr
    doc = sr.emit()
    assert doc["samples"], "expected sample records"
    for s in doc["samples"]:
        env, body = s["envelope"], s["body"]
        rv = oec.recompute(env, {env["ref"]: body}, oec.SCHEMA_REGISTRY)
        assert rv["verdict"] == "recomputed", (s["id"], rv)
    assert any(s["envelope"]["canonicalization"] in ("json/jcs-rfc8785", "JCS") for s in doc["samples"]), \
        "expected at least one alias-labeled sample to exercise alias resolution"


def test_record_carries_no_verdict_or_action_field_in_honest_records(doc):
    # Every record except the deliberate self-grade probe omits action/severity/decision.
    for c in doc["cases"]:
        if c["id"] == "producer_selfgrade_ignored":
            continue
        for body in c["body_store"].values():
            for forbidden in ("action", "severity", "decision", "verdict"):
                assert forbidden not in body, (c["id"], forbidden)


# ── Invariants reported by the reference verifier ───────────────────────────────────────────────


def test_reference_verifier_reports_all_invariants(tmp_path):
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps(oec.emit()))
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "observed_effect_consumer.py"), "verify", "vectors.json"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    res = json.loads(out.stdout)
    assert res["all_expected"] is True
    assert res["all_invariants_hold"] is True


# ── Two-implementation interop bar ──────────────────────────────────────────────────────────────


def test_independent_reproducer_shares_no_runner_import():
    src = open(os.path.join(HERE, "independent_consumer.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert "observed_effect_consumer" not in a.name
        if isinstance(node, ast.ImportFrom):
            assert node.module is None or "observed_effect_consumer" not in node.module


def test_independent_reproducer_rederives_every_result(tmp_path):
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps(oec.emit()))
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "independent_consumer.py"), "vectors.json"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    res = json.loads(out.stdout)
    assert res["all_reproduced"] is True, res["failures"]
    assert res["cases"] == len(oec.emit()["cases"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-q"]))
