#!/usr/bin/env python3
"""Tests for the neutral-carriers embeddability proof.

Run: python3 -m pytest test_neutral_carriers.py -q
"""
from __future__ import annotations

import ast
import base64
import copy
import json
import os

import neutral_carriers as nc

HERE = os.path.dirname(os.path.abspath(__file__))


def _doc():
    return nc.emit()


# ── The core invariant: one address per record, identical across all four carriers ────────────────
def test_one_address_across_all_carriers():
    res = nc.verify(_doc())
    assert res["all_carriers_resolve_to_one_address"] is True
    for r in res["results"]:
        assert r["ok"], r
        assert len(set(r["addresses"].values())) == 1
        assert set(r["addresses"]) == set(nc.CARRIERS)


def test_addresses_equal_frozen_v0_digests():
    # The embedded record bytes are the frozen v0 bytes the drift consumer already recomputed.
    doc = _doc()
    by_id = {r["id"]: r for r in doc["records"]}
    assert by_id["match_agreement"]["expected_digest"] == "sha256:c2a9723ea19504aad6f8336ccbac9d9e434d6246064d404ed8e741e1930c789c"
    assert by_id["divergence_egress"]["expected_digest"] == "sha256:07c8ade8a21a0447ad2b871947cb87e4fbd8590fb6bf2c13f1f8bd707e6f5713"


def test_all_four_carriers_present():
    doc = _doc()
    for r in doc["records"]:
        assert set(r["carriers"]) == set(nc.CARRIERS)


# ── Each carrier carries the byte-identical body ──────────────────────────────────────────────────
def test_each_carrier_holds_identical_body():
    doc = _doc()
    for r in doc["records"]:
        bodies = [nc.EXTRACTORS[name](r["carriers"][name]) for name in nc.CARRIERS]
        canon0 = nc.jcs(bodies[0])
        for b in bodies[1:]:
            assert nc.jcs(b) == canon0  # byte-identical, not merely equal-looking


def test_scitt_payload_is_the_canonical_record_bytes():
    doc = _doc()
    for r in doc["records"]:
        c = r["carriers"]["scitt-cose-statement"]
        raw = base64.b64decode(c["payload_b64"])
        assert raw == nc.jcs(nc.EXTRACTORS["standalone-jcs"](r["carriers"]["standalone-jcs"]))
        assert c["statement_digest"] == r["expected_digest"]


def test_intoto_subject_digest_is_the_content_address():
    doc = _doc()
    for r in doc["records"]:
        st = json.loads(base64.b64decode(r["carriers"]["in-toto-dsse-statement"]["dsse"]["payload"]))
        assert "sha256:" + st["subject"][0]["digest"]["sha256"] == r["expected_digest"]


# ── Ownership boundary: we own the predicate type; the envelopes are neutral ───────────────────────
def test_predicate_type_is_assay_namespaced_not_a_vendor_envelope():
    doc = _doc()
    assert doc["predicate_type"].startswith("https://assay.dev/")
    for r in doc["records"]:
        st = json.loads(base64.b64decode(r["carriers"]["in-toto-dsse-statement"]["dsse"]["payload"]))
        assert st["predicateType"].startswith("https://assay.dev/")
        # The envelope itself is the neutral in-toto Statement type, owned by no vendor.
        assert st["_type"] == "https://in-toto.io/Statement/v1"


# ── Label is non-load-bearing: the alias spelling resolves to the same address ────────────────────
def test_alias_label_recomputes_to_the_same_address():
    doc = _doc()
    alias = next(r for r in doc["records"] if r["id"] == "alias_labeled_egress")
    assert alias["canonicalization_label"] == "json/jcs-rfc8785"
    assert alias["resolves_to"] == "jcs-json-v1"
    # The recompute does not read the label; every carrier still lands on the one address.
    res = nc.verify({"records": [alias]})
    assert res["all_carriers_resolve_to_one_address"] is True


# ── Fail closed: tamper in any carrier breaks the address ─────────────────────────────────────────
def test_tamper_in_intoto_predicate_fails():
    doc = _doc()
    rec = copy.deepcopy(doc["records"][1])
    st = json.loads(base64.b64decode(rec["carriers"]["in-toto-dsse-statement"]["dsse"]["payload"]))
    st["predicate"]["tool"] = "tampered"
    rec["carriers"]["in-toto-dsse-statement"]["dsse"]["payload"] = base64.b64encode(nc.jcs(st)).decode()
    res = nc.verify({"records": [rec]})
    assert res["all_carriers_resolve_to_one_address"] is False
    assert res["results"][0]["carriers_agree"] is False


def test_tamper_in_scitt_payload_fails():
    doc = _doc()
    rec = copy.deepcopy(doc["records"][0])
    body = json.loads(base64.b64decode(rec["carriers"]["scitt-cose-statement"]["payload_b64"]))
    body["basis"] = "unknown"
    rec["carriers"]["scitt-cose-statement"]["payload_b64"] = base64.b64encode(nc.jcs(body)).decode()
    res = nc.verify({"records": [rec]})
    assert res["results"][0]["ok"] is False


def test_stripping_non_claims_breaks_the_address():
    # The limits-on-the-tin ride inside the digest; you cannot drop them and keep the address.
    doc = _doc()
    rec = copy.deepcopy(doc["records"][0])
    rec["carriers"]["standalone-jcs"]["body"].pop("non_claims")
    res = nc.verify({"records": [rec]})
    assert res["results"][0]["carriers_agree"] is False


# ── Independence: the reproducer shares no code with the emitter ───────────────────────────────────
def test_reproducer_does_not_import_the_emitter():
    src = open(os.path.join(HERE, "independent_recompute.py"), "r", encoding="utf-8").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                assert n.name != "neutral_carriers"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "neutral_carriers"


def test_committed_golden_matches_fresh_emit():
    p = os.path.join(HERE, "carriers.json")
    if not os.path.isfile(p):
        return  # golden written by verify-golden.sh; skip if absent
    committed = open(p, "r", encoding="utf-8").read()
    fresh = json.dumps(nc.emit(), indent=2, sort_keys=True) + "\n"
    assert committed == fresh, "carriers.json drifted from a fresh emit"
