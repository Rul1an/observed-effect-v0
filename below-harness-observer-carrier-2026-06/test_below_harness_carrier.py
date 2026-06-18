#!/usr/bin/env python3
"""Tests for observer/coverage normalization and the Tetragon adapter.

Mirrors the required check-list: observer.type required, unknown coverage fails closed, missing /
not_observed required coverage -> incomplete (never match), declared-vs-observed mismatch, the
Tetragon mapping, and recompute-from-bytes digest stability. A second implementation that shares no
code re-derives every verdict and digest.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys

import pytest

import observer_carrier as oc
import tetragon_adapter as ta

HERE = os.path.dirname(os.path.abspath(__file__))


# ── Observer / coverage normalization + the invariant ───────────────────────────────────────

def test_observer_type_required():
    rec = oc.build_record("t", {"network": []}, {"network": []}, [], "observed", "s",
                          {"type": "", "version": "1", "mode": "observe", "kernel": "k"},
                          {d: "observed" for d in oc.COVERAGE_DIMENSIONS})
    assert oc.evaluate(rec, ["network_connect"])["verdict"] == "invalid"


def test_unknown_coverage_value_fails_closed_not_match():
    rec = oc.build_record("t", {"network": []}, {"network": []}, [], "observed", "s",
                          {"type": "tetragon"}, {"network_connect": "partial"})
    v = oc.evaluate(rec, ["network_connect"])
    assert v["verdict"] == "invalid"
    assert v["verdict"] != "match"


def test_missing_required_coverage_is_incomplete():
    rec = oc.build_record("t", {"network": []}, {}, [], "not_observed", "s",
                          {"type": "tetragon"}, {"process_exec": "observed"})  # network dim absent
    assert oc.evaluate(rec, ["network_connect"])["verdict"] == "incomplete"


def test_not_observed_required_dimension_is_incomplete():
    rec = oc.build_record("t", {"network": []}, {}, [], "not_observed", "s",
                          {"type": "tetragon"}, {"network_connect": "not_observed"})
    assert oc.evaluate(rec, ["network_connect"])["verdict"] == "incomplete"


def test_match_only_when_all_required_observed_and_matching():
    full = {d: "observed" for d in oc.COVERAGE_DIMENSIONS}
    rec = oc.build_record("t", {"network": []}, {"network": []}, [], "observed", "s",
                          {"type": "tetragon"}, full)
    assert oc.evaluate(rec, ["network_connect"])["verdict"] == "match"
    # remove the required dimension's observation -> must drop out of match
    partial = dict(full); partial["network_connect"] = "not_observed"
    rec2 = oc.build_record("t", {"network": []}, {"network": []}, [], "not_observed", "s",
                           {"type": "tetragon"}, partial)
    assert oc.evaluate(rec2, ["network_connect"])["verdict"] != "match"


def test_mismatch_when_observed_diverges_under_full_coverage():
    full = {d: "observed" for d in oc.COVERAGE_DIMENSIONS}
    rec = oc.build_record("t", {"network": []}, {"network": ["egress:tcp:203.0.113.7:443"]},
                          ["egress"], "observed", "s",
                          {"type": "tetragon"}, full)
    assert oc.evaluate(rec, ["network_connect"])["verdict"] == "mismatch"


def test_invariant_no_match_with_missing_required_coverage_across_all_cases():
    doc = oc.emit()
    for group in ("observer_coverage_cases", "tetragon_adapter_cases"):
        for c in doc[group]:
            case = c["case"]
            if case["verdict"]["verdict"] == "match":
                for dim in case["required_coverage"]:
                    assert case["record"]["coverage"].get(dim) == "observed", (c["id"], dim)


# ── Tetragon adapter ────────────────────────────────────────────────────────────────────────

def test_tetragon_connect_maps_to_network_connect_observed():
    carrier = ta.to_carrier(ta.FIXTURES["tetragon_connect_mismatch"])
    rec = carrier["record"]
    assert rec["coverage"]["network_connect"] == "observed"
    assert rec["observed_effect"]["network"] == ["egress:tcp:203.0.113.7:443"]
    assert rec["observer"]["type"] == "tetragon"


def test_tetragon_declared_no_network_plus_connect_is_mismatch():
    carrier = ta.to_carrier(ta.FIXTURES["tetragon_connect_mismatch"])
    assert carrier["verdict"]["verdict"] == "mismatch"


def test_tetragon_watched_but_no_connect_is_match():
    carrier = ta.to_carrier(ta.FIXTURES["tetragon_watched_no_connect_match"])
    assert carrier["verdict"]["verdict"] == "match"


def test_tetragon_network_not_watched_is_incomplete_not_pass():
    carrier = ta.to_carrier(ta.FIXTURES["tetragon_network_not_watched_incomplete"])
    assert carrier["record"]["coverage"]["network_connect"] == "not_observed"
    assert carrier["verdict"]["verdict"] == "incomplete"
    assert carrier["verdict"]["verdict"] not in ("match", "pass")


def test_tetragon_malformed_event_is_invalid_not_match():
    carrier = ta.safe_to_carrier(ta.FIXTURES["tetragon_malformed_invalid"])
    assert carrier["verdict"]["verdict"] == "invalid"
    assert carrier["record"] is None
    assert carrier["verdict"]["verdict"] != "match"


def test_tetragon_recompute_from_input_bytes_same_digest():
    # Re-run the adapter on the committed input bytes -> identical record digest.
    inp = json.loads(json.dumps(ta.FIXTURES["tetragon_connect_mismatch"]))
    a = ta.to_carrier(inp)
    b = ta.to_carrier(json.loads(json.dumps(inp)))
    assert a["digest"] == b["digest"]
    assert a["digest"] == oc.digest(a["record"])


# ── Whole-suite verify + independent reproduction ────────────────────────────────────────────────

def test_reference_verify_green(tmp_path):
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps(oc.emit()))
    out = subprocess.run([sys.executable, os.path.join(HERE, "observer_carrier.py"), "verify", "vectors.json"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    res = json.loads(out.stdout)
    assert res["all_expected"] and res["all_invariants_hold"]


def test_independent_reproducer_shares_no_code():
    src = open(os.path.join(HERE, "independent_consumer.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert "observer_carrier" not in a.name and "tetragon_adapter" not in a.name
        if isinstance(node, ast.ImportFrom):
            assert not node.module or ("observer_carrier" not in node.module and "tetragon_adapter" not in node.module)


def test_independent_reproducer_rederives_all(tmp_path):
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps(oc.emit()))
    out = subprocess.run([sys.executable, os.path.join(HERE, "independent_consumer.py"), "vectors.json"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    assert json.loads(out.stdout)["all_reproduced"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-q"]))
