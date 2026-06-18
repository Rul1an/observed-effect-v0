#!/usr/bin/env python3
"""Canonical observed_effect v0 sample records for a consumer reader.

A producer-side (the effect observer, e.g. Assay) set of valid ``observed_effect`` v0 records plus their
evidenceRef envelopes, for a consumer building a net-new reader to build and test against. Each sample is
self-contained: resolve the body from ``envelope.ref``, verify ``envelope.digest`` over the canonical
bytes of the body (recognized aliases resolve to the canonical ``jcs-json-v1``), then read ``basis`` and
the ``divergence`` kinds. The record carries no verdict; the decision stays on the consumer side.

Built on the frozen v0 producer functions in ``observed_effect_consumer`` so the samples can never drift
from the pinned shape. The digest is always over the canonical RFC 8785 bytes; one sample stamps a
recognized alias label on the envelope (same algorithm, different label) so a reader can prove it resolves.

Usage:
    python3 sample_records.py emit            > sample-records.json
    python3 sample_records.py verify sample-records.json
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from observed_effect_consumer import (
    SCHEMA_REGISTRY,
    _confined_path,
    build_evidence_ref,
    build_observed_effect,
    recompute,
)

CANONICAL = "jcs-json-v1"
RECOGNIZED_ALIASES = ["json/jcs-rfc8785", "JCS"]
KIND_MEANINGS = {
    "egress": "an outbound network effect",
    "filesystem": "a file write, modify, or delete",
    "data_read": "a read of sensitive data",
    "exec": "a process spawn or code execution",
}


def _sample(sid: str, note: str, body: Dict[str, Any], label: str = CANONICAL) -> Dict[str, Any]:
    loc = f"audit://sample/{sid}"
    # The digest is always over the canonical RFC 8785 bytes; the envelope may carry a recognized alias
    # label (same algorithm, different spelling) that a reader resolves to the canonical on read.
    env = build_evidence_ref(body, CANONICAL, ref=loc)
    if label != CANONICAL:
        env["canonicalization"] = label
    return {"id": sid, "note": note, "envelope": env, "body": body}


def build_samples() -> List[Dict[str, Any]]:
    return [
        _sample(
            "match_agreement",
            "basis=observed, divergence=[]: observed matched declared. Within the declared set.",
            build_observed_effect(
                "sync_repo", {"network": ["egress:tcp:api.github.com:443"]},
                {"network": ["egress:tcp:api.github.com:443"]}, [], "observed", "ipv4_tcp_connect")),
        _sample(
            "divergence_egress",
            "basis=observed, divergence=[egress]: declared no network, an outbound connect was observed.",
            build_observed_effect(
                "fetch_doc", {"network": [], "filesystem": ["read:/docs"]},
                {"network": ["egress:tcp:203.0.113.7:443"], "filesystem": ["read:/docs"]},
                ["egress"], "observed", "ipv4_tcp_connect")),
        _sample(
            "divergence_filesystem",
            "basis=observed, divergence=[filesystem]: declared no writes, a file write was observed.",
            build_observed_effect(
                "render_report", {"filesystem": []},
                {"filesystem": ["write:/etc/cron.d/sched"]}, ["filesystem"], "observed", "file_write")),
        _sample(
            "divergence_data_read",
            "basis=observed, divergence=[data_read]: a read of sensitive data outside the declared scope.",
            build_observed_effect(
                "summarize", {"filesystem": ["read:/docs"]},
                {"filesystem": ["read:/etc/shadow"]}, ["data_read"], "observed", "file_read")),
        _sample(
            "divergence_exec",
            "basis=observed, divergence=[exec]: an undeclared process spawn was observed.",
            build_observed_effect(
                "lint", {}, {"process": ["spawn:/bin/sh"]}, ["exec"], "observed", "process_exec")),
        _sample(
            "divergence_multi",
            "basis=observed, divergence=[egress, filesystem]: more than one capability axis diverged.",
            build_observed_effect(
                "deploy", {"network": [], "filesystem": []},
                {"network": ["egress:tcp:203.0.113.7:443"], "filesystem": ["write:/opt/app/cfg"]},
                ["egress", "filesystem"], "observed", "ipv4_tcp_connect")),
        _sample(
            "insufficient_not_observed",
            "basis=not_observed: the relevant channel was not in coverage. Insufficient coverage, never a pass.",
            build_observed_effect(
                "fetch_doc", {"network": [], "filesystem": ["read:/docs"]}, {}, [], "not_observed",
                "ipv4_tcp_connect")),
        _sample(
            "insufficient_unknown",
            "basis=unknown: observed inconclusively. Insufficient coverage, never a pass.",
            build_observed_effect("fetch_doc", {"network": []}, {}, [], "unknown", "ipv4_tcp_connect")),
        _sample(
            "alias_labeled_egress",
            "Same record as divergence_egress, but the envelope is stamped json/jcs-rfc8785 (a recognized "
            "alias). A reader resolves the alias to jcs-json-v1 and the digest still verifies.",
            build_observed_effect(
                "fetch_doc", {"network": []}, {"network": ["egress:tcp:203.0.113.7:443"]},
                ["egress"], "observed", "ipv4_tcp_connect"),
            label=RECOGNIZED_ALIASES[0]),
    ]


def emit() -> Dict[str, Any]:
    return {
        "schema": "assay.observed_effect.samples.v0",
        "canonical_canonicalization": CANONICAL,
        "recognized_aliases": RECOGNIZED_ALIASES,
        "divergence_kinds": KIND_MEANINGS,
        "reader_contract": (
            "Resolve the body from envelope.ref, verify envelope.digest is sha256 over the canonical "
            "bytes of the body under the label (recognized aliases resolve to jcs-json-v1), then read "
            "basis and the divergence kinds. basis in (not_observed, unknown) is insufficient coverage, "
            "never a pass. The record carries no verdict; the decision is the consumer's."
        ),
        "samples": build_samples(),
    }


def verify(path: str) -> int:
    with open(_confined_path(path), encoding="utf-8") as fh:
        doc = json.load(fh)
    failures: List[str] = []
    summary: List[Dict[str, Any]] = []
    for s in doc["samples"]:
        env, body = s["envelope"], s["body"]
        rv = recompute(env, {env.get("ref"): body}, SCHEMA_REGISTRY)
        if rv.get("verdict") != "recomputed":
            failures.append(f"{s['id']}: {rv}")
        summary.append({
            "id": s["id"],
            "canonicalization": env.get("canonicalization"),
            "basis": body.get("basis"),
            "divergence": body.get("divergence"),
            "recompute": rv.get("verdict"),
        })
    result = {
        "schema": "assay.observed_effect.samples.v0",
        "samples": len(doc["samples"]),
        "all_recomputed": not failures,
        "summary": summary,
        "failures": failures,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


def main(argv: List[str]) -> int:
    if len(argv) >= 2 and argv[1] == "emit":
        print(json.dumps(emit(), indent=2, sort_keys=True))
        return 0
    if len(argv) >= 2 and argv[1] == "verify":
        return verify(argv[2] if len(argv) > 2 else "sample-records.json")
    sys.stderr.write(__doc__ or "")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
