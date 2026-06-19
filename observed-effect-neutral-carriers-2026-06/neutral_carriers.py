#!/usr/bin/env python3
"""Neutrality by construction: one observed-effect record, four neutral carriers, one address.

The point this experiment makes is structural, not rhetorical. An ``assay.observed_effect.v0``
record is addressed by ``sha256`` over its canonical bytes (RFC 8785 JCS). That content address does
not change when the record is carried inside someone else's envelope. So the SAME record body, byte
for byte, rides inside four independent neutral carriers and resolves to the SAME address in every
one:

  1. standalone-jcs          — the bare content-addressed record (the baseline shape).
  2. in-toto-dsse-statement  — an in-toto Statement (DSSE payload). The observed-effect body is the
                               ``predicate``; ``predicateType`` is an Assay-namespaced URI; the
                               Statement ``subject`` digest is the record's content address.
  3. mcp-sep1913-evidenceRef — a small trust annotation that points at the record through a
                               reference slot ``{type, digest, canonicalization, schema, ref}``
                               (the shape the SEP-1913 thread converged on: a stable annotation
                               rides the protocol, the evidence sits behind the reference).
  4. scitt-cose-statement    — a SCITT-shaped signed statement: the record's canonical bytes are the
                               COSE_Sign1 payload, addressed by ``sha256`` over those bytes.

A record that N independent envelopes can carry, and that N independent parties can recompute to the
same address from the bytes alone, is by construction not any one envelope's profile. The neutrality
is shown by use, not asserted in a preamble.

What this is NOT:
  - Not a signing demo. DSSE signatures and the COSE_Sign1 / SCITT transparency receipt are modeled
    structurally and left unsigned (``signatures: []`` / ``receipt: null``); the record asserts no
    signature of its own (see the record's own ``non_claims``). The claim here is embeddability and
    address-stability, not authenticity.
  - Not a claim that any one canonical label is "the" standard label. The address recomputes
    regardless of the label string (the alias record proves it). The label is a registry name for
    versioning; the recompute is what carries the neutrality.

Stdlib only, fail closed. Same discipline as the sibling observed-effect-drift and evidenceref
experiments. The frozen v0 record bytes are reused unchanged, so a digest here equals the digest the
drift consumer already recomputed.

Usage:
    python3 neutral_carriers.py emit             > carriers.json
    python3 neutral_carriers.py verify carriers.json
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Tuple

# ── Identity of the predicate / record (Assay-namespaced; the envelope is neutral) ────────────────
PREDICATE_TYPE = "https://assay.dev/predicates/observed-effect/v0"
RECORD_SCHEMA = "assay.observed_effect.v0"
RECORD_SCHEMA_URL = "https://assay.dev/schemas/observed-effect.v0.json"
CANONICAL_LABEL = "jcs-json-v1"  # RFC 8785 JCS; the recompute is label-independent
CANON_ALIASES = {"json/jcs-rfc8785": "jcs-json-v1", "JCS": "jcs-json-v1"}
CARRIERS = ("standalone-jcs", "in-toto-dsse-statement", "mcp-sep1913-evidenceRef", "scitt-cose-statement")

# The frozen v0 non_claims (the limits-on-the-tin ride inside the digest and cannot be stripped).
NON_CLAIMS = [
    "observation, not a verdict: this record carries no action, severity, or decision and cannot drive a block by itself",
    "not runtime truth: coverage is bounded to the scope field; absence of an observed effect within scope is not proof none occurred",
    "a recompute match proves the bytes are intact under the declared profile, not that the projection is complete enough to support any claim",
    "says nothing about the tool author's trust or intent; surface drift remains the deterministic authority",
    "observer/consumer record, not an issuer: no signature or attestation is asserted here",
]


def _body(basis: str, declared: Dict[str, Any], observed: Dict[str, Any], divergence: List[str], scope: str, tool: str) -> Dict[str, Any]:
    return {
        "basis": basis,
        "coverage": "bounded",
        "declared_effect": declared,
        "divergence": divergence,
        "non_claims": list(NON_CLAIMS),
        "observed_effect": observed,
        "schema": RECORD_SCHEMA,
        "schema_version": "0",
        "scope": scope,
        "tool": tool,
    }


# Representative subset of the frozen v0 sample records, with their frozen content addresses. Each
# `expected` is asserted at emit time, so any byte drift in the body breaks the build (these are the
# exact bytes the drift consumer recomputed).
RECORDS: List[Dict[str, Any]] = [
    {
        "id": "match_agreement",
        "label": "jcs-json-v1",
        "expected": "sha256:c2a9723ea19504aad6f8336ccbac9d9e434d6246064d404ed8e741e1930c789c",
        "body": _body("observed",
                      {"network": ["egress:tcp:api.github.com:443"]},
                      {"network": ["egress:tcp:api.github.com:443"]},
                      [], "ipv4_tcp_connect", "sync_repo"),
    },
    {
        "id": "divergence_egress",
        "label": "jcs-json-v1",
        "expected": "sha256:07c8ade8a21a0447ad2b871947cb87e4fbd8590fb6bf2c13f1f8bd707e6f5713",
        "body": _body("observed",
                      {"filesystem": ["read:/docs"], "network": []},
                      {"filesystem": ["read:/docs"], "network": ["egress:tcp:203.0.113.7:443"]},
                      ["egress"], "ipv4_tcp_connect", "fetch_doc"),
    },
    {
        "id": "divergence_multi",
        "label": "jcs-json-v1",
        "expected": "sha256:64e3a25a43f1904b40439ac1ab97bafd5bc5bdbaa11def8df95e0f5ce0822647",
        "body": _body("observed",
                      {"filesystem": [], "network": []},
                      {"filesystem": ["write:/opt/app/cfg"], "network": ["egress:tcp:203.0.113.7:443"]},
                      ["egress", "filesystem"], "ipv4_tcp_connect", "deploy"),
    },
    {
        "id": "insufficient_not_observed",
        "label": "jcs-json-v1",
        "expected": "sha256:69b842ea8668c5617cc6ed36897bb1d1bfab3ad6b095e345d8c1b7bad89d7ca4",
        "body": _body("not_observed",
                      {"filesystem": ["read:/docs"], "network": []},
                      {},
                      [], "ipv4_tcp_connect", "fetch_doc"),
    },
    {
        # Same algorithm, stamped under a recognized alias label. The address is identical to the
        # canonical-label spelling — the recompute does not depend on the label string.
        "id": "alias_labeled_egress",
        "label": "json/jcs-rfc8785",
        "expected": "sha256:49e3f6d790539b4de1adfeae43a3970f1782bfc4284f2c500b4cc020d599fc51",
        "body": _body("observed",
                      {"network": []},
                      {"network": ["egress:tcp:203.0.113.7:443"]},
                      ["egress"], "ipv4_tcp_connect", "fetch_doc"),
    },
]


# ── Canonicalization + address (RFC 8785 JCS over a float-free value space) ────────────────────────
def jcs(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def address(body: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs(body)).hexdigest()


def _hex(digest: str) -> str:
    return digest.split(":", 1)[1]


# ── Carrier builders: the SAME body embedded four ways ────────────────────────────────────────────
def build_standalone(rec: Dict[str, Any], digest: str) -> Dict[str, Any]:
    ref = f"audit://neutral/{rec['id']}"
    return {
        "envelope": {
            "type": "observed-effect",
            "canonicalization": rec["label"],
            "digest": digest,
            "schema": RECORD_SCHEMA_URL,
            "schema_version": "0",
            "ref": ref,
        },
        "body": rec["body"],
    }


def build_intoto(rec: Dict[str, Any], digest: str) -> Dict[str, Any]:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": f"observed-effect/{rec['id']}", "digest": {"sha256": _hex(digest)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": rec["body"],
    }
    payload = jcs(statement)  # JCS for a deterministic golden; DSSE itself does not require it
    return {
        "dsse": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [],  # signing out of scope
        }
    }


def build_sep1913(rec: Dict[str, Any], digest: str) -> Dict[str, Any]:
    ref = f"mcp-evidence://{rec['id']}"
    # Mirrors the SEP-1913 reference-slot shape: a small stable annotation rides the protocol; the
    # evidence record sits behind an envelope-agnostic reference. Namespace shown illustratively.
    return {
        "_meta": {
            "dev.assay/trust-annotations": {
                "trust": "review",
                "evidenceRef": {
                    "type": "observed-effect",
                    "digest": digest,
                    "canonicalization": rec["label"],
                    "schema": RECORD_SCHEMA_URL,
                    "ref": ref,
                },
            }
        },
        "resolved_evidence": {ref: rec["body"]},
    }


def build_scitt(rec: Dict[str, Any], digest: str) -> Dict[str, Any]:
    payload = jcs(rec["body"])  # the record's canonical bytes ARE the statement payload
    return {
        "cose_sign1_modeled": True,
        "protected": {
            "3": "application/observed-effect+json",  # COSE label 3 = content type
            "scitt_statement_note": "COSE_Sign1 / transparency receipt modeled; signing out of scope",
        },
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "statement_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "receipt": None,  # SCITT transparency receipt out of scope
    }


BUILDERS = {
    "standalone-jcs": build_standalone,
    "in-toto-dsse-statement": build_intoto,
    "mcp-sep1913-evidenceRef": build_sep1913,
    "scitt-cose-statement": build_scitt,
}


# ── Reference extraction: pull the body back out of each carrier, its native way ──────────────────
def extract_standalone(c: Dict[str, Any]) -> Dict[str, Any]:
    return c["body"]


def extract_intoto(c: Dict[str, Any]) -> Dict[str, Any]:
    statement = json.loads(base64.b64decode(c["dsse"]["payload"]))
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError("unexpected predicateType")
    return statement["predicate"]


def extract_sep1913(c: Dict[str, Any]) -> Dict[str, Any]:
    slot = c["_meta"]["dev.assay/trust-annotations"]["evidenceRef"]
    return c["resolved_evidence"][slot["ref"]]


def extract_scitt(c: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(base64.b64decode(c["payload_b64"]))


EXTRACTORS = {
    "standalone-jcs": extract_standalone,
    "in-toto-dsse-statement": extract_intoto,
    "mcp-sep1913-evidenceRef": extract_sep1913,
    "scitt-cose-statement": extract_scitt,
}


# ── emit / verify ─────────────────────────────────────────────────────────────────────────────────
def emit() -> Dict[str, Any]:
    records = []
    for rec in RECORDS:
        digest = address(rec["body"])
        if digest != rec["expected"]:
            raise SystemExit(f"FROZEN BYTE DRIFT for {rec['id']}: {digest} != {rec['expected']}")
        carriers = {name: BUILDERS[name](rec, digest) for name in CARRIERS}
        records.append({
            "id": rec["id"],
            "canonicalization_label": rec["label"],
            "resolves_to": CANON_ALIASES.get(rec["label"], rec["label"]),
            "expected_digest": digest,
            "carriers": carriers,
        })
    return {
        "schema": "assay.observed_effect.neutral_carriers.v0",
        "canonical_canonicalization": CANONICAL_LABEL,
        "recognized_aliases": sorted(CANON_ALIASES),
        "predicate_type": PREDICATE_TYPE,
        "carriers_proven": list(CARRIERS),
        "invariant": "one content address per record, identical across every carrier and equal to the frozen v0 digest",
        "records": records,
    }


def verify(doc: Dict[str, Any]) -> Dict[str, Any]:
    results = []
    all_agree = True
    for rec in doc["records"]:
        expected = rec["expected_digest"]
        addresses = {}
        for name in CARRIERS:
            body = EXTRACTORS[name](rec["carriers"][name])
            addresses[name] = address(body)
        agree = len(set(addresses.values())) == 1 and next(iter(addresses.values())) == expected
        # Cross-check the in-toto subject digest and the SCITT statement digest name the same address.
        subj = json.loads(base64.b64decode(rec["carriers"]["in-toto-dsse-statement"]["dsse"]["payload"]))["subject"][0]["digest"]["sha256"]
        scitt_d = rec["carriers"]["scitt-cose-statement"]["statement_digest"]
        anchors_agree = ("sha256:" + subj == expected) and (scitt_d == expected)
        ok = agree and anchors_agree
        all_agree = all_agree and ok
        results.append({
            "id": rec["id"],
            "expected_digest": expected,
            "addresses": addresses,
            "carriers_agree": agree,
            "embedded_anchors_agree": anchors_agree,
            "ok": ok,
        })
    return {
        "schema": "assay.observed_effect.neutral_carriers.result.v0",
        "records_checked": len(results),
        "carriers_per_record": len(CARRIERS),
        "all_carriers_resolve_to_one_address": all_agree,
        "results": results,
    }


def main(argv: List[str]) -> int:
    if len(argv) >= 1 and argv[0] == "emit":
        print(json.dumps(emit(), indent=2, sort_keys=True))
        return 0
    if len(argv) >= 2 and argv[0] == "verify":
        path = argv[1]
        if os.path.isabs(path) or ".." in path.replace("\\", "/").split("/"):
            raise SystemExit(f"refusing an unsafe path: {path!r}")
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        res = verify(doc)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0 if res["all_carriers_resolve_to_one_address"] else 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
