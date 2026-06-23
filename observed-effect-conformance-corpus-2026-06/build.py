#!/usr/bin/env python3
"""Generate the observed-effect v0 conformance corpus (two suites).

This mints the corpus records, computes each envelope digest under jcs-json-v1 (RFC 8785), writes the
committed `expected.json` (the authoritative per-case verdicts), and stamps `corpus-meta.json` with a
`corpusDigest` over the corpus file bytes. `run.py` is the independent verifier: it re-derives every
digest and verdict from the bytes alone and checks them against the committed expectations, importing
no code from this repository.

Two suites, mapped to the record-reference contract properties:
  record_conformance_v0 — per-record, key-free recompute: the content address recomputes from the
    body bytes under the declared canonicalization, with no issuer and no key; tampering fails closed;
    a value that is not independently re-derived is marked, not implied.
  record_set_v0 — coverage across a set under one boundary: a required channel that was not observed
    is surfaced as incomplete, so absent never quietly reads as clean. (observed-effect carries
    completeness on `basis`/`coverage`, the way vaara.receipt carries it on a per-boundary sequence.)
"""
import hashlib
import json
import os

PROFILE = "jcs-json-v1"
ALIASES = {"json/jcs-rfc8785": PROFILE, "JCS": PROFILE}
SCHEMA = "assay.observed_effect.v0"
HERE = os.path.dirname(os.path.abspath(__file__))

NON_CLAIMS = [
    "observation, not a verdict: this record carries no action, severity, or decision",
    "a recompute match proves the bytes are intact under the declared profile, not that coverage is "
    "complete enough to support any claim",
    "not an issuer: no signature or attestation is asserted by the record itself",
]


# ── RFC 8785 JCS (pure standard library; the corpus value space is float-free) ─────────────────────
def _jcs_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\r':
            out.append('\\r')
        elif c < 0x20:
            out.append('\\u%04x' % c)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _jcs(o):
    if o is True:
        return "true"
    if o is False:
        return "false"
    if o is None:
        return "null"
    if isinstance(o, str):
        return _jcs_string(o)
    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        if o != o or o in (float("inf"), float("-inf")):
            raise ValueError("RFC 8785 rejects NaN and Infinity")
        if o.is_integer():
            return str(int(o))
        raise ValueError("non-integer float not serialized by jcs-json-v1")
    if isinstance(o, list):
        return "[" + ",".join(_jcs(x) for x in o) + "]"
    if isinstance(o, dict):
        items = sorted(o.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v) for k, v in items) + "}"
    raise TypeError(type(o).__name__)


def address(body):
    return "sha256:" + hashlib.sha256(_jcs(body).encode("utf-8")).hexdigest()


def body(basis, declared, observed, divergence, scope="ipv4_tcp_connect", tool="fetch_doc", extra_nc=None):
    nc = list(NON_CLAIMS) + (extra_nc or [])
    return {
        "basis": basis,
        "coverage": "bounded",
        "declared_effect": declared,
        "divergence": divergence,
        "non_claims": nc,
        "observed_effect": observed,
        "schema": SCHEMA,
        "schema_version": "0",
        "scope": scope,
        "tool": tool,
    }


def envelope(b, canon=PROFILE, digest_over=None):
    return {
        "canonicalization": canon,
        "digest": address(digest_over if digest_over is not None else b),
        "ref": "audit://observed-effect/rec",
        "schema": SCHEMA,
        "type": "application/assay-observed-effect+json",
    }


# ── Suite 1: record_conformance_v0 ─────────────────────────────────────────────────────────────────
def conformance_cases():
    cases = []

    ok = body("observed", {"network": ["egress:tcp:api.github.com:443"]},
              {"network": ["egress:tcp:api.github.com:443"]}, [])
    cases.append(("ok_observed", {"id": "ok_observed", "kind": "match", "envelope": envelope(ok), "body": ok},
                  {"recompute": "recomputed", "verdict": "match"}))

    dv = body("observed", {"network": []}, {"network": ["egress:tcp:203.0.113.7:443"]}, ["egress"])
    cases.append(("divergence_observed", {"id": "divergence_observed", "kind": "mismatch",
                  "envelope": envelope(dv), "body": dv},
                  {"recompute": "recomputed", "verdict": "mismatch"}))

    ab = body("not_observed", {"filesystem": ["write:/var/out"]}, {}, [], scope="filesystem_writes")
    cases.append(("coverage_absent", {"id": "coverage_absent", "kind": "incomplete",
                  "envelope": envelope(ab), "body": ab},
                  {"recompute": "recomputed", "verdict": "incomplete"}))

    ia = body("unknown", {"network": ["egress:tcp:api.github.com:443"]},
              {"network": ["egress:tcp:api.github.com:443"]}, [],
              extra_nc=["issuer-attested: this observation is reported by an upstream source and is "
                        "not independently re-derived by this record"])
    cases.append(("issuer_attested", {"id": "issuer_attested", "kind": "incomplete",
                  "envelope": envelope(ia), "body": ia},
                  {"recompute": "recomputed", "verdict": "incomplete"}))

    # alias label: digest under a recognized alias resolves to jcs-json-v1 and still recomputes.
    al = body("observed", {"network": ["egress:tcp:api.github.com:443"]},
              {"network": ["egress:tcp:api.github.com:443"]}, [], tool="fetch_alias")
    cases.append(("alias_label", {"id": "alias_label", "kind": "match",
                  "envelope": envelope(al, canon="json/jcs-rfc8785"), "body": al},
                  {"recompute": "recomputed", "verdict": "match"}))

    # tampered: digest taken over the original body, then one field mutated -> recompute fails closed.
    orig = body("observed", {"network": ["egress:tcp:api.github.com:443"]},
                {"network": ["egress:tcp:api.github.com:443"]}, [], tool="fetch_tampered")
    tampered = json.loads(json.dumps(orig))
    tampered["observed_effect"] = {"network": ["egress:tcp:evil.example:443"]}
    cases.append(("tampered_body", {"id": "tampered_body", "kind": "invalid",
                  "envelope": envelope(orig, digest_over=orig), "body": tampered},
                  {"recompute": "mismatch", "verdict": "invalid"}))

    # unsupported canonicalization: a label this profile does not implement -> fail closed.
    un = body("observed", {"network": []}, {"network": []}, [], tool="fetch_unsupported")
    env = envelope(un)
    env["canonicalization"] = "jcs-json-v2-unimplemented"
    cases.append(("unsupported_canonicalization", {"id": "unsupported_canonicalization", "kind": "invalid",
                  "envelope": env, "body": un},
                  {"recompute": "unsupported_canonicalization", "verdict": "invalid"}))

    return cases


# ── Suite 2: record_set_v0 ─────────────────────────────────────────────────────────────────────────
def _rec(b):
    return {"envelope": envelope(b), "body": b}


def set_cases():
    cases = []
    req = ["network", "filesystem"]

    net_ok = body("observed", {"network": ["egress:tcp:api.github.com:443"]},
                  {"network": ["egress:tcp:api.github.com:443"]}, [], scope="ipv4_tcp_connect")
    fs_ok = body("observed", {"filesystem": ["write:/var/out"]}, {"filesystem": ["write:/var/out"]}, [],
                 scope="filesystem_writes", tool="write_out")
    cases.append(("set_complete", {"id": "set_complete", "boundary": "chain:agent-run-7a1d",
                  "required_channels": req, "records": [_rec(net_ok), _rec(fs_ok)]},
                  {"verdict": "sufficient"}))

    fs_absent = body("not_observed", {"filesystem": ["write:/var/out"]}, {}, [],
                     scope="filesystem_writes", tool="write_out")
    cases.append(("set_coverage_absent", {"id": "set_coverage_absent", "boundary": "chain:agent-run-7a1d",
                  "required_channels": req, "records": [_rec(net_ok), _rec(fs_absent)]},
                  {"verdict": "incomplete"}))

    fs_unknown = body("unknown", {"filesystem": ["write:/var/out"]}, {}, [],
                      scope="filesystem_writes", tool="write_out")
    cases.append(("set_unknown", {"id": "set_unknown", "boundary": "chain:agent-run-7a1d",
                  "required_channels": req, "records": [_rec(net_ok), _rec(fs_unknown)]},
                  {"verdict": "incomplete"}))

    net_dv = body("observed", {"network": []}, {"network": ["egress:tcp:203.0.113.7:443"]}, ["egress"],
                  scope="ipv4_tcp_connect")
    cases.append(("set_divergence", {"id": "set_divergence", "boundary": "chain:agent-run-7a1d",
                  "required_channels": req, "records": [_rec(net_dv), _rec(fs_ok)]},
                  {"verdict": "mismatch"}))

    return cases


def write_corpus():
    expected = {"record_conformance_v0": {}, "record_set_v0": {}}
    for sub, cases in (("record_conformance_v0", conformance_cases()), ("record_set_v0", set_cases())):
        d = os.path.join(HERE, "corpus", sub)
        os.makedirs(d, exist_ok=True)
        for name, rec, exp in cases:
            with open(os.path.join(d, name + ".json"), "w", encoding="utf-8") as f:
                f.write(json.dumps(rec, indent=2, sort_keys=True) + "\n")
            expected[sub][name] = exp
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(expected, indent=2, sort_keys=True) + "\n")

    # corpusDigest over the corpus file bytes (relpath -> sha256 of the file), then one address.
    manifest = {}
    root = os.path.join(HERE, "corpus")
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, HERE).replace(os.sep, "/")
            manifest[rel] = "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
    corpus_digest = address(manifest)
    meta = {"version": "1.0.0", "profile": PROFILE, "corpusDigest": corpus_digest,
            "files": manifest, "suites": ["record_conformance_v0", "record_set_v0"]}
    with open(os.path.join(HERE, "corpus-meta.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    print("wrote corpus; corpusDigest =", corpus_digest)


if __name__ == "__main__":
    write_corpus()
