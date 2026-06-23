#!/usr/bin/env python3
"""Independent verifier for the observed-effect v0 conformance corpus.

Imports no code from this repository and needs only the Python standard library, so passing it is
conformance to the published fixtures, not to any one implementation. It re-derives every content
address and every verdict from the record bytes alone — no issuer, no key, no callback — and checks
them against the committed `expected.json`, then recomputes the `corpusDigest` in `corpus-meta.json`.

    python3 run.py        # exit 0 = all cases reproduce; 1 = any divergence

Two suites:
  record_conformance_v0 — per-record recompute: sha256(JCS(body)) must equal envelope.digest under the
    declared canonicalization (recognized aliases resolve to jcs-json-v1); an unimplemented label and a
    tampered body both fail closed; basis maps to the consumer vocabulary match|mismatch|incomplete.
  record_set_v0 — coverage across a set: a required channel with no observed record is incomplete, so
    absent never reads as clean; an observed divergence is a mismatch; otherwise sufficient.
"""
import hashlib
import json
import os
import sys

PROFILE = "jcs-json-v1"
ALIASES = {"json/jcs-rfc8785": PROFILE, "JCS": PROFILE, PROFILE: PROFILE}
HERE = os.path.dirname(os.path.abspath(__file__))


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


def recompute(rec):
    """Return one of recomputed | mismatch | unsupported_canonicalization for a record."""
    env = rec["envelope"]
    if ALIASES.get(env.get("canonicalization")) != PROFILE:
        return "unsupported_canonicalization"
    return "recomputed" if address(rec["body"]) == env["digest"] else "mismatch"


def record_verdict(rec):
    rc = recompute(rec)
    if rc != "recomputed":
        return rc, "invalid"
    b = rec["body"]
    basis = b.get("basis")
    if basis in ("not_observed", "unknown"):
        return rc, "incomplete"
    if basis == "observed":
        return rc, "mismatch" if b.get("divergence") else "match"
    return rc, "invalid"


def set_verdict(case):
    recs = case["records"]
    for r in recs:
        if recompute(r) != "recomputed":
            return "invalid"
    for ch in case["required_channels"]:
        observed_here = any(
            r["body"].get("basis") == "observed"
            and (ch in (r["body"].get("declared_effect") or {}) or ch in (r["body"].get("observed_effect") or {}))
            for r in recs
        )
        if not observed_here:
            return "incomplete"
    if any(r["body"].get("divergence") for r in recs):
        return "mismatch"
    return "sufficient"


def load(sub, name):
    with open(os.path.join(HERE, "corpus", sub, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def main():
    expected = json.load(open(os.path.join(HERE, "expected.json"), encoding="utf-8"))
    meta = json.load(open(os.path.join(HERE, "corpus-meta.json"), encoding="utf-8"))
    fails = 0
    checks = 0

    print("\nobserved-effect v0 conformance corpus — independent recompute (stdlib only)\n")

    print("record_conformance_v0:")
    for name, exp in sorted(expected["record_conformance_v0"].items()):
        rec = load("record_conformance_v0", name)
        rc, verdict = record_verdict(rec)
        ok = (rc == exp["recompute"] and verdict == exp["verdict"])
        checks += 1
        fails += 0 if ok else 1
        print("  %s %-28s recompute=%-26s verdict=%s" % ("OK " if ok else "XX ", name, rc, verdict))
        if not ok:
            print("       expected recompute=%s verdict=%s" % (exp["recompute"], exp["verdict"]))

    print("\nrecord_set_v0:")
    for name, exp in sorted(expected["record_set_v0"].items()):
        case = load("record_set_v0", name)
        verdict = set_verdict(case)
        ok = (verdict == exp["verdict"])
        checks += 1
        fails += 0 if ok else 1
        print("  %s %-28s verdict=%s" % ("OK " if ok else "XX ", name, verdict))
        if not ok:
            print("       expected verdict=%s" % exp["verdict"])

    # corpusDigest: rebuild the manifest from the corpus bytes and re-address it.
    manifest = {}
    root = os.path.join(HERE, "corpus")
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, HERE).replace(os.sep, "/")
            manifest[rel] = "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
    recomputed_digest = address(manifest)
    digest_ok = recomputed_digest == meta.get("corpusDigest")
    checks += 1
    fails += 0 if digest_ok else 1
    print("\ncorpusDigest: %s  %s" % ("OK" if digest_ok else "XX", recomputed_digest))

    print("\n%d checks, %d failed" % (checks, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
