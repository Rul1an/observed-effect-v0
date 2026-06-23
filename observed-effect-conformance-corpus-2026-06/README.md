# observed-effect v0 — conformance corpus

A standalone, dependency-free corpus that exercises the observed-effect v0 record against the
record-reference contract: artifact bytes, a content-address digest over exactly those bytes, an
evidence family and schema, a scope, key-free recompute, explicit coverage, and explicit non-claims.
`run.py` imports no code from this repository and needs only the Python standard library, so passing
it is conformance to the published fixtures, not to any one implementation.

```
python3 run.py        # exit 0 = every address and verdict reproduces from the bytes; 1 = divergence
python3 build.py      # regenerate the corpus + expected.json + corpus-meta.json
```

`corpusDigest` (v1.0.0): `sha256:a329ad40b61d18d8418e791e07092ead0dfd462c7ca6129a0a5366aea91ca1aa`

## Two suites

- **`record_conformance_v0`** — per-record, key-free recompute. For each record, `sha256(JCS(body))`
  must equal `envelope.digest` under the declared canonicalization (recognized aliases resolve to
  `jcs-json-v1`). `tampered_body` mutates the body after the digest was taken and fails closed on
  recompute; `unsupported_canonicalization` names a label this profile does not implement and fails
  closed; `issuer_attested` carries an observation the record marks as upstream-reported and not
  independently re-derived (`basis: unknown`), so it reads as incomplete, never as observed.
- **`record_set_v0`** — coverage across a set under one boundary. A required channel with no observed
  record is `incomplete`, so absent never quietly reads as clean; an observed divergence is a
  `mismatch`; otherwise `sufficient`. observed-effect carries completeness on `basis`/`coverage`, the
  way other receipt formats carry it on a per-boundary sequence — the same contract property, a
  different mechanism.

The consumer vocabulary is `match | mismatch | incomplete | invalid`. The record itself carries no
verdict; `run.py` derives one the way a consuming gate would, from the bytes alone.

## Mapping to the record-reference contract

| Property | Where it lives | Status |
|----------|----------------|--------|
| canonical bytes | `envelope.canonicalization` names the transform (`jcs-json-v1` = RFC 8785) | declared on the record |
| content address | `envelope.digest` = `sha256` over the canonical body bytes, not over a later assertion | recomputed key-free in `run.py` |
| evidence family + schema | `envelope.type` + `schema` / `schema_version` | declared on the record |
| scope | `body.scope` names the observation boundary | declared on the record |
| freshness | **not pinned in v0** — the record carries no external time anchor | **honest gap**, stated below |
| recompute | `run.py` re-derives address and verdict with no issuer/key; `issuer_attested` is marked, not implied | yes |
| coverage | `basis ∈ {observed, not_observed, unknown}`; `record_set_v0` surfaces a not-observed required channel as incomplete | yes |
| non-claims | every record carries `non_claims` | yes |

## Non-claims

- A recompute match proves the bytes are intact under the declared profile, not that coverage is
  complete enough to support any claim.
- The record carries no verdict, no severity, and no action; the decision is the consumer's.
- The record is not an issuer: no signature or attestation is asserted by the record itself.
- **Freshness is not pinned in v0.** The corpus does not carry an external time anchor, so it makes
  no claim about when an observation was made relative to a trusted clock. A record-reference contract
  that pins freshness would add an external time attestation alongside the address; that is out of
  scope for v0 and called out here rather than implied.
- This is one worked instance under the record-reference contract, not the envelope: it sits beside
  other conforming receipt formats as a peer, none of them the contract itself.

## Canonicalization

`jcs-json-v1` is RFC 8785. `build.py` and `run.py` each carry a pure-standard-library RFC 8785
implementation (keys ordered by UTF-16 code units, JSON minimal string escaping, integers as decimal)
that fails closed on non-integer floats, `NaN`, and `Infinity` rather than emit bytes that could
diverge from RFC 8785. It is not the `json.dumps(sort_keys=True)` shortcut; see
[`../observed-effect-neutral-carriers-2026-06/test_canonicalization_rfc8785.py`](../observed-effect-neutral-carriers-2026-06/test_canonicalization_rfc8785.py)
for the divergence points.
