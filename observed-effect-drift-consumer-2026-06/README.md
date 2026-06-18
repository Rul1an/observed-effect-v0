# Observed-effect drift: a bounded advisory beneath a deterministic gate

> Experimental worked example. Not a stable Assay API. This is the observation and composition
> layer only, not a trust, issuer, or runtime-truth verdict.

A surface-drift gate compares a tool's baseline declaration against its current declaration, hashed
both ways. It is deterministic and recomputable, same bytes in same verdict, which is what lets it
sit in a blocking path without inference. It cannot see the case where the declaration never moves
but the implementation does something else at runtime: a tool that keeps `network: []` declared and
still makes an egress connect. This experiment shows an `assay.observed_effect.v0` record catching
that divergence, and composes it with the surface verdict under one rule that keeps the deterministic
core clean.

The record stays strictly subordinate to the surface hash. It carries no action, severity, or
decision; the merge reads facts only and is monotone toward caution. "Advisory, not authoritative"
is therefore structural, not a label: there is nothing in the record to wire to an auto-block.

What the record carries is an **independent observed effect, below the harness, bounded**.
*Independent*: the effect is seen from a vantage separate from the tool being observed — not the
server's self-report (an attested execution record a producer signs about itself), and not only what
crossed a gateway (a proxy sees what passes through it, not a side effect that goes around it). The
observer is not the observed. *Below the harness*: at the level where the effect actually happens, an
egress connect or a file write, beneath the declared surface a hash can pin and beneath the protocol a
gateway sees. *Bounded*: every record names its own coverage in `scope` and `coverage`, those bounds
ride inside the digest, and absence within scope is never a clean pass. That is the whole claim, and
deliberately no more.

## Run

```bash
python3 observed_effect_consumer.py emit            > vectors.json   # regenerate the vector bytes
python3 observed_effect_consumer.py verify vectors.json              # reference: reproduce + invariants
python3 independent_consumer.py vectors.json                         # independent: reproduce from bytes alone
python3 sample_records.py emit > sample-records.json                 # producer-side sample set for a reader
python3 sample_records.py verify sample-records.json                 # every sample envelope recomputes
pytest                                                               # 18 tests: matrix, guards, interop, alias, samples
```

Over 14 cases the reference and a second implementation that shares no code agree on every composed
decision. The independent reproducer re-derives both layers (recompute and merge) from `vectors.json`
with separate code, asserted by an AST test, so the set reproduces from the bytes alone rather than
from one implementation trusting another. Two canonicalization profiles are exercised, `jcs-json-v1`
(RFC 8785) and `cbor-deterministic-v1` (RFC 8949 section 4.2); the headline record resolves to the
same composed decision under both.

## Two layers

1. **Recompute (content addressing).** The record is addressed by `sha256` over its canonical bytes
   under the declared profile. A consumer re-derives the digest and resolves required-field
   completeness against its **own** registry. Digest mismatch, unsupported profile, unknown schema,
   and incomplete projection all fail closed. The envelope is the same
   `{type, digest, canonicalization, schema, ref}` shape a drift record is cited by in the MCP
   trust-annotations draft (io.modelcontextprotocol, 2026-06-10), so it drops into a gate that
   already cites evidence by digest. The canonical canonicalization label is `jcs-json-v1` (RFC 8785
   JCS); `json/jcs-rfc8785` and `JCS` are recognized aliases that resolve to it, so a record exported
   under another spelling still verifies.

2. **Merge (the decision).** The recomputed record folds into a deterministic surface verdict under
   one invariant: **effect evidence is monotone toward caution.** It may raise caution
   (`surface_clean` → `review_required`, or `quarantine` only under an explicit operator opt-in) or
   be neutral. It may never downgrade a surface block, and it never mints a hash-authority auto-block.
   The surface hash is always the authority.

## The seam (the headline case)

A tool keeps `network: []` declared while the observed effect is an egress connect. The surface
declaration never moved, so a surface gate alone sees nothing. The observed-effect record carries
`divergence: ["egress"]`, `basis: observed`, `scope: ipv4_tcp_connect`,
recomputes clean, and the merge raises the decision to `review_required` — not a hard block. Under an
operator opt-in the same record promotes to `quarantine`, still labelled effect-driven and distinct
from a surface block.

`scope` is `ipv4_tcp_connect` because that is the one observation channel this carries honestly today;
the record names its own bound rather than implying full runtime coverage.

## Five false-green cases, impossible by construction

1. **Absence is not clean.** `basis: not_observed` or `unknown` resolves to `insufficient_coverage`
   and `review_required`, never `allow`. A missing observation is a coverage gap, not a pass.
2. **Effect evidence cannot borrow the hash's authority.** The record emits no verdict, so there is
   structurally nothing for it to block with; the surface hash stays the deterministic core and effect
   divergence raises only to `review_required` unless the operator opts in.
3. **Stripping the bounds breaks the digest.** `basis`, `scope`, and `coverage` are inside the
   canonical bytes the digest commits to, so the limits-on-the-tin cannot be dropped while keeping a
   clean recompute; the advisory is rejected.
4. **A broken advisory fails closed and never downgrades.** A tampered body mismatches its digest, the
   advisory is rejected, and the decision falls back to the surface verdict — a block stays a block, and
   a clean surface stays `allow`. Defeating the advisory can never do better than no advisory at all.
5. **The producer cannot grade its own coverage.** Completeness and profile meaning resolve on the
   consumer side; a body that smuggles its own `action` field still recomputes, but the merge derives
   from facts and ignores it.

## Five non-claims

1. **Observation, not a verdict.** The record carries no action, severity, or decision and cannot drive
   a block by itself.
2. **Not runtime truth.** Coverage is bounded to `scope`; absence of an observed effect within scope is
   not proof none occurred. Observed support is the ceiling.
3. **A recompute match is not claim sufficiency.** It proves the bytes are intact under the declared
   profile, not that the projection is complete enough to support any block.
4. **Composition layer only.** Grounding the declaration against an independent observed basis is this
   experiment's axis; verifying issuer or signature trust is a separate one and is out of scope. This is
   an observer/consumer record, not an issuer: no signature or attestation is asserted here.
5. **Bounded value space and counts.** The two profiles cover the value space of these vectors
   (float-free JSON and the CBOR types used here); counts describe this vector set only, not real-world
   prevalence.

## A documented design choice

A rejected advisory on a clean surface falls back to `allow` rather than raising to review. That keeps
the rule strictly monotone: a broken or absent advisory contributes nothing and can never make a
decision less cautious than the surface verdict alone. A consumer that *expects* an advisory for a
given tool may instead treat `advisory_rejected` as raise-to-review; the neutral fallback is the
conservative interop default, chosen so a tampered advisory can never be more permissive than no
advisory.
