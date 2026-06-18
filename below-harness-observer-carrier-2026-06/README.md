# Below-harness observer carrier — observer/coverage normalization + first adapter

> Experimental worked example. Not a stable Assay API, not an eBPF agent, not a runtime
> security product. This is the evidence-contract layer over a below-harness observer's output.

The below-harness space is splitting into two parts: the sensor/enforcement substrate (eBPF plumbing
such as Tetragon) and the evidence contract over what that substrate produced.
This experiment takes the second. It does not observe anything itself; it normalizes whatever a
below-harness observer reported into a bounded, recomputable carrier, and renders one honest verdict.

What the carrier carries is an **independent observed effect, below the harness, bounded**: independent
because the observer is a vantage separate from the tool, below the harness because the effect is a
real syscall-level event (an egress connect), and bounded because every record states, per dimension,
what the observer actually watched.

## Two parts

**Part 1 — observer/coverage normalization** (`observer_carrier.py`). Append-only extension of
`assay.observed_effect.v0` to `v1`: an `observer` block (`type`, `version`, `mode`, `kernel`) and a
per-dimension `coverage` map (`process_exec`, `network_connect`, `file_open`, `payload_content` →
`observed` / `not_observed`). Both ride inside the digest, so neither the source nor the bounds can be
stripped while keeping the recompute intact.

**Part 2 — Tetragon adapter** (`tetragon_adapter.py`). The first adapter: a Tetragon export (events +
the coverage profile Tetragon was configured to watch) → an `observed_effect.v1` carrier. It claims
only what it can: *Tetragon observed a network effect under this coverage profile; normalized into
bounded evidence against a declared no-network expectation.* It does not claim Tetragon proves
maliciousness or runtime truth, and it does not treat Tetragon as a trusted oracle.

## The load-bearing invariant (a test, not a doc line)

```
missing or not_observed REQUIRED coverage  ->  incomplete, never match
```

A verdict can be `match` only when every coverage dimension the expectation requires was actually
observed. An unobserved network channel cannot clear a "declared no network" expectation — you did not
look. The honesty hinges on the **coverage profile**, not on event presence: "Tetragon watched the
network and saw no connect" is a real match; "Tetragon was not watching the network" is `incomplete`.
Those two facts must never collapse into the same verdict, and the Tetragon adapter keeps them apart.

## Run

```bash
python3 observer_carrier.py emit            > vectors.json
python3 observer_carrier.py verify vectors.json      # reference: recompute + invariants
python3 independent_consumer.py vectors.json         # independent: reproduce from bytes alone
pytest                                               # 16 tests: observer normalization, adapter, invariant, interop
```

Verdicts over the committed set: `match` 2, `incomplete` 3, `invalid` 3, `mismatch` 2. A second
implementation that shares no code (AST-asserted) re-derives every digest and verdict from the bytes.

## Verdicts

- `match` — required coverage present and observed; observed matched declared.
- `mismatch` — required coverage present and observed; the observed effect diverges from the declaration
  (declared no network, an egress was observed).
- `incomplete` — a required coverage dimension was missing or `not_observed`. Never a pass.
- `invalid` — malformed: no `observer.type`, an unknown coverage value, or a Tetragon event the adapter
  cannot map. Fails closed, never match.

> The verdict `match` means observed matched declared under complete required coverage; it is **not** a
> safety claim. The external vocabulary is `match | mismatch | incomplete | invalid`.

## Non-claims

1. Observation, not runtime truth — bounded to the coverage map; an unobserved dimension is a gap, not
   a pass.
2. The observer is a source of evidence, not a trusted oracle of intent or maliciousness.
3. A match verdict means observed matched declared under the stated coverage, and says nothing about
   what was not observed.
4. Declared-vs-observed is against the tool's own declaration, **not** a learned behavioral baseline.
5. Observer/consumer record, not an issuer — no signature or attestation is asserted here, and Assay
   does not enforce; it normalizes what an enforcer or observer already produced.

## Scope

This is integration-before-agents: Assay consumes a below-harness observer's output, it does not build
one. Tetragon is the first adapter because it is the widest-deployed substrate; AgentSight and an
ActPlane enforcement receipt are the next adapters. No eBPF is built or shipped here.
