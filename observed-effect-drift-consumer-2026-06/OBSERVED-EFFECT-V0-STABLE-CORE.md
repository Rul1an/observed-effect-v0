# Observed-effect record — v0 stable core (producer/consumer interop)

> Experimental. The stable core below is the part a consuming gate depends on; everything else
> is advisory detail. Pinned with one consumer (a drift gate) signing off on the shape; the record
> stays producer-agnostic and is not defined by any single consumer.

## What the record is

An **independent observed effect, below the harness, bounded**: a vantage separate from the tool
(not the tool's self-report, not only what crossed a gateway), at the level where the effect happens
(an egress connect, a file write), with its coverage named so absence within scope is never a clean
pass. The record carries **no verdict** — it hands a consumer honest signals, and the consumer decides.

## Stable core (what a gate reads to reach a call)

A consumer's gate reads exactly three things, and nothing else has to be parsed field-by-field:

1. **`basis`** — the observation's honesty/coverage for this record:
   - `observed` — the effect was actually observed.
   - `not_observed` — the relevant channel was not in coverage. Cannot be clean → the consumer
     maps this to insufficient-coverage / review.
   - `unknown` — observed inconclusively. Same: cannot be clean.
   Absence is carried here, never laundered into a clean pass.

2. **`divergence`** — a list of capability-axis **kinds** naming what diverged from the declaration.
   Kinds are axis-level and consumer-readable, encoding neither producer nor consumer internals:
   - `egress` — an outbound network effect.
   - `filesystem` — a file write, modify, or delete.
   - `data_read` — a read of sensitive data.
   - `exec` — a process spawn or code execution.

3. **The envelope** the consumer already cites by: `{ type, digest, canonicalization, schema, ref }`.
   `digest` is `sha256:<hex>` over the canonical record bytes (`canonicalization: "jcs-json-v1"`),
   so any party can recompute the address from the bytes without trusting the producer.

   The canonical canonicalization label is **`jcs-json-v1`** (RFC 8785 JCS). Two other spellings name the
   same RFC 8785 algorithm and are **recognized aliases** that resolve to it: `json/jcs-rfc8785` (the
   drift-gate emitter's wire value) and `JCS` (the SEP-2828 side). A conformant implementation stamps the
   canonical label for new records and resolves any recognized alias on read, so records already exported
   under an alias still verify. The whole substrate converges on one canonical label with the rest as
   recognized aliases, rather than each pair maintaining bilateral aliases.

## Advisory detail (in the digest, not a gate input)

`declared_effect`, `observed_effect`, `scope`, `coverage` ride inside the digest as the operator's
"why". They cannot be stripped without breaking verification, but a consumer's gate does not read them
field-by-field to reach its call.

**Scope is advisory in v0.** A divergence is a divergence regardless of how much else the observer was
watching; coverage breadth bites the *clean* side, and `basis` already carries that (`not_observed` →
insufficient coverage). If a consumer ever genuinely keys on coverage breadth (treating a mismatch under
narrow coverage differently from one under broad), `scope` joins the stable core as an explicit
append-only bump — but it stays out of v0.

## Producer and consumer roles

The **producer** on this axis is an effect observer (for example Assay) that emits records. A
**consumer** is a gate that reads them, resolving the record from the envelope, verifying the digest
before trusting the body, mapping divergence kinds to its own decision, and treating `not_observed` /
`unknown` as insufficient coverage. A surface-drift-only tool is a **consumer on this axis, not a
producer**: a declaration diff is `basis = not_observed` (a diff, not an observation), so it reads
observed-effect records rather than emitting them.

## Rules

- **Producer-agnostic.** Anything that observes effects emits this shape. A gate is one consumer of it,
  not its definition. The kinds read cleanly for any consumer.
- **Pinned, append-only versioning.** A new field, a new `basis` value, or a new `divergence` kind is an
  explicit version bump, never a quiet reinterpretation of v0.
- **No verdict on the record.** The consumer's verdict vocabulary lives on the consumer side. Suggested
  external vocabulary: `match | mismatch | incomplete | invalid`. "clean" is avoided in external wording
  because it reads as "safe" in a security context.

## Conformance

Two independent implementations agree on: the canonical bytes, the `basis` value, the `divergence`
kinds, and the digest a gate cites — read from the bytes alone, with neither implementation importing
the other. That recompute-from-bytes agreement is the interop gate; the verdict each consumer derives is
explicitly out of scope.
