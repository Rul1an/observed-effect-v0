# observed_effect v0

This export contains three worked observed-effect experiments:

- `below-harness-observer-carrier-2026-06/` shows observer/coverage normalization and a Tetragon adapter.
- `observed-effect-drift-consumer-2026-06/` shows the v0 producer/consumer contract, sample records, and an independent consumer.
- `observed-effect-neutral-carriers-2026-06/` shows the same frozen v0 record embedded in four neutral carriers (standalone JCS, in-toto DSSE Statement, an MCP reference slot, and a SCITT-shaped COSE statement), recomputing to one identical content address in each.

The examples are bounded evidence-contract artifacts. They do not claim runtime truth, intent inference,
maliciousness detection, safety, compliance, or runtime enforcement. The external verdict vocabulary is
`match | mismatch | incomplete | invalid`.

## Source class and claim ceiling

An observed-effect record is independently issued: the observer that emits it is not the component whose
behaviour it describes. That places it in a different source class than a self-report, or a record signed
by the party that made the decision it records. The class is part of the contract, because it bounds what
a verifier may conclude.

Recomputing a digest confirms the bytes are intact under the declared canonicalization. It does not raise
the record's vantage. Recomputing a self-issued record confirms what the issuer recorded, not what
occurred; the same recompute over an independently observed record supports a stronger conclusion because
the vantage is stronger, not because the hash is. Signing, hash-chaining, and time-anchoring raise
tamper-evidence, never vantage.

The record does not establish its own issuer. Nothing in it tells an observer's record apart from one
the subject wrote in the same shape, so `basis: observed` is the writer's statement, and the verdict a
consumer derives from it is only as independent as the writer. Which class a record belongs to is fixed
outside the record, by where the consumer obtained it: which observer, over which channel. A verifier
that accepts `basis: observed` from a writer it has not identified is grading a self-report as an
observation.

These records are correspondingly not an envelope for other formats to profile under, and they do not
conform to any vendor's envelope. The same frozen record travels in four carriers below and recomputes to
one content address in each; any carrier that declares its canonicalization beside its digest can hold
it. What the record contributes is the observation and its explicit limits (the `non_claims` ride inside
the digest), nothing more.

## Composing with MCP

The neutral-carriers example carries the record in an MCP reference slot. Since late June 2026 that shape
is specified in the Tool Annotations extension draft
([experimental-ext-tool-annotations](https://github.com/modelcontextprotocol/experimental-ext-tool-annotations),
`specification/draft/trust-annotations.mdx`, merged 2026-06-26): an `evidenceRef` whose
`type`/`digest`/`canonicalization` triple is the minimum a client needs to re-derive the referenced
record locally, with `cbor/rfc8949` and `jcs/rfc8785` both valid and neither the default.

A worked pointer to the frozen record in this export, using the merged field set:

```jsonc
{
  "_meta": {
    "io.modelcontextprotocol/trust-annotations": {
      "evidenceRef": {
        "type": "observed-effect",
        "digest": "sha256:c2a9723ea19504aad6f8336ccbac9d9e434d6246064d404ed8e741e1930c789c",
        "canonicalization": "jcs/rfc8785",
        "schema": "https://assay.dev/schemas/observed-effect.v0.json",
        "ref": "audit://observed-effect/match_agreement"
      }
    }
  }
}
```

A client that resolves the record behind this pointer can recompute the address from the bytes alone with
the stdlib consumer in `observed-effect-drift-consumer-2026-06/`, and should read the record's own
`non_claims` before concluding anything. The carrier example in
`observed-effect-neutral-carriers-2026-06/` predates the merged draft and uses an equivalent earlier
canonicalization label; the recompute is label-independent, which that example's alias record
demonstrates. The record is not part of, nor endorsed by, the extension. It composes with the reference
shape, the same way it resolves under in-toto and SCITT.

To verify deterministic goldens:

```sh
cd below-harness-observer-carrier-2026-06 && ./verify-golden.sh
cd ../observed-effect-drift-consumer-2026-06 && ./verify-golden.sh
cd ../observed-effect-neutral-carriers-2026-06 && ./verify-golden.sh
```

To run tests:

```sh
python -m pytest below-harness-observer-carrier-2026-06 observed-effect-drift-consumer-2026-06 observed-effect-neutral-carriers-2026-06
```

## Someone other than the author has run these

In June 2026, Syed Maaz Ahmed ([@MaazAhmed47](https://github.com/MaazAhmed47)), an external
implementer, ran all three examples and then tried to break two of the five false-green cases above:
*absence is not clean* and *the producer cannot grade its own coverage*. The documented behaviour and
both guards held under those tests.

Recorded because the section above claims these records are independently issued, and until now the
only person on record as having executed them was their author. That is a weaker position than the
text implies, and the gap was invisible rather than argued.

It is not an audit and not an endorsement, and it is not offered as either. What it establishes is
narrow and worth stating exactly: on the vectors in this export, at that time, the two guards
withstood an outside attempt to defeat them. Cited with permission.

## Related

- [Assay](https://github.com/Rul1an/assay) produces and verifies evidence bundles at the MCP tool-call boundary; these records compose with that layer.
- [gateway-evidence-replay](https://github.com/Rul1an/gateway-evidence-replay) replays gateway-path evidence offline to a bounded verdict.
- [RGE-Bench](https://github.com/rge-bench/rge-bench) is a neutral conformance kit whose axes can be read against this record format (among others).
