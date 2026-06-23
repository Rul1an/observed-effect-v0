# observed_effect v0

This export contains four worked observed-effect experiments:

- `below-harness-observer-carrier-2026-06/` shows observer/coverage normalization and a Tetragon adapter.
- `observed-effect-drift-consumer-2026-06/` shows the v0 producer/consumer contract, sample records, and an independent consumer.
- `observed-effect-neutral-carriers-2026-06/` shows the same frozen v0 record embedded in four neutral carriers (standalone JCS, in-toto DSSE Statement, an MCP reference slot, and a SCITT-shaped COSE statement), recomputing to one identical content address in each.
- `observed-effect-conformance-corpus-2026-06/` is a standalone, dependency-free conformance corpus (two suites: `record_conformance_v0` per-record key-free recompute, and `record_set_v0` coverage across a set) with a stdlib-only verifier that re-derives every address and verdict from the bytes and checks a `corpusDigest`.

All canonicalization is RFC 8785 (`jcs-json-v1`); each example carries a pure-standard-library RFC 8785 implementation that fails closed on non-integer floats, `NaN`, and `Infinity` rather than the `json.dumps(sort_keys=True)` shortcut (see the neutral-carriers `test_canonicalization_rfc8785.py` for the divergence points).

The examples are bounded evidence-contract artifacts. They do not claim runtime truth, intent inference,
maliciousness detection, safety, compliance, or runtime enforcement. The external verdict vocabulary is
`match | mismatch | incomplete | invalid`.

## Composing with MCP

The neutral-carriers example carries the record in an MCP reference slot, the shape being worked out in
[MCP SEP-1913 (Trust and Sensitivity Annotations)](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1913):
a small annotation rides the protocol and points at the evidence behind a `{digest, canonicalization,
schema, ref}` slot. The record resolves there by digest, the same way it resolves under in-toto and
SCITT. It is not part of, nor endorsed by, the SEP — it just composes with a neutral reference shape.

To verify deterministic goldens:

```sh
cd below-harness-observer-carrier-2026-06 && ./verify-golden.sh
cd ../observed-effect-drift-consumer-2026-06 && ./verify-golden.sh
cd ../observed-effect-neutral-carriers-2026-06 && ./verify-golden.sh
cd ../observed-effect-conformance-corpus-2026-06 && python3 run.py
```

To run tests:

```sh
python -m pytest below-harness-observer-carrier-2026-06 observed-effect-drift-consumer-2026-06 observed-effect-neutral-carriers-2026-06
```
