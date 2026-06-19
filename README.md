# observed_effect v0

This export contains three worked observed-effect experiments:

- `below-harness-observer-carrier-2026-06/` shows observer/coverage normalization and a Tetragon adapter.
- `observed-effect-drift-consumer-2026-06/` shows the v0 producer/consumer contract, sample records, and an independent consumer.
- `observed-effect-neutral-carriers-2026-06/` shows the same frozen v0 record embedded in four neutral carriers (standalone JCS, in-toto DSSE Statement, an MCP reference slot, and a SCITT-shaped COSE statement), recomputing to one identical content address in each.

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
```

To run tests:

```sh
python -m pytest below-harness-observer-carrier-2026-06 observed-effect-drift-consumer-2026-06 observed-effect-neutral-carriers-2026-06
```
