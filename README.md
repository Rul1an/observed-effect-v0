# observed_effect v0

This export contains two worked observed-effect experiments:

- `below-harness-observer-carrier-2026-06/` shows observer/coverage normalization and a Tetragon adapter.
- `observed-effect-drift-consumer-2026-06/` shows the v0 producer/consumer contract, sample records, and an independent consumer.

The examples are bounded evidence-contract artifacts. They do not claim runtime truth, intent inference,
maliciousness detection, safety, compliance, or runtime enforcement. The external verdict vocabulary is
`match | mismatch | incomplete | invalid`.

To verify deterministic goldens:

```sh
cd below-harness-observer-carrier-2026-06 && ./verify-golden.sh
cd ../observed-effect-drift-consumer-2026-06 && ./verify-golden.sh
```

To run tests:

```sh
python -m pytest below-harness-observer-carrier-2026-06 observed-effect-drift-consumer-2026-06
```
