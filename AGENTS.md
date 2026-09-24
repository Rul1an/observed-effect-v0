# AGENTS.md

Instructions for coding agents working in or reading this repository. The human
overview is [README.md](README.md); this file is the machine-oriented entry point.

## What this is

Three worked observed-effect experiments. An observed-effect record is issued by
an observer that is not the component whose behaviour it describes, so it sits in
a different source class than a self-report. The record does not prove who wrote it: the class
is fixed by where a consumer obtained the record, not by anything inside it (README,
"Source class and claim ceiling"). The records are bounded evidence
artifacts: they claim no runtime truth, intent, maliciousness, safety, or
enforcement. The external verdict vocabulary is `match | mismatch | incomplete
| invalid`.

## Layout

Each directory is a self-contained experiment with the same shape:

- `below-harness-observer-carrier-2026-06/`: observer and coverage normalization, with a Tetragon adapter.
- `observed-effect-drift-consumer-2026-06/`: the v0 producer and consumer contract, sample records, an independent consumer.
- `observed-effect-neutral-carriers-2026-06/`: one frozen record in four neutral carriers (standalone JCS, in-toto DSSE Statement, an MCP reference slot, a SCITT-shaped COSE statement), recomputing to one content address in each.

Inside each: a generator, an independent reproducer or consumer that shares no
code with it, committed `vectors.json` and `result.json` goldens, a `test_*.py`,
and a `verify-golden.sh`.

## Run it

Every experiment verifies with the standard library only, no network:

```bash
cd <experiment-dir> && bash verify-golden.sh
```

The golden script checks three things: the committed vectors match a fresh emit,
the committed result matches a fresh verify, and the independent reproducer
re-derives everything from the bytes alone. Exit 0 means no drift.

## The invariants a change must not break

1. The observer is not the observed component. That separation is the source class, and it is what a verifier may rely on; do not blur it into a self-report.
2. Recomputing a digest confirms the bytes are intact under the declared canonicalization. It does not raise the record's vantage. Signing, hash-chaining, and time-anchoring raise tamper-evidence, never vantage.
3. The record is not an envelope for other formats to profile under, and it conforms to no vendor's envelope. The same frozen record travels in several carriers and recomputes to one content address in each.
4. The `non_claims` ride inside the digest. What the record contributes is the observation and its explicit limits, nothing more.

## Editing conventions

- Keep the reproducers standard-library-only and free of shared code with the generators; that independence is the point.
- Regenerate the goldens with the experiment's own generator, never by hand, and keep `verify-golden.sh` at a clean pass before committing.
- The generators are cwd-confined and reject absolute or out-of-tree paths; keep that.
