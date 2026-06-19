# Observed-effect record — neutrality by construction (four carriers, one address)

> Experimental. A producer artifact. It carries no verdict and makes no security claim. The point is
> structural: an observed-effect record's identity is its content address, and that address does not
> change when the record rides inside someone else's envelope.

## What this shows

The same `assay.observed_effect.v0` record body — byte for byte, the frozen v0 bytes a drift
consumer already recomputed — is embedded in **four independent neutral carriers**, and resolves to
**one identical content address** in every one:

| Carrier | Where the record sits | What names the address |
|---|---|---|
| `standalone-jcs` | the bare content-addressed record | `envelope.digest` |
| `in-toto-dsse-statement` | the in-toto `predicate` (DSSE payload) | `subject[0].digest.sha256` |
| `mcp-sep1913-evidenceRef` | behind a reference slot on a small trust annotation | `evidenceRef.digest` |
| `scitt-cose-statement` | the COSE_Sign1 payload of a SCITT-shaped statement | `statement_digest` |

`address = sha256( JCS(record_body) )`, RFC 8785. A reproducer that shares no code with the emitter
pulls the body back out of each carrier its own way and recomputes the address; all four agree, and
all four equal the frozen v0 digest. A record that four independent envelopes can carry, and that two
independent implementations recompute to the same address, is **by construction not any one
envelope's profile**.

## Why it matters

The neutral container in this space is being framed by various producers as something to *pin to* as
a downstream profile. This experiment answers that without arguing about it: the record is a **typed
predicate** (`predicateType: https://assay.dev/predicates/observed-effect/v0`, an Assay-namespaced
URI) that rides on **neutral primitives** — RFC 8785 JCS canonicalization, SHA-256 content
addressing, and a small `{type, digest, canonicalization, schema, ref}` reference shape. The envelope
layers (in-toto Statement, the MCP reference slot, a SCITT statement) are owned by no single vendor;
Assay owns only the predicate type. That is the in-toto model: the envelope is neutral, a predicate
type belongs to whoever defines it.

## The label is non-load-bearing

One record (`alias_labeled_egress`) is stamped under a recognized alias label (`json/jcs-rfc8785`
instead of the registry canonical `jcs-json-v1`). It still recomputes to the same address in every
carrier, because the recompute reads the bytes, not the label string. The canonical label is a
registry name for versioning; **the neutrality rests on recompute-from-bytes, not on owning a label**.
Recognized aliases (`json/jcs-rfc8785`, `JCS`) name the same RFC 8785 algorithm.

## Files

- `neutral_carriers.py` — reference emitter + verifier (builds the four carriers, checks the one-address invariant).
- `independent_recompute.py` — independent reproducer, imports nothing from the emitter (asserted in tests).
- `carriers.json` — the emitted four-carrier golden.
- `result.json` — the committed verify output.
- `test_neutral_carriers.py` — invariant, byte-identity, tamper-fails-closed, alias resolution, ownership-boundary, reproducer-independence.
- `verify-golden.sh` — golden sync-guard.

## Run

```
python3 neutral_carriers.py emit > carriers.json
python3 neutral_carriers.py verify carriers.json
python3 independent_recompute.py carriers.json
python3 -m pytest test_neutral_carriers.py -q
./verify-golden.sh
```

## Claims and non-claims

**Claim.** The observed-effect record's content address is stable across four neutral carriers and is
independently recomputable from the bytes in each. Embeddability and address-stability — nothing more.

**Non-claims.**
- Not a signing demo. DSSE signatures and the COSE_Sign1 / SCITT transparency receipt are modeled
  structurally and left unsigned; the record asserts no signature of its own.
- Not a claim that any one canonicalization label is *the* standard label. No SEP pins one; the field
  is envelope-agnostic and the recompute is label-independent.
- The record still carries no verdict, is not runtime truth, and says nothing about a tool author's
  trust or intent. Observed support is the ceiling. These are inherited from the v0 record and ride
  inside the digest (stripping them breaks the address — see the test).
- The SEP-1913 annotation namespace shown here is illustrative of the reference-slot shape, not a
  registered identifier.
