# Daylight v15 Meridian Authorized Envelope (MAE)

Date: 2026-06-30

The Meridian Authorized Envelope is the full realization of v15 Meridian as a
cryptographic system: a real, vector-checked AEAD whose key derivation and
open-gate are governed by Meridian's evidence-derived, fail-closed obligation
logic. It is the Daylight v0.6 authorized-envelope pattern made concrete —
`Open = bottom` unless an authorization holds — with Meridian obligations as the
authorization predicate.

Design and scores: [WUCI_DAYLIGHT_V15_MERIDIAN.md](WUCI_DAYLIGHT_V15_MERIDIAN.md).
Artifact/CLI: [DAYLIGHT_V15_MERIDIAN_SOFTWARE_ARTIFACT.md](DAYLIGHT_V15_MERIDIAN_SOFTWARE_ARTIFACT.md).
Host vault built on this envelope: [WUCI_DAYLIGHT_V15_MERIDIAN_VAULT.md](WUCI_DAYLIGHT_V15_MERIDIAN_VAULT.md).

## The law, enforced cryptographically

```text
NoEvidence(x)  -> NoScore(x)  -> NoSeal(x)
NoProof(x)     -> NoClaim(x)  -> NoOpen(x)
ManualScore(x) -> Reject(x)   -> NoOpen(x)
```

A scorecard is never trusted; it is re-derived from frozen evidence on both seal
and open. A tampered scorecard, an inflated score, an unmet policy, or a missing
obligation yields no key and no plaintext.

## The cipher (real and verifiable)

`src/aead.py` is a faithful pure-Python implementation of:

- **ChaCha20-Poly1305 AEAD** — RFC 8439
- **HKDF-SHA256** — RFC 5869

Correctness is proven against the published RFC test vectors in
`tests/test_aead_vectors.py` (ChaCha20 §2.3.2/§2.4.2 keystream, Poly1305 §2.5.2,
the AEAD §2.8.2 "Ladies and Gentlemen" vector, and HKDF RFC 5869 case 1). This is
real, standard cryptography — not a toy.

Boundary: it is a research reference, written for clarity and determinism, **not
constant-time** and not side-channel hardened. Do not protect real secrets with
it.

## How Meridian governs the encryption

The AEAD key and the authenticated header are both bound to a Meridian
**authorization tag**:

```text
authorization_tag = SHA256( domain || canonical{
    obligations_digest, scorecard_digest, final_score_M,
    closed_obligation_ids (sorted), policy } )

aead_key = HKDF-SHA256(
    ikm  = caller_key,
    salt = SHA256(MAGIC || header_bytes),
    info = "DAYLIGHT-v15-MERIDIAN-MAE v1 aead-key:" || authorization_tag )

AAD = MAGIC || u32(len(header)) || header_bytes   # authenticated, not encrypted
```

The header carries the **policy** (`min_score_M`, `required_closed_obligations`,
`obligations_digest`) and the authorization summary. Because the key depends on
the authorization tag and the whole header is the AEAD associated data, any change
to the policy, the score, or the closed-obligation set produces a different key
and fails the Poly1305 tag — in addition to the explicit fail-closed checks.

### Seal (authorize, then encrypt)

1. Generate a scorecard from frozen evidence (ledger + corpus) and verify it
   evidence-bound. If it does not verify → refuse.
2. Check the policy: `final_score_M >= min_score_M`, registry digest matches, and
   every `required_closed_obligations` id is closed. If not → refuse
   (`NoScore -> NoSeal`).
3. Derive the key from `caller_key` + authorization tag; AEAD-encrypt.

### Open (re-authorize, then decrypt) — fail-closed

1. Parse the header (keyless).
2. Re-derive the scorecard from the caller's evidence and verify it
   evidence-bound. If not → `Open = bottom`.
3. Re-check the sealed policy. If not satisfied → `Open = bottom`.
4. Recompute the authorization tag; it must equal the sealed one → otherwise
   `Open = bottom`.
5. Only now derive the key and check the AEAD tag. Wrong key or tampered bytes →
   `Open = bottom`.

## Frame layout

```text
offset  field
0       8     ASCII "WUCIMAE1"
8       4     little-endian uint32 header length H
12      H     canonical-JSON header (magic, version, suite, nonce, policy,
              authorization, boundary)
12+H    N     ChaCha20-Poly1305 ciphertext
12+H+N  16    Poly1305 tag over (AAD = MAGIC || u32(H) || header) and ciphertext
```

The header validates against
[`schema/envelope-header.v15.schema.json`](../daylight/v15-meridian/schema/envelope-header.v15.schema.json).

## Perfect-logic gate

Set `min_score_M = 1000000` to seal a secret that opens **only** under a perfect
Meridian state — i.e., only when every external obligation has been closed by a
genuine non-harness external attestation. With internal-only evidence the score
is `998,900M`, so `seal` refuses (you cannot even create such a secret without the
perfect evidence), and a perfect-sealed secret refuses to open under internal
evidence. This is "perfect-logic encryption": the ciphertext is gated by the
complete obligation set, external frontier included. See
`tests/test_envelope.py::test_perfect_logic_gate`.

## Command line

```bash
export PYTHONPATH=daylight/v15-meridian

# seal: authorize from evidence + policy, then encrypt
python3 -m src.cli seal --keyfile daylight/v15-meridian/examples/demo.key \
  --min-score 998900 --require-closed o.q1.master_law_executable o.q4.fail_closed_tests \
  --message "sealed by evidence, opened by proof." --out secret.mae

# inspect: keyless metadata, no plaintext
python3 -m src.cli envelope-inspect --in secret.mae

# open: re-authorize from evidence, then decrypt (fail-closed)
python3 -m src.cli open --keyfile daylight/v15-meridian/examples/demo.key \
  --ledger daylight/v15-meridian/examples/ledger.seed.jsonl \
  --corpus daylight/v15-meridian/examples/corpus.seed.jsonl --in secret.mae
```

Make targets:

```bash
make daylight-meridian-envelope-test   # AEAD RFC vectors + envelope fail-closed matrix
make daylight-meridian-envelope-demo   # seal -> inspect -> open the committed demo
```

A committed demonstration artifact is at
[`examples/demo.mae`](../daylight/v15-meridian/examples/demo.mae) with the public
demo key [`examples/demo.key`](../daylight/v15-meridian/examples/demo.key) (the key
is public on purpose — the demo shows the authorization logic, not key secrecy).

## Library API

```python
from src import api

registry = api.load_registry()
policy = api.make_policy(registry, min_score_M=998900,
                         required_closed_obligations=["o.q1.master_law_executable"])
sealed = api.seal_envelope(plaintext=b"secret", caller_key=key,
                           ledger_path=ledger, corpus_path=corpus, policy=policy)
opened = api.open_envelope(envelope=sealed, caller_key=key,
                           ledger_path=ledger, corpus_path=corpus)   # fail-closed
meta = api.inspect_envelope(sealed)                                  # keyless
```

## Boundary

The Meridian Authorized Envelope is a deterministic research demonstration of
evidence-governed access control over a standard AEAD. It is not production
cryptography, not constant-time, not a key-management system, not external
certification, and not a claim of post-quantum security. The cipher is a faithful
RFC 8439 reference; the authorization is Meridian's evidence-derived obligation
logic.
