# DAYLIGHT-v16 Analemma Witnessed Envelope

Cryptographic construction name:

```text
D16-AWE
Daylight v16 Analemma Witnessed Envelope
```

Version:

```text
daylight-v16-analemma-witnessed-envelope-v0.1
```

Magic:

```text
D16AWE1
```

## Boundary

D16-AWE is a construction over standard primitives. It is not a new lattice
primitive, not a new AEAD primitive, not FIPS-validated, and not production-ready
until reviewed.

D16-AWE must not add exploit generation, offensive scanning, jailbreak
harnesses, network attack logic, or placeholder post-quantum verifiers. Missing
real primitive support is a hard implementation blocker, not a reason to add a
stub.

## Required Corrections To The Draft

The construction is sound enough to preserve as a design target, with these
repo-specific corrections made normative:

1. `VerifyDaylightV16Evidence` must receive the policy, or it must return a
   canonical closure set. This spec uses `VerifyDaylightV16Evidence(EA, P)` so
   `required_closed_obligations` and `required_proof_units` are verified by the
   evidence verifier instead of trusted from the header.
2. When sender signatures are used, `sender_public_bundle` must appear in the
   authenticated header. Signature records carry public-key digests only; they
   are not enough to reconstruct public keys during open.
3. HKDF is fixed to HKDF-SHA384 for this suite. Domain hashes remain SHA3-512
   unless explicitly marked `H256`.
4. The key schedule binds the preliminary header `H0` without the authorization
   field. The final AEAD AAD binds the final header, including authorization and
   commitment. Mutating either form must fail closed.
5. Sequence reuse detection is a store/vault responsibility. A stateless open
   can reject malformed sequence numbers, but only a stateful store can reject
   repeated `(recipient_id, kem_bundle_digest, sequence_number)`.

## Primitive Suite

```text
H(x)       = SHA3-512(x)
H256(x)    = SHA256(x)
C(x)       = deterministic-canonical-daylight-v2(x)
HKDF       = HKDF-SHA384
AEAD       = CHACHA20-POLY1305-RFC8439
MLKEM      = ML-KEM-1024
DHKEM      = DHKEM-P384-HKDF-SHA384
SIGN_MAIN  = ML-DSA-87
SIGN_BACKUP = SLH-DSA-SHAKE-256s
```

Canonical encoding must reject duplicate map keys, floats, NaN, infinities,
non-canonical integers, unsupported tags, and unknown critical fields.

Both KEM legs are required in this profile. Missing ML-KEM, missing DHKEM, or a
failed decapsulation returns bottom. Single-leg fallback requires a different
suite id.

## Domain Separation

```text
D_SUITE     = "DAYLIGHT-v16-AWE-SUITE:"
D_RECIPIENT = "DAYLIGHT-v16-AWE-RECIPIENT:"
D_EVIDENCE  = "DAYLIGHT-v16-AWE-EVIDENCE:"
D_POLICY    = "DAYLIGHT-v16-AWE-POLICY:"
D_AUTHZ     = "DAYLIGHT-v16-AWE-AUTHORIZATION:"
D_HEADER    = "DAYLIGHT-v16-AWE-HEADER:"
D_KEM       = "DAYLIGHT-v16-AWE-HYBRID-KEM:"
D_EXTRACT   = "DAYLIGHT-v16-AWE-HKDF-EXTRACT:"
D_EXPAND    = "DAYLIGHT-v16-AWE-HKDF-EXPAND:"
D_NONCE     = "DAYLIGHT-v16-AWE-NONCE:"
D_AAD       = "DAYLIGHT-v16-AWE-AAD:"
D_COMMIT    = "DAYLIGHT-v16-AWE-COMMIT:"
D_SIG       = "DAYLIGHT-v16-AWE-SIGNATURE:"
D_EXPORT    = "DAYLIGHT-v16-AWE-EXPORT:"
D_REJECT    = "DAYLIGHT-v16-AWE-REJECT:"
```

`DomainHash(domain, x) = SHA3-512(domain || C(x))`.

## Evidence Context

D16-AWE never trusts a score supplied by an envelope header. Seal and open both
consume an evidence artifact and call:

```text
VerifyDaylightV16Evidence(EA, P) -> EvidenceContext or bottom
```

The returned `EvidenceContext` must be canonical and must include:

```text
version
daylight_claim_score_M
analemma_score_A
proof_mass
proof_mass_baseline
proof_mass_digest
solstice_scorecard_digest
solstice_artifact_manifest_digest
analemma_registry_digest
zenith_report_digest
claim_level
production_allowed
runtime_containment_claim
whole_system_post_quantum_safety_claim
external_certification_claim
score_inflation_M
```

Verifier requirements:

```text
score_inflation_M = 0
daylight_claim_score_M >= 0
analemma_score_A >= 0
proof_mass >= 0
proof_mass_baseline > 0
required_closed_obligations in P are closed
required_proof_units in P are closed
claim boundary flags are recomputed, not trusted
```

Mathematical state:

```text
P(t) = sum_u base_credit(u) * Closed(u,t) - RegressionDebt(t) - StalenessDebt(t)
A_self(t) = floor(10^6 * P(t) / P(t0))
D_claim(t) = conservative claim score
score_inflation_M = ZenithAdjustedScore_M(t) - D_claim(t)
```

`score_inflation_M != 0` is always a rejection.

## Policy

Policy contains minimum Daylight claim score, minimum Analemma score, required
claim level, optional required digests, required obligations, required proof
units, production/runtime/PQ/external-certification flags, and sender-signature
requirements.

`PolicySatisfied(E, P)` checks score floors, claim level, boundary flags, and
required digest equality. Obligation and proof-unit closure is checked inside
`VerifyDaylightV16Evidence(EA, P)`.

Policies that require production, runtime containment, whole-system PQ safety,
or external certification must fail closed unless the evidence verifier proves
the corresponding flag. Classical-only evidence must not satisfy whole-system
PQ safety.

## Suite ID

```text
Suite = {
  version,
  kem_pq,
  kem_classical,
  kdf,
  hash,
  aead,
  signature_main,
  signature_backup,
  canonical_encoding
}

SuiteID = DomainHash(D_SUITE, Suite)
```

Any primitive substitution changes the suite id.

## Recipient Keys

`RecipientID` is:

```text
H256(C({
  suite_id,
  pk_mlkem_digest: H256(pk_mlkem),
  pk_dh_digest: H256(pk_dh)
}))
```

`RecipientPublicKeyDigest(pkR) = DomainHash(D_RECIPIENT, pkR)`.

Recipient secret keys must never appear in public evidence, headers, vectors, or
inspection output.

## Authorization Tag

`AuthorizationTag(E, P, pkR, sender_public_bundle?)` is a domain-separated hash
over:

```text
suite_id
evidence_tag
policy_tag
recipient_public_key_digest
sender_public_key_digest or null
daylight_claim_score_M
analemma_score_A
proof_mass_digest
solstice_scorecard_digest
solstice_artifact_manifest_digest
analemma_registry_digest
zenith_report_digest
claim_level
anti_inflation: { score_inflation_M, invariant }
```

Changing evidence, policy, recipient key, sender public key, proof mass, claim
level, or anti-inflation state changes the authorization tag.

## Hybrid KEM Combiner

Sender side:

```text
(ct_mlkem, ss_mlkem) = MLKEM.Encaps(pkR.pk_mlkem)
(ct_dh, ss_dh)       = DHKEM.Encaps(pkR.pk_dh)

kem_context = {
  suite_id,
  auth_tag,
  mlkem_id,
  mlkem_pk_digest,
  mlkem_ct_digest,
  dhkem_id,
  dh_pk_digest,
  dh_ct_digest
}

ikm = LEN(ss_mlkem) || ss_mlkem || LEN(ss_dh) || ss_dh
hybrid_secret = HKDF-SHA384-Extract(DomainHash(D_KEM, kem_context), ikm)
```

Recipient side recomputes the same `kem_context`, verifies the
`kem_context_digest`, decapsulates both legs, then derives the same
`hybrid_secret`.

Implementations must zeroize shared secrets, IKM, hybrid secret, and derived
keys where the language/runtime gives a meaningful way to do so.

## Header And AAD

The preliminary header `H0` contains:

```text
magic
version
suite
recipient_id
policy
evidence_summary
kem_bundle
nonce_mode
sequence_number
plaintext_commitment_mode
sender_signature_mode
sender_public_bundle?    # required when sender signatures are required
```

The final header is `H0` plus:

```text
authorization: {
  auth_tag,
  commitment
}
```

`AAD(Header) = MAGIC || uint32_le(len(C(Header))) || C(Header)`.

Public header metadata may reveal suite id, recipient id, policy, evidence
summary digests, scores, proof mass digest, claim level, KEM ciphertexts, nonce
mode, sequence number, and hidden commitment digest. It must not reveal
plaintext, unblinded plaintext hash, AEAD keys, commitment keys, hybrid secrets,
KEM shared secrets, private evidence, signing secrets, or recipient secrets.

## Key Schedule

```text
transcript_digest = DomainHash(D_HEADER, H0)

salt = DomainHash(D_EXTRACT, {
  suite_id,
  transcript_digest,
  auth_tag
})

prk = HKDF-SHA384-Extract(salt, hybrid_secret)

K_aead   = HKDF-SHA384-Expand(prk, D_EXPAND || "aead-key" || C(...), 32)
N_base   = HKDF-SHA384-Expand(prk, D_EXPAND || "nonce-base" || C(...), 12)
K_commit = HKDF-SHA384-Expand(prk, D_EXPAND || "commit-key" || C(...), 32)
K_export = HKDF-SHA384-Expand(prk, D_EXPORT || "exporter" || C(...), 32)
```

`Nonce(N_base, sequence_number)` XORs the 96-bit base nonce with
`0x00000000 || uint64_be(sequence_number)`.

For a fixed `K_aead`, `sequence_number` must not repeat. Because each seal uses
fresh KEM encapsulation, `K_aead` should be unique per envelope; stateful stores
must still reject repeated `(recipient_id, kem_bundle_digest, sequence_number)`.

## Commitment

```text
PlaintextCommitment(K_commit, plaintext, AuthTag) =
  DomainHash(D_COMMIT, {
    auth_tag,
    plaintext_digest: SHA3-512(plaintext),
    keyed_blind: SHA3-512(K_commit || SHA3-512(plaintext))
  })
```

The public header exposes the commitment, not the raw plaintext hash alone.

## Seal

```text
D16_AWE_Seal(pkR, plaintext, EA, P, sender_secret_bundle?, sequence_number = 0)
```

Required order:

1. Verify evidence with `VerifyDaylightV16Evidence(EA, P)`.
2. Reject unless `score_inflation_M = 0` and `PolicySatisfied(E, P)`.
3. Build `sender_public_bundle` if signing is requested.
4. Compute `AuthTag`.
5. Encapsulate both KEM legs.
6. Build `H0`, including sender public keys when signatures are used.
7. Derive key schedule from `hybrid_secret`, `H0`, and `AuthTag`.
8. Compute nonce and hidden plaintext commitment.
9. Build final header with authorization.
10. Seal using AEAD over `AAD(Header)`.
11. Sign `DomainHash(D_SIG, {header_digest, ciphertext_digest, tag})` if
    requested.
12. Return envelope.

No plaintext, KEM shared secret, derived key, or signing secret may be emitted in
inspection output or public vectors.

## Open

```text
D16_AWE_Open(skR, pkR, Envelope, EA_local)
```

Required order:

1. Parse and canonicalize; reject malformed or unsupported envelopes.
2. Verify magic, version, suite, and recipient id.
3. Verify local evidence with `VerifyDaylightV16Evidence(EA_local, P)`.
4. Reject unless `score_inflation_M = 0` and `PolicySatisfied(E_local, P)`.
5. Extract `sender_public_bundle` from the authenticated header if present.
6. Recompute `AuthTag` and require equality with the header.
7. Rebuild `H0` by removing only the `authorization` field.
8. Decapsulate both KEM legs and derive the key schedule.
9. Verify required sender signatures before plaintext release.
10. AEAD-open with final header AAD.
11. Verify hidden plaintext commitment.
12. Return plaintext only after every check succeeds.

No partial plaintext release is allowed before all checks pass.

## Signature Layer

When `require_sender_signature` is true, `sender_public_bundle.pk_mldsa` is
required and an ML-DSA-87 signature over `BodyToSign` must verify.

When `require_backup_signature` is true, `sender_public_bundle.pk_slh` is also
required and an SLH-DSA-SHAKE-256s signature over the same `BodyToSign` must
verify.

Unsigned mode is allowed only when policy does not require signatures.

## Rejection Rules

Reject on:

```text
float in any score/evidence/policy field
unknown critical field
non-canonical encoding
duplicate canonical map key
unsupported suite id
missing ML-KEM ciphertext
missing DHKEM ciphertext
KEM decapsulation failure
evidence verification failure
policy failure
AuthTag mismatch
header digest mismatch
nonce sequence reuse in a stateful store
AEAD tag failure
commitment mismatch
required signature missing
required signature invalid
score_inflation_M != 0
production policy requested without production evidence
runtime containment policy requested without containment evidence
whole-system PQ policy requested without whole-system PQ evidence
external certification policy requested without external certification evidence
```

## Required Vector Classes

Deterministic test fixtures may use fixed RNG seeds only in test mode.

```text
V1  recipient keygen vector
V2  evidence context digest vector
V3  policy tag vector
V4  authorization tag vector
V5  hybrid KEM combiner vector
V6  key schedule vector
V7  header/AAD vector
V8  seal/open positive vector
V9  wrong evidence negative vector
V10 wrong policy negative vector
V11 wrong recipient negative vector
V12 KEM ciphertext mutation negative vector
V13 header mutation negative vector
V14 ciphertext mutation negative vector
V15 tag mutation negative vector
V16 commitment mutation negative vector
V17 missing sender signature negative vector
V18 invalid sender signature negative vector
V19 score inflation negative vector
V20 non-canonical encoding negative vector
```

## Implementation Direction

The first implementation should target the existing Rust Daylight crypto lane,
not a Python stdlib placeholder:

```text
daylight-equation/rust/daylight-crypto/
```

A Python package may exist later for canonicalization, evidence inspection, or
test-vector validation, but it must not pretend to implement ML-KEM, ML-DSA, or
SLH-DSA without a real reviewed backend.

Minimum implementation gates:

```text
cargo test --offline
make qcage-policy-matrix
make harden0-proof
make cage-proof
make pq-verifier-fips204-proof
make daylight-meridian-envelope-test
```

Passing these gates is still not production readiness or whole-system
post-quantum security.
