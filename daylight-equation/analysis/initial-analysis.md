# Initial Analysis

The Daylight Equation should start as a specification and model compartment,
not as a new cryptographic implementation lane. The poster combines several
powerful ideas that need to be separated into typed interfaces and falsifiable
predicates before code is allowed to handle secrets or authority.

## What Changes From WJ-Next

Daylight moves beyond the current WJ-next model in five important ways:

1. It shifts the default threshold story toward 3-of-5 normal authorization
   and 4-of-5 ceremony authorization.
2. It makes hybrid evidence central instead of optional future evidence.
3. It introduces a larger algorithm suite: ML-KEM-1024,
   DHKEM(P-384,HKDF-SHA384), ML-DSA-87, SLH-DSA-SHAKE-256s, an unresolved
   FROST lane, KMAC/cSHAKE, AES-GCM, ChaCha20-Poly1305, HKDF-SHA384, and
   Argon2id.
4. It ties authorization, witness, ledger, provenance, install evidence,
   no-downgrade policy, and claim vocabulary into one acceptance predicate.
5. It states a strict no-plaintext rule: no plaintext output unless Gate,
   AEAD, and no-overwrite checks all pass.

## Immediate Design Risks

The most important issue is transcript staging. The corrected spec splits the
old recursive `T_D` into `T0` for pre-encryption binding and `T1` for
post-ciphertext authorization. `m0` is derived from `T0`; `m_D` is derived from
`T1`. This keeps ciphertext, KEM encapsulations, policy, keyset root, ledger
head, and metadata bound without making a transcript depend on itself.

The hybrid KEM combiner is another high-risk point. Combining ML-KEM-1024 and
DHKEM(P-384,HKDF-SHA384) through KMAC must be specified as a hybrid KEM
combiner with explicit `EncTuple` input encoding, public key binding,
ciphertext binding, failure behavior, and test vectors. It should not be
improvised in implementation code.

The poster's public `h_D(A)` leaks a deterministic plaintext digest. Daylight
must either declare `ell_A=(|A|,h_D(A))` as public leakage and use a
leakage-respecting confidentiality game, or use `ell_A=|A|` and put any
artifact commitment behind a post-KEM KMAC key.

The threshold model needs identity and domain definitions. `P`, `D`, `d(P)`,
`Q_m`, signer custody domains, root authority keys, and verifier key sets must
be canonical data, not comments around a signature check.

The PQ mode naming must remain conservative. `compact` is classical threshold
evidence. `hybrid` is dual classical/PQ evidence when real verifiers are
pinned and tested. `pq-strict` must fail closed until every required authority,
parser, verifier, audit, and migration boundary exists.

The AEAD lane requires nonce uniqueness and 128-bit tag-forgery accounting.
The corrected design uses HPKE-style `N_j=N_base xor I2OSP_96(j)`. Single-shot
envelopes use `j=0` and a single-use `K_E`; multi-message envelopes need a
mechanical no-repeat proof.

The Argon2id entry needs a separate password-key lane. It should not silently
become a production root, artifact key, or signer secret derivation path
without memory, time, parallelism, salt, and recovery policy.

## First Safe Milestone

The first milestone should be a non-secret, fail-closed model:

- Typed action sets for each Daylight release level `r`.
- Typed modes: `compact`, `hybrid`, and `pq-strict`.
- Typed claim levels.
- Threshold profile constants and probability arithmetic.
- A transcript dependency graph with `T0`, `T1`, and no cycles.
- Mode-dependent authorization requirements `Req(r,mu)` instead of
  `V_Auth * PQOK_mu`.
- Parser fixtures that reject duplicate fields, unknown critical fields,
  downgrade attempts, private witness material, and impossible mode claims.
- No encryption, decryption, signing, signature verification, KEM operation,
  key derivation, or password handling.

The initial Rust crate in this directory starts only with the first four items.

## Implementation Direction

Rust is a good fit for the eventual implementation because the Daylight model
needs narrow types, explicit state transitions, structured errors, immutable
transcript inputs, and dependency isolation. The first real crate should still
be a model/parser crate, not a cryptography crate.

Future cryptography must be integrated behind small verifier/envelope traits
that fail closed by default. Concrete implementations should be selected only
after crate provenance, maintenance status, algorithm conformance, side-channel
discipline, KAT coverage, negative tests, and dependency review are documented.

## Boundary Statement

Daylight can eventually become a stronger Wuci-Ji acceptance equation only if
it preserves the current project discipline: every accepted claim is backed by
an enforced predicate, and every unsupported claim fails closed.
