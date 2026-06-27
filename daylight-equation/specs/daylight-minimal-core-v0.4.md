# Daylight Envelope Minimal Math Core v0.4

Status(Daylight) = `research_draft`

ProductionAllowed(Daylight) = 0 until Maturity(Daylight) >= M5.

Maturity ladder:

- M0: math sketch
- M1: byte-level spec
- M2: reference implementation
- M3: test vectors + negative tests
- M4: formal model
- M5: external review
- M6: production candidate

This is the active Daylight target for the Rust subtree.

## Design Rule

Daylight does not define a new primitive.

```text
Daylight = Envelope + HybridKEM + AEAD + Authorization + PolicyGate + OptionalAudit
```

Custom components are forbidden in the core unless they are typed, encoded,
test-vectored, fuzzed, and externally reviewed.

## Domains

`r in {0,1,2,3}`.

Openable `mu` is only:

```text
mu in {hybrid, pq-strict}
ord(hybrid) = 1
ord(pq-strict) = 2
```

No compact release mode exists. Compact may exist only for non-opening research
proofs outside the openable core.

Profiles:

```text
D2-HYBRID
D3-ROOT
D2-HYBRID-FROST
```

Actions:

```text
Act_0 = {research, proof}
Act_1 = Act_0 + {open}
Act_2 = Act_1 + {release, install}
Act_3 = Act_2 + {root_rotate, audit_accept}
```

## Encoding

`ENC = Deterministic-CBOR-Daylight-v1`.

The reference remains incomplete until parser fuzzing and persisted vectors
cover every typed artifact. The current Rust code uses fixed arrays rather than
maps for the v4 header/envelope shape, and implements an encoder plus rejecting
decoder subset for arrays, byte strings, text strings, unsigned integers, typed
v4 headers, and typed v4 envelopes.

## Hash And KDF

```text
H(x) = SHA3-512(ENC(x))
Hb(b) = SHA3-512(b)
H32(x) = SHAKE256(ENC(x),32)

KDF.Extract = HKDF-SHA512.Extract
KDF.Expand = HKDF-SHA512.Expand
```

The v4 key schedule is:

```text
Split(OKM) = (K_E, K_COM, N_base)
```

## Suite And Strength

The suite contains deterministic encoding, SHA3-512, SHAKE256, HKDF-SHA512,
ML-KEM-1024, DHKEM-P384-HKDF-SHA384, AES-256-GCM or ChaCha20-Poly1305,
ML-DSA-87, SLH-DSA-SHAKE-256s, and optional FROST ciphersuite.

No global `security_strength = 256` claim is allowed. Strength is
theorem-specific and component-specific.

## Authorization Requirements

```text
Req(D2-HYBRID,r,mu) =
  {Q}      if r < 3 and mu = hybrid
  {Q,H}    if r < 3 and mu = pq-strict
  {Q,H}    if r = 3

Req(D3-ROOT,r,mu) =
  {Q,H}    if mu in {hybrid,pq-strict}

Req(D2-HYBRID-FROST,r,mu) =
  {Q,F}      if r < 3 and mu = hybrid
  {Q,H,F}    if r = 3
```

If the FROST ciphersuite is not specified, `V_F = 0`.

## Open Algorithm Target

```text
if PublicPreOK(omega) = 0:
  return bottom

derive ss_Q, ss_C, K_E, K_COM, N0

if DeriveOK = 0:
  return bottom

A_prime = AEAD.Dec(K_E,N0,C,AD=T0)

if PrivateOpenOK(A_prime,omega) = 0:
  zeroize A_prime
  return bottom

return A_prime
```

Important ordering rule:

```text
PublicPreOK(omega) = 0 => Open(omega) = bottom and AEAD.Dec MUST NOT be called
```

## Current Rust Scope

Implemented:

- v4 action/profile/mode model with no compact openable release mode.
- deterministic-CBOR encoder/decoder subset for current transcript values.
- typed v4 header encode/decode roundtrip and negative parser checks.
- typed v4 envelope encode/decode roundtrip, 96-bit record-index encoding, and
  negative parser checks.
- deterministic v4 reference-vector builder, CLI printer, and persisted vector
  file.
- deterministic v4 negative parser seed corpus.
- HKDF-SHA512 v4 key schedule from supplied shared secrets and from
  ML-KEM-1024+DHKEM(P-384,HKDF-SHA384) encapsulation/decapsulation.
- v4 `T0`, `T1`, and authorization message construction.
- v4 supplied-schedule and KEM-derived seal/open enforcing public precheck
  before private derivation/AEAD, derivation rejection, AEAD rejection, hidden
  artifact commitment, leak verification, nonce bounds, and fail-closed FROST
  requirements.
- caller-supplied `CryptoRng` KEM seal API for non-vector sealing.

Not implemented:

- coverage-guided deterministic-CBOR parser fuzzing and complete
  cross-implementation positive/negative vector corpus.
- OS RNG selection policy, key management, and full key lifecycle handling.
- real policy, gate, log, install, witness, provenance, review receipt, and
  authorization quorum validators.
- fuzzing, formal model, or external review.

Therefore Daylight remains below M2/M5 and is not production-allowed.
