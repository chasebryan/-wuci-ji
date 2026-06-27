# Daylight Envelope Math Spec v0.3

Status(Daylight) = `research_draft`

ProductionAllowed(Daylight) = 0 until Maturity(Daylight) >= M5.

Maturity ladder:

- M0: mathematical sketch
- M1: byte-level specification
- M2: reference implementation
- M3: test vectors + negative tests
- M4: formal model
- M5: external review
- M6: production candidate

This file is the controlling v0.3 target for the Rust reference work in this
subtree. The implementation must preserve fail-closed claim discipline while it
moves toward the full reference profile.

## Core Corrections From v0.3

- Release level `r` and mode `mu` are separate from security strength.
- Level 0 is proof-only; open starts at level 1; release/install start at
  level 2; root rotation and audit acceptance require level 3.
- Supported profiles are `P2-HYBRID`, `P3-ROOT`, and `P2-HYBRID-FROST`.
- Default deployable profile candidate is `P2-HYBRID` with `Req={Q}`.
- Root ceremony profile candidate is `P3-ROOT` with `Req={Q,H}`.
- Production remains disallowed until the M5 external-review gate.

## Executable Predicate Target

The reference implementation target is:

```text
DL(profile,r,mu,A',Omega) = PreOK(profile,r,mu,Omega) * PostOK(A',Omega)

Open(Omega) =
  A'     if DL(profile,r,mu,A',Omega) = 1
  bottom otherwise
```

`PreOK` is the product of parse, suite, environment, mode, policy, gate,
provenance, install, witness, log, claim, downgrade, and authorization checks.
Every check is fail-closed.

`PostOK` is the product of AEAD decryption success, hidden commitment
verification, and declared leakage verification.

## v0.3 Byte-Level Work Items

The current code must not claim M1/M2 completion until all of these are true:

- `ENC` is fully fixed and has a rejecting decoder.
- Every envelope field is typed and covered by canonical encoding tests.
- Seal and open implement the full hybrid KEM path, not only a supplied key
  schedule.
- Test vectors cover valid, bad signature, bad ciphertext, bad nonce, bad
  downgrade, bad log proof, bad witness, bad claim, and bad overwrite cases.
- The transparency log, witness, policy, gate, provenance, and install
  validators are real integrations rather than permissive stubs.
- Formal model and at least two external reviews are complete before any
  production-candidate claim.

## v0.3 Strength Discipline

No equation or implementation status may claim a global `lambda_s = 256`.

```text
s_D = (
  s_PQ_KEM,
  s_classical_DH,
  s_PQ_SIG,
  s_hash_SIG,
  s_AEAD_conf,
  s_AEAD_int
)

s_PQ_KEM = category_5
s_classical_DH <= 192
s_PQ_SIG = category_5
s_hash_SIG = category_5
s_AEAD_conf ~= 256
s_AEAD_int <= 128
```

## v0.3 Authorization Requirements

```text
Req(P2-HYBRID,r,mu) =
  {Q}      if r < 3 and mu = hybrid
  {Q,H}    if r < 3 and mu = pq-strict
  {Q,H}    if r = 3
  invalid  if mu = compact and action in {open, release, install, root_rotate}

Req(P3-ROOT,r,mu) =
  {Q,H}    if mu in {hybrid, pq-strict}
  invalid  if mu = compact

Req(P2-HYBRID-FROST,r,mu) =
  {Q,F}      if r < 3 and mu = hybrid
  {Q,H,F}    if r = 3
  invalid    if mu = compact and action in {open, release, install, root_rotate}
```

The FROST extension remains fail-closed until a real ciphersuite and share
transcript verifier are specified, implemented, tested, and reviewed.

## v0.3 Fail-Closed Invariants

The reference open path must reject on any failed precheck, AEAD rejection,
commitment mismatch, leakage mismatch, or nonce violation. In particular:

```text
ParseOK(Omega) = 0 => Open(Omega) = bottom
SuiteOK(Omega) = 0 => Open(Omega) = bottom
EnvOK(Omega) = 0 => Open(Omega) = bottom
ModeOK(profile,r,mu,action) = 0 => Open(Omega) = bottom
PolicyOK = 0 => Open(Omega) = bottom
GateOK = 0 => Open(Omega) = bottom
V_Auth(profile,r,mu) = 0 => Open(Omega) = bottom
V_Log = 0 => Open(Omega) = bottom
WitnessOK = 0 => Open(Omega) = bottom
NoDowngradeFinal(T0) = 0 => Open(Omega) = bottom
AEAD.Dec(K_E,N0,C,T0) = bottom => Open(Omega) = bottom
CommitOK(A') = 0 => Open(Omega) = bottom
```

The Rust code may expose interim lower-level helper functions, but those helpers
must be named so they cannot be mistaken for full M2 reference completion.
