# Nightlight V6 Defensive Assault Assessment

Status: defensive local assessment battery.

Nightlight v6 is an open-ended fail-closed gate over the existing Daylight v6
research evidence. Its purpose is to make Daylight experience adversarial
validation scenarios that resemble malicious tampering patterns against crypto
envelopes, without turning Daylight into attack crypto or adding offensive
tooling. It is designed to grow by adding deterministic local simulation cases
while preserving the same gate shape:

- all public-boundary simulations must reject before private KEM or AEAD;
- all reference negative cases must fail closed at the expected error;
- private-path reach is allowed only for the existing provider-backed mutation
  checks that already require non-production external precheck evidence;
- score, production authority, runtime containment, and whole-system
  post-quantum-safety claims remain false.

Current machine vector:
`daylight-equation/rust/daylight-crypto/vectors/nightlight-v6-equation-battery-v1.txt`

Deep assessment vector:
`daylight-equation/rust/daylight-crypto/vectors/nightlight-v6-deep-assault-assessment-v1.txt`

Current proof target:

```sh
make daylight-v6-nightlight-battery-test
make daylight-v6-nightlight-deep-assessment-test
```

## Current Coverage

The current battery covers 60 deterministic defensive cases:

- 46 public-boundary simulations;
- 14 reference negative cases;
- 60 fail-closed outcomes;
- 0 offensive logic additions;
- 0 network requirements.

Public-boundary assault-simulation categories:

- malformed or noncanonical CBOR input;
- envelope schema mutation;
- suite and mode downgrade boundaries;
- aux-hash mismatch and unbound aux object insertion;
- policy mismatch, expiry, provenance, install, witness, log, and review gates;
- claim class and claim-shape denial;
- KEM key-id and KEM shape rejection;
- auth-block shape rejection;
- baseline public authorization failure at `REJECT_AUTH_SIGNATURE`.

Reference negative categories:

- auth-signature and external-authority denial;
- review, downgrade, log, install, witness, policy, and claim denial;
- private-path AEAD mutation denial;
- private-path commitment mutation denial;
- private-path derivation denial;
- private-path leak-validation denial.

## Learning-Guided Gap Closure

Nightlight deep assessment uses `deterministic-coverage-learning-v1`. This is
not an online model, exploit generator, scanner, or attacker harness. It is a
local deterministic scoring pass over existing fail-closed evidence:

- each public rejection stage and reference failure family is a learning arm;
- each arm is scored by risk weight, observed novelty, fail-closed count, and
  private-path reach count;
- the top eight arms become learning epochs for the next defensive hardening
  pass;
- target coverage is checked against 14 public rejection stages and 4 private
  failure classes;
- recommendations are emitted only as defensive validation gaps.

The current deep assessment keeps all 60 adversarial cases fail-closed,
covers all 14 tracked public rejection stages, covers all 4 tracked private
failure classes, and closed the previous install, derive, and leak gaps:

- `REJECT_INSTALL` is covered by a hash-bound but unsupported install-manifest
  public simulation;
- `Derive` is covered by a deterministic malformed recipient decapsulation-key
  private-path denial;
- `Leak` is covered by a deterministic metadata leak-value mismatch that passes
  AEAD and commitment checks before failing at leak validation.

It still identifies these sparse-coverage priorities for future defensive
hardening:

- `sparse_auth_signature_stage`: broaden public authorization-denial variants;
- `sparse_review_stage`: add review receipt shape and hash-binding simulations;
- `sparse_log_witness_stages`: broaden log and witness object-shape
  simulations.

These recommendations are a defensive backlog, not instructions for offensive
use. They describe where Daylight needs stronger local rejection evidence
before any score, production, runtime-containment, or whole-system
post-quantum-safety claim changes.

## Open-Ended Gate Rules

The gate uses lower bounds instead of exact corpus sizes:

- at least 12 reference negative cases;
- at least 40 public simulation cases;
- all cases must fail closed;
- public simulations must not reach the private path;
- private-path reach count must equal the private mutation count;
- stage-count and failure-count totals must sum back to their inventories.

This lets future Nightlight work add cases without rewriting the verifier
contract.

## Exclusions

Nightlight does not add exploit generation, vulnerability reproduction,
offensive scanning, jailbreak harnesses, network attack logic, production
authority, runtime sandboxing, or new cryptography. The simulations are
defensive validation inputs: they force rejection-stage evidence for tampered
or malformed Daylight envelopes.

It does not make Daylight production-ready. Public authority remains external,
and Daylight score claims remain unchanged.
