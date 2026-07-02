# Daylight v18 Binaric Vector Format

Daylight v18 Binaric Bastion is a binary-measured, evidence-gated substrate.
v18.0 implements the deterministic measurement vector. v18.1 adds the Binaric
Transition Ledger for user-authorized state changes. It does not claim host
cleanliness, runtime containment, production
cryptography, FIPS validation, external certification, or whole-system
post-quantum safety.

## Product Law

```text
NoBinaricProof -> NoOpen
NoUserVerifiedTamper -> NoTransition
NoVectorAgreement -> NoPlaintext
Contradiction -> Collapse
```

## Vector

```text
BinaricVector = {
  version,
  subject_kind,
  subject_path_normalized,
  file_sha256,
  file_sha3_512,
  size_bytes,
  executable_metadata,
  section_digests,
  dependency_digests,
  event_horizon_scorecard_digest,
  policy_digest,
  previous_vector_digest?,
  user_verification_digest?,
  vector_digest
}
```

`vector_digest` is:

```text
canonical_sha256(vector_without_vector_digest, "DAYLIGHT-v18-BINARIC-VECTOR:")
```

## Measurement

v18.0 measures regular files only. The subject path must be relative, must not
contain `..`, must resolve under the caller's base directory, and must not be a
symlink. Missing files reject.

The first section digest is the deterministic `whole_file` section:

```text
section_digests[0] = {
  id: "whole_file",
  offset: 0,
  size_bytes,
  sha256: file_sha256,
  sha3_512: file_sha3_512
}
```

This is intentionally not a claim of complete binary semantic analysis. It is a
stable minimum vector that later section-aware analyzers can extend under a new
version.

## v18.1 Binaric Transition Ledger

v18.0 could record a `user_verification_digest` marker. v18.1 makes that
insufficient by default. A changed binary, policy, or Event Horizon binding is
accepted only when the exact before-to-after transition is signed by the local
user ceremony and included in the append-only transition ledger.

Domains:

```text
D_USER_KEY        = "DAYLIGHT-v18-BASTION-USER-KEY:"
D_USER_PROOF      = "DAYLIGHT-v18-BASTION-USER-PROOF:"
D_TRANSITION      = "DAYLIGHT-v18-BASTION-TRANSITION:"
D_TRANSITION_LOG  = "DAYLIGHT-v18-BASTION-TRANSITION-LOG:"
D_TRANSITION_HEAD = "DAYLIGHT-v18-BASTION-TRANSITION-HEAD:"
```

User proof:

```text
user_key = PBKDF2-HMAC-SHA256(passphrase, transition_salt, 200000)
transition_digest = H_TRANSITION(transition_without_user_proof)
user_proof = HMAC-SHA256(user_key, transition_digest)
```

Transition validity:

```text
TransitionValid(before, after, transition) :=
  VectorDigestValid(before)
  and VectorDigestValid(after)
  and transition.before_vector_digest = before.vector_digest
  and transition.after_vector_digest = after.vector_digest
  and transition.changed_fields = DiffFields(before, after)
  and UserProofValid(transition)
  and transition.accepted = true
  and ContradictionFirewall(before, after, transition) = pass
```

The contradiction firewall rejects invalid vector digests, transition digest
mismatch, changed-field mismatch, broken `previous_vector_digest` chains,
unsupported version transitions, runtime/production/external/PQ overclaims,
missing user proof, invalid user proof, and `accepted != true`.

Ledger head:

```text
GENESIS_HEAD = H_TRANSITION_HEAD({"genesis": "daylight-v18-bastion-transition-ledger-v0.1"})
entry_digest = H_TRANSITION_LOG(transition_record)
head_n = H_TRANSITION_HEAD({"previous_head": head_{n-1}, "entry_digest": entry_digest})
```

Ledger validity requires all heads to recompute, all previous-head links to
match, and no duplicate `entry_id` or `transition_digest`.

Tamper acceptance:

```text
TamperAccepted(before, after, transition, ledger) :=
  TransitionValid(before, after, transition)
  and TransitionLedgerValid(ledger)
  and transition_digest appears in ledger
```

Default `tamper-check` is strict. The v18.0 marker behavior is only available
behind `--legacy-digest-marker`.

## Canonical JSON

JSON floats are rejected during parse. Duplicate map keys reject. Python float
instances reject before digesting. Unknown critical fields reject.

## Non-Claims

Daylight v18 Binaric Bastion is not:

- production cryptography
- host cleanliness proof
- runtime containment
- FIPS validation
- external certification
- whole-system post-quantum safety
- remote attestation
- production identity
- hardware-backed attestation

It is the binary measurement and transition-authorization layer that future
Bastion vault, release, and PQ authorization layers can consume.
