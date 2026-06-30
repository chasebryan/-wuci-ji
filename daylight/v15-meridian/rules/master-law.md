# Daylight v15 Meridian Master Law

Daylight v15 Meridian is not a score. Meridian is a score-generating condition.

The executable law is unchanged from v14C+:

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
NoTrace(x) -> NoTrust(x)
ManualScore(x) -> Reject(x)
```

Meridian adds the rule that makes `ManualScore(x) -> Reject(x)` mechanical rather
than aspirational.

## The derivation law

In v14C+ every q-value was an asserted `target`, gated only by the *presence* of
required evidence types. That left a loophole: the same evidence could justify any
target a reviewer typed, up to a narrated `1000/1000`.

Meridian removes the loophole. Every q-value is derived, never asserted:

```text
q_i = (sum of weights of closed obligations in dimension i) / 1000
```

An obligation is closed only by a witnessed, transcript-bound evidence item that
names the obligation id. The verifier re-derives the q-vector from the pinned
obligation registry and the sealed closed-obligation set, so:

```text
EditedScore(x) != ObligationDerived(x) -> Reject(x)
```

Editing a q-value, a target, an evaluator, or a registry weight changes nothing
admissible: the re-derivation rejects the edit, and the registry digest pin rejects
a rewritten registry.

## The external-frontier law

Obligations are `internal` or `external`.

* internal obligations are closeable by repository evidence.
* external obligations are closeable only by an `external_attestation` whose
  `external_signer_id` differs from the harness identity.

```text
SelfSigned(external_attestation) -> Reject(x)
```

The harness cannot manufacture the external frontier. Therefore the maximum score
the repository can honestly generate from its own evidence is the **internal
ceiling** (`998,900M`), strictly below `1,000,000M`. The residual `1,100M` is the
external-attestation mass: independent formal-methods audit, downstream release
reproduction, external boundary fuzzing, external red-team, post-quantum / external
crypto audit, independent statistical replication, external provenance audit, an
external falsification program, and external communication review.

A perfect `1,000,000M` is reachable, but only by closing every external obligation
with a genuine non-harness attestation. Claiming `1,000,000M` from inside the
repository is exactly the overclaim the master law forbids.

Manual scores are invalid even if the arithmetic appears correct.
