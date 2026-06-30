# Daylight v15 Meridian

Daylight v15 Meridian is the executable successor to the
[Daylight v14C+](../daylight/v14c-plus/) execution package. It is not a roadmap
profile and not a narrated score. It is a runnable scoring **condition** whose
output is regenerated from frozen evidence.

```text
DAYLIGHT-MERIDIAN-v15

Internal ceiling:  998,900M / 1,000,000M   (candidate, generated)
External residue:    1,100M                (external-attestation mass)
Perfect:           1,000,000M              (reachable only with external attestations)
```

The package lives at [`daylight/v15-meridian/`](../daylight/v15-meridian/). Build,
verify, and frontier commands are in its
[README](../daylight/v15-meridian/README.md). This document explains the design
and the honest answer to "can it reach 1,000,000M?"

![WUCI v15 MAE Meridian Authorized Envelope visual map](../daylight/v15-meridian/assets/wuci-v15-mae-meridian-authorized-envelope.jpeg)

## What v14C+ proved, and the one gap it left

v14C+ established the doctrine and the exact-rational arithmetic:

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
NoTrace(x) -> NoTrust(x)
ManualScore(x) -> Reject(x)
```

But in v14C+ each q-value was an asserted `target` in `q-evaluators.json`, gated
only by the *presence* of required evidence types. The harness read the target; the
verifier trusted the q-vector and only rechecked the weighted sum and digest.

That is a manual-score loophole. The same eight evidence entries justify a narrated
`998/1000` or a narrated `1000/1000` equally well — nothing in the machine ties the
*magnitude* of a q-value to the *content* of evidence. `ManualScore(x) -> Reject(x)`
was doctrine, but not mechanically enforced.

## The Meridian move: derive, then re-derive

Meridian makes every q-value a derived coverage ratio over **obligations**:

```text
q_i = ( sum of weights of closed obligations in dimension i ) / 1000
```

Each dimension's obligations are listed in
[`rules/obligations.v15.json`](../daylight/v15-meridian/rules/obligations.v15.json)
and sum to exactly `1000` thousandths. An obligation closes only when a witnessed,
transcript-bound evidence item (a ledger entry or a frozen corpus entry) names its
id in `closes_obligations`.

The decisive change is at verification time. The verifier:

1. pins the obligation registry by digest (a rewritten registry is rejected);
2. re-derives the q-vector from the sealed closed-obligation set;
3. requires the re-derived vector to equal the scorecard's q-vector;
4. when given the ledger and corpus, re-resolves which obligations the evidence
   actually closes and requires an exact match (this enforces
   `NoEvidence -> NoScore` and `NoTrace -> NoTrust` at verify time).

```text
EditedScore(x) != ObligationDerived(x) -> Reject(x)
```

Editing a q-value, a target, or a registry weight now changes nothing admissible.
Only appending witnessed, transcript-bound evidence moves the score, and only as far
as the obligations it discharges.

## Internal versus external obligations

Each obligation is `internal` or `external`.

* internal obligations are closeable by repository evidence.
* external obligations are closeable only by an `external_attestation` whose
  `external_signer_id` differs from the harness identity.

```text
SelfSigned(external_attestation) -> Reject(x)
```

So the maximum score the repository can honestly generate from its own evidence is
the **internal ceiling**, and it is strictly below `1,000,000M`.

## The score

Same v13 weight vector as v14C+. The internal ceiling raises five dimensions over
v14C+, each by adding real internal evidence (a machine-checked kernel proof, a
reproducible release lane, a boundary-closure matrix, a traceability map, and a
completed documentation set):

```text
q-id   v14C+   Meridian internal ceiling   external residue (thousandths)
q1     1000    1000                         0
q2      998     999                         1   external formal-methods audit
q3     1000    1000                         0
q4     1000    1000                         0
q5      997     999                         1   downstream release-reproduction audit
q6      995     998                         2   external boundary fuzzing
q7      995     995                         5   external red-team (unbounded adversary)
q8      998     998                         2   post-quantum / external crypto audit
q9      997     997                         3   independent statistical replication
q10     997     999                         1   external provenance audit
q11     990     990                        10   external falsification program
q12     997     999                         1   external communication review

Internal ceiling = 998,900M   (v14C+ was 998,200M; +700M, all earned)
External residue  =   1,100M
Perfect           = 1,000,000M
```

## Can it reach 1,000,000M?

Yes — and only honestly. `1,000,000M` is reachable exactly when every external
obligation is closed by a genuine non-harness attestation
([`examples/ledger.perfect.jsonl`](../daylight/v15-meridian/examples/ledger.perfect.jsonl)
demonstrates this, and the harness verifies it). From inside the repository it is
**not** reachable, because:

* `q7` adversarial survival assumes an unbounded adversary;
* `q8` cryptographic margin is classical-only with fixture FROST, not post-quantum
  and not externally audited;
* `q9` statistical confidence needs independent replication;
* `q11` external falsification readiness needs a real external falsifier by
  definition;
* the residual single points in `q2`, `q5`, `q6`, `q10`, `q12` need independent
  audits.

Claiming a perfect internal score would be the overclaim `ManualScore -> Reject`
exists to forbid. Meridian therefore treats `998,900M` as the honest candidate and
carries the `1,100M` residue as an explicit, named, open external frontier rather
than quietly absorbing it. `tests/test_external_residue.py` proves both directions:
internal evidence cannot reach the perfect score, and a self-signed external
attestation is refused.

## Boundary

This is research-evidence scoring, not external certification. The Meridian package
does not change Wuci-Ji's cryptographic claims, does not grant release authority,
and does not assert runtime containment or post-quantum safety. Its only claim is
that the candidate score is regenerated from frozen, witnessed, transcript-bound
evidence and that no number in it survives a manual edit.
