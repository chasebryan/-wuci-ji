# Daylight v15+ Solstice

Daylight v15+ Solstice is the hermetic evidence-closure layer over Daylight v15
Meridian. Meridian made q-values obligation-derived. Solstice makes the closure
standard stricter: weights are digest-pinned, corpus closures are replay-bound,
ledger/corpus evidence must pass semantic shape checks, external mass requires a
signed non-harness attestation accepted by an explicit rootset, and verification
proves the output-ledger transition.

```text
DAYLIGHT-SOLSTICE-v15+

SolsticeScore_M = 998900 / 1000000
InternalCeiling_M = 998900
ExternalResidue_M = 1100
PerfectScore_M = 1000000

ScoreSource = hermetic evidence closure
QSource = obligation-derived
WeightSource = digest-pinned v13 vector
ExternalCredit = signed non-harness role attestations only
OutputLedgerProof = required
ArtifactManifestProof = required

ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalCertificationClaim = 0
```

## Theorems

```text
Theorem 1 - Internal ceiling.
For any artifact A with no valid external attestation quorum,
VerifySolstice(A)=pass implies Score_M(A) <= 998900.

Theorem 2 - Perfect iff externally closed.
VerifySolstice(A)=pass and Score_M(A)=1000000 iff every internal obligation is
semantically closed and every external obligation is closed by a valid signed
non-harness role attestation quorum.

Theorem 3 - Manual score rejection.
Any mutation to q_vector, weight_vector_digest, term_contributions_M,
final_score_M, closed_obligations, evidence_resolution_digest, receipt_digest,
score_entry_digest, output_ledger_head, artifact_manifest_digest, or
scorecard_digest causes verification to reject unless dependent proof objects are
regenerated from valid evidence.

Theorem 4 - No synthetic external mass.
An external obligation contributes nonzero score mass only through a
signature-verified attestation set satisfying the obligation's role policy.
Unsigned attestations contribute zero. Harness-signed external attestations reject.

Theorem 5 - Artifact closure.
A Solstice score is claim-usable only when the scorecard, receipt, output ledger,
manifest, SHA256SUMS, input ledger, corpus, obligation registry, and weight vector
form one digest-closed artifact.
```

## Implementation

The source-tree package is under `daylight/v15-solstice/`.

```sh
make daylight-solstice-ci
make daylight-solstice-frontier
make daylight-solstice-artifact
```

The default external rootset is empty. Use a supplied rootset and signed
attestation set to close external obligations; otherwise the status remains
`solstice_internal_ceiling_external_frontier_open`.
