# Daylight v15+ Solstice

Daylight v15+ Solstice is the hermetic frontier layer over v15 Meridian. It keeps
Meridian's obligation-derived q-values and exact rational scoring, then tightens
the closure standard:

```text
NoPinnedWeights(x)     -> NoScore(x)
NoReplay(x)            -> NoClosure(x)
NoSemanticEvidence(x)  -> NoClosure(x)
UnsignedExternal(x)    -> TemplateOnly(x) -> NoExternalCredit(x)
SelfSignedExternal(x)  -> Reject(x)
NoOutputLedgerProof(x) -> NoArtifactClaim(x)
```

The default repository evidence reaches the honest internal ceiling:

```text
Score_M = 998900 / 1000000
InternalCeiling_M = 998900
ExternalResidue_M = 1100
```

External obligations contribute only through signed, non-harness attestations
accepted by an explicit external rootset. The shipped rootset is empty, so copied
or unsigned external-attestation templates receive no credit.

## Commands

```sh
make daylight-solstice-score
make daylight-solstice-verify
make daylight-solstice-frontier
make daylight-solstice-artifact
make daylight-solstice-external-demo
make daylight-solstice-ci
```

Direct CLI use:

```sh
PYTHONPATH=daylight/v15-solstice python3 -m src.cli score \
  --ledger daylight/v15-solstice/examples/ledger.seed.jsonl \
  --corpus daylight/v15-solstice/examples/corpus.seed.jsonl \
  --rootset daylight/v15-solstice/rules/external-rootset.solstice.json \
  --out daylight/v15-solstice/examples/expected-scorecard.v15-solstice.json \
  --receipt daylight/v15-solstice/examples/reproducibility-receipt.v15-solstice.json \
  --output-ledger daylight/v15-solstice/examples/output-ledger.v15-solstice.jsonl

PYTHONPATH=daylight/v15-solstice python3 -m src.cli verify-scorecard \
  daylight/v15-solstice/examples/expected-scorecard.v15-solstice.json \
  --ledger daylight/v15-solstice/examples/ledger.seed.jsonl \
  --corpus daylight/v15-solstice/examples/corpus.seed.jsonl \
  --rootset daylight/v15-solstice/rules/external-rootset.solstice.json \
  --receipt daylight/v15-solstice/examples/reproducibility-receipt.v15-solstice.json \
  --output-ledger daylight/v15-solstice/examples/output-ledger.v15-solstice.jsonl
```

Boundary: Solstice is research-evidence scoring and artifact closure. It is not
production authority, runtime containment, external certification, or a
whole-system post-quantum safety claim.
