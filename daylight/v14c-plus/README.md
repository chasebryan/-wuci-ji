# Daylight v14C+ Execution Package

This package does not assert the Daylight v14C+ score manually.

It defines the conditions under which the score is admissible.

A scorecard is valid only when generated from:

1. a frozen ledger head,
2. a frozen negative-evidence corpus snapshot,
3. exact rational scoring,
4. a reproducibility receipt,
5. transcript-bound evidence.

The package enforces:

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
NoTrace(x) -> NoTrust(x)
ManualScore(x) -> Reject(x)
```

## Status

`DAYLIGHT v14C+ ASCENDANT CANDIDATE` is a candidate state. The value
`998,200M / 1,000,000M` is admissible only when the harness regenerates it from
the frozen ledger, frozen corpus, exact weights, q-evaluator rules, and receipt.

The score is not release authority. It is a generated candidate scorecard.

## Regenerate the Example

Run from the repository root:

```bash
PYTHONPATH=daylight/v14c-plus python3 -m src.cli score \
  --ledger daylight/v14c-plus/examples/ledger.seed.jsonl \
  --corpus daylight/v14c-plus/examples/corpus.seed.jsonl \
  --out daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json \
  --receipt daylight/v14c-plus/examples/reproducibility-receipt.v14c-plus.json \
  --output-ledger daylight/v14c-plus/examples/ledger.with-scorecard.jsonl
```

Verify the generated scorecard:

```bash
PYTHONPATH=daylight/v14c-plus python3 -m src.cli verify-scorecard \
  daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json
```

Run the package tests:

```bash
PYTHONPATH=daylight/v14c-plus python3 -m unittest discover \
  -s daylight/v14c-plus/tests \
  -t daylight/v14c-plus
```

Expected checked values:

```text
Correct v14C+ vector:   998200M
Incorrect C vector:     995600M
```

The second value is deliberate. It proves the validator recalculates rather than
accepting an inflated narrated score.

## Pipeline

```text
GenerateEvidence
AppendEvidence
FreezeLedger
FreezeCorpus
ScoreSnapshot
AppendScorecard
EmitReceipt
```

Scoring consumes only frozen inputs. It must not mutate the corpus or ledger
while evaluating q-values.

## Module Path

The directory name is kept as `v14c-plus` for the artifact label. Because hyphens
are not Python package identifiers, commands use:

```bash
PYTHONPATH=daylight/v14c-plus python3 -m src.cli ...
```

