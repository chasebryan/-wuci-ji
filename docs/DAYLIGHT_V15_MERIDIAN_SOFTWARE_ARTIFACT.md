# Daylight v15 Meridian Software Artifact

Date: 2026-06-30

## What this is

Meridian is a deterministic evidence-derived scoring and verification tool for
Wuci-Ji research artifacts. It turns claims, evidence, obligations, receipts, and
release gates into machine-checkable outputs. A score is never asserted; it is
derived from witnessed, transcript-bound evidence that closes named obligations,
and the verifier re-derives it from a pinned obligation registry so a manually
edited number is rejected, not trusted.

The design and the honest-ceiling argument live in
[WUCI_DAYLIGHT_V15_MERIDIAN.md](WUCI_DAYLIGHT_V15_MERIDIAN.md). This document is
the artifact's operating manual: how to install it, run it, and wire it into a
build or release pipeline.

## Quickstart

Install (editable) from the repository root:

```bash
python3 -m pip install -e daylight/v15-meridian
```

The package also runs without installation:

```bash
export PYTHONPATH=daylight/v15-meridian
alias daylight-meridian="python3 -m src.cli"
```

Derive and verify a score from frozen evidence:

```bash
daylight-meridian score \
  --ledger daylight/v15-meridian/examples/ledger.seed.jsonl \
  --corpus daylight/v15-meridian/examples/corpus.seed.jsonl \
  --out scorecard.json --receipt receipt.json

daylight-meridian verify-scorecard scorecard.json \
  --ledger daylight/v15-meridian/examples/ledger.seed.jsonl \
  --corpus daylight/v15-meridian/examples/corpus.seed.jsonl
```

Inspect the frontier, build a release artifact, and run a gate:

```bash
daylight-meridian frontier
daylight-meridian artifact --out-dir build/daylight/v15-meridian
daylight-meridian gate --scorecard scorecard.json \
  --ledger daylight/v15-meridian/examples/ledger.seed.jsonl \
  --corpus daylight/v15-meridian/examples/corpus.seed.jsonl \
  --min-score 998900 --require-no-open-internal --allow-external-residue
```

## Commands

| Command | Purpose |
| --- | --- |
| `score` | Derive the evidence-bound scorecard (`--format json|text`, `--out`, `--receipt`, `--output-ledger`). |
| `verify-scorecard` | Re-derive q from obligations and recompute the score; `--strict` requires an evidence-bound check. |
| `frontier` | Print the internal ceiling, residue, and external obligations (`--json`, `--markdown-out`). |
| `attestation-template` | Emit an unsigned external-attestation template for one external obligation. |
| `explain` | Explain why each q-value has its value, with closed/open obligations and evidence ids. |
| `gate` | CI/release gate: verify, enforce `--min-score`, `--require-no-open-internal`, `--allow-external-residue`. |
| `doctor` | Self-check Python, registry, fixtures, and a seed score. |
| `artifact` | Build the deterministic release artifact directory. |
| `init-ledger`, `append-entry`, `freeze-corpus`, `check-downgrade` | Evidence and downgrade-machine utilities. |

## Practical uses

- Evidence-derived claim scoring for Wuci-Ji research artifacts.
- Release gating in CI (`gate` + `make daylight-meridian-ci`).
- Audit preparation: a frozen scorecard, receipt, and SHA256SUMS bundle.
- External attestation tracking via `attestation-template` and the external frontier.
- Reproducibility receipts that pin the ledger head, corpus digest, and registry digest.
- Regression detection: a changed score forces a changed digest, caught by `verify-scorecard`.
- Public witness/report generation via `frontier --markdown-out` and the artifact manifest.
- CI enforcement of "no evidence, no score" (missing evidence lowers q deterministically).
- Research comparison between v14C+ (asserted targets) and v15 Meridian (derived q).
- Education/demo for deterministic, tamper-evident claim verification.

## Not uses

- Not production cryptography.
- Not a vulnerability scanner.
- Not a runtime sandbox.
- Not a replacement for AES, TLS, FIPS validation, external audit, or formal certification.
- Not proof of post-quantum security.
- Not government validation.
- Not a legal or compliance certification system.

## Artifact contract

Inputs:

- obligation registry (`rules/obligations.v15.json`)
- ledger (`*.jsonl`, witnessed + transcript-bound evidence entries)
- corpus (`*.jsonl`, negative-evidence entries)
- external attestations where applicable (non-harness signed `external_attestation` entries)

Outputs (under `build/daylight/v15-meridian/`):

- `scorecard.v15-meridian.json`
- `reproducibility-receipt.v15-meridian.json`
- `frontier-report.v15-meridian.json`
- `frontier-report.v15-meridian.md`
- `ledger.with-scorecard.jsonl`
- `artifact-manifest.json` (generated date 2026-06-30, repo-relative input paths, SHA-256 of every input and output, command, package version, internal ceiling, external residue, boundary)
- `SHA256SUMS`

The output is byte-reproducible: no wall-clock time, no absolute paths.

## Score and external frontier

| Quantity | Value |
| --- | --- |
| Internal candidate ceiling | `998,900M / 1,000,000M` |
| External residue | `1,100M` |
| Perfect | `1,000,000M` (external attestations required) |

The internal ceiling is the most the repository can honestly generate from its
own evidence. The `1,100M` residue is held by external obligations the harness
cannot self-issue (external red-team, post-quantum / external crypto audit,
independent replication, external falsification, downstream release reproduction,
boundary fuzzing, and independent formal-methods / provenance / communication
audits). `frontier` lists each one. Closing them requires genuine non-harness
external attestations; `attestation-template` emits the structure to fill in. The
harness refuses any self-signed external attestation.

## Security boundary

Meridian sits beside the boundaries enumerated in
[SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md). It is evidence-and-scoring
machinery only: it does not decrypt, sign with production keys, sandbox a runtime,
or certify anything externally. Its single enforced claim is that a scorecard's
q-vector is re-derivable from a pinned obligation registry and witnessed evidence,
and that a manual edit fails verification.

## Developer API

```python
from src import api

registry = api.load_registry()
ledger = api.load_ledger("daylight/v15-meridian/examples/ledger.seed.jsonl")
corpus = api.load_corpus("daylight/v15-meridian/examples/corpus.seed.jsonl")

closed = api.resolve_closed_obligations(registry, ledger, corpus)
q_vector = api.derive_q_vector(registry, closed)
score = api.score_q_vector(q_vector, api.load_weights(), api.labels(registry))
assert score["final_score_M"] == 998900

scorecard, receipt, _ = api.generate_scorecard(
    ledger_path="daylight/v15-meridian/examples/ledger.seed.jsonl",
    corpus_path="daylight/v15-meridian/examples/corpus.seed.jsonl",
)
result = api.verify_scorecard(scorecard,
                              ledger_path="daylight/v15-meridian/examples/ledger.seed.jsonl",
                              corpus_path="daylight/v15-meridian/examples/corpus.seed.jsonl")
assert result.ok

frontier = api.frontier_status(registry)        # internal ceiling / residue / open frontier
print(api.frontier_markdown(frontier))
```

All score-critical arithmetic is exact (`fractions.Fraction` / integers); the API
never uses floating point on the scoring path.

## CI integration

Make targets:

```bash
make daylight-meridian-test            # unit tests (74)
make daylight-meridian-smoke           # CLI smoke checks
make daylight-meridian-artifact        # write the release artifact directory
make daylight-meridian-frontier        # print the frontier
make daylight-meridian-perfect-demo    # demonstrate 1,000,000M from external-attestation fixtures
make daylight-meridian-package         # editable install + console-script check
make daylight-meridian-ci              # test + smoke + artifact
```

GitHub Actions: [`.github/workflows/daylight-v15-meridian.yml`](../.github/workflows/daylight-v15-meridian.yml)
installs the package, runs the console script, runs `make daylight-meridian-ci`,
and uploads the artifact directory.

## Boundary

Daylight v15 Meridian is a deterministic research-evidence scoring artifact. It
verifies that a score is derived from pinned obligations and witnessed evidence;
it is not production cryptography, runtime containment, external certification,
government validation, or a claim of post-quantum security.
