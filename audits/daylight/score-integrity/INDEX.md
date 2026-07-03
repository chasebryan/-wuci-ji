# Daylight Score-Integrity Audit Index

## Current Runs

| Run id | Audited commit | Generated result evidence |
| --- | --- | --- |
| `2026-07-03-558d9fa` | `558d9fa71f65fcb5346dfcb92128f60ae118739f` | Generated report result `PASS_SCORE_INTEGRITY`; see this run's manifest. |

## Generated JSON Paths

- `reports/daylight-score-claims.json` - generated claim ledger.
- `reports/ratio-percent-audit.json` - generated ratio and percentage report.
- `reports/public-surface-score-diff.json` - generated public-surface report.
- `reports/daylight-score-integrity.report.json` - generated final report.

## Validation Commands

- `make daylight-score-integrity-audit`
- `make daylight-score-integrity-audit-directory-check`
- `make daylight-npt-ci`
- `make site-validate`
- `make daylight-v20-aperture-singularity-ci`

## Caveats

The run records score integrity, not security certification, production
readiness, audit status, post-quantum security, agency endorsement,
Singularity declaration, or mathematical finality. DaylightNPT file and number
counts are scan-tree properties and must be recorded exactly for each run.
