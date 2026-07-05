# Tarski Review Appliance

Tarski Review Appliance is the reviewer-facing evidence generator and claim-to-evidence mapper for WuciOS v2.4.

The generated review packet is local evidence. It is not an external audit, certification, or approval.

Safe validation targets must not modify tracked files. Timestamped evidence is written only to ignored `build/wucios/` outputs.

## Expected Output Files

- `build/wucios/review/review.md`
- `build/wucios/review/review.json`
- `build/wucios/review/euclid-trial-phase-1.md`
- `build/wucios/review/euclid-trial-phase-1.json`
- `build/wucios/review/euclid-trial-phase-2.md`
- `build/wucios/review/euclid-trial-phase-2.json`
- `build/wucios/review/substrate-matrix.md`
- `build/wucios/review/substrate-matrix.json`
- `build/wucios/review/surface-report.md`
- `build/wucios/review/surface-report.json`
- `build/wucios/review/package-manifest.txt`
- `build/wucios/review/enabled-services.txt`
- `build/wucios/review/listening-ports.txt`
- `build/wucios/review/suid-sgid.txt`
- `build/wucios/review/kernel-modules.txt`
- `build/wucios/review/hash-manifest.sha256`
- `build/wucios/review/godel-boundary.md`
- `build/wucios/review/daylight-wucios-score.json`
- `build/wucios/review/daylight-wucios-score.md`

## NOT_MEASURED

`NOT_MEASURED` means the value was not collected from a current WuciOS artifact or trial output. Missing values must remain explicit. They must not be filled by estimates or narrative claims.

## Diagnostic-Only Scoring

If only the current host repo is scanned, the score status is `DIAGNOSTIC_ONLY` and `score_valid` remains `false`. A release-authoritative score requires a current artifact hash and complete required inputs.
