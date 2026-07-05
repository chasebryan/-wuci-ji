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
- `build/wucios/review/euclid-trial-phase-2b.md`
- `build/wucios/review/euclid-trial-phase-2b.json`
- `build/wucios/review/euclid-trial-phase-3a.md`
- `build/wucios/review/euclid-trial-phase-3a.json`
- `build/wucios/review/euclid-trial-phase-3b-readiness.md`
- `build/wucios/review/euclid-trial-phase-3b-readiness.json`
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

## Phase 3A Review Status

If `build/wucios/review/euclid-trial-phase-3a.json` exists, the review packet summarizes Phase 3A global status, execution mode, backend summary, candidate definition statuses, attempt readiness, and missing inputs. If the file does not exist, the review packet records `Euclid Trial Phase 3A: NOT_RUN`.

Phase 3A does not make the review packet release-complete. Without a current WuciOS artifact and artifact-bound evidence, review status remains partial and score status remains `NO_ARTIFACT_SCORE`.

## Phase 3B Readiness Review Status

If `build/wucios/review/euclid-trial-phase-3b-readiness.json` exists, the review packet summarizes Phase 3B readiness global status, execution mode, backend summary, candidate readiness statuses, future authorization levels, score status, and build/container/VM boundary booleans. If the file does not exist, the review packet records `Euclid Trial Phase 3B Readiness: NOT_RUN`.

Phase 3B readiness does not make the review packet release-complete. It does not authorize execution, select a substrate, rank candidates, or create an artifact score.

## Phase 3C-A Review Status

If `build/wucios/review/euclid-trial-phase-3c-a.json` exists, the review packet summarizes Phase 3C-A global status, execution mode, backend summary, L2 synthetic smoke status, guardrail results, score status, and boundary booleans. If the file does not exist, the review packet records `Euclid Trial Phase 3C-A: NOT_RUN`.

Phase 3C-A does not make the review packet release-complete. The synthetic smoke image is not a WuciOS artifact, not a substrate artifact, and not score eligible.
