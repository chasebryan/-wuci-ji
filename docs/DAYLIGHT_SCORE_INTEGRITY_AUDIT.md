# Daylight Score Integrity Audit

## Purpose

This audit verifies that every distinct public Daylight / Wuci-Ji score claim
matches its machine evidence and its original claim boundary. It asks one
question: does each public score claim exactly match the generated evidence
and the boundary under which it was first introduced? It is not a
score-improvement pass and it does not change any score.

Required principle:

```text
NoGeneratedScore -> NoScoreClaim
NoOriginalBoundary -> NoIntegrityClaim
ScoreChanged + NoEvidence -> Reject
FixtureEvidence + ExternalClaim -> Reject
DeclarationBlocked -> NoDeclarationClaim
```

## Methodology

1. All canonical numbers were produced in a disposable clean worktree outside
   the active checkout, never a dirty local tree. The audited commit is
   recorded in each generated report.
2. Every required baseline gate was executed and its exit code recorded.
3. Distinct score claims were enumerated from tracked public surfaces
   (`git grep` over README, docs, site, daylight, data) and recorded as claim
   ledger entries with origin, evidence, recompute command, and boundary.
4. Each claim was recomputed from committed evidence or matched byte-for-byte
   against generated artifacts. Exact arithmetic uses `fractions.Fraction`
   and `decimal.Decimal` (precision 100); no floats.
5. Original claims were traced with `git log -S <value> --reverse`,
   `git log --diff-filter=A -- <path>`, and tag inspection, never from
   conversation memory.
6. The generator is `tools/daylight_score_integrity_audit.py`
   (`make daylight-score-integrity-audit`). It is deterministic, stdlib-only,
   reads tracked files only, and writes four reports under
   `build/daylight/score-audit/`. The permanent public record for copied,
   sanitized run artifacts is `audits/daylight/score-integrity/`.

## Commands run (all exit 0 in the clean worktree)

```text
make daylight-npt-test          make daylight-npt
make daylight-npt-report       make daylight-npt-ci
make site-validate             make daylight-v20-aperture-singularity-ci
make daylight-cplus-test       make daylight-meridian-test
make daylight-meridian-frontier make daylight-meridian-artifact
make daylight-meridian-ci      make daylight-meridian-public-artifact-test
make daylight-public-artifact-firewall
make daylight-v17-event-horizon-test
make daylight-solstice-verify  make daylight-zenith-verify
make daylight-analemma-verify  make daylight-v18-bastion-test
make daylight-v19-aperture-bastion-verify
```

## Score families audited

```text
family                 claim                                    status
v14C+                  998,200M / 1,000,000M candidate          recomputed (sum of term contributions, exact rational)
v15 Meridian           998,900M / 1,000,000M internal ceiling   recomputed (sum, residue 1,100M, 24 closed / 9 open obligations)
v15 Solstice/v16       998,900M held constant                   evidence-matched (verify targets pass; no inflation)
v17 Event Horizon      999,999,687 AM+ undeclared               evidence-matched (current == expected scorecard; site binding enforced)
v19 Aperture Bastion   no score family (capsule gates only)     verified via daylight-v19-aperture-bastion-verify
v20 Aperture Sing.     999,801,305 AM+ repo-owned ceiling       recomputed (floor(1e9*(1-e^-omega_eff)) reproduces the integer exactly)
v20.2                  no score (rebuild receipt intake gate)   boundary checked
v20.3                  no score (exactly 3-of-3 quorum gate)    boundary checked
DaylightNPT v1         report counts (see closeout doc)         evidence-matched; counts are tree-dependent by design
v13 Sovereign          991,300M design target (historical)      non-claim boundary (specification target, never generated)
Grok audit page        955/973/984 per 1000, 941,000M           non-claim boundary (Grok-attributed quotations, not adopted)
```

## Original-claim tracing

```text
value        first tracked introduction                 original boundary            current boundary
998,200M     16631f7 (v14C+ execution package)          generated candidate          unchanged
998,900M     e09d5da (v15 Meridian)                     honest internal ceiling      unchanged (held by v15/v16 layers)
999,999,687  f4cf2db (v17.1 Event Horizon kernel)       undeclared, gate refuses     unchanged; site-bound via daylight-status.json
999,801,305  d656951 (tag v20-aperture-singularity-     repo-owned no-external       unchanged; declaration refused;
             score-999801305)                           ceiling, fixture non-claim   fixture=true, claim_usable=false
999,999,999  ed09778 (v17 declaration target constant)  formula cap, not achieved    unchanged
991,300M     3e9d4e9 (v13 Sovereign spec doc)           design target                unchanged (historical spec)
3-of-3       cc3b5c7 (v20.3 quorum contract)            exactly three families       unchanged; more or fewer rejected
NPT counts   228666c / 014a117 (NPT v1 + hardening)     clean-checkout reference     unchanged; tree-dependence documented
```

No claim changed meaning, unit, denominator, or boundary between its original
introduction and the audited commit. No candidate value became "verified", no
internal value became "external", and no refused declaration became a
declaration anywhere on tracked public surfaces.

## Ratio and percentage recomputation

All recomputed with exact Decimal arithmetic; full results in
`build/daylight/score-audit/ratio-percent-audit.json`:

```text
998,200 / 1,000,000 = 99.82%      stated 99.82%   match (documented half-up, 2 places)
29,300 / 962,000    = 3.0457%     stated 3.0457%  match (rule undocumented; matches half-up, 4 places)
29,300 / 38,000     = 77.1053%    stated 77.1053% match (rule undocumented; matches half-up, 4 places)
120,000 / 500,000   = 24%         stated 24%      match (exact, no remainder)
```

## Quorum and blocker boundary (v20.3)

The quorum contract requires exactly three distinct external verifier
families; more than three is rejected; fixture vectors are never claim-usable;
self/internal/local/repo/harness/wuci/noxframe identities are rejected as
external; quorum closes only `independent_verifier_quorum.claim_usable_3_of_3`
and neither raises the score nor declares Singularity. A sweep for
quorum-weakening phrasings (word-form two-of-three, majority or plurality
wording, and vague multiple-verifier wording) found matches only in
intentional negative fixtures and rejected-example commands. The v20 capsule keeps `declaration_allowed: false`
with a populated blocker vector, and the score ceiling equals the capsule
score with `singularity_possible_without_external_validation: false`.

## Public-surface comparison

`site/validate.mjs` mechanically binds both public score numbers: the v17
headline (`data-am-plus` hooks must equal `site/daylight-status.json`, which
must equal the committed scorecard score and digest) and the v20 surface
(`data-v20-am-plus` hooks must equal
`site/daylight-v20-aperture-singularity-status.json`, which must match the
committed capsule digest, score, omega, blockers, and non-claims).
`site/claim-evidence.json` records evidence paths, validation commands, and
`does_not_prove` lists for each public claim. README, docs, site, and
artifacts state the same values with the same boundaries; the full location
map is in `build/daylight/score-audit/public-surface-score-diff.json`.

## DaylightNPT cross-check

The clean-worktree DaylightNPT run reproduced the expected baseline exactly
(see `docs/DAYLIGHT_NPT_V1_CLOSEOUT.md` for the values and their
tree-dependence caveat). A disposable negative test added a temporary
markdown file claiming a perfect manually-asserted score under a scanned
root: DaylightNPT failed the scan with `NPT009_MANUAL_SCORE_ASSERTION` and
`NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION` and exit code 1. The file
was removed; no missing fixture was revealed (the committed
`manual-perfect-score` fixture already covers the shape).

## Findings

No integrity failures. Zero claims were wrong, inflated, unsupported, or
boundary-drifted at the audited commit. The generated report is
`build/daylight/score-audit/daylight-score-integrity.report.json` with
`result: pass`.

The permanent repository-side record for this run is under the
`audits/daylight/score-integrity/runs/` directory.

## Residual limitations

- The v13 Sovereign percentages predate any documented rounding rule; they
  recompute exactly under half-up rounding at the stated precision, and the
  rule is recorded here rather than in that historical spec.
- DaylightNPT `files_scanned`/`numbers_seen` are properties of the scanned
  tree; untracked local files under scanned roots change them. Clean-checkout
  and CI values are the reference.
- Original-claim tracing relies on repository history; anything said about
  scores outside the repository (posts, chats, third-party outputs) is out of
  scope except where the repository itself quotes and bounds it.
- The audit tool checks the enumerated distinct claims; DaylightNPT remains
  the line-level gate for new or drifting numeric claims.

## Non-claim caveat

This audit checks score integrity against repository evidence and original
claim boundaries. It does not certify security, production readiness, audit
status, post-quantum security, external endorsement, or mathematical
finality.
