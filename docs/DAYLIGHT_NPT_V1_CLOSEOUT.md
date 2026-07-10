# DaylightNPT v1 Closeout

## Purpose

DaylightNPT v1 is the deterministic number-precision firewall for Wuci-Ji /
Daylight public claim surfaces. It checks numeric-claim precision and evidence
binding before scores, percentages, ratios, quorums, versions, dates, digests,
repository counts, or endorsement/certification implications become public
claims.

NoNumberWithoutEvidence -> NoPublicClaim

DaylightNPT v1 checks numeric-claim precision and evidence binding. It does
not certify correctness, production readiness, security, audit status,
post-quantum security, agency endorsement, or mathematical finality.

## Exact Commands

```sh
git status --short
make daylight-npt-test
make daylight-npt
make daylight-npt-report
make daylight-npt-ci
make site-validate
```

Final validation also runs:

```sh
git diff --check
make daylight-v20-aperture-singularity-ci
```

## Verified Local Results

These values are copied from `build/daylight/npt-v1/daylight-npt.report.json`
generated from a checkout containing only tracked files, after the
verification-coverage hardening pass:

```text
result: pass
files_scanned: 324
numbers_seen: 1404
claims_checked: 8
verified: 6
exempt: 2
warnings: 0
errors: 0
registry_sha256: 23c8bebdd2e19826adce62204c431000b784e2bc636506988885c4ba5c449016
```

`files_scanned` and `numbers_seen` are properties of the scanned tree, not
constants: untracked or gitignored Markdown/JSON files under the scanned roots
are included by the filesystem walker and raise the counts locally. The
clean-checkout values above (and the CI run) are the reference. `verified`
counts registry claims with status `verified`; `exempt` counts narrow
non-claim/illustrative/exempt entries; `claims_checked` counts all registry
claims plus emitted findings.

## Report And Registry

- Report path: `build/daylight/npt-v1/daylight-npt.report.json`
- Registry path: `daylight/npt/v1/number-claims.registry.json`

The report is generated evidence. Do not edit report values by hand.

## Fixture Coverage Summary

Positive fixtures cover registered score evidence, recomputed percentages,
verifier quorum contracts, valid digest literals, and narrow non-claim
numbers.

Negative fixtures cover unsupported numeric claims, evidence mismatch,
percentage mismatch, unsupported score assertions, quorum mismatch, version
drift, malformed digest literals, false precision, manual score assertions,
volatile public counts, stale registry entries, ambiguous numeric claims, and
endorsement/certification implications.

The test suite asserts coverage for all DaylightNPT v1 finding codes from
`NPT001_UNSUPPORTED_NUMERIC_CLAIM` through
`NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION`.

## CI Integration Points

DaylightNPT v1 runs through:

- `make daylight-npt-test`
- `make daylight-npt`
- `make daylight-npt-report`
- `make daylight-npt-ci`

CI workflow integration:

- `.github/workflows/ci.yml` runs `make daylight-npt-ci` after proof/unit
  checks and before later release/publication lanes.
- At closeout, `.github/workflows/pages.yml` ran `make daylight-npt-ci` before
  `make site-validate` and before Pages publication. That redundant publisher
  was retired on 2026-07-10; Cloudflare Pages is now the sole publisher.

## Known Limitations

- DaylightNPT v1 is deterministic local static analysis, not external review.
- It checks registered evidence and recomputable forms where configured; it
  does not prove every number is globally true.
- It scans Markdown and JSON public surfaces by default and skips fenced code
  blocks, indented code lines, generated caches (including `build/`, `dist/`,
  `__pycache__/`, and Rust `target/` directories), binary files, and
  intentionally failing negative fixture directories during default repo
  scans. Numbers inside fenced or indented code are therefore invisible to
  the gate by design.
- Claim context is evaluated line by line. Claim wording on one line and the
  number on the next line are not paired.
- Quorum detection is digit-based. Word-form quorums such as "three of three"
  produce no numeric token and are not checked.
- Non-digest numeric tokens inside `.json` files are treated as data, not
  prose claims, unless a registry entry binds them.
- A token matched by a passing registry claim is accepted without further
  wording checks on that line; registry entries must stay narrow.
- Untracked or gitignored Markdown/JSON files under scanned roots change
  local `files_scanned`/`numbers_seen`; clean-checkout and CI values are the
  reference.
- It does not fetch live public counts. Volatile counts require local
  as-of/source evidence.
- Valid digest format alone is not evidence for broader claims.

## Non-Claim Caveats

DaylightNPT v1 is not certification, audit status, production readiness,
security approval, post-quantum security, agency endorsement, or mathematical
finality. It is a fail-closed precision gate for repository-local numeric
claims.

## Next Recommended Improvements

- Add more generated-evidence registrations for long-lived Daylight score
  references.
- Add targeted public artifact checks only if NPT reports are intentionally
  included in a release artifact.
- Expand recomputation checks for more ratio and percentage families.
- Add reviewer-submitted examples once external users begin exercising the
  precision gate.
