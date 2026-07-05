# DaylightNPT v1

## Purpose

DaylightNPT v1 is a deterministic anti-inflation precision gate for Wuci-Ji /
Daylight public claim surfaces. It checks numeric claims before they become
public claims, with special attention to score inflation, version drift, false
precision, percentage mismatch, quorum mismatch, digest-format errors, stale
public-count claims, and unsupported certification or endorsement wording.

DaylightNPT v1 is not a new score system. It is a number-precision firewall.

Required caveats and non-claim language for DaylightNPT v1:

DaylightNPT v1 must be presented as a deterministic number-precision firewall,
not as a certification system.

It may say:

    DaylightNPT v1 checks whether numeric claims are evidence-bound, reproducible, mechanically recomputable where possible, and narrow enough to audit.

    DaylightNPT v1 is intended to reduce unsupported number inflation in AI-assisted and human-authored project materials.

    DaylightNPT v1 forces score, percentage, ratio, quorum, version, date, digest, and public-count claims to answer to evidence before they become public claims.

    DaylightNPT v1 treats numeric precision as a high-assurance requirement.

It must not say or imply:

    DaylightNPT v1 proves all numbers are true.
    DaylightNPT v1 proves AI-generated number data is universally accurate.
    DaylightNPT v1 proves mathematical finality.
    DaylightNPT v1 certifies correctness.
    DaylightNPT v1 certifies security.
    DaylightNPT v1 certifies production readiness.
    DaylightNPT v1 certifies audit status.
    DaylightNPT v1 makes Wuci-Ji production cryptography.
    DaylightNPT v1 makes Daylight post-quantum secure.
    DaylightNPT v1 creates external approval, endorsement, or review by any tagged agency, organization, company, or public account.
    DaylightNPT v1 sets a legally binding external standard for all AI systems.

Required documentation statement:

    DaylightNPT v1 is a project-local deterministic precision gate. It checks whether numeric claims in Wuci-Ji / Daylight public surfaces are supported by registered evidence, recomputable artifacts, exact formulas, valid digest formats, or explicit non-claim markings. It does not prove that every number is globally true, certified by external evidence, secure, production-ready, audited, or final. Its role is to make unsupported numeric claims fail closed.

Required AI-specific caveat:

    DaylightNPT v1 is designed for AI-assisted development because AI systems can generate plausible but unsupported numbers, rounded scores, stale counts, false percentages, mismatched quorums, and inflated precision. The test does not make AI outputs automatically trustworthy. It requires AI-authored numeric claims to be checked against evidence before they are accepted into the repository.

Required high-assurance caveat:

    High-assurance number handling means deterministic refusal, not confident wording. If a number cannot be traced, recomputed, validated, or explicitly marked as non-claim, DaylightNPT v1 must reject it.

Required public-language boundary:

    Public posts, release notes, README sections, docs, and site copy may describe DaylightNPT v1 as a precision firewall, evidence gate, numeric-claim checker, or anti-inflation guard. They must not describe it as certification, audit, official validation, government review, mathematical proof of all claims, or production security approval.

Prominent rules:

    NoNumberWithoutEvidence -> NoPublicClaim

    UnsupportedPrecision -> DeterministicRejection

    AIClaimedNumber + NoEvidence -> Reject

    ManualScore + NoGeneratedArtifact -> Reject

    AgencyTag + NoExplicitEndorsement -> NoEndorsementClaim

Implementation requirement:

    The scanner should flag unsupported numeric claims even when the surrounding language sounds confident, promotional, patriotic, institutional, or high-assurance. Confidence is not evidence. Public tagging is not endorsement. Prior conversation history is not evidence. A number must be bound to repository evidence, generated artifacts, exact recomputation, validated format, or a narrow non-claim exemption.

Finding code:

    NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION

Trigger this finding when public text combines numeric claims with language
implying official certification, audit, government endorsement, external
approval, or universal AI-standard authority without explicit evidence.

Examples that must fail:

    "DaylightNPT proves all AI number data is accurate."
    "DaylightNPT certifies our scores."
    "DaylightNPT makes the system production ready."
    "Tagged agencies have been made aware, therefore the numbers are validated."
    "This score is as precise as current technology allows" without a defined method, evidence source, and recomputation path.

Examples that may pass:

    "DaylightNPT checks whether numeric claims are evidence-bound."
    "DaylightNPT rejects unsupported score claims."
    "DaylightNPT recomputes percentages from exact numerator and denominator pairs."
    "DaylightNPT validates digest format and registered digest equality."
    "DaylightNPT does not certify security, audit status, production readiness, or external endorsement."

DaylightNPT v1 exists because numeric claims are high-risk. Scores,
percentages, quorum counts, versions, dates, digests, and public repository
counts can mislead reviewers if they are stale, rounded, inflated, or
unsupported. This test makes number claims auditable and fail-closed.

## Refusal Model

Core rule:

```text
Number(x) + ClaimContext(x) + NoEvidence(x) -> Reject(x)
Score(x) + ManualAssertion(x) -> Reject(x)
Percent(x) + NonRecomputable(x) -> Reject(x)
Quorum(x) + ContractMismatch(x) -> Reject(x)
DigestLabel(x) + InvalidLengthOrHex(x) -> Reject(x)
```

DaylightNPT v1 checks numeric precision. It does not certify correctness,
production readiness, security, or audit status.

## How To Run

```sh
make daylight-npt
make daylight-npt-test
make daylight-npt-report
make daylight-npt-ci
```

Direct CLI use:

```sh
PYTHONPATH=daylight/npt/v1 python3 -m daylight_npt scan \
  --registry daylight/npt/v1/number-claims.registry.json \
  --out build/daylight/npt-v1/daylight-npt.report.json \
  README.md BUILD_NOTES.md SECURITY.md docs daylight site data
```

The scanner uses only the Python standard library and performs no network
access.

## Registry

Numeric claims are registered in:

```text
daylight/npt/v1/number-claims.registry.json
```

Each claim must identify its value, allowed files, context regex, evidence,
check type, and rationale. A score-like value must point to generated evidence
or a machine-readable artifact. A registry entry cannot become a manual score
source.

Supported checks:

- `json_equals`
- `json_ratio_percent`
- `contains_all`
- `digest_format`
- `digest_equals`
- `quorum_contract`
- `version_path_consistency`
- `exact_text_non_claim`
- `exempt_with_rationale`

## Non-Claim Numbers

A number may be exempt only when it is narrow and explicit, such as an ordered
list marker, section number, file path version, command example, code-block
literal, standalone valid digest literal, or version identifier that does not
assert status. Broad exemptions are not acceptable.

## Findings

Findings are deterministic and sorted by path, line, column, code, and raw
value. `NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION` is emitted when a
numeric claim is paired with unsupported certification, audit, endorsement,
official validation, government-review, or universal AI-standard language.

Unsupported numbers are release blockers because public numeric claims can
mislead reviewers even when the surrounding prose is confident.

## Acceptance Criteria

1. `make daylight-npt-test` passes.
2. `make daylight-npt` scans the configured public claim surfaces and writes `build/daylight/npt-v1/daylight-npt.report.json`.
3. The report is byte-stable across repeated runs when inputs do not change.
4. Unsupported score claims fail.
5. Manual score assertions fail.
6. Percentage and ratio mismatches fail.
7. Quorum mismatches fail.
8. Malformed digest claims fail.
9. Volatile public counts fail unless explicitly evidence-bound with an as-of date and source.
10. No tool output contains absolute local machine paths.
11. The implementation does not change any Daylight scores or claim values to make tests pass.
12. The documentation clearly states: "DaylightNPT v1 checks numeric precision. It does not certify correctness, production readiness, security, or audit status."
13. Documentation includes the required caveats and non-claim language.
14. Public-facing copy does not imply certification, audit, production readiness, post-quantum security, agency endorsement, or universal AI-standard authority.
15. The test suite includes negative fixtures for certification/endorsement implication.
16. The scanner emits `NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION` when numeric claims are paired with unsupported certification, audit, endorsement, or universal-standard language.
17. The phrase "as precise as current technology allows" must fail unless the text defines the method, the evidence source, the recomputation path, and the limitation boundary.
