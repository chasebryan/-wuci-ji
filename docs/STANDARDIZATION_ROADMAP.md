# Daylight / Wuci-Ji Standardization Roadmap

This roadmap moves Wuci-Ji / Daylight from a high-assurance research/proof
artifact toward an evidence-bound security control plane and product-standard
candidate. It does not claim production cryptography, runtime containment,
post-quantum security, independent audit completion, government approval,
cATO authorization, RMF authorization, FIPS validation, FedRAMP authorization,
NIAP/Common Criteria certification, or replacement of EDR, SIEM, IAM, backups,
patch management, or incident response.

The product category is:

```text
Evidence-Bound Security Control Plane
```

The standard equation is:

```text
Claim + Evidence + Provenance + Reproducibility + Boundary + Monitoring + Falsification = Authority
```

## Strategic Boundary

Wuci-Ji should not compete with antivirus, EDR, firewall, SIEM, IAM, backup,
patch-management, or incident-response products. Those systems can become
evidence producers. Daylight decides which security claims, release claims,
audit scores, cryptographic boundaries, supply-chain records, and deployment
authority statements are supported by evidence.

## Phase Zero: Preserve Claim Integrity

Lock the current truth boundary before productization.

- Keep `docs/SECURITY_BOUNDARY.md` and `docs/PRODUCTION_READINESS.md`
  controlling.
- Publish `docs/WUCI_SECURITY_PRODUCT_BOUNDARY.md`.
- State that Wuci-Ji is not a production security replacement today.
- State that the first product category is evidence-bound security assurance,
  not endpoint protection.

Exit condition: no public page, README section, JSON status file, or claim
ledger implies current production authority.

## Phase One: Daylight Equation Standard

Publish `docs/DAYLIGHT_EQUATION_STANDARD.md` and
`specs/daylight-equation/v1/` with stable terms, schemas, examples, forbidden
claims, allowed claims, and conformance rules.

Exit condition: the weakest required field governs authority and unsupported
claims cannot be averaged away.

## Phase Two: Conformance Profile

Publish `docs/WUCI_CONFORMANCE_PROFILE.md` with levels D0 through D9.

Exit condition: a conformance report can classify a project without manual
score assertion. D9 always requires an external authority and cannot be
self-issued.

## Phase Three: Schemas

Publish canonical JSON schemas for claims, evidence, attestations, scorecards,
release gates, control maps, monitoring signals, conformance reports, and the
Daylight equation profile.

Exit condition: examples validate and deliberately broken objects fail.

## Phase Four: Product CLI Skeleton

Expose deterministic stdlib-only commands through
`tools/daylight_conformance.py` and focused wrappers.

Exit condition: the CLI validates examples and produces deterministic pass/fail
reports without manual score override.

## Phase Five: Product Readiness Score

Publish `docs/WUCI_PRODUCT_REQUIREMENTS.md` and generate
`build/daylight/product-standard-readiness.json`.

Exit condition: product maturity can improve without inflating any Daylight
security score.

## Phase Six: CI/CD Integration

Publish a GitHub Action, example workflows, and Make targets:

- `daylight-standard-schema-test`
- `daylight-standard-examples-test`
- `daylight-conformance-test`
- `daylight-product-score`
- `daylight-standard-site-test`
- `daylight-standard-ci`

Exit condition: another project can copy one workflow and receive a Daylight
conformance report.

## Phase Seven: Website Standard

Publish public pages for the standard, roadmap, conformance, enterprise
adoption, product boundary, no-external-validation value, external-validation
uplift, and default-standard path.

Exit condition: the website presents the product standard without implying
production security authority.

## Phase Eight: Standards and Framework Mappings

Publish `docs/WUCI_CONTROL_PLANE_ARCHITECTURE.md`,
`docs/WUCI_ENTERPRISE_ADOPTION.md`, and
`docs/WUCI_DEFAULT_STANDARD_EXIT_CRITERIA.md`.

Mappings to NIST CSF, NIST SSDF, NIST SP 800-53, SLSA-style provenance,
in-toto-style step transparency, Sigstore/cosign-style signing, SBOM outputs,
OpenSSF Scorecard, CVE, and CISA KEV are evidence indexes only.

Exit condition: reviewers can see where Wuci-Ji fits without mistaking mapping
for certification.

## Phase Nine: Adoption Flow

Support Claim Firewall, Release Evidence Gate, Supply-Chain Evidence Gate,
Audit Packet Generator, Control Mapping Export, Monitoring-Downgrade
Prototype, and External Evidence Intake modes.

Exit condition: a company can run Wuci-Ji without knowing the full research
history.

## Phase Ten: Minimum Viable Security Product

Publish `docs/WUCI_SECURITY_PRODUCT_MVP.md` for the Wuci-Ji Daylight Standard
MVP.

Exit condition: a v0 product release can be downloaded, run, and integrated
into CI.

## Phase Eleven: Adoption Flywheel

Publish `docs/WUCI_MARKET_POSITIONING.md`.

Exit condition: Wuci-Ji remains useful even to users who disagree with its
score model because evidence objects and rejection rules still add value.

## Phase Twelve: Governance

Publish `docs/WUCI_STANDARD_GOVERNANCE.md` with versioning, registries,
extension rules, disputes, vulnerability disclosure, changelog, and
compatibility policy.

Exit condition: standard evolution is versioned and reviewable.

## Phase Thirteen: Monitoring and Downgrade

Publish `docs/WUCI_MONITORING_DOWNGRADE_MODEL.md`.

Exit condition: Daylight can reduce or revoke authority when evidence changes.

## Phase Fourteen: External Validation as Uplift

Publish `docs/WUCI_NO_EXTERNAL_VALIDATION_VALUE.md` and
`docs/WUCI_EXTERNAL_VALIDATION_UPLIFT.md`.

Exit condition: external validation is treated as powerful evidence, not a
magic unlimited claim.

## Phase Fifteen: Default-Standard Exit Criteria

Publish `docs/WUCI_DEFAULT_STANDARD_EXIT_CRITERIA.md`.

Exit condition: default standard status is adoption and utility, not
self-declared supremacy.

## Final Phases: Public Surface, Validation, Response, and Posture

- Update README discovery tables and Daylight Equation Standard section.
- Update the public claim-evidence map.
- Wire validation Make targets.
- Publish `docs/WUCI_VULNERABILITY_RESPONSE.md`.
- Preserve the final posture: evidence-bound security control plane and
  standard candidate, useful today for claim integrity, release evidence, and
  conformance reporting, with production cryptography, runtime containment,
  formal certification, and government authority left as separate evidence
  gates.
