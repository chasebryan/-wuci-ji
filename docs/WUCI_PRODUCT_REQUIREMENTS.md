# Wuci-Ji Product Requirements

This document defines product-standard readiness. It is separate from any
Daylight security score. Product readiness measures whether the standard is
usable, documented, integrated, and adoptable.

## Product Standard Readiness Score

```text
Product Standard Readiness Score =
min(
  SpecCompleteness,
  SchemaStability,
  ConformanceTesting,
  CLIUsability,
  CIIntegration,
  DocumentationCompleteness,
  ControlMapping,
  EvidenceInteroperability,
  MonitoringDesign,
  AdoptionReadiness
)
```

The score is an integer readiness value. It is not a security-performance
claim, certification, production authority, or audit score.

## Categories

- Spec completeness.
- Schema completeness.
- Example coverage.
- Negative test coverage.
- README discoverability.
- Website discoverability.
- CI integration.
- Control mapping.
- Non-claim enforcement.
- Product usability.
- Packaging readiness.
- Adoption guidance.

## Required Product Capabilities

1. Claim scanner.
2. Evidence registry.
3. Deterministic scorecard generator.
4. Release gate.
5. SBOM/provenance binder.
6. Conformance report.
7. Control-map export.
8. Audit packet generator.
9. Website/status JSON verifier.
10. CI/CD action.

## Readiness Output

The readiness tool writes:

```text
build/daylight/product-standard-readiness.json
```

The output must include category scores, blocker list, weakest category, and
the non-claim that product readiness is not a security score.
