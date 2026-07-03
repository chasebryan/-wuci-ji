# Wuci-Ji Daylight Product Standard

Wuci-Ji / Daylight is being developed from a research/proof artifact into a
credible product-standard path for evidence-bound security assurance.

The product category is:

```text
Evidence-Bound Security Control Plane
```

The product thesis is:

```text
Security products usually claim protection.
Daylight/Wuci-Ji must prove claims.
```

## Current Positioning

Allowed current positioning:

- High-assurance research/proof artifact.
- Evidence-bound release and claim-integrity system.
- Security-claim verification framework.
- Reproducibility and audit-boundary system.
- Product-standard candidate.
- Default equation candidate for evidence-derived security assurance.

Current positioning must not imply production cryptography, general runtime
sandboxing, post-quantum security, independent audit completion, certification,
government approval, cATO authorization, RMF authorization, FIPS validation,
FedRAMP authorization, NIAP/Common Criteria certification, or replacement of
security operations products.

## Target Future Positioning

After the roadmap evidence exists, the target positioning is:

- Evidence-bound security control plane.
- Release authority gate.
- Audit score integrity layer.
- Supply-chain assurance layer.
- Standards-mapped security claim system.
- High-assurance product candidate.
- Enterprise pilot-ready security assurance product.

These targets remain gated by implementation, review, proof lanes, adoption,
and external authority where applicable.

## Product Architecture

| Layer | Name | Role |
| --- | --- | --- |
| Layer Zero | Daylight Equation Standard | Formal equation, vocabulary, refusal rules, and schema references. |
| Layer One | Evidence Object Model | Canonical claim, evidence, attestation, scorecard, gate, control, monitor, and conformance objects. |
| Layer Two | Conformance Engine | Validator that checks whether a project obeys the Daylight equation. |
| Layer Three | Product CLI | User-facing commands for validation, scoring, gates, explanations, exports, monitoring, and status. |
| Layer Four | CI/CD Gate | GitHub Actions and Make targets that fail closed on missing evidence or unsupported claims. |
| Layer Five | Website Standard | Public explanations of the standard, roadmap, conformance profile, non-claims, and adoption path. |
| Layer Six | Enterprise Profile | Local, CI, release-gate, compliance-map, monitoring, and evaluation modes. |
| Layer Seven | Future Runtime Profile | Future policy enforcement only after implementation, review, and proof lanes exist. |

## Default Question Set

Daylight should answer:

1. What security claim is being made?
2. What evidence supports it?
3. Who or what produced the evidence?
4. Can the result be reproduced?
5. What boundary does the claim cover?
6. What remains unproven?
7. What release, install, decrypt, publish, trust, or deploy action is allowed?
8. What would falsify the claim?
9. What monitoring proves the claim still holds?
10. What score is derivable without manual assertion?
