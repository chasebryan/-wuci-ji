# Wuci-Ji Market Positioning

Wuci-Ji / Daylight should become useful as the default evidence layer for
security claims, not as a replacement for security products.

## Category

```text
Evidence-Bound Security Control Plane
```

## Positioning Rule

Wuci-Ji earns trust by refusing unsupported claims, not by maximizing claims.

## Adoption Flywheel

1. Open standard: publish spec, schemas, examples, and conformance tests.
2. Easy adoption: provide one command and one GitHub Action.
3. Immediate value: find unsupported claims, missing evidence, missing SBOMs,
   weak release gates, and false certification language.
4. Public badge: generate non-misleading conformance badges such as
   `Daylight D2 Claim-Bounded`, `Daylight D3 Reproducible`,
   `Daylight D4 Release-Gated`, and `Daylight D5 Control-Mapped`.
5. No fake authority: badges are bounded labels. They are not government
   approved and are not certifications or production authorizations.
6. Third-party compatibility: allow other tools to generate
   Daylight-compatible evidence objects.
7. Competitive neutrality: do not require users to replace current security
   tools.
8. Security ecosystem integration: treat existing tools as evidence producers.
9. Continuous downgrade: allow claims to fall when monitoring, vulnerability,
   or supply-chain evidence changes.
10. Product trust: make unsupported security claims look obsolete.

## Buyers and Users

- Open-source maintainers.
- Security-conscious companies.
- Internal platform teams.
- Release engineering teams.
- Auditors.
- Research labs.
- Defense-adjacent software teams that need proof discipline without claiming
  authorization.

## Message Boundary

Do not say:

- Wuci-Ji replaces EDR, SIEM, IAM, backup, patching, or incident response.
- Production cryptography is not claimed.
- A general runtime sandbox is not claimed.
- Post-quantum secure is not claimed.
- Not government endorsed; not independently audited.

Do say:

- Wuci-Ji / Daylight verifies whether a claim has evidence.
- Daylight makes claim boundaries machine-checkable.
- Daylight can fail releases closed when evidence is missing.
- Daylight can map evidence to controls without claiming compliance.
- External review can strengthen authority without changing the equation.
