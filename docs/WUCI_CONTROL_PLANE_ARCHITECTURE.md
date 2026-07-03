# Wuci-Ji Control Plane Architecture

The Wuci-Ji Daylight Standard is an evidence-bound security control plane. It
coordinates claims, evidence, provenance, reproduction, boundaries, monitoring,
falsification, control maps, release gates, and vulnerability response.

It is not a general runtime sandbox, production cryptography, government
approval, certification, EDR, SIEM, IAM, backup, patch manager, or incident
response system.

## Control Plane Layers

| Layer | Component | Function |
| --- | --- | --- |
| Layer Zero | Daylight Equation Standard | Defines authority rules and vocabulary. |
| Layer One | Evidence Object Model | Defines canonical JSON objects. |
| Layer Two | Conformance Engine | Validates schema shape and policy obligations. |
| Layer Three | Product CLI | Runs validation, scoring, gates, maps, status, and monitoring updates. |
| Layer Four | CI/CD Gate | Blocks unsafe release actions in automation. |
| Layer Five | Website Standard | Publishes the adoption boundary and status JSON. |
| Layer Six | Enterprise Profile | Defines local, CI, release-gate, compliance-map, monitoring, and evaluation modes. |
| Layer Seven | Future Runtime Profile | Future enforcement only after implementation, review, and proof lanes exist. |

## NIST CSF 2.0 Mapping

Mappings do not equal compliance. They are evidence indexes.

| Function | Daylight Fit |
| --- | --- |
| Govern | Claim boundary, conformance profile, governance, vulnerability response. |
| Identify | Evidence registry, provenance, SBOM/provenance binding, control maps. |
| Protect | Release gates, install/trust/decrypt policy, non-claim enforcement. |
| Detect | Monitor signals, evidence drift, digest/signature mismatch. |
| Respond | Downgrade model, emergency release blocks, vulnerability response. |
| Recover | Regenerated evidence, rebuilt artifacts, patched scorecards, expired-claim handling. |

## NIST SSDF Mapping

| Area | Daylight Fit |
| --- | --- |
| Secure software development practices | Reproducible build evidence and release gates. |
| Vulnerability reduction | CVE/KEV review, downgrade rules, patch clocks. |
| Producer/consumer communication | Claim/evidence maps, conformance reports, audit packets. |

## NIST SP 800-53 Mapping

| Control Family | Daylight Fit |
| --- | --- |
| Access Control | Release, trust, decrypt, and deploy allowed-action records. |
| Audit and Accountability | Evidence registry, scorecards, conformance reports. |
| Configuration Management | Source commit, environment, and build transcript binding. |
| Identification and Authentication | Attestor identity and public key references. |
| Incident Response | Vulnerability response and downgrade actions. |
| Risk Assessment | Blocker vectors and gap fields. |
| System and Services Acquisition | Supply-chain evidence and SBOM/provenance objects. |
| System and Communications Protection | Cryptographic boundary and runtime non-claims. |
| System and Information Integrity | Digest, signature, and monitor-signal checks. |
| Supply-Chain Risk Management | SLSA-style provenance, in-toto-style steps, SBOMs. |
| Assessment, Authorization, and Monitoring | Conformance reports, control maps, and monitoring signals. |

## Supply-Chain Standards

Daylight can index:

- SLSA-style provenance.
- in-toto-style supply-chain step transparency.
- Sigstore/cosign-style artifact signing and verification.
- SBOM and provenance outputs.
- OpenSSF Scorecard as an external project-health signal.

These references do not create certification or complete assurance by
themselves.

## Vulnerability Operations

Daylight should represent:

- CVE review.
- CISA KEV review.
- Patch/remediation clock.
- Known-exploit downgrade rules.
- Release freeze conditions.

## Formal Validation Paths

- FIPS 140-3 / CMVP for cryptographic modules if cryptographic module claims
  are made.
- NIAP/Common Criteria if a product evaluation profile is pursued.
- FedRAMP only if a cloud service offering exists.
- cATO/RMF mapping only as a review aid unless actual authorization exists.

Rule: mappings do not equal compliance. Mappings are evidence indexes.
