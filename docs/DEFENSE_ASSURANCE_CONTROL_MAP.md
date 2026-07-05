# Defense Assurance Control Map

Purpose: map Wuci-Ji / Daylight to public assurance families without claiming formal compliance.

This document is a roadmap and evidence index. It is not an RMF authorization package, not cATO approval, not a compliance certificate, and not a substitute for an Authorizing Official.

## Mapping Status

The current mapping status is draft review aid. Wuci-Ji / Daylight has evidence-bound research proof lanes and external evidence intake contracts, but it does not have RMF authorization, cATO authorization, FIPS validation, operational deployment authority, government endorsement, or independent audit completion.

## NIST SP 800-53 Family Alignment

This section maps project evidence to public control-family topics such as access control, audit and accountability, configuration management, identification and authentication, incident response, risk assessment, system and services acquisition, system and communications protection, system and information integrity, and supply chain risk management.

Alignment means "review topic exists." It does not mean control implementation, assessment, authorization, or equivalency.

## NIST SSDF / SP 800-218 Alignment

The secure software development mapping covers documented build lanes, deterministic tests, public evidence bundles, claim-boundary checks, negative corpus handling, and reproducibility-oriented review capsules. It remains a roadmap until an external reviewer verifies the evidence for a stated scope.

## DoW cATO-Style Evidence Model

The cATO-style model is limited to documentation of possible continuous monitoring evidence: monitored components, logs/events, alert conditions, integrity drift, release-gate telemetry, incident-response hooks, and status JSON. This does not claim cATO authorization.

## DoW CSRMC-Style Lifecycle Model

The lifecycle model tracks public evidence from source to build, release, review, external evidence intake, monitoring design, and claim-boundary review. It is a Department of War-aligned lifecycle roadmap, not a Department of War validation claim.

## Supply-Chain Evidence

Supply-chain evidence today includes local build and proof targets, public artifacts, digest records, install manifest checks, and release boundary documents. Gaps remain for SBOM maturity, external provenance review, dependency risk register completion, and independently verified rebuilds.

## Audit and Accountability Evidence

Audit and accountability evidence today includes Daylight score-integrity records, witness bundles, ledger history, public claim/evidence mapping, and machine-readable site status files. Gaps remain for external audit completion, external falsification closure, and mission-environment logging.

## Incident Response Evidence

Incident response evidence is currently a roadmap item. The project has vulnerability reporting and security-boundary documents, but it does not yet have a mission-environment incident-response model, alert routing, response runbooks, or closure metrics.

## System Integrity Evidence

System integrity evidence today includes deterministic proof lanes, artifact firewalling, capsule digests, public evidence checks, safe I/O hardening, fixture quarantine, and DaylightNPT claim-surface checks. Gaps remain for external review closure, production cryptographic validation, and monitored runtime drift evidence.

## Assessment/Authorization/Monitoring Evidence

Assessment, authorization, and monitoring evidence is roadmap-only. Wuci-Ji / Daylight can prepare a public review packet and cATO-style monitoring design, but mapping is not authorization and does not replace an Authorizing Official.

| Public assurance area | Wuci-Ji / Daylight evidence today | Gap | Required next artifact |
| --------------------- | --------------------------------- | --- | ---------------------- |
| Access control / authority boundary | Gate, Warrant, fixture authority boundaries, SECURITY_BOUNDARY, PRODUCTION_READINESS. | No production authority or external authority package. | External authority package with trust root model and blocker register. |
| Audit and accountability | Witness bundles, ledger history, Daylight score-integrity audits, claim-evidence map. | No independent audit completion or mission audit pipeline. | External audit report and mission logging model. |
| Configuration management | Deterministic proof lanes, pinned examples, build targets, release process docs. | No full configuration baseline for supported deployment. | Supported host profile and configuration baseline. |
| Identification and authentication | Fixture authority roots, pinned attestation material, local install root key handling. | Fixture authority is not production identity. | Production identity and trust-root migration plan. |
| Incident response | Security reporting policy and boundary docs. | No mission incident-response hooks or closure metrics. | Incident-response model and alert routing design. |
| Risk assessment | Threat model, production readiness blockers, non-claim boundaries. | No external risk assessment closure. | External risk review and accepted-risk register. |
| System and services acquisition | Build targets, install lane, release process, public artifact firewall. | No acquisition package or external supply-chain assessment. | SBOM, provenance statement, and acquisition review packet. |
| System and communications protection | WJSEAL research artifact lanes, Gate checks, public evidence boundaries. | No production crypto validation or deployment network stance. | Cryptographic review and deployment network profile. |
| System and information integrity | Deterministic tests, Daylight proof lanes, artifact firewalling, safe I/O hardening. | No continuous integrity drift monitoring. | Integrity-drift checks and monitoring status JSON. |
| Supply chain risk management | Signed local install manifest, copied local root key, artifact digests. | No mature SBOM or external provenance review. | SBOM, dependency inventory, and supply-chain risk register. |
| Continuous monitoring | Roadmap-level monitoring design only. | No mission-environment monitoring. | Monitored component list, alert conditions, telemetry, and dashboard/status JSON. |
| Secure software development | Deterministic tests, negative fixtures, DaylightNPT, release process. | No external SSDF assessment closure. | SSDF mapping with external review notes. |
| External assessment | Daylight v20 external evidence contracts and reviewer packet. | External evidence slots remain open. | Independent rebuild, verifier quorum, security review, and falsification reports. |
| Operational deployment boundary | Production readiness and security boundary documents. | No supported deployment authority or operational profile. | Supported/unsupported host profile, rollback/removal path, and secure update path. |
