# Defense Assurance Contingencies

Purpose: create a machine-readable-style human checklist of required evidence slots for the Wuci-Ji / Daylight public defense-assurance roadmap.

This document is not Department of War approval, cATO authorization, RMF authorization, FIPS validation, production authority, external certification, or government endorsement. It lists the evidence that must exist before stronger claims can be considered.

## External Validation

Objective:
Prove that a qualified reviewer outside the repository author path can review and verify the evidence without relying on author assertion.

Required artifacts:

* reviewer identity or organization description
* reviewed commit
* reviewed artifact digest
* review transcript digest
* signed or otherwise pinned attestation
* non-claim acknowledgement

Failure condition:
Any unsigned, fixture, author-generated, unverifiable, contradictory, or scope-ambiguous review must fail closed.

Exit condition:
The external evidence verifier accepts the material and links it to the correct capsule digest.

Claim allowed after closure:
"External review evidence exists for the stated scope."

Claim still forbidden:
Government-approval, production-certification, invulnerability, FIPS-validation,
cATO-authorization, or Department-of-War-system language.

## Reproducibility

Objective:
Prove that a non-author reviewer can rebuild the stated artifact from the pinned source and produce the expected digest evidence.

Required artifacts:

* independent rebuild receipt
* pinned source commit
* clean checkout statement
* build command transcript digest
* expected artifact digests
* produced artifact digests
* build environment record
* non-claim acknowledgement

Failure condition:
Any digest mismatch, unpinned source, author-generated receipt, missing transcript digest, or ambiguous build environment must fail closed.

Exit condition:
The Daylight v20 external evidence path accepts the independent rebuild receipt for the stated scope.

Claim allowed after closure:
"Independent rebuild evidence exists for the stated artifact and commit."

Claim still forbidden:
Production-release-authority, government-approval, cATO-authorization,
RMF-authorization, or independent-audit language.

## Security Review

Objective:
Expose the claim surface, capsule parsing, public evidence firewall, and proof lanes to external security review and falsification.

Required artifacts:

* external security review report
* red-team or falsification report
* parser/capsule fuzzing results
* negative corpus results
* artifact firewall bypass attempt log
* issue disposition register
* accepted-risk register, if any

Failure condition:
Any unresolved high-impact finding, missing scope statement, unreviewed parser surface, or undocumented accepted risk must fail closed.

Exit condition:
All findings are fixed, explicitly accepted with rationale, or promoted into blocker status.

Claim allowed after closure:
"External security review evidence exists for the stated scope."

Claim still forbidden:
Invulnerability, independent-audit language without an actual audit report,
operational-defense-system language, or Department-of-War-approval language.

## Cryptographic Review

Objective:
Separate research cryptography and fixture authority from any future validated production cryptography path.

Required artifacts:

* cryptographic design review
* AEAD implementation review
* key-handling review
* timing and side-channel boundary review
* fixture-authority register
* production/FIPS gap register
* validated-crypto migration plan, if pursued

Failure condition:
Any placeholder verifier, fixture authority treated as production authority, classical-only evidence labeled quantum-safe, or missing production/FIPS gap must fail closed.

Exit condition:
The project either remains clearly research-only or has a documented migration path to reviewed validated cryptography.

Claim allowed after closure:
"Cryptographic review evidence exists for the stated research or migration scope."

Claim still forbidden:
"Production cryptography," "FIPS validated," "post-quantum secure," or "quantum-safe" without actual validated evidence.

## Installation/Use Testing

Objective:
Prove that documented installation and use paths are deterministic, noninteractive where required, and bounded to local signed evidence.

Required artifacts:

* install transcript
* local root-key copy evidence
* signed manifest verification evidence
* atomic write evidence where practical
* rollback/removal transcript
* supported host profile
* unsupported host profile
* operator-use notes

Failure condition:
Any unsigned manifest, remote-code shell pipeline, interactive install requirement, unchecked symlink proof read, or unsupported host ambiguity must fail closed.

Exit condition:
The documented install/use path is repeatable on supported hosts and rejects unsupported inputs.

Claim allowed after closure:
"Installation/use evidence exists for the stated supported host profile."

Claim still forbidden:
Operational-deployment-ready, production-authority, runtime-sandboxing, or
government-approval language.

## Continuous Monitoring

Objective:
Define what ongoing monitoring would measure if Wuci-Ji / Daylight entered a real mission environment.

Required artifacts:

* monitored components list
* emitted logs and events
* alert conditions
* integrity-drift checks
* release-gate telemetry
* incident-response hooks
* dashboard/status JSON design
* evidence-retention policy

Failure condition:
Any monitoring claim without defined events, alert conditions, retention boundary, or integrity drift model must fail closed.

Exit condition:
A reviewer can inspect the monitoring model and determine what signal would prove drift, failure, or release blocking.

Claim allowed after closure:
"A cATO-style continuous monitoring evidence model is documented."

Claim still forbidden:
"cATO authorized," "RMF authorized," "continuous monitoring approved," or "operational mission deployment."

## Supply Chain

Objective:
Make source, dependencies, toolchain, build environment, and release artifacts traceable without relying on author assertion.

Required artifacts:

* SBOM
* provenance statement
* dependency inventory
* pinned toolchain record
* release artifact digest registry
* build environment reproducibility notes
* supply-chain risk register

Failure condition:
Any unpinned dependency, missing release digest, unverifiable toolchain, or undocumented supply-chain risk must fail closed.

Exit condition:
A reviewer can trace the build and release chain from source to artifact with explicit gaps.

Claim allowed after closure:
"Supply-chain evidence exists for the stated source, toolchain, and release scope."

Claim still forbidden:
SLSA-certification, government-approval, production-authority, or total
supply-chain-assurance language without external authority.

## Operational Boundary

Objective:
Define where the system could safely run and which environments remain unsupported.

Required artifacts:

* supported host profile
* unsupported host profile
* operator model
* trust root model
* network stance
* installation boundary
* rollback/removal path
* secure update path
* residual-risk register

Failure condition:
Any deployment recommendation outside the supported boundary, unsupported no-network claim, unsupported runtime containment claim, or unclear trust root must fail closed.

Exit condition:
The project documents exactly where it can run, what authority it needs, and what remains unsupported.

Claim allowed after closure:
"A deployment boundary is documented for the stated supported host profile."

Claim still forbidden:
"Operational defense system," "runtime sandboxing," "mission ready," or "Department of War system."

## Claim-Boundary Review

Objective:
Ensure all public claim surfaces obey the Daylight rule and do not imply certification or authority.

Required artifacts:

* SECURITY_BOUNDARY review
* PRODUCTION_READINESS review
* DaylightNPT report
* README claim review
* website claim review
* claim-evidence map review
* blocker register

Failure condition:
Any unsupported certification, production, PQ, DoW, cATO, RMF, FIPS, audit, endorsement, or operational claim must fail closed.

Exit condition:
DaylightNPT passes and all public claim surfaces match the registered evidence boundary.

Claim allowed after closure:
"Public claim surfaces passed the stated DaylightNPT and boundary review."

Claim still forbidden:
No-risk, total-assurance, government-endorsement, FIPS-validation,
cATO-authorization, or RMF-authorization language.

## Website/Public Surface Review

Objective:
Make the public website, machine-readable status files, and discovery metadata match the repository evidence and non-claim boundary.

Required artifacts:

* site validation report
* defense-assurance page review
* defense-assurance status JSON review
* sitemap review
* llms.txt review
* claim-evidence map review
* public-link integrity review

Failure condition:
Any public page that implies approval, certification, production authority, independent audit completion, or unsupported score credit must fail closed.

Exit condition:
The public website and machine-readable surfaces describe the roadmap as roadmap-only and link to the controlling evidence.

Claim allowed after closure:
"The public defense-assurance roadmap surface is published and claim-bounded."

Claim still forbidden:
Department-of-War-approval, cATO-authorization, RMF-authorization,
FIPS-validation, production-authority, or external-certification language.
