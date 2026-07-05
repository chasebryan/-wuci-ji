# Defense Assurance Roadmap

Wuci-Ji / Daylight is currently a defensive research and proof artifact. This roadmap defines what must be completed before the system can honestly be described as a high-assurance Department of War-aligned defensive system candidate. It is a roadmap, not a certification claim.

The controlling Daylight rule remains:

```text
NoEvidence(x) -> NoScore(x)
NoProvenance(x) -> NoAuthority(x)
NoExecution(x) -> NoRuntimeScore(x)
ManualScore(x) -> Reject(x)
```

This document uses claim-bounded language: Department of War-aligned, defense-grade roadmap, high-assurance candidate path, and public defense-assurance roadmap. It does not claim Department of War approval, cATO authorization, RMF authorization, FIPS validation, production authority, external certification, independent audit completion, or operational deployment readiness.

## A. Current Status

The current Wuci-Ji / Daylight system has:

* deterministic proof lanes
* public evidence bundles
* Daylight score-boundary enforcement
* artifact firewalling
* external evidence intake contracts
* reproducibility-oriented review capsules
* explicit non-claim boundaries

The current system does not yet have:

* independent security audit completion
* production cryptographic validation
* RMF authorization
* cATO authorization
* FIPS 140-3 validation
* operational deployment authority
* continuous monitoring in a mission environment
* external red-team closure
* Department of War approval or endorsement

## B. Target Posture

The target posture is:

"An externally reviewed, continuously monitored, reproducibly built, evidence-bound, defense-grade high-assurance system candidate."

This target means the system can be reviewed as a serious defensive system candidate. It does not mean automatic acceptance by any government body.

## C. Roadmap Phases

| Phase | Objective | Required evidence | Exit condition |
| --- | --- | --- | --- |
| Phase 0 — Claim Boundary Lock | Prevent overclaiming before expansion. | SECURITY_BOUNDARY reviewed; PRODUCTION_READINESS reviewed; DaylightNPT passes; README and site claim surfaces checked. | No unsupported certification, production, PQ, DoW, cATO, RMF, or FIPS claim exists. |
| Phase 1 — Reproducible Build Authority | Prove independent rebuildability. | Clean independent rebuild receipt; pinned source commit; expected artifact digests; produced artifact digests; transcript digest; environment record; non-claim acknowledgement. | A non-author, external rebuild receipt verifies through the Daylight v20 external evidence path. |
| Phase 2 — Independent Verifier Quorum | Prove verifier agreement beyond the repository-owned implementation. | Three distinct verifier-family outputs; canonical verifier-output format; matching capsule output digest; non-fixture status; pinned attestation material. | The v20 3-of-3 verifier-family quorum gate closes without manual scoring. |
| Phase 3 — Security Review and Falsification | Expose the system to real adversarial review. | External security review report; red-team or falsification report; parser/capsule fuzzing results; negative corpus results; artifact firewall bypass attempts; overclaim-surface review. | All findings are either fixed, documented as accepted risk, or converted into explicit blockers. |
| Phase 4 — Cryptographic Review | Separate research cryptography from production cryptography. | Cryptographic design review; AEAD implementation review; key-handling review; timing/side-channel boundary review; production/FIPS gap register. | The project either remains clearly research-only or has a documented validated-crypto migration path. |
| Phase 5 — Supply Chain and SBOM Maturity | Make the full build and dependency chain inspectable. | SBOM; provenance statement; dependency inventory; pinned toolchain record; release artifact digest registry; build environment reproducibility notes. | A reviewer can trace source, toolchain, dependencies, build outputs, and release artifacts without relying on author assertion. |
| Phase 6 — Operational Monitoring Model | Define what continuous monitoring would mean if the system entered a real mission environment. | Monitored components list; logs/events produced by Wuci-Ji / Daylight; alert conditions; integrity-drift checks; release-gate telemetry; incident-response hooks; dashboard/status JSON design. | The project has a documented cATO-style monitoring model, but still does not claim cATO authorization. |
| Phase 7 — RMF / Control Mapping | Map Wuci-Ji / Daylight evidence to public control families without claiming equivalency. | NIST SP 800-53 family mapping; SSDF mapping; supply-chain risk mapping; assessment/authorization/monitoring mapping; system/information integrity mapping; audit/accountability mapping. | The mapping exists as a review aid and clearly states that mapping is not authorization. |
| Phase 8 — Deployment Boundary | Define where the system could safely run. | Supported host profile; unsupported host profile; operator model; trust root model; network stance; installation boundary; rollback/removal path; secure update path. | No deployment is recommended outside the documented supported boundary. |
| Phase 9 — External Authority Package | Prepare materials that an external organization could review. | Reviewer packet; reproducible build packet; threat model; security boundary; production readiness report; SBOM/provenance; audit/falsification reports; control mapping; unresolved blocker register. | The repository contains a complete public review packet without claiming approval. |
| Phase 10 — Candidate Defense System Review | Only after all prior phases, describe the project as a candidate for formal defense review. | All blockers closed or accepted; external attestations pinned; independent audit reports linked; continuous monitoring model complete; operational boundary documented; claim surface checked by DaylightNPT. | The project may say "high-assurance defense-system candidate for external review," not "Department of War system." |

## D. Contingencies Required Before Any Defense-System Claim

* [ ] Independent rebuild completed by non-author reviewer
* [ ] External verifier quorum complete
* [ ] External security audit complete
* [ ] External falsification/red-team review complete
* [ ] Fuzzing and negative-corpus evidence complete
* [ ] Cryptographic review complete
* [ ] Production cryptography boundary resolved
* [ ] SBOM and provenance complete
* [ ] Supply-chain risk register complete
* [ ] Continuous monitoring model complete
* [ ] Incident-response model complete
* [ ] RMF/control mapping complete
* [ ] cATO-style evidence model documented
* [ ] Deployment boundary documented
* [ ] Unresolved blocker register empty or explicitly accepted
* [ ] Public claim surface passes DaylightNPT
* [ ] No government endorsement implied
* [ ] No production authority implied
* [ ] No FIPS/cATO/RMF status claimed without actual evidence

## E. Scoring Rule

The defense-assurance roadmap does not raise the Daylight score by itself. Documentation creates obligations, not credit. Credit can only be assigned when evidence closes a registered obligation and the verifier can re-derive the result.

If every external validation, reproducibility, security review, installation/use, and evidence-audit contingency closes cleanly, the system may describe the result as:

"100.0 / 100.0 under the defined evidence rubric, within the validated audit scope."

This is not a claim of perfection, invulnerability, Department of War approval, production authority, or validity outside the tested scope.

## F. Warning Levels

| Level | Meaning |
| --- | --- |
| RED | Research-only; major blockers open. |
| AMBER | Internally reproducible; external validation incomplete. |
| BLUE | Externally reviewable; independent evidence intake active. |
| GREEN | External review complete within defined scope; no unresolved findings. |
| GOLD | Formal authority exists from an actual external authority. |

The current status must remain AMBER or BLUE unless real external evidence exists.
