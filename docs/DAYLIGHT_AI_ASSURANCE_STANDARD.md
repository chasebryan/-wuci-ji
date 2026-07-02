# Daylight AI Assurance Standard

## 1. Purpose

The Daylight AI Assurance Standard defines how AI technical reviews, model
assessments, and AI-attributed score claims are classified against evidence. It
prevents unsupported validation language, false precision risk, and provenance
failure from being treated as runtime verification.

## 2. Terminology

**AI review:** a technical assessment produced by, attributed to, or materially
assisted by an AI system.

**Model-confidence assessment:** an AI judgment or estimate that is not derived
from an executed Daylight gate.

**Runtime-derived score:** a score generated from actual local command
execution, public artifact generation, blocker-vector review, score-report
verification, and required cryptographic checks.

**External validation claim:** a claim that independent reviewer evidence or
external attestation satisfies a Daylight gate.

## 3. Evidence Classes

- E0: no evidence / model interpretation only
- E1: public file inspection
- E2: static repository review
- E3: local command execution
- E4: artifact generation
- E5: artifact hash verification
- E6: blocker vector / score report verification
- E7: cryptographic attestation verification
- E8: independent external reviewer quorum

## 4. Score Classes

- S0: no score allowed
- S1: informal model-confidence assessment
- S2: static-review estimate
- S3: local execution score
- S4: artifact-backed score
- S5: externally attested score

**Mapping:**

- E0 → S0 only
- E1/E2 → at most S1 or S2, explicitly marked non-runtime
- E3/E4/E5/E6 → may support runtime score if all required gates pass
- E7/E8 → may support external validation if required by the gate

## 5. Prohibited Scoring Patterns

- using “validated” without executed verification
- using “independently validated” without independent reviewer evidence
- using “final locked score” without reproducible score report
- using exact-looking numbers without evidence basis
- using “make target simulation” as if it were make execution
- comparing against deployed cryptographic systems without a clear evidence boundary
- implying production readiness when production allowance is zero

## 6. Required Disclosures for AI Technical Reviews

Every AI review must state:

- what was inspected
- what was executed
- what was not executed
- whether artifacts were generated
- whether hashes were verified
- whether cryptographic attestations were checked
- whether the score is runtime-derived or model-confidence only
- whether external review occurred
- whether the result authorizes production claims

## 7. Runtime Verification Standard

A Daylight runtime score requires actual execution of the relevant gate. Public
file inspection is not runtime verification. Reading a repository is not
executing a gate. A model-confidence score is not cryptographic evidence.

A runtime verification packet must include the exact repository URL, commit
hash, branch or tag, make target, terminal output, generated public artifact,
artifact hash, blocker vector, score report, and required cryptographic
verification.

## 8. External Attestation Standard

External validation requires verified external evidence. Reviewer identity,
verifier vectors, signed attestations, sealed-chain checks, or cryptographic
attestation verification must be real, pinned, deterministic, and testable
where the gate requires them. External validation cannot be inferred from
phrasing alone.

## 9. National Defense / Critical Systems Warning

If AI systems are used or referenced in aerospace, defense, cryptography, cyber,
military-industrial, critical-infrastructure, or national-security-adjacent
workflows, unsupported precision and unsupported validation language can create
false assurance. That is a national defense AI assurance concern and a
standards-level review concern.

## 10. Non-Claims

- This standard does not claim any federal agency has adopted, reviewed, or endorsed Daylight.
- This standard does not claim Daylight is production-ready.
- This standard does not claim all AI reviews are invalid.
- This standard does not claim intent by any model provider or person.
- This standard records evidence requirements for scoring authority.
