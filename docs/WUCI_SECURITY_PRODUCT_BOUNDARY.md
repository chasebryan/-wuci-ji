# Wuci-Ji Security Product Boundary

This document controls the product-standard claim boundary. It does not replace
`docs/SECURITY_BOUNDARY.md` or `docs/PRODUCTION_READINESS.md`; those files
remain controlling for implementation and production-readiness claims.

## Current Truth Boundary

Wuci-Ji / Daylight is not a production security replacement today. It is being
developed into an evidence-bound security control plane that can verify claims,
gate releases, map controls, and expose unproven security assumptions.

The first product category is evidence-bound security assurance, not endpoint
protection, malware detection, network firewalling, identity management, backup,
patch management, or incident response.

## Current Product Category

```text
Evidence-bound release and claim-integrity system.
Security-claim verification framework.
Product-standard candidate.
```

## Explicit Non-Claims

Wuci-Ji / Daylight is not currently:

- Production cryptography.
- A general runtime sandbox.
- Post-quantum secure.
- Independently audited.
- Department of War approved.
- Government endorsed.
- cATO authorized.
- RMF authorized.
- FIPS validated.
- FedRAMP authorized.
- NIAP/Common Criteria certified.
- A replacement for EDR, SIEM, IAM, backups, patch management, or incident response.

## Product Boundary

Wuci-Ji can help answer whether a claim is evidence-bound. It does not make the
claim true by itself. Authority is derived from claim scope, evidence,
provenance, reproducibility, boundary precision, monitoring, falsification, and
response discipline.

## Runtime Boundary

No current Daylight product-standard document may claim general runtime
containment. Runtime policy enforcement belongs to a future profile and remains
blocked until OS-level enforcement, implementation tests, review, and proof
lanes exist.

## Cryptographic Boundary

Classical signatures, secp256k1, ECDSA, RSA, DH, ECDH, and X25519 are not
quantum-safe claims. Fixture authority is test evidence only. Production
cryptographic claims require reviewed implementation evidence and, where
claimed, the applicable external validation evidence.

## Certification Boundary

Control mappings are evidence indexes, not certifications. D9 formal authority
requires actual external certification, authorization, or regulatory authority
from the appropriate body. Wuci-Ji can prepare evidence for that process; it
cannot self-issue the result.
