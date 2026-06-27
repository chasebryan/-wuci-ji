# Standards Baseline

This is the initial primary-source baseline for Daylight design work. It is not
a crate recommendation and does not approve any implementation.

## Poster Algorithms And Primary Sources

- ML-KEM is standardized by NIST FIPS 203. The final standard was published on
  2024-08-13 and defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024. NIST also
  lists a 2025 planning note about errata/potential updates, so an
  implementation lane must pin the exact document and errata state.
  Source: https://csrc.nist.gov/pubs/fips/203/final

- ML-DSA is standardized by NIST FIPS 204. NIST describes ML-DSA as a digital
  signature standard believed secure against large-scale quantum computers.
  The CSRC page lists 2025 and 2026 planning notes for FAQ/errata material.
  Source: https://csrc.nist.gov/pubs/fips/204/final

- SLH-DSA is standardized by NIST FIPS 205. It is the stateless hash-based
  signature standard based on SPHINCS+.
  Source: https://csrc.nist.gov/pubs/fips/205/final

- SHA3-512 and SHAKE256 are in NIST FIPS 202. NIST has a 2025 planning note
  stating FIPS 202 will be updated, so Daylight should pin the exact revision
  and test vectors used.
  Source: https://csrc.nist.gov/pubs/fips/202/final

- cSHAKE, KMAC, and TupleHash are specified by NIST SP 800-185. NIST has a
  2025 planning note stating that SP 800-185 will be revised.
  Source: https://csrc.nist.gov/pubs/sp/800/185/final

- AES-GCM is specified by NIST SP 800-38D. NIST has a 2024 planning note
  stating that SP 800-38D will be revised.
  Source: https://csrc.nist.gov/pubs/sp/800/38/d/final

- ECDH-style pair-wise key establishment over approved elliptic curves is
  covered by NIST SP 800-56A Rev. 3. SP 800-56A lists P-384 as supporting up
  to 192-bit classical security strength, not 256-bit strength.
  Source: https://csrc.nist.gov/pubs/sp/800/56/a/r3/final

- HPKE is specified by RFC 9180. The Daylight classical KEM lane should be the
  named HPKE interface `DHKEM(P-384,HKDF-SHA384)`, which defines validation,
  shared-secret length, and encapsulated key length, not an informal
  `ECDH-P384` operation.
  Source: https://www.rfc-editor.org/rfc/rfc9180.html

- FROST is specified by RFC 9591 as an informational CFRG/IRTF document for
  two-round Schnorr threshold signatures. The RFC states FROST depends on a
  prime-order group and cryptographic hash function and specifies multiple
  ciphersuites. It does not define `FROST-P384-SHA384`. Any P-384/SHA-384
  FROST lane must be marked custom and needs a full ciphersuite specification
  and implementation review.
  Source: https://www.rfc-editor.org/rfc/rfc9591.html

- Hash-to-curve considerations for curve-based protocols are specified by
  RFC 9380. This matters if any P-384 suite or FROST ciphersuite needs
  domain-separated hashing to curve points.
  Source: https://www.rfc-editor.org/rfc/rfc9380.html

- ChaCha20-Poly1305 AEAD is specified by RFC 8439. If used as the non-AES
  lane, Daylight needs separate nonce uniqueness and key separation rules.
  Source: https://www.rfc-editor.org/rfc/rfc8439.html

- Argon2 is specified by RFC 9106. Any Daylight password-derived key lane
  needs explicit Argon2id parameters and must remain separate from production
  authority unless a real authority policy exists.
  Source: https://www.rfc-editor.org/rfc/rfc9106.html

## Current Research Conclusions

The poster's algorithm selection is plausible for a high-assurance hybrid
design discussion, but it is too broad for immediate implementation. The safe
starting point is model code, parser constraints, transcript dependency checks,
and deterministic test vectors.

The first implementation pass now pins locally available Rust hash, AEAD, KEM,
signature, and KDF dependencies:

```text
aes-gcm          = 0.10.3
argon2           = 0.5.3
chacha20poly1305 = 0.10.1
fips203          = 0.4.3, feature ml-kem-1024
fips204          = 0.4.6, feature ml-dsa-87
fips205          = 0.4.1, feature slh_dsa_shake_256s
hkdf             = 0.12.4
p384             = 0.13.1, feature ecdh
sha2             = 0.10.9
sha3             = 0.10.9
```

This is not an endorsement that the full Daylight suite is production-ready.
It only establishes a reproducible local lane for digest derivation, AEAD
roundtrips, ML-KEM-1024 KATs, DHKEM(P-384,HKDF-SHA384) KEM-only experiments,
ML-DSA-87 verification experiments, SLH-DSA-SHAKE-256s verification
experiments, and Argon2id parameter checks.

The highest-risk implementation questions are:

- How to fixture the corrected `T0` and `T1` transcript stages.
- Whether to use an RFC 9591 FROST ciphersuite or define and review a custom
  P-384/SHA-384 ciphersuite.
- How to review the ML-KEM and DHKEM(P-384,HKDF-SHA384) combiner against
  downgrade or key-substitution gaps.
- How to make AEAD nonce uniqueness mechanically checkable.
- How to express `pq-strict` without claiming whole-system quantum safety too
  early.
- How to pin exact verifier artifacts and test vectors for ML-KEM, ML-DSA, and
  SLH-DSA.
