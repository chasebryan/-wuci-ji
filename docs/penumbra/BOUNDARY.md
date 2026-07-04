# Penumbra Boundary

## §0 Boundary (read first; this is load-bearing)

Penumbra seals a message so that `Open = ⊥` unless the caller presents evidence that re-derives a verifying transcript under a sealed policy. The key is **derived from** the verifying transcript; it is never stored and never guarded behind a software check.

**Penumbra IS:**
- an authenticated envelope whose opening is gated by re-derived, policy-verifying evidence;
- fail-closed and tamper-evident on every header and ciphertext byte;
- built entirely on standard, externally-cryptanalyzed primitives.

**Penumbra IS NOT** (the built artifact MUST NOT claim otherwise, in code, output, or docs):
- unbreakable. No such property is asserted or achievable here.
- post-quantum "immune." It is symmetric; see §3 for the exact, reduced PQ figure.
- a source of confidentiality from *public* evidence. A lock anyone can satisfy is a lock anyone can open (§5).
- self-certifying of its own strength. Strength depends on facts (witness entropy, AEAD standing) that live outside this repository.

Governing logic (Daylight rules apply):
```
NoEvidence      -> NoSeal
Open            -> ⊥        unless verifying witness re-derives τ AND AEAD tag holds
ManualScore     -> Reject    (any asserted strength without its KAT/attestation fails closed)
NoTrace         -> NoTrust
```

## §3 Security boundary statement (must appear in docs verbatim)

> A Penumbra ciphertext's confidentiality is **`min( AEAD_strength , H∞(τ | adversary) )`**.
>
> - **AEAD_strength:** ChaCha20-Poly1305 (RFC 8439), 256-bit key. Confidentiality/key-recovery ≈ **2²⁵⁶ classical, ≈2¹²⁸ under Grover**. No structural break is known; this is not a claim that none exists. Authentication (forgery) is governed by the standard Poly1305/AEAD analysis and is not meaningfully accelerated by Grover beyond key search.
> - **H∞(τ | adversary):** the min-entropy of the verifying transcript *from the adversary's viewpoint*. In `SEALED_SECRET` mode this is dominated by the min-entropy of the secret witness component. In `SEALED_PUBLIC` mode it is **~0** and there is **no confidentiality**.
>
> HKDF extracts entropy; it does **not** manufacture it. If τ is guessable, the key is guessable.
>
> The `min(...)` figure for any real deployment cannot be certified from inside this repository, because `H∞(τ)` is an external fact about how hard the policy is to satisfy. See §12.
