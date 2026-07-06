# Penumbra — Build Specification (v1)

**Subsystem:** Wuci-Ji (无此机) · Daylight line
**Primitive:** Evidence-derived key encapsulation (proof-gated AEAD envelope)
**Status:** buildable spec. The *code* described here is completable. A *security-strength claim about any deployment* is **not** self-certifiable and is reserved to the External Residue section.
**Audience:** an implementing agent. Follow this verbatim. Where a choice is dangerous, it has been made for you.

---

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

---

## §1 Hard prerequisites (do not start without these)

1. **Deterministic transcript.** `CanonicalTranscript(policy, witness)` MUST be **byte-identical** on Seal and on any later Open, across machines and builds. It is defined as the existing Meridian canonical scorecard re-derivation, serialized under §6 rules. If the current Meridian derivation contains *any* nondeterminism — map/iteration ordering, floating point, locale, wall-clock timestamps, unpinned registry — that nondeterminism MUST be eliminated or pinned **before** Penumbra is built. Penumbra has no meaning if τ is not reproducible.
2. **Vetted crypto only.** Do **not** hand-roll ChaCha20, Poly1305, HKDF, or SHA-256. Use audited, constant-time implementations (e.g. RustCrypto `chacha20poly1305`, `hkdf`, `sha2`, plus `subtle`, `zeroize`, `getrandom`). Hand-rolling these is the classic footgun this spec exists to avoid.
3. **CSPRNG.** All randomness (salts, nonces) from the OS CSPRNG (`getrandom`). Never a PRNG seeded from τ, time, or the message.

---

## §2 Threat model

**In scope (must resist):**
- An adversary holding the full envelope and no verifying witness: must not recover plaintext beyond the §3 bound.
- Tampering with any header field (policy, mode, salt, nonce, ids) or the ciphertext: must yield `⊥`.
- Substitution of a forged/edited scorecard: must yield `⊥`, because τ is *re-derived from the pinned registry*, never read from an asserted field. (This is the exact v14C+ weakness Meridian closed; do not regress it.)
- Malformed / truncated / oversized envelopes: no panic, no UB — always `⊥` or a clean parse error.

**Out of scope (state plainly in docs):**
- Compromise of the intended opener's secret witness component (§5). If the secret leaks, the plaintext is exposed. Penumbra protects the channel, not the opener's key management.
- Coercion / rubber-hose. Not a deniability system.
- Confidentiality in `SEALED_PUBLIC` mode — by construction there is none (§5).
- Metadata: policy descriptor, mode, sizes, and ids are visible in cleartext by design.

---

## §3 Security boundary statement (must appear in docs verbatim)

> A Penumbra ciphertext's confidentiality is **`min( AEAD_strength , H∞(τ | adversary) )`**.
>
> - **AEAD_strength:** ChaCha20-Poly1305 (RFC 8439), 256-bit key. Confidentiality/key-recovery ≈ **2²⁵⁶ classical, ≈2¹²⁸ under Grover**. No structural break is known; this is not a claim that none exists. Authentication (forgery) is governed by the standard Poly1305/AEAD analysis and is not meaningfully accelerated by Grover beyond key search.
> - **H∞(τ | adversary):** the min-entropy of the verifying transcript *from the adversary's viewpoint*. In `SEALED_SECRET` mode this is dominated by the min-entropy of the secret witness component. In `SEALED_PUBLIC` mode it is **~0** and there is **no confidentiality**.
>
> HKDF extracts entropy; it does **not** manufacture it. If τ is guessable, the key is guessable.
>
> The `min(...)` figure for any real deployment cannot be certified from inside this repository, because `H∞(τ)` is an external fact about how hard the policy is to satisfy. See §12.

---

## §4 Cryptographic components (fixed)

| Role | Choice | Params |
|---|---|---|
| AEAD | ChaCha20-Poly1305, RFC 8439 | key 32 B, nonce 12 B, tag 16 B |
| KDF | HKDF (RFC 5869) with SHA-256 | output 32 B |
| Hash | SHA-256 | for header binding and secret folding |
| CSPRNG | OS (`getrandom`) | 32 B salts, 12 B nonces |
| Constant-time | `subtle` | tag/compare paths |
| Zeroize | `zeroize` | keys, PRK, τ, secret component |

Rationale for reuse over invention: Penumbra's *only* honest strength argument is that its components are already under sustained external cryptanalysis. Introducing a novel cipher would replace a known bound with an unknown one — the opposite of "properly."

---

## §5 Modes (explicit, non-defaulting)

The envelope carries a mandatory `mode` field. There is no default; the caller MUST choose.

**`SEALED_SECRET` — genuine confidentiality.**
The witness includes a high-entropy `secret_component` held only by the intended opener. It is folded into the transcript:
```
τ = TAU_TAG ‖ base ‖ SHA-256( SECRET_TAG ‖ secret_component )
```
where `base = CanonicalTranscript_Meridian(policy, public_witness)`.
Nothing about the secret is stored anywhere in the envelope — no commitment, no salted hash. A wrong `secret_component` yields a wrong τ → wrong K → AEAD tag failure → `⊥`. The AEAD tag *is* the check; this leaks nothing and needs no separate verification step. Confidentiality ≈ min-entropy of `secret_component`, capped by AEAD.

**`SEALED_PUBLIC` — verifiable-but-open envelope.**
```
τ = TAU_TAG ‖ base
```
No secret. Any party who can satisfy the public policy re-derives τ and opens it. This provides **binding, tamper-evidence, and policy-gated authenticity — and zero confidentiality.** It is a useful primitive (a signed, self-verifying container) but a different one. `inspect` MUST flag it loudly (§9).

Constants (fixed byte strings):
```
TAU_TAG    = "wuci-daylight/penumbra/tau/v1"
SECRET_TAG = "wuci-daylight/penumbra/secret/v1"
KDF_LABEL  = "wuci-daylight/penumbra/v1"
```

---

## §6 Canonical wire format (`WJSEAL` · Penumbra)

Encoding rules (make τ, AAD, and the artifact byte-exact and cross-implementable — an asm/C verifier must be able to reproduce these bytes):
- All integers **big-endian**, fixed width.
- Every variable field is prefixed with its length as **u32 BE**.
- Fields serialized in the exact order below. No omission; absence is an explicit presence flag with a zero-length body.
- Enumerations are **u8**.

**`header_core`** (everything except ciphertext and tag):

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | magic | 16 B | `"WJSEAL\0PENUMBRA\0"` (exactly 16 bytes) |
| 2 | version | u16 | `1` |
| 3 | mode | u8 | `1`=SEALED_SECRET, `2`=SEALED_PUBLIC |
| 4 | policy | u32 len + bytes | canonical policy descriptor, reproduced verbatim: pins obligation-registry hash, `min_score` (u64), predicate id + params |
| 5 | canon_descriptor | u32 len + bytes | identifies the Meridian derivation version/rules used for τ |
| 6 | kdf_id | u8 | `1` = HKDF-SHA-256 |
| 7 | kdf_label | u32 len + bytes | `KDF_LABEL` |
| 8 | seal_salt | 32 B | fresh CSPRNG per seal |
| 9 | aead_id | u8 | `1` = ChaCha20-Poly1305 (RFC 8439) |
| 10 | nonce | 12 B | fresh CSPRNG per seal |
| 11 | asserted_entropy_present | u8 | `0` or `1` |
| 12 | asserted_entropy_bits | u16 | present iff (11)=1; **caller-asserted, unverified** |

**Envelope** = `header_core ‖ ct_len(u32) ‖ ciphertext ‖ tag(16 B)`.

- **AAD** for the AEAD = the serialized `header_core` (binds policy, mode, salt, nonce, ids).
- No plaintext scorecard is ever stored. τ is re-derived on Open, never read.

---

## §7 Algorithms

```
Seal(m, policy P, mode, witness w0 [, secret_component], asserted_bits?):
  require VerifyPolicy(P, public_of(w0)) == VERIFY_OK          # NoEvidence -> NoSeal
  base = CanonicalTranscript_Meridian(P, public_of(w0))        # byte-deterministic (§1)
  if mode == SEALED_SECRET:
      τ = TAU_TAG ‖ base ‖ SHA256(SECRET_TAG ‖ secret_component)
  else:                                # SEALED_PUBLIC
      τ = TAU_TAG ‖ base
  seal_salt = CSPRNG(32);  nonce = CSPRNG(12)
  header_core = encode(§6 fields 1..12)
  prk = HKDF_Extract(salt = seal_salt, IKM = τ)
  K   = HKDF_Expand(prk, info = KDF_LABEL ‖ SHA256(header_core), L = 32)
  (ct, tag) = ChaCha20Poly1305_Seal(K, nonce, aad = header_core, pt = m)
  zeroize(K, prk, τ, secret_component)
  return header_core ‖ u32(len ct) ‖ ct ‖ tag

Open(envelope, witness w [, secret_component]):
  parse header_core; validate magic/version/known ids   else return ⊥
  if VerifyPolicy(P, public_of(w)) != VERIFY_OK: return ⊥      # Open -> ⊥
  base = CanonicalTranscript_Meridian(P, public_of(w))
  τ'   = (mode==SEALED_SECRET) ? TAU_TAG‖base‖SHA256(SECRET_TAG‖secret_component)
                               : TAU_TAG‖base
  prk = HKDF_Extract(salt = seal_salt, IKM = τ')
  K'  = HKDF_Expand(prk, info = KDF_LABEL ‖ SHA256(header_core), L = 32)
  m   = ChaCha20Poly1305_Open(K', nonce, aad = header_core, ct, tag)   # constant-time tag
  zeroize(K', prk, τ', secret_component)
  return (m == FAIL) ? ⊥ : m

Inspect(envelope):        # NEVER decrypts; NEVER prints an absolute claim
  parse & print: magic, version, mode, policy descriptor, canon descriptor, aead_id, kdf_id, sizes
  print "AEAD: ChaCha20-Poly1305 — key recovery ~2^256 classical / ~2^128 Grover"
  if mode == SEALED_PUBLIC:
      print "CONFIDENTIALITY: NONE (public witness). Integrity / policy-binding only."
  else:
      a = asserted_entropy_present ? asserted_entropy_bits : "UNSPECIFIED"
      print "CONFIDENTIALITY (ASSERTED, NOT PROVEN): min(AEAD, H∞(τ)) = min(256/128, " + a + ")"
      print "This tool cannot verify witness entropy. Any strength claim requires external attestation (§12)."
  assert output contains none of the forbidden strings (§9)
```

Per-seal `seal_salt` makes `K` unique to each seal even for identical (policy, τ, message); therefore **ChaCha20-Poly1305 nonce reuse cannot occur across seals**, and RFC 8439's 96-bit nonce is safe here. Do not derive the nonce deterministically from the message; do not reuse salts.

---

## §8 Key & memory hygiene

- Zeroize `K`, `prk`, `τ`, and `secret_component` on every path, including error paths (`zeroize` / `Drop`).
- Constant-time tag comparison and any secret-dependent branch (`subtle`).
- No secret in logs, error strings, panics, or `inspect` output.
- `mlock` the buffers holding `K`/`prk`/`secret_component` where the platform allows (fits the low-level ethos; best-effort, documented if unavailable).
- **Unified `⊥`.** For any use beyond a trusted local CLI, do not let callers distinguish "policy failed" from "tag failed" via timing, error code, or message — that is a decryption oracle. One opaque failure.

---

## §9 Anti-overclaim requirements (the Daylight discipline, operationalized)

These are acceptance-blocking, not stylistic.

1. **Forbidden-output test.** A CI test runs `inspect` (and any status/help output) and asserts it contains **none** of: `unbreakable`, `uncrackable`, `perfect secrecy`, `impossible to break`, `guaranteed secure`, `quantum-proof`, `100% secure`. Presence fails the build. (`ManualScore -> Reject`.)
2. **Asserted vs proven.** `asserted_entropy_bits` is always rendered as *asserted, not proven*. The tool never prints a bound it cannot back with a KAT or attestation.
3. **No confidentiality-by-default.** `mode` has no default; `SEALED_PUBLIC` output is flagged as NONE-confidentiality by `inspect`.
4. **Boundary text shipped.** `§0` and `§3` text ship verbatim in `docs/penumbra/`.
5. **External residue file.** `docs/penumbra/EXTERNAL_RESIDUE.md` exists and enumerates what cannot be self-certified in the External Residue section. The repo never self-scores Penumbra as "complete security."

---

## §10 Test vectors / KATs (required CI gates)

- **Upstream KATs pass:** RFC 8439 (ChaCha20-Poly1305) and RFC 5869 (HKDF-SHA-256) test vectors.
- **Penumbra end-to-end KATs**, with `seal_salt` and `nonce` injected deterministically **in test builds only** so outputs are fixed:
  1. `SEALED_SECRET` round-trip succeeds; recovered plaintext == input.
  2. Correct public policy, **wrong `secret_component`** → `⊥`.
  3. Any single header byte flipped → `⊥`.
  4. Any single ciphertext/tag byte flipped → `⊥`.
  5. Forged scorecard field → `⊥` (τ re-derivation rejects it).
  6. Truncated / oversized / malformed envelope → clean `⊥`, no panic.
  7. `SEALED_PUBLIC` round-trip succeeds **and** `inspect` reports NONE-confidentiality.
- **Fuzz** `Open` and the parser (malformed envelopes): no panic, no UB; result is always `⊥` or `Ok`.
- **Determinism check:** same (policy, witness) → identical `base`/`τ` across two independent builds.

---

## §11 CLI surface

```
penumbra seal   --policy <file> --mode secret|public
                --witness <file> [--secret <file>]
                --asserted-entropy-bits <n>            # optional, marked asserted
                --in <plaintext> --out <envelope.wjseal>

penumbra open   --witness <file> [--secret <file>]
                --in <envelope.wjseal> --out <plaintext>     # ⊥ -> nonzero exit, no output

penumbra inspect --in <envelope.wjseal>                      # never decrypts; honest bound only
```
Exit codes: `0` success; nonzero on `⊥` / parse error, with a **single opaque** failure for `open` (§8). Secrets are never echoed.

---

## §12 Acceptance criteria and external residue

**"Done" for the code** (all required):
- §10 KATs and fuzz pass in CI; §9 forbidden-output test passes.
- Constant-time tag/policy compare; zeroization on all paths (verified).
- §3 boundary text and `EXTERNAL_RESIDUE.md` present.
- `inspect` emits only the honest, mode-appropriate bound.

**Not self-certifiable — the reserved residue** (the Penumbra analog of Daylight's held-back margin; must live in `EXTERNAL_RESIDUE.md`, and no build may score Penumbra past this line by asserting them internally):
- Independent cryptographic review of *this integration* (not just the upstream primitives).
- A signed post-quantum posture statement (the honest figure is ~128-bit symmetric under Grover; anything stronger is out of scope for a symmetric envelope).
- **Per-deployment** attestation of `H∞(secret_component)` — the actual confidentiality figure — produced by someone other than the sealing party.

Passing everything above means the **code** is complete. It does **not** mean any deployment's confidentiality is proven. That claim is external, by construction and by doctrine.

---

## §13 Deliverables / repo layout

```
penumbra/
  src/            core library (Seal / Open / Inspect, canonical codec)
  cli/            thin CLI (§11)
  tests/
    kat_rfc/      RFC 8439 + RFC 5869 vectors
    kat_penumbra/ end-to-end vectors (§10)
    fuzz/         Open + parser fuzz targets
    overclaim/    forbidden-output test (§9)
  docs/penumbra/
    SPEC.md              (this document)
    BOUNDARY.md          (§0 + §3 verbatim)
    EXTERNAL_RESIDUE.md  (§12)
```

Core in Rust with vetted crates (§4). The §6 wire format is specified precisely enough to be re-implemented in x86_64 asm/C for an independent verifier — keep it dependency-light and byte-exact; do not introduce a serializer whose output can vary.

---
*Wuci-Ji · Daylight. Penumbra opens on proof, not on assertion. It states its bound and refuses to overstate it.*
