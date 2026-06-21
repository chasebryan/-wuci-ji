# WUCI-QCAGE Model

WUCI-QCAGE / 无此量笼 / No Such Quantum Cage is a quantum-aware evidence
layer above WUCI-CAGE. It does not make Wuci-ji quantum-proof. It records which
evidence is classical-only, which evidence is quantum-aware public evidence,
and which evidence is missing until a real post-quantum verifier exists.

Let `A` be artifact bytes, `H_n(x)` be SHA-n over bytes, and `||` be byte
concatenation.

## Evidence Tuple

For an artifact `A`, QCAGE defines:

```text
E_Q(A) =
  (
    D(A),
    C(A),
    S_classic(A),
    S_pq(A),
    B(A),
    W(A),
    L(A),
    R_Q(A)
  )
```

Where:

```text
D(A) = digest vector:
       SHA256(A), SHA384(A), SHA512(A)

C(A) = cryptographic bill of materials:
       algorithms, parameters, roles, quantum status, migration target

S_classic(A) = existing WUCI-FROST / secp256k1 WUCI-WARRANT evidence

S_pq(A) = detached post-quantum authority evidence

B(A) = build/toolchain provenance:
       source hash set, Makefile hash, tool versions, build graph digest,
       optional reproducible-builder quorum

W(A) = public WUCI-WITNESS evidence

L(A) = WUCI-LEDGER entry / inclusion evidence

R_Q(A) = quantum migration risk score
```

## Digest Vector

```text
D(A) = (SHA256(A), SHA384(A), SHA512(A))
```

Quantum hash score:

```text
quantum_preimage_bits(n) = floor(n / 2)
quantum_collision_bits(n) = floor(n / 3)
```

Policy consequence:

```text
SHA-256 is retained for compatibility with existing assembly and ledger
surfaces.

SHA-384 is the minimum quantum-aware collision-sensitive digest.

SHA-512 is the preferred high-assurance digest for public witness, ledger, and
long-lived release evidence.
```

## Transcript

The QCAGE transcript for future hybrid signing is:

```text
T(A) =
  "WUCI-QCAGE-v1"
  || action
  || sha256(A)
  || sha384(A)
  || sha512(A)
  || sha512(CBOM(A))
  || sha512(build_graph(A))
  || sha512(witness_index(A))
  || policy_id
```

## Authority Evidence

```text
S_classic(A) = existing WUCI-FROST / secp256k1 WUCI-WARRANT evidence.
```

This is current compatibility evidence and is marked
`quantum-vulnerable-under-crqc`.

```text
S_pq(A) = detached post-quantum authority evidence.
```

Allowed future algorithm families:

```text
ML-DSA
SLH-DSA
LMS
XMSS
```

QCAGE v1 does not include a real PQ verifier. Any mode requiring PQ evidence
fails closed until a real, pinned, deterministic verifier is added and tested.

## Hybrid Acceptance

Hybrid acceptance is conjunctive:

```text
Accept_hybrid(A) =
  Verify_classic(T(A), sigma_classic, pk_classic)
  AND
  Verify_pq(T(A), sigma_pq, pk_pq)
```

Never implement hybrid acceptance as OR.

```text
Verify_classic(...) OR Verify_pq(...)
```

is a downgrade vulnerability.

## Quantum Migration Debt

```text
QMD(A) = max(0, T_migrate(A) + T_trust(A) - T_CRQC)
```

Where:

```text
T_migrate(A) = estimated time to replace all consumers/verifiers/roots for A
T_trust(A) = how long A's signature/provenance must remain trustworthy
T_CRQC = assumed arrival horizon for cryptanalytically relevant quantum computers
```

If `QMD(A) > 0`, classical-only signatures may remain compatibility evidence,
but the artifact must not be labeled quantum-safe.

## QCAGE Acceptance

```text
Accept_QCAGE(A) =
  Accept_CAGE(A)
  AND DigestVectorOK(A)
  AND CryptoInventoryOK(A)
  AND NoDowngrade(A)
  AND NoFalseQuantumClaim(A)
  AND WitnessPublicOnly(A)
  AND LedgerReady(A)
  AND ModeOK(A)
```

Modes:

```text
compat:
  Current WUCI-CAGE evidence can pass with quantum_safe=false.

hybrid-required:
  Require existing WUCI evidence and real PQ signature verification.
  In v1 this fails closed unless a real verifier is implemented.

pq-required:
  Require real PQ signature verification.
  Classical-only authority is insufficient.
```

Boundary statement:

```text
Q CAGE v1 provides quantum-aware artifact evidence and downgrade resistance.
It does not claim post-quantum security unless real PQ evidence is verified.
```
