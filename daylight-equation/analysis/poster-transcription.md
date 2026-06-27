# Poster Transcription

This is a visual transcription of `../notes/daylight-eq.jpeg`. Treat it as a
historical draft, not the active specification. The controlling mathematical
correction pass is `corrected-daylight-equation.md`.

## Core Definition

```text
DL_{lambda,mu}(a, Omega_D) = 1
lambda_s = 256
```

## Suite Definition

```text
Suite_D = {
  KEM_Q  = ML-KEM-1024,
  KEM_C  = ECDH-P384,
  SIG_Q  = ML-DSA-87,
  SIG_H  = SLH-DSA-SHAKE-256s,
  SIG_T  = FROST-P384-SHA384,
  AEAD_0 = AES-256-GCM,
  AEAD_1 = ChaCha20-Poly1305,
  XOF    = cSHAKE256,
  HASH   = SHA3-512,
  KDF_0  = KMAC256,
  KDF_1  = HKDF-SHA512,
  PWD    = Argon2id
}
```

```text
Omega_D = (
  C, M, Gamma, alpha, B, L, rho, iota, E, P, D,
  X_Q, X_C, sigma_F, Sigma_Q, sigma_H, eta
)
```

```text
a in A_lambda

A_0 = {open, release}
A_1 = {open, release, install}
A_2 = {open, release, install}
A_3 = {open, release, install, root_rotate, audit_accept}
```

## Verification Components

```text
DomQuorum_{t,n}(P, d) =
  1[|P| >= t] * 1[|d(P)| >= t]

V_F =
  FROSTVerify_{t/n}(PK_F, m_D, sigma_F) *
  DomQuorum_{t,n}(P, d)

Q_m =
  {j : ML-DSA-87.Verify(pk_j^Q, m_D, sigma_j^Q) = 1}

V_Q =
  1[|Q_m| >= t_Q] * 1[|d(Q_m)| >= t_Q]

V_H =
  1[lambda < 3] +
  1[lambda = 3] * SLH-DSA-SHAKE-256s.Verify(pk_H, m_D, sigma_H)

V_Auth = V_F * V_Q * V_H

V_Gate = GateOK(Gamma, a, M, alpha, m_D)

V_Witness =
  WitnessOK(B, M, Gamma, alpha, m_D) *
  1[PrivateMaterial(B) = 0]
```

The poster also defines Merkle/ledger epoch checks, provenance checks, and
install checks. The exact epoch-ratchet line should be rechecked against source
notation before implementation.

```text
R_i = MerkleRoot{h_D(B_0), h_D(B_1), ..., h_D(B_i)}

E_i = cSHAKE256(
  Tuple(..., R_i, m_D, i, h_D(B_i)),
  512,
  N = "WUCI-DAYLIGHT",
  S = "epoch-ratchet/v1"
)

V_Ledger =
  InclusionOK(h_D(B_i), R_i, pi_i) *
  ConsistencyOK(R_{i-1}, R_i, k_i) *
  1[epoch ratchet condition]

V_p = ProvenanceOK(rho, h_D(A), h_D(C), h_D(M))
V_i = InstallOK(iota, h_D(C), h_D(M), m_D)
```

## Hashing And Canonicalization

```text
Hvec_D(x) = (SHA2-512(x), SHA3-512(x), SHAKE256(x, 512))

h_D(x) =
  TupleHash256("wuci/daylight/hash/v1", Hvec_D(x), 512)

M =
  C14N_M(v, SuiteID, h_D(A), |A|, rho, Gamma, alpha)

T_D =
  C14N_D(
    a, h_D(M), h_D(Gamma), h_D(alpha), h_D(B),
    head(L), h_D(rho), h_D(iota), E, P, D, mu, lambda, eta
  )

m_D =
  cSHAKE256(T_D, 512, N = "WUCI-DAYLIGHT", S = "authorization/v1")
```

## Envelope And Key Schedule

```text
(ss_Q, X_Q) <- ML-KEM-1024.Encaps(pk_Q)
ss_C        = ECDH-P384(sk_e, pk_C)

Z_D =
  KMAC256(
    0^256,
    Tuple(ss_Q, ss_C, m_D, h_D(alpha), h_D(M)),
    512,
    S = "wuci/daylight/kem-combine/v1"
  )

(K_E, K_N, K_A, K_R, K_W, K_L) =
  KMAC256(
    Z_D,
    Tuple(T_D, X_Q, X_C, eta),
    6 * 256,
    S = "wuci/daylight/key-schedule/v1"
  )

N_i =
  Trunc96(
    KMAC256(K_N, Tuple(i, m_D, h_D(M)), 96, S = "nonce/v1")
  )

AD_D = T_D
C    = AEAD_eta.Enc_{K_E}(N_0, A, AD_D)
```

The poster appears to then rebind the ciphertext and KEM material into a final
transcript and authorization message:

```text
T_D = C14N_D(T_D, h_D(C), X_Q, X_C, AEAD_eta)
m_D = cSHAKE256(T_D, 512, N = "WUCI-DAYLIGHT", S = "authorization/v1")
```

This apparent reuse of `T_D` and `m_D` is a design issue to resolve before any
implementation. A future spec should name separate pre-envelope and final
authorization transcripts if both stages are required.

## Policy And Claims

```text
mu in {compact, hybrid, pq-strict}

PQOK_mu =
  V_F              if mu = compact
  V_F * V_Q        if mu = hybrid
  V_Q * V_H        if mu = pq-strict

NoDowngrade(lambda, mu, T_D) =
  1[lambda' >= lambda] * 1[mu' >= mu] * 1[SuiteID' in S_lambda]

C_0 = {research, proof}
C_1 = C_0 union {release-candidate}
C_2 = C_1 union {hybrid-evidence}
C_3 = C_2 union {root-ceremony, audit-evidence}

V_Claim = product over c in Claims(Omega_D): 1[c in C_lambda]
```

## Main Acceptance Predicate

```text
DL_{lambda,mu}(a, Omega_D) =
  1[a in A_lambda] *
  Parse_D(Omega_D) *
  EnvOK(C, M) *
  RootOK(alpha, a, PK_F, PK_Q) *
  V_Auth *
  V_Gate *
  V_Witness *
  V_Ledger *
  V_p *
  V_i *
  NoDowngrade(lambda, mu, T_D) *
  PQOK_mu *
  V_Claim
```

Boolean multiplication means logical AND.

## Threshold And Mode Parameters

```text
(n, t, n_Q, t_Q, mu) =
  (3, 2, 3, 2, compact)    if lambda = 0
  (5, 3, 5, 3, hybrid)     if lambda = 1
  (5, 3, 5, 3, hybrid)     if lambda = 2
  (5, 4, 5, 4, pq-strict)  if lambda = 3
```

## AEAD Selection

```text
AEAD_eta =
  AES-256-GCM         if eta = FIPS/HW
  ChaCha20-Poly1305   if eta = SW/noAES
```

## Probability Models And Bounds

```text
P_auth(p; n, t) =
  sum from i=t to n of binom(n, i) * p^i * (1 - p)^(n-i)

P_break(c; n, t) =
  sum from i=t to n of binom(n, i) * c^i * (1 - c)^(n-i)

P_domain(kappa; D, t) =
  sum from i=t to D of binom(D, i) * kappa^i * (1 - kappa)^(D-i)
  + p_corr

P_auth(0.95; 5, 3) = 0.998841875
P_break(0.01; 5, 3) = 9.8506e-6
P_auth(0.95; 5, 4) = 0.9774075
P_break(0.01; 5, 4) = 4.960e-8

(5, 3) = default
(5, 4) = ceremony
```

## Fail-Closed And No-Plaintext Guarantees

```text
GateOK = 0  =>  not exists A_plain
AEADOK = 0  =>  not exists A_plain

A_out exists iff GateOK * AEADOK * NoOverwrite = 1

Open(C, Omega_D) =
  AEAD_eta.Dec_{K_E}(N_0, C, AD_D)  if DL_{lambda,mu}(a, Omega_D) = 1
  bottom                            if DL_{lambda,mu}(a, Omega_D) = 0
```

## Pipeline Selection

```text
Pi_D = arg max over Pi in P_std of:

  Sec_Q(Pi) * FailClosed(Pi) * Auditability(Pi) * Verifiability(Pi)
  ------------------------------------------------------------------
  Complexity(Pi) * Latency(Pi) * StateRisk(Pi)

P_std = {Pi : Pi subset of FIPS union SP800 union RFC}
```

## Poster Summary

```text
Daylight =
  C14N -> h_D -> m_D -> (ML-KEM-1024 + P384) -> KMAC256 -> AEAD256 ->
  (FROST_3/5 and ML-DSA-87_3/5) -> Gate -> Witness -> Ledger -> NoDowngrade

DL_{2,hybrid} = society default
DL_{3,pq-strict} = root ceremony
```
