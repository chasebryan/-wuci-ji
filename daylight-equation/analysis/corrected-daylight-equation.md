# Corrected Daylight Equation

This document is the controlling correction pass for the Daylight poster math.
The poster transcription remains historical source material; implementation
work follows this corrected structure.

## Symbols

Daylight release level and cryptographic security strength are separate:

```text
r in {0,1,2,3}
s in {128,192,256}
DL_{r,mu}(A, Omega_D) in {0,1}
```

There is no global `lambda_s = 256` claim. Security strength is a vector, not a
single scalar:

```text
s_PQ-KEM = category 5
s_PQ-SIG = category 5
s_classical-DH <= 192
s_AEAD-conf ~= 256
s_AEAD-int <= 128
s_min = 128
```

## Suite Interfaces

The classical KEM lane is HPKE's named KEM, not a raw ECDH label:

```text
KEM_C = DHKEM(P-384, HKDF-SHA384)
(ss_C, enc_C) <- DHKEM(P384,HKDF-SHA384).Encap(pk_C)
ss_C <- DHKEM(P384,HKDF-SHA384).Decap(sk_C, enc_C)
```

The keyset root is explicit:

```text
KeySet_D = C14N_keys(
  ek_Q, pk_C, PK_F, {pk_j^Q}_{j in J_Q}, pk_H, certs, revocations
)
k_D = h_D(KeySet_D)
```

FROST over P-384/SHA-384 is not an RFC 9591 ciphersuite. Daylight either uses
an RFC 9591 ciphersuite such as `FROST(P-256,SHA-256)` or marks the P-384 lane
as custom and unsupported until a separate ciphersuite specification defines
serialization, scalar encoding, challenge hash, nonce hash, commitment hash,
validation, and signature encoding. FROST is classical discrete-log evidence,
not a post-quantum signature.

## Hashing And Tuple Encoding

The Daylight digest is:

```text
Hvec_D(x) = (SHA2-512(x), SHA3-512(x), SHAKE256(x,512))
h_D(x) = TupleHash256(Hvec_D(x), 512, S="wuci/daylight/hash/v1")
```

KMAC inputs use one injective byte encoder:

```text
EncTuple(x_1,...,x_n) =
  left_encode(n) || encode_string(x_1) || ... || encode_string(x_n)
```

## Public Leakage

Publishing `h_D(A)` leaks a deterministic plaintext digest. Daylight has two
content modes:

```text
ell_A = (|A|, h_D(A))  public content commitment
ell_A = |A|            confidential content
```

Confidentiality claims are leakage-respecting. If a hidden commitment is needed,
derive it after KEM/key schedule:

```text
com_A = KMAC256(K_A, A, 256, S="artifact-commit/v1")
```

## Transcript Phases

There is no self-referential `T_D`. Daylight has distinct phases:

```text
T0 = C14N_D(
  "pre/v1",
  v, SuiteID, r, mu, eta, a, ell_A,
  h_D(M), h_D(Gamma), h_D(alpha), k_D,
  head_{i-1}, h_D(rho), h_D(iota)
)

m0 = cSHAKE256(T0, 512, N="WUCI-DAYLIGHT", S="pre-envelope/v1")

(ss_Q, ct_Q)  <- ML-KEM-1024.Encaps(ek_Q)
(ss_C, enc_C) <- DHKEM(P384,HKDF-SHA384).Encap(pk_C)

Z_D = KMAC256(
  salt_D,
  EncTuple(ss_Q, ss_C, ct_Q, enc_C, m0, k_D),
  512,
  S="wuci/daylight/kem-combine/v1"
)

OKM = KMAC256(
  Z_D,
  EncTuple(T0, ct_Q, enc_C, eta),
  6*256 + 96,
  S="wuci/daylight/key-schedule/v1"
)

(K_E,K_A,K_R,K_W,K_L,K_X,N_base) = Split(OKM)
N_j = N_base xor I2OSP_96(j)
C = AEAD_eta.Enc_{K_E}(N_0, A, T0)

T1 = C14N_D("auth/v1", h_D(T0), h_D(C), ct_Q, enc_C, eta)
m_D = cSHAKE256(T1, 512, N="WUCI-DAYLIGHT", S="authorization/v1")
```

Single-shot envelopes use `j = 0` and a single-use `K_E`. Multi-message use
must enforce `0 <= j < 2^96` and no nonce reuse under one `K_E`.

## Authorization Requirements

The mode-dependent requirement set replaces `V_Auth * PQOK_mu`:

```text
Req(r,mu) =
  {F}       if mu=compact and r<3
  {F,Q}     if mu=hybrid and r<3
  {Q,H}     if mu=pq-strict
  {F,Q,H}   if r=3 and the root ceremony requires classical co-signing

V_Auth(r,mu) = product_{X in Req(r,mu)} V_X
```

FROST quorum evidence requires public roster/share transcript evidence, not
only a final aggregate signature:

```text
V_F =
  FROSTVerify(PK_F, m_D, sigma_F)
  * FROSTShareTranscriptOK(tau_F, m_D, PK_F)
  * QuorumOK(P,d,t_F,u_F)

QuorumOK(P,d,t,u) =
  1[|P| >= t] * 1[|{d(p):p in P}| >= u] * Unique(P)
```

ML-DSA quorum verification is likewise explicit:

```text
ctx_D = "WUCI-DAYLIGHT:authorization:v1"

Q_m = {
  j in J_Q:
    ML-DSA-87.Verify(pk_j^Q, m_D, sigma_j^Q, ctx_D)=1
    and CertOK(j) and NotRevoked(j)
}

V_Q =
  1[|Q_m| >= t_Q]
  * 1[|{d(j):j in Q_m}| >= u_Q]
  * UniqueKeys(Q_m)
```

`m_D` is the pure ML-DSA message. It is not an implicit HashML-DSA invocation.

## Open Predicate

Fail-closed statements are about this algorithm's output:

```text
PreOK_{r,mu}(Omega_D) =
  Parse_D(Omega_D)
  * SuiteOK(SuiteID,r,mu)
  * EnvOK(Omega_D)
  * RootOK(alpha,a,k_D)
  * NoDowngrade(T0)
  * V_Auth(r,mu)
  * V_Gate(Gamma,a,M,alpha,m_D)
  * V_Witness
  * V_Ledger
  * V_P
  * V_iota
  * V_Claim

A' = AEAD_eta.Dec_{K_E}(N_0,C,T0)
AEADOK(A',Omega_D) = 1[A' != bottom]
LeakOK(A',ell_A) = 1[declared leakage matches A']
PostOK(A',Omega_D) =
  AEADOK(A',Omega_D) * LeakOK(A',ell_A) * NoOverwriteOK(A',Omega_D)

DL_{r,mu}(A',Omega_D) =
  PreOK_{r,mu}(Omega_D) * PostOK(A',Omega_D)

Open_D(Omega_D) =
  A'      if DL_{r,mu}(A',Omega_D)=1
  bottom  otherwise
```

Thus:

```text
GateOK(Omega_D)=0 => Open_D(Omega_D)=bottom
AEAD.Dec_{K_E}(N,C,AD)=bottom => Open_D(Omega_D)=bottom
A_out != bottom => GateOK * AEADOK * NoOverwriteOK = 1
```

## Ledger

The signed pre-transcript binds the previous ledger state. The new leaf and
epoch are computed after authorization/encryption:

```text
head_{i-1} = (i-1,R_{i-1},E_{i-1})

leaf_i = h_D(C14N_leaf(
  "daylight-leaf/v1", h_D(T1), h_D(C), ct_Q, enc_C
))

R_i = MerkleAppend(R_{i-1}, leaf_i)

E_i = cSHAKE256(
  EncTuple(E_{i-1}, R_i, leaf_i, h_D(alpha_i)),
  512,
  N="WUCI-DAYLIGHT",
  S="epoch-ratchet/v1"
)

V_Ledger =
  InclusionOK(leaf_i,R_i,pi_i)
  * ConsistencyOK(R_{i-1},R_i,kappa_i)
  * 1[E=E_i]
```

`E_i` is not included in the object whose hash becomes `leaf_i`.

## Downgrade Policy

```text
ord(compact)=0
ord(hybrid)=1
ord(pq-strict)=2

(r_T,mu_T,SuiteID_T) = ParseMode(T0)
(r_min,mu_min) = PolicyMin(a,alpha,rho,head_{i-1})

NoDowngrade(T0) =
  1[r_T >= r_min]
  * 1[ord(mu_T) >= ord(mu_min)]
  * 1[SuiteID_T = HashSuite(Suite_D)]
  * 1[Suite_D in AllowedSuites(r_T,mu_T)]
  * 1[not Revoked(SuiteID_T,head_{i-1})]

NoDowngrade_ledger =
  1[r_T >= r_{i-1}]
  * 1[ord(mu_T) >= ord(mu_{i-1})]
```

Ledger monotonicity may be bypassed only by an explicitly authorized
`root_rotate` action.

## Probability Assumptions

The poster probability formulas assume independent signer availability or
compromise:

```text
P_auth(p;n,t) = sum_{i=t}^{n} binom(n,i) p^i (1-p)^{n-i}
P_break(c;n,t) = sum_{i=t}^{n} binom(n,i) c^i (1-c)^{n-i}

QuorumBreak <=
  P_break^signer(c;n,t)
  + P_break^domain(kappa;D,u)
  + p_corr
```

Where `0 <= p_corr <= 1 - P_break^iid`.

## Security Games

Daylight uses separate theorems, not one scalar bound.

Confidentiality is leakage-respecting:

```text
Adv^{priv,ell}_DL(A) <=
  Adv^{hybKEM}_D(B)
  + Adv^{priv}_{AEAD_eta}(C)
  + Adv^{cr}_{h_D}(D)
  + epsilon_parse + epsilon_impl + epsilon_side

Adv^{hybKEM}_D <=
  min(
    Adv^{IND-CCA}_{ML-KEM-1024},
    Adv^{SS}_{DHKEM(P384)}
  )
  + Adv^{KDF}_{KMAC256}
  + epsilon_bind
```

Authorization is mode-dependent:

```text
Adv^{auth}_{DL,r,mu} <=
  min_{X in Req(r,mu)}(Adv^{forge}_X + P^{quorum-break}_X)
  + epsilon_bind + epsilon_policy + epsilon_impl
```

Fail-closed release safety is separate:

```text
Pr[Open_D(Omega) != bottom and Bad(Omega)] <=
  epsilon_parse + epsilon_policy + epsilon_gate + epsilon_impl + epsilon_op
```

## Summary

```text
Daylight_D =
  FailClosedOpen
  o LedgerGate
  o Auth_{Req(r,mu)}
  o AEAD_eta
  o KDF_{KMAC256}
  o HybridKEM(ML-KEM-1024,DHKEM(P384,HKDF-SHA384))
  o C14N_D
```

Confidentiality comes from hybrid KEM plus AEAD and is leakage-respecting if
`h_D(A)` is public. Authorization comes from mode-dependent threshold evidence.
Fail-closed behavior means `Open_D(Omega)=bottom` unless every precheck,
decrypt check, and postcheck passes.
