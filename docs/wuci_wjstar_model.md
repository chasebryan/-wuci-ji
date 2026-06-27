# WUCI WJ* Composition Model

This document records the target composition model for WUCI-JI. It is a formal
direction and release-evidence contract, not a production-readiness claim. The
current repository still treats fixture FROST as test-only, requires external
audit evidence before production claims, and does not claim post-quantum system
security or general runtime sandboxing.

## Golden Lock V1

WJ* now uses Golden Lock v1 as its authority target:

```text
WJ* = GoldenLock_v1(AEAD + FROST_(3/5,4/5) + H-Merkle + G + R)
```

Normal defense-grade open/release uses:

```text
(n, t) = (5, 3)
```

Root rotation, authority ceremony, audit acceptance, and any future
publish/trust authority use:

```text
(n, t) = (5, 4)
```

Definitions:

```text
Omega_G = (C, M, Gamma, alpha, B, L, rho, iota, sigma_F, epsilon_Q, E, P)

Hvec(x) = (SHA256(x), SHA384(x), SHA512(x))

T_G = C14N_G(
  action        = a,
  artifact      = Hvec(C),
  manifest      = Hvec(M),
  gate_contract = Hvec(Gamma),
  authority     = Hvec(alpha),
  witness       = Hvec(B),
  ledger_head   = head(L),
  provenance    = Hvec(rho),
  install       = Hvec(iota),
  epoch         = E,
  participants  = P,
  pq_mode       = mu,
  pressure      = lambda
)

m_G = H_DST("wuci/golden-lock/v1" || T_G)
```

Domain diversity is part of the normal quorum target:

```text
DomainQuorum_3/5(P,d) =
  1[ |P| >= 3 ] * 1[ |d(P)| >= 3 ]
```

The Golden Lock predicate is:

```text
GoldenLock_{lambda,mu}(a, Omega_G) = 1 iff
  a in {open, release}
  and Parse_G(Omega_G)
  and EnvOK(C, M)
  and RootOK(alpha, a, PK_F)
  and DomainQuorum_3/5(P,d)
  and FROSTVerify_3/5(PK_F, m_G, sigma_F)
  and GateOK(Gamma, a, M, alpha, m_G)
  and WitnessOK(B, M, Gamma, alpha, m_G)
  and PrivateMaterial(B) = 0
  and LedgerOK(L, Hvec(B))
  and RatchetOK(E, L, B, m_G)
  and ProvenanceOK(rho, Hvec(C))
  and InstallOK(iota, Hvec(C))
  and NoDowngrade(mu, lambda, T_G)
  and PQModeOK_mu(epsilon_Q, m_G)
  and ClaimOK_lambda(Omega_G)
```

The golden rule is:

```text
No plaintext before Gate.
```

## PQ Modes

```text
mu = compat
  -> 1

mu = hybrid-evidence
  -> MLDSA_Verify(PK_Q, m_G, sigma_Q)
     and PinOK(verifier_Q)
     and KAT_OK(verifier_Q)

mu = pq-secure
  -> 0 until signed production authority,
     pinned reviewed PQ verifier,
     parser evidence,
     external audit,
     and release-grade proof gates exist
```

## Dynamic Thresholds

```text
lambda = 0 research/proof
  -> (3, 2, compat)

lambda = 1 release candidate
  -> (5, 3, compat)

lambda = 2 defense-grade evidence
  -> (5, 3, hybrid-evidence)

lambda = 3 authority/root/audit ceremony
  -> (5, 4, hybrid-evidence)
```

The purpose is:

```text
canonical transcript
-> one golden authorization hash
-> diverse threshold authority
-> rooted Gate enforcement
-> public witness and ledger continuity
-> fail-closed PQ evidence
-> no overclaim
```

The executable policy fixture lives in
`docs/wuci_golden_lock_policy.json` and
`docs/wuci_golden_lock_transcript_fixture.json`. `make
golden-lock-policy-matrix` checks pressure thresholds, domain quorum,
downgrade rejection, claim discipline, and pinned `C14N_G` / `m_G` evidence.
This lane is still policy/transcript evidence only; it does not implement
production 5-party FROST authority.

## Threshold Rationale

For a 3-of-5 quorum, the probability that at least three authorities are
available when each is independently available with probability `p` is:

```text
P_auth(p; 5, 3) = C(5,3)p^3(1-p)^2 + C(5,4)p^4(1-p) + p^5

p = 0.95 -> P_auth = 0.9988418750
```

The probability that at least three authorities are compromised when each is
independently compromised with probability `c` is:

```text
P_break(c; 5, 3) = C(5,3)c^3(1-c)^2 + C(5,4)c^4(1-c) + c^5

c = 0.01 -> P_break = 0.0000098506
```

For the 4-of-5 ceremony quorum:

```text
P_auth(p; 5, 4) = C(5,4)p^4(1-p) + p^5
p = 0.95 -> P_auth = 0.9774075000

P_break(c; 5, 4) = C(5,4)c^4(1-c) + c^5
c = 0.01 -> P_break = 4.96E-8
```

By comparison:

```text
(1/1) -> P_break = c
(3/5) -> P_break approximately 10c^3 for small c
(4/5) -> P_break approximately 5c^4 for small c
```

## Implementation Mapping

AEAD maps to the assembly envelope secrecy boundary and Gate-authorized open
paths.

FROST_Golden_Lock maps to the intended production authority profile. The
current deterministic fixture FROST material remains test-only until a signed
non-fixture production authority ceremony is supplied and verified. The current
assembly and Python proof lanes do not implement production 5-party FROST
authority.

H-Merkle maps to witness and ledger evidence: public bundle hashes, Merkle
leaf/root/proof primitives, ledger inclusion proofs, and ledger consistency
history.

G maps to Gate predicates: action, manifest binding, contract binding, rooted
authority allow bits, and reserved-action denial.

R maps to witness material: public release/open evidence, publish index,
attestation, and ledger anchoring.

PQ maps to QCAGE and real-PQ verifier evidence gates. `pq-secure` remains false
until independently earned.

## Current Non-Claims

- This model does not make fixture FROST production authority.
- This model does not implement production 5-party FROST authority.
- This model does not claim post-quantum system security.
- This model does not claim runtime sandboxing.
- This model does not replace independent cryptographic audit.
