# WUCI WJ-Next Transcript Model

This document records the next target verifier shape:

```text
WJ_next = Accept_v2_mu(a, Omega)

Omega = (C, M, Gamma, alpha, B, L, rho, iota, sigma_F, epsilon_Q)

Hvec(x) = (SHA256(x), SHA384(x), SHA512(x))

T_v2 = C14N_v2(
  a,
  Hvec(C),
  Hvec(M),
  Hvec(Gamma),
  Hvec(alpha),
  Hvec(B),
  head(L),
  Hvec(rho),
  Hvec(iota),
  mu
)

m_v2 = H("wuci/transcript/v2" || T_v2)
```

The acceptance predicate is:

```text
Accept_v2_mu(a, Omega) = 1 iff
  a in {open, release}
  and Parse_v2(Omega)
  and EnvOK(C, M)
  and RootOK(alpha, a, PK_F)
  and FROSTVerify_2_of_3(PK_F, m_v2, sigma_F)
  and GateOK(Gamma, a, M, alpha, m_v2)
  and WitnessOK(B, M, Gamma, alpha, m_v2)
  and PrivateMaterial(B) = 0
  and LedgerOK(L, Hvec(B))
  and ProvenanceOK(rho, Hvec(C))
  and InstallOK(iota, Hvec(C))
  and PQModeOK_mu(epsilon_Q, m_v2)
```

Post-quantum modes:

```text
mu = compat          -> 1
mu = hybrid-evidence -> MLDSA_Verify and PinOK and KAT_OK
mu = pq-secure       -> 0 until earned
```

The purpose is:

```text
canonical transcript -> one authorization hash -> typed verifier predicate
```

This model is intentionally stricter than ad hoc evidence composition: every
verifier receives the same transcript hash `m_v2`, and each predicate names the
evidence it binds. It is still a target model, not a production claim.

## Non-Claims

- Compat mode does not claim post-quantum security.
- Hybrid-evidence mode requires pinned ML-DSA evidence and KAT verification,
  but still does not by itself make the whole system quantum-safe.
- PQ-secure mode is false until independently earned.
- This transcript model does not claim runtime sandboxing.
- This transcript model does not replace signed production authority or
  independent audit evidence.
