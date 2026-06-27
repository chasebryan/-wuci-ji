# WUCI Golden Lock Model

Wuci-Ji Golden Lock is a repo-native model for artifact authorization and
release-evidence gating. The model does not secure host systems by itself. The
model is not production cryptography. The model is not a runtime sandbox. The
model does not claim post-quantum system security.

The purpose is to mechanically bind sealed artifacts, manifests, Gate
contracts, quorum authorization, witness bundles, ledger continuity,
provenance, install evidence, and PQ-mode discipline into a typed verifier
predicate.

```text
WJ_gold = G_{lambda,mu}(a, Omega_G)
```

Where:

```text
Omega_G = (C, M, Gamma, alpha, B, L, rho, iota, sigma_F, epsilon_Q, E, P)

C         = sealed artifact
M         = manifest
Gamma     = Gate contract
alpha     = authority root
B         = public witness bundle
L         = ledger proof / ledger head
rho       = SBOM + provenance evidence
iota      = install evidence
sigma_F   = FROST quorum receipt
epsilon_Q = PQ verifier evidence
E         = epoch / ratchet state
P         = public signer participant/domain set
```

## Transcript

```text
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

This gives the model its center:

```text
canonical transcript
-> one authorization hash
-> typed verifier predicate
-> public evidence
-> fail-closed claims
```

## Acceptance Predicate

```text
G_{lambda,mu}(a, Omega_G) = 1 iff
  a in {open, release}
  and Parse_G(Omega_G)
  and EnvOK(C, M)
  and RootOK(alpha, a, PK_F)
  and DomainQuorum_3_5(P, d)
  and FROSTVerify_3_5(PK_F, m_G, sigma_F)
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

This first repo implementation is a model validator. It checks structured
evidence, modes, booleans, thresholds, domain diversity, downgrade rules, and
claim gates. It does not implement production FROST verification or ML-DSA
verification.

## Domain Quorum

```text
DomainQuorum_3_5(P, d) =
  |P| >= 3
  and |d(P)| >= 3
```

A quorum from three signers in one custody domain fails. The 3-of-5 normal
path only improves the model over 2-of-3 when custody domains are distinct.

## Pressure Levels

```text
lambda = 0 research/proof
  -> n = 3, t = 2, mu = compat

lambda = 1 release-candidate
  -> n = 5, t = 3, mu = compat

lambda = 2 defense-evidence
  -> n = 5, t = 3, mu = hybrid-evidence

lambda = 3 authority-root / audit / ceremony
  -> n = 5, t = 4, mu = hybrid-evidence
```

Normal release/open uses 3-of-5. Authority-root rotation, external audit
acceptance, and high-consequence ceremony use 4-of-5. The normal path does not
use 4-of-5 because it is availability-brittle.

For 3-of-5 authorization over five participants:

```text
P_auth(p; 5, 3) =
  sum i=3..5 C(5,i)p^i(1-p)^(5-i)

P_break(c; 5, 3) =
  sum i=3..5 C(5,i)c^i(1-c)^(5-i)
```

At `p = 0.95`, `P_auth = 0.998841875`.

At `c = 0.01`, `P_break = 0.0000098506`.

Comparison:

```text
2/3:
  P_auth = 0.99275
  P_break = 0.000298

3/5:
  P_auth = 0.998841875
  P_break = 0.0000098506
```

Conclusion:

```text
(3/5) is preferred over (2/3) only if custody domains are distinct.
```

## PQ Modes

```text
PQModeOK_mu(epsilon_Q, m_G):

mu = compat
  -> pass

mu = hybrid-evidence
  -> MLDSA_Verify evidence present
     and PinOK evidence present
     and KAT_OK evidence present

mu = pq-secure
  -> fail closed until earned
```

`pq-secure` remains false until a future repository state includes signed
production authority, a pinned reviewed PQ verifier, parser evidence, external
audit evidence, and release-grade proof gates. The current model validator
always rejects `pq-secure`.

## Claim Policy

`ClaimOK_lambda(Omega_G)` rejects overclaims. The model rejects these input
claims:

```text
production cryptography
host security
complete runtime sandboxing
post-quantum system security
independent audit
production authority
defense-grade achieved security
```

The only bounded internal states are:

```text
research/proof
release-candidate
defense-evidence profile
authority-root ceremony profile
```

The phrase "defense-evidence profile" is an internal evidence level, not a
security claim.

## Gate Invariant

Golden rule:

```text
No plaintext before Gate.
```

Next implementation invariant:

```text
GateOK = 0 -> no plaintext file exists
AEAD tag fail -> no plaintext file exists
final output exists iff GateOK and AEADOK and NoOverwrite
```

The intended staged open path is:

```text
Stage A: verify transcript / Gate / root / witness / ledger / claim mode
Stage B: decrypt only after authorization succeeds
Stage C: commit output only after AEAD tag succeeds
```

This pass records the invariant in the model and validator. It does not change
the assembly open implementation.

## Non-Claims

- The model is not production cryptography.
- The model is not host security.
- The model is not runtime sandboxing.
- The model does not claim post-quantum system security.
- The model is not independently audited.
- The model is not production authority.
