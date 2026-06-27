# WUCI WJ* Composition Model

This document records the target composition model for WUCI-JI. It is a formal
direction and release-evidence contract, not a production-readiness claim. The
current repository still treats fixture FROST as test-only, requires external
audit evidence before production claims, and does not claim post-quantum system
security or general runtime sandboxing.

## Composition

```text
WJ* = AEAD_K(A; M || G) intersect
      FROST_(2/3)(H(M || G || R)) intersect
      Merkle(C, M, G, R, sigma)

open = 1 iff
  D_K(C) = A
  and V_Sigma(sigma) = 1
  and G(M) = 1
  and I_H(R) = 1
```

Definitions:

```text
A = artifact
M = H(A || v || pi)
G = pi(M)
K = KDF(s, M)

C = AEAD.Enc_K(A; AD = M || G)

W = (M, G, tau, rho)
sigma_F = FROST.Sign_(2/3)(H(W))

V_F(sigma_F, H(W), PK_F) = 1

R = MerkleRoot{H(C), H(M), H(G), H(W), H(sigma_F)}

Omega = (C, M, G, W, sigma_F, R, path)
```

The open predicate is:

```text
OPEN(Omega) = 1 iff
  AEAD.Dec_K(C; M || G) = A
  and V_F(sigma_F, H(W), PK_F) = 1
  and G(M) = 1
  and MerkleVerify(H(W), R, path) = 1
```

The short form is:

```text
WJ* = AEAD + FROST_(2/3) + H-Merkle + G + R

AEAD         -> secrecy
FROST_(2/3) -> authority
H-Merkle     -> evidence
G            -> policy
R            -> witness
```

## Threshold Rationale

For a 2-of-3 quorum, the probability that at least two authorities are
available when each is independently available with probability `p` is:

```text
P_auth(p; 3, 2) = C(3,2)p^2(1-p) + p^3
                = 3p^2 - 2p^3

p = 0.95 -> P_auth = 0.99275
```

The probability that at least two authorities are compromised when each is
independently compromised with probability `c` is:

```text
P_break(c; 3, 2) = C(3,2)c^2(1-c) + c^3
                 = 3c^2 - 2c^3

c = 0.01 -> P_break = 0.000298
```

By comparison:

```text
(1/1) -> P_break = c
(2/3) -> P_break approximately 3c^2 for small c
```

The selected authority shape is therefore:

```text
(n, t) = (3, 2)
sweet spot = min(complexity)
             intersect max(loss tolerance)
             intersect max(single-key compromise resistance)
```

## Implementation Mapping

AEAD maps to the assembly envelope secrecy boundary and Gate-authorized open
paths.

FROST_(2/3) maps to the intended production authority profile. The current
deterministic fixture FROST material remains test-only until a signed
non-fixture production authority ceremony is supplied and verified.

H-Merkle maps to witness and ledger evidence: public bundle hashes, Merkle
leaf/root/proof primitives, ledger inclusion proofs, and ledger consistency
history.

G maps to Gate predicates: action, manifest binding, contract binding, rooted
authority allow bits, and reserved-action denial.

R maps to witness material: public release/open evidence, publish index,
attestation, and ledger anchoring.

## Current Non-Claims

- This model does not make fixture FROST production authority.
- This model does not claim post-quantum system security.
- This model does not claim runtime sandboxing.
- This model does not replace independent cryptographic audit.
