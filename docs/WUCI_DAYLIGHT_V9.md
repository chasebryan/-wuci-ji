# Daylight v9

## Proof-Carrying Subtractive Cryptographic Operating Substrate

Benchmark lock:

```text
Daylight v8 benchmark: 973/1000
Daylight v9 formal-spine upgrade budget: 27 points
Daylight v9 target: 990-995
```

Correction carried forward from v8:

```text
NoProof_D(x) => NoClaim_D(x) => NoRelease_D(x)
```

There is no `NoNotice(x)` state in this model. A public notice or disclosure
state can be added later, but v9 keeps claim authorization and release
authorization as the governing law.

## Top Release Equation

```text
Publish_D(ISO)=1
  IFF EXISTS s in Gamma(X,F):
    Gate_D(s)
    AND FinalVerify_D(s)
    AND LedgerValid_D(L_T)
    AND Boot_D_strong(ISO)
    AND AttackSurface_D(s) subseteq Closed_D

Publish_D(ISO)=0
  IFF NOT(Publish_D(ISO)=1)
```

Daylight v9 is less a manifesto and more a proof artifact preview: local
evidence must glue into one global section, each gate is meet-only, every
artifact carries its own proof obligations, and the remaining attack surface
must be closed by public evidence before publish.

## 1. Evidence Sheaf

Commutative evidence diagram:

```text
        Source Evidence
              |
              v
Package Evidence ------> RootFS Evidence
       |                         |
       v                         v
Overlay Evidence ------> Final ISO Evidence
       |                         |
       v                         v
Boot Evidence ----------> Ledger Evidence
              |
              v
        Release Evidence
```

Formal condition:

```text
FORALL U,V subseteq X:
  rho_{U,U_intersect_V}(F(U))
    =
  rho_{V,U_intersect_V}(F(V))

Gamma(X,F) != empty

Gamma(X,F) = empty => Publish_D(ISO)=0
```

Interpretation:

```text
No local evidence island can authorize release alone.
Only globally coherent evidence can publish.
```

## 2. Subtractive Capability Algebra

Capabilities only contract unless a proof-carrying gate restores a narrow
operation:

```text
C_{t+1}
  =
  C_t
  intersect Verified_D(E_t)
  intersect Policy_D(S_t)
  \ Forbidden_D

C_{t+1} subseteq C_t

c in C_{t+1}
  IFF
    c in C_t
    AND EXISTS pi:
      Verify_D(pi,c,root_D,policy_D)=1

c in Forbidden_D => c notin C_t FORALL t
```

Forbidden capabilities are absolute. Fixture authority remains fixture-only:

```text
FixtureAuthority =/> ProductionAuthority
```

## 3. Meet-Semilattice Gate

Gate algebra is meet-only:

```text
Gate_D(S) = AND_i g_i(S)

EXISTS i: g_i(S)=0 => Gate_D(S)=0
```

No additive score can compensate for a failed proof:

```text
Score_D(S) = AND_i Verify_D^i(S)
Score_D(S) = 0 IFF EXISTS i: Verify_D^i(S)=0
```

Z3 fail-closed proof box:

```python
from z3 import *

Source, Package, RootFS, Boot, Seal, Ledger, Final = Bools(
    "Source Package RootFS Boot Seal Ledger Final"
)

Gate = And(Source, Package, RootFS, Boot, Seal, Ledger, Final)

s = Solver()

# A failed gate must fail the whole release gate.
s.add(Not(Boot))
s.add(Gate)

assert s.check() == unsat
print("fail-closed proven: no failed component can publish")
```

Caption:

```text
Gate_D is meet-only. No additive score can compensate for a failed proof.
```

## 4. Attack-Surface Closure

| Attack surface | Daylight closure |
| --- | --- |
| Stale manifest replay | Ledger-bound AAD |
| ISO drift | Final manifest digest root |
| Package dependency gap | XBPS fixed-point closure |
| Private key leakage into public witness | Noninterference law |
| Boot success without proof | QEMU + hardware bisimulation |
| Fixture authority promotion | FixtureAuthority =/> ProductionAuthority |
| Score masking | Meet-semilattice gate only |
| Claim inflation | NoProof => NoClaim => NoRelease |

Formal law:

```text
AttackSurface_D(S)
  =
  Surface_raw(S) \ Closed_D(E,W,L,P)

Publish_D(S)=1
  => AttackSurface_D(S) subseteq Closed_D
```

## 5. Proof-Carrying Artifact v9

Every artifact proves bytes, policy, claims, proof class, and the attack
surface it closes.

```text
Artifact_i =
  <bytes_i, digest_i, policy_i, claims_i, proof_i, surface_i, closure_i>

ValidArtifact_D(i)
  IFF
    H(bytes_i)=digest_i
    AND Verify_D(proof_i,claims_i,policy_i)=1
    AND surface_i subseteq closure_i
    AND NoLeak_D(i)=1

leaf_i =
  H_D(
    "daylight/leaf/v9"
    || digest_i
    || H(policy_i)
    || H(claims_i)
    || H(proof_i)
    || H(surface_i)
    || H(closure_i)
  )
```

This is the v9 advancement: a public Merkle leaf binds not only bytes and
claims, but also the attack-surface accounting for that artifact.

## 6. Daylight Cryptographic Wire

The v9 wire keeps the v8 invariant: keys are transcript-bound, ledger-bound,
and policy-bound. Private cryptography only opens a shape that public evidence
has already authorized.

```text
Open_priv(x)=1
  => Verify_pub(H(x), Witness_D, Policy_D, Ledger_D)=1

I(K_priv ; W_pub) = 0

s1 ==_pub s2
  => Exec_D(s1)|_pub == Exec_D(s2)|_pub

ell(secret) not<= ell(public)
  => secret -/-> public
```

Decrypt remains fail-closed:

```text
Decrypt_D(i)=1
  IFF
    VerifySeal_D=1
    AND LedgerValid_D=1
    AND Policy_D(i)=1
    AND AAD_i=current
```

## 7. Build And Boot Bisimulation

Build success is not proof. Boot proof requires trace agreement:

```text
T_B = trace(Build(Void_musl, PackageDAG, Overlay, Policy_D))
T_Q = trace(QEMU(ISO))
T_H = trace(Hardware(ISO))

alpha_D(T) =
  <bootloader, kernel, initramfs, rootfs, wuci_prompt,
   witness_check, policy_gate>

T_Q ~_D T_H
  IFF alpha_D(T_Q) == alpha_D(T_H)

Boot_D_strong(ISO)=1
  IFF
    QEMU(ISO) reaches WJ_prompt
    AND Hardware(ISO) reaches WJ_prompt
    AND T_Q ~_D T_H
```

## 8. Lean-Style Gate Sketch

```lean
structure DaylightState where
  source_ok     : Prop
  package_ok    : Prop
  rootfs_ok     : Prop
  boot_ok       : Prop
  seal_ok       : Prop
  ledger_ok     : Prop
  final_ok      : Prop
  sheaf_ok      : Prop
  claims_proven : Prop

def Gate (s : DaylightState) : Prop :=
  s.source_ok and
  s.package_ok and
  s.rootfs_ok and
  s.boot_ok and
  s.seal_ok and
  s.ledger_ok and
  s.final_ok and
  s.sheaf_ok and
  s.claims_proven

def Publish (s : DaylightState) : Prop :=
  Gate s

theorem fail_closed_boot :
  forall s : DaylightState,
  not s.boot_ok -> not Publish s := by
  intro s hBoot hPub
  unfold Publish Gate at hPub
  exact hBoot hPub.right.right.right.left
```

Caption:

```text
If any required proposition is false, Publish is impossible.
```

## 9. Final Manifest Signature

```text
FinalManifest_D =
  C14N(
    H(Void_musl),
    H(PackageDAG_star),
    H(RootFS_star),
    H(Overlay_minus),
    H(KernelPolicy),
    H(Initramfs),
    H(BootGraph),
    H(ISO),
    root_D,
    claimroot_D,
    policyroot_D,
    L_t,
    AttackSurface_D,
    Closed_D
  )

FinalSig_D =
  Sign_sk_D(
    H_D("daylight/final-manifest/v9" || FinalManifest_D)
  )
```

## 10. v9 One-Line Law

Bottom centerpiece:

```text
NoProof_D(x) => NoClaim_D(x) => NoRelease_D(x)
```

Expanded:

```text
Proof_D(x)=0 => Claim_D(x)=0 => Publish_D(x)=0
```

Stronger publish implication:

```text
Publish_D(x)=1
  =>
    Proof_D(x)=1
    AND Claim_D(x) subseteq Proven_D
    AND Surface_D(x) subseteq Closed_D
```

## 11. v9 Diagram Structure

```text
Daylight v9
Proof-Carrying Subtractive Cryptographic Operating Substrate

Top:
  Global release equation

Left:
  1) Evidence Sheaf + commutative diagram

Center:
  2) Subtractive capability algebra
  3) Meet-semilattice gate proof
  4) Z3 fail-closed snippet

Right:
  5) Daylight cryptographic wire
  6) Attack-surface closure table

Middle flow:
  Void musl Source
  -> Package Fixed Point
  -> RootFS Normal Form
  -> Evidence Sheaf
  -> Merkle Root
  -> Daylight Seal
  -> Boot Bisimulation
  -> Final Manifest
  -> Publish Gate

Bottom:
  Lean pseudocode
  Final manifest signature
  One-line law
  cursive cb
```

## Current Implementation Boundary

This document is a formal target and release-gate contract. The current Wuci-OS
ISO lane binds v9 as public evidence, but it does not claim production crypto,
production authority, completed package fixed-point closure, hardware boot
bisimulation, post-quantum safety, or runtime containment until matching
implementation and verifier evidence exist.
