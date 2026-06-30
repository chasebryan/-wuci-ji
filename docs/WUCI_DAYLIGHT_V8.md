# Daylight v8

## Sheaf-Gated Subtractive Cryptographic Substrate

Daylight is not only encryption. In the Wuci-Ji / Wuci-OS lane it is the
release authority, evidence graph, public/private boundary, boot verifier, and
fail-closed substrate. Every artifact, key, claim, ISO state, boot receipt,
ledger event, and release decision is a typed object in one verifiable system.

```text
Daylight_v8 =
  CryptographicWire
+ SubtractiveCapabilityLattice
+ EvidenceSheaf
+ MerkleizedReleaseLedger
+ BootBuildBisimulation
+ FailClosedGateAlgebra
+ PublicBeforePrivateNoninterference
```

Core law:

```text
Nothing is trusted because it exists.
Nothing is released because it builds.
Nothing is decrypted because a key exists.
Everything opens only when its public proof, local policy, global witness,
ledger history, and release state agree.
```

## Evidence Sheaf

The whole system is modeled as local evidence regions:

```text
X = {
  source, package, rootfs, overlay, kernel, initramfs,
  boot, witness, ledger, release
}

F(U) = {
  evidence, claims, digests, policies, witnesses, blockers
}
```

Daylight succeeds only when local evidence glues into one global section:

```text
Gamma(X,F) != empty
  IFF FORALL U,V subset X:
    F(U)|_{U intersect V} == F(V)|_{U intersect V}
```

Meaning:

```text
source evidence agrees with package evidence
package evidence agrees with rootfs evidence
rootfs evidence agrees with ISO evidence
ISO evidence agrees with boot evidence
boot evidence agrees with ledger evidence
ledger evidence agrees with release evidence
```

Final release:

```text
Publish_D(ISO) = 1
  IFF EXISTS s in Gamma(X,F) AND Gate_D(s) = 1

Gamma(X,F) = empty => Publish_D(ISO) = 0
```

Daylight is therefore a global coherence engine, not a checklist.

## Subtractive Capability Algebra

Capabilities contract unless proof re-admits a narrower action:

```text
C_{t+1} =
  C_t
  intersect Verified_D(E_t)
  intersect Policy_D(S_t)
  \ Forbidden_D

C_{t+1} subseteq C_t

c in C_{t+1}
  IFF
    c in C_t
    AND EXISTS pi: Verify_D(pi,c,root_D,policy_D) = 1

c in Forbidden_D => c notin C_t FORALL t
```

This makes Daylight a privilege contraction system.

## Gate Algebra

All gates are meet operations, never additive scores:

```text
Gate_D(S) =
  Source_D(S)
  AND Package_D(S)
  AND RootFS_D(S)
  AND Boot_D(S)
  AND Seal_D(S)
  AND Ledger_D(S)
  AND FinalVerify_D(S)

EXISTS g_i: g_i(S)=0 => Gate_D(S)=0

Score_D(S) = AND_i g_i(S)
Score_D(S) != SUM_i weight_i * g_i(S)
```

A strong seal cannot compensate for a failed boot, and a valid boot cannot
compensate for a missing manifest signature.

## Public-Before-Private Law

The private open path is unavailable until public evidence validates:

```text
Open_priv(x)=1
  => Verify_pub(H(x), Witness_D, Policy_D, Ledger_D)=1

I(K_priv ; W_pub) = 0

s1 ==_pub s2
  => Exec_D(s1)|_pub == Exec_D(s2)|_pub

ell(secret) not<= ell(public)
  => secret -/-> public
```

Principle:

```text
Public evidence authorizes the shape.
Private cryptography only opens the already-authorized shape.
```

## Cryptographic Wire v2

Encryption is transcript-bound, ledger-bound, and policy-bound:

```text
ctx_D =
  H_D(
    "daylight/context/v2"
    || root_D
    || policyroot_D
    || claimroot_D
    || ledger_D
    || artifact_id
  )

(ms, ct_kem) <- KEM.Encaps(pk_D)

K_0 =
  KDF(ms || ctx_D || H(FinalManifest_D))

K_i =
  HKDFExpand(
    K_0,
    "daylight/artifact/v2" || artifact_i || seq_i || H(AAD_i),
    n
  )

N_i =
  H_D("daylight/nonce/v2" || root_D || artifact_i || seq_i)[0..95]

AAD_i =
  C14N(
    schema_i, artifact_i, seq_i, prev_i, root_D,
    claimroot_D, policyroot_D, ledger_D, release_mode
  )

(C_i,T_i) = AEAD.Enc_{K_i}(N_i, P_i, AAD_i)
P_i = AEAD.Dec_{K_i}(N_i, C_i, AAD_i, T_i)

AEAD.Verify_{K_i}(N_i,C_i,AAD_i,T_i)=0 => P_i=bottom

Decrypt_D(i)=1
  IFF
    VerifySeal_D=1
    AND LedgerValid_D=1
    AND Policy_D(i)=1
    AND AAD_i=current
```

This blocks stale evidence, wrong context, wrong artifact identity, and ledger
replay from opening data.

## Proof-Carrying Artifacts

Every artifact carries proof obligations:

```text
Artifact_i =
  <bytes_i, type_i, path_i, digest_i, policy_i, claims_i, proof_i>

ValidArtifact_D(i)
  IFF
    H(bytes_i)=digest_i
    AND Verify_D(proof_i,claims_i,policy_i)=1
    AND NoLeak_D(i)=1

leaf_i =
  H_D(
    "daylight/leaf/v2"
    || type_i
    || path_i
    || digest_i
    || H(policy_i)
    || H(claims_i)
  )

root_D = Merkle(leaf_1,...,leaf_n)
```

The Merkle tree binds bytes, policy, claims, and proof class.

## Build And Boot Bisimulation

A working ISO is not proven by build success. It is proven by trace agreement:

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

Publish_D(ISO)=1 => Boot_D_strong(ISO)=1
```

## Double-Entry Release Ledger

Every event debits one previous state and credits one new state:

```text
event_t =
  <kind_t, prevroot_t, newroot_t, actor_t, scope_t, proof_t>

L_{t+1} =
  H_D(
    "daylight/ledger/v2"
    || L_t
    || prevroot_t
    || newroot_t
    || H(event_t)
  )

LedgerStep_D(t)=1
  IFF
    prevroot_t=root_t
    AND newroot_t=root_{t+1}
    AND Verify_D(proof_t,event_t)=1

LedgerValid_D(L_T) =
  AND_{t=0..T-1} LedgerStep_D(t)

root_{t+1} != root_t
  => EXISTS event_t:
    L_{t+1}=H_D(L_t,root_t,root_{t+1},H(event_t))
```

Daylight is cryptographic accounting for state change.

## Claim Subtraction

Every claim starts unproven:

```text
claim_0(c)=Unknown

claim_{t+1}(c)=Proven
  IFF EXISTS pi in E_t: Verify_D(pi,c,root_D)=1

claim_t(c) != Proven => c in Subtracted_D

ReleaseText_D subseteq { c | claim_t(c)=Proven }
```

The public statement about an ISO must be no stronger than the evidence.

## Final Release Equation

```text
Publish_D(ISO)=1
  IFF
    Gamma(X,F) != empty
    AND Gate_D(S)=1
    AND FinalVerify_D(S)=1
    AND LedgerValid_D(L_T)=1
    AND Boot_D_strong(ISO)=1
    AND Claims_D(S) subseteq Proven_D

Publish_D(ISO)=0
  IFF
    Gamma(X,F)=empty
    OR Gate_D(S)=0
    OR FinalVerify_D(S)=0
    OR LedgerValid_D(L_T)=0
    OR Boot_D_strong(ISO)=0
    OR Claims_D(S) not subseteq Proven_D
```

Bottom rule:

```text
NoProof_D(x) => NoClaim_D(x) => NoRelease_D(x)
```

## Next Sheet

Title:

```text
Daylight v8
Sheaf-Gated Subtractive Cryptographic Substrate
```

Top equation:

```text
Publish_D(ISO)=1
  IFF EXISTS s in Gamma(X,F):
    Gate_D(s)
    AND FinalVerify_D(s)
    AND LedgerValid_D(L_T)
    AND Boot_D_strong(ISO)
```

Panels:

```text
1) Evidence Sheaf
   local proofs glue into global release state

2) Subtractive Capability Algebra
   capabilities only decrease unless proof restores them

3) Daylight Cryptographic Wire
   keys are transcript-bound, ledger-bound, and policy-bound
```

Flow:

```text
Void musl Source
-> Package Fixed Point
-> RootFS Normal Form
-> Evidence Sheaf
-> Merkle Root
-> Daylight Seal
-> Boot Bisimulation
-> Final Manifest
-> Publish Gate
```

Signature:

```text
cb
```

## Current Implementation Boundary

This document is a target model and release-gate contract. The current Wuci-OS
ISO lane binds it as public evidence, but it does not claim production crypto,
production authority, hardware boot bisimulation, post-quantum safety, or
runtime containment until the corresponding implementation and verifier evidence
exist.
