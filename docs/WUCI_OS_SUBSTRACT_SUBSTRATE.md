# Wuci-OS Substract Substrate Model

Wuci-OS is a proof-carrying substrate lane, not a prettier ISO remaster.
Every public OS claim must be proven by local evidence or subtracted from the
release surface.

```text
SSM_v1 =
  FailClosed
AND SourceVerified(Void-musl)
AND PackageClosureFixedPoint
AND DeterministicRootFS
AND BootTraceBisimulation
AND GateRelease
AND PublicBeforePrivate
AND ClaimSubtract
AND Sign(FinalISOManifest)
AND Ledger(WitnessEvidence)
```

The current lane is allowed to produce local evidence candidates. It is not
allowed to publish a release when any required proof is missing.

Daylight v8 is the advanced mathematical spine for this substrate:
[`docs/WUCI_DAYLIGHT_V8.md`](WUCI_DAYLIGHT_V8.md). It upgrades the release lane
from a fixed checklist into a sheaf-gated global consistency model where local
evidence regions must glue into one publishable section.

## Formal Target Model

This is the target calculus for Wuci-OS substrate releases. It is not a claim
that the current implementation has package closure, final signing, hardware
boot bisimulation, or ledger publication.

```text
D =
  <S, C, E, K, P, W, L, V, G>

S_t =
  <B_t, R_t, O_t, P_t, K_t, E_t, W_t, L_t, C_t, Gamma_t>

WUCI_D = Fix(Phi_D)
```

The state transformer is subtractive and fail-closed:

```text
S_{t+1} =
  Phi_D(S_t, a_t)

Phi_D(S_t, a_t) =
  G_D(
    Seal_D(
      Sub_D(
        Evolve(S_t, a_t)
      )
    )
  )

Sub_D(S) =
  S \ { x |
      Verify_D(x) = 0
      OR Claim(x) not in Proven_D
      OR Leak_D(x) > 0
  }
```

Capabilities only shrink unless evidence re-admits a narrower proven operation:

```text
C_{t+1} =
  C_t
  INTERSECT gamma_D(alpha_D(tau_t))
  INTERSECT Pi_D(E_t)
  \ C_forbidden

C = { bottom < Denied < Unknown < Candidate < Proven }

claim_{t+1}(c) =
  JOIN_{pi in E_t} Verify_D(pi, c)

claim_{t+1}(c) = Proven
  IFF EXISTS pi:
    Verify_D(pi, c, root_D) = 1
```

Release and publish are meet-style gates. A single failed verifier collapses the
release result to zero.

```text
Release_D(S) = 1
  IFF
    AND_i Verify_D^i(S) = 1
    AND Blockers(S) = empty
    AND Boot_D(S) = 1
    AND Seal_D(S) = 1

Release_D(S) = 0 otherwise

G_D(S) =
  S      if Release_D(S) = 1
  bottom if Release_D(S) = 0
```

Public evidence must precede private opening. Public witness material must not
carry private key information.

```text
PublicBeforePrivate_D =
  FORALL a:
    Open_priv(a) => Verify_pub(H(a), W_pub, sigma_D) = 1

I(K_priv ; W_pub) = 0

FORALL s1,s2:
  s1 ==_pub s2 =>
    Exec_D(s1)|_pub == Exec_D(s2)|_pub

ell(x) not<= ell(y) => x -/-> y
ell(secret) not<= ell(public)
```

Daylight sealing binds artifact bytes, claims, policy, and ledger state. The
notation below is the target transcript shape; algorithm choice and production
authority remain gated by the existing Wuci-Ji boundary docs.

```text
(ms, ct_kem) <- KEM.Encaps(pk_D)

K_0 =
  KDF(ms || H(M_D) || H(E_D) || H(P_D) || ctx)

K_i =
  HKDFExpand(K_0, "daylight/v1" || i || H(tau_i), n)

N_i =
  H("daylight/nonce/v1" || H(M_D) || i || artifact_id_i)[0..95]

AAD_i =
  C14N(schema_i, artifact_i, chain_i, seq_i, prev_i, policy_i, claims_i, root_D)

(C_i, T_i) = AEAD.Enc_{K_i}(N_i, P_i, AAD_i)
P_i = AEAD.Dec_{K_i}(N_i, C_i, AAD_i, T_i)
P_i = bottom IFF AEAD.Verify_{K_i}(N_i, C_i, AAD_i, T_i) = 0
```

The evidence graph is domain-separated:

```text
leaf_i =
  H_D("daylight/leaf/v1" || type_i || path_i || len_i || H(bytes_i))

node_{i,j} =
  H_D("daylight/node/v1" || leaf_i || leaf_j)

root_D = Merkle(leaf_1, ..., leaf_n)
claimroot_D = Merkle(H(c_1), ..., H(c_m))
policyroot_D = Merkle(H(p_1), ..., H(p_k))

seal_D =
  Sign_{sk_D}(
    H_D("daylight/seal/v1" || root_D || claimroot_D || policyroot_D || L_t)
  )

VerifySeal_D =
  Verify_{pk_D}(
    seal_D,
    H_D("daylight/seal/v1" || root_D || claimroot_D || policyroot_D || L_t)
  )
```

The ledger is append-only:

```text
L_0 =
  H_D("daylight/genesis/v1" || root_0)

L_{t+1} =
  H_D(
    "daylight/ledger/v1"
    || L_t
    || root_{D,t}
    || seal_{D,t}
    || H(event_t)
  )

LedgerValid(L_T) =
  AND_{t=0..T-1}
    L_{t+1} ==
      H_D("daylight/ledger/v1" || L_t || root_{D,t} || seal_{D,t} || H(event_t))
```

The OS build path is deterministic only after package closure, normalized
rootfs generation, and boot evidence converge.

```text
ISO_{t+1} =
  Build(Void_musl, PackageDAG_t, Overlay_t^-, KernelPolicy_t, DaylightTools_t)

H(ISO_{t+1}) == H(ISO_t)
  IFF Reproducible(ISO_t) = 1

PackageDAG* =
  mu X. (PackageRoots UNION Deps(X))

PackageClosure(X) = 1
  IFF Deps(X) SUBSET X

RootFS* =
  Normalize(Extract(PackageDAG*, Overlay^-, Policy_D))

rootfs_D =
  H_D(C14N(RootFS*))
```

Boot evidence starts with QEMU and becomes strong only after target hardware
trace agreement:

```text
Boot_D(ISO) = 1
  IFF EXISTS T_Q:
    QEMU(ISO) reaches WJ_PROMPT
    AND TraceVerify_D(T_Q) = 1

T_Q ~_D T_H
  IFF
    alpha_D(T_Q) == alpha_D(T_H)
    AND Checkpoints(T_Q) == Checkpoints(T_H)

Boot_D_strong(ISO) = 1
  IFF EXISTS T_Q,T_H:
    QEMU(ISO) reaches WJ_PROMPT
    AND Hardware(ISO) reaches WJ_PROMPT
    AND T_Q ~_D T_H
```

Actions are allowed only when public evidence is valid, no leak is present, and
the post-state remains capability-monotone:

```text
delta_D(s,a) =
  s'     if Pre_D(s,a)=1 AND Cap(a) SUBSET C_s AND Post_D(s,a,s')=1
  bottom otherwise

Pre_D(s,a) =
  VerifyPublic(s) AND NoLeak(s) AND AuthorityValid(a)

Post_D(s,a,s') =
  C_{s'} SUBSET C_s
  AND root_D(s') == H_D(root_D(s) || H(a) || H(s'))

Auth_D(a,o) = 1
  IFF
    Verify_{pk_D}(sigma_a, H(o || scope || ttl || root_D)) = 1
    AND scope(a) SUBSET C_o

FixtureAuthority does not imply ProductionAuthority

ProductionAuthority
  IFF Verify_D(ceremony, threshold, audit, root_D) = 1
```

Gap selection can rank defensive tests, but scores do not override a failed
gate:

```text
Gaps_t = { c | claim_t(c) != Proven }

priority(g) =
  severity(g) * blast(g) * uncertainty(g) / (cost(g) + 1)

a_t =
  argmax_{a in Arms} (mu_hat_a + sqrt(2 ln(t) / (n_a + 1)))

E_{t+1} =
  E_t UNION Test_D(a_t, Gaps_t)

Score_D(S) =
  AND_i Verify_D^i(S)

Score_D(S) = 0
  IFF EXISTS i: Verify_D^i(S) = 0
```

The final manifest is the object that must be signed:

```text
FinalManifest_D =
  C14N(
    H(Void_musl),
    H(PackageDAG*),
    H(RootFS*),
    H(Overlay^-),
    H(KernelPolicy),
    H(Initramfs),
    H(BootGraph),
    H(ISO),
    root_D,
    claimroot_D,
    policyroot_D,
    L_t
  )

FinalSig_D =
  Sign_{sk_D}(
    H_D("daylight/final-manifest/v1" || FinalManifest_D)
  )

FinalVerify_D =
  Verify_{pk_D}(
    FinalSig_D,
    H_D("daylight/final-manifest/v1" || FinalManifest_D)
  )

Publish_D(ISO) = 1
  IFF
    FinalVerify_D = 1
    AND Release_D(S) = 1
    AND Boot_D(ISO) = 1
    AND LedgerValid(L_T) = 1

Publish_D(ISO) = 0 otherwise
```

## Fixed-Point Rule

```text
BuildState_next = F(SourceISO, PackageSet, Overlay, BootGraph, Evidence_current)

release_allowed =
  BuildState_next == BuildState_current
  AND every positive claim has evidence
  AND blockers == []
```

Missing proof does not become a warning-only note in public release language.
It becomes a blocker or a subtracted claim.

## Substract Operator

```text
Substrate =
    ImplementedBehavior
  - UnprovenSecurityClaims
  - NonreproducibleInputs
  - PrivateMaterial
  - FixtureAuthority
  - NetworkRuntimeSandboxOverclaim
```

Claims may move from `unknown` to `proven`, or from `unknown` to `denied`.
They must not move to `proven` through score inflation, release pressure, or
cosmetic boot success.

## Current Implemented Evidence

- Source ISO digest and layout evidence under `build/wuci-os/source`.
- Wuci rootfs overlay and Daylight/WJSEAL overlay seal evidence.
- Rebuilt `LiveOS/squashfs.img` with a wrapped `LiveOS/rootfs.img` layout.
- xorriso replay ISO assembly that preserves the source boot equipment.
- QEMU boot evidence reaching the Wuci live login prompt.
- Negative failure specimen ingest with `tools/wuci-os failure ingest`.

## Current Blockers

- Package closure is not yet a fixed point unless `--install-suite-packages`
  succeeds and records package metadata.
- Final ISO manifest signing is not yet implemented as an independent release
  signature lane.
- Hardware boot trace evidence is operator-supplied and must be ledgered before
  a hardware-specific release claim.
- Wuci-OS does not claim OS runtime containment, host containment, post-quantum
  safety, production authority, or independent external audit authority.

## Failure Specimens

Failed ISOs are negative evidence, not release bases. Ingest them with:

```sh
tools/wuci-os failure ingest path/to/failed.iso path/to/notes.json
```

The notes JSON must include:

```json
{
  "observed_failure": "what failed",
  "boot_log": "log text or summary",
  "qemu_plan": "how the failure was reproduced",
  "target_hardware": "machine or VM profile"
}
```

Optional `evidence_files` may map labels to local files. The ingest lane writes
`build/wuci-os/failures/<iso-sha256>/failure.json` and refuses to overwrite an
existing specimen.

## Release Gate Target

```text
source-admit
  -> package-closure
  -> rootfs-build
  -> boot-graph
  -> boot-bisim
  -> final-seal
  -> sign
  -> witness-ledger
  -> release-gate
```

The release gate fails closed unless source admission, package closure, final
ISO sealing, manifest signing, and required boot traces all pass.
