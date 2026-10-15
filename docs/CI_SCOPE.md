# WUCI CI Scope

GitHub Actions is a public regression signal, not a release authority and not a
production-readiness certificate.

## CI Guarantees

The checked-in workflows run on Ubuntu Linux x86_64 and currently verify:

- Native `make clean && make test`.
- Reproducible build metadata.
- Parser and artifact boundary regression tests.
- Install regression tests.
- High-attestation metadata gates that do not depend on kernel namespace setup.
- Native self-release, anchored release, rooted publish, witness, and archive
  proof lanes.
- Zig cross-build, Zig release proofs, Zig witness verification, and Zig
  witness archive checks.
- Daylight Aperture Bastion (v19): capsule tests, doctor, committed-example
  verification, capsule demo, public artifact, and the public artifact
  firewall; the workflow uploads only the firewalled public directory
  (`daylight-v19-aperture-bastion.yml`).
- Offline live-integrity response-policy tests and repository-maintenance
  policy checks. These deterministic CI lanes perform no public network reads.
- The separate scheduled/manual `live-integrity` workflow explicitly checks
  out `main`, installs the locked Bottle dependencies with Node 22.23.1 and npm
  11.8.0, rebuilds and verifies `apps/bottle/dist`, then performs only bounded
  public GET/HEAD requests. The local build defines the Bottle request set and
  byte caps; the remote manifest cannot add paths or legitimize substituted
  bytes. The workflow also builds the deterministic Pages upload tree and
  compares every staged public file—code, claim/evidence data, discovery text,
  and media—directly with `main` under fixed local count, byte, MIME, and shared
  deadline budgets. The workflow sends no secrets or user content.
- Defensive CodeQL analysis for repository-owned JavaScript/TypeScript and
  Python. Third-party, frozen-fixture, dependency, build, and deployment-output
  paths are excluded by the checked-in CodeQL configuration.
- The separate `lovelace-source-review` workflow runs the strict Lovelace
  profile tests, host-supervisor unit and negative tests, builder
  configuration/lock/source-manifest checks, and WuciOS registry validation.
  This covers the hostile-smoke and separate fixed-benign payload-smoke
  contracts and producer logic, not either KVM runtime invocation.
  Its test steps poison HTTP proxy routes and do not acquire Alpine packages,
  Ghidra, or any other runtime input. Checkout and Python setup still use the
  normal GitHub Actions infrastructure; this is a source-test property, not a
  kernel-enforced runner network-isolation claim.

Dependabot proposes reviewable updates for the two npm locks, GitHub Actions,
and only the first-party Cargo directories listed in `.github/dependabot.yml`.
It does not auto-merge and does not update vendored or frozen fixture trees.

## CI Non-Claims

CI does not claim:

- Production cryptographic audit.
- Runtime sandboxing or VM containment.
- Quantum-safe verification.
- Fixture authority as production trust.
- Absence of exploitable vulnerabilities.
- That CodeQL or dependency automation covers every language, dependency,
  generated artifact, or deployment behavior.
- Release authority for any artifact.
- That a Lovelace image was fetched, built, structurally inspected, booted, or
  exercised with Ghidra.
- Lovelace KVM availability, hostile-cell containment, persistent-storage
  round trips, execution of either host-local hostile smoke, operator-selected
  payload behavior, or safety for arbitrary malicious code.

## Local-Only Or Runner-Dependent Gates

The following gates may depend on host CPU, kernel, or local tool availability:

- `make kernel-sandbox-proof` requires seccomp plus Linux user and network
  namespaces and fails closed if the assembly seccomp network-syscall deny
  selftest does not observe `EPERM`.
- `make carrot-policy` emits CARROT attestation with the same kernel proof.
- `make high-attestation-proof` composes the full local evidence lane and
  includes qemu, CARROT, CAGE/QCAGE, Gate, and full Linux CLI tests.
- `make rust-sandbox-build` and `make rust-sandbox-test` require `rustc`.
- `make pq-verifier-detect` records local OpenSSL/PQ verifier availability and
  does not claim quantum safety unless a real pinned verifier is detected.
- `make wucios-lovelace-fetch` is the explicit networked acquisition and lock
  maintenance step for Alpine and Ghidra runtime inputs; CI does not run it.
- `make wucios-lovelace-inputs`, `make wucios-lovelace-build`,
  `make wucios-lovelace-reproducibility`, and
  `make wucios-lovelace-structural-verify` require the complete local input
  cache and host image-building tools. Those commands perform no network
  requests; the reproducibility target builds in two independent roots and
  requires byte-identical artifacts.
- `make wucios-lovelace-boot-smoke`,
  `make wucios-lovelace-ghidra-headless`,
  `make wucios-lovelace-noxframe-smoke`, and
  `make wucios-lovelace-persistent-round-trip` require QEMU system emulation
  and are functional TCG checks only. They do not establish hostile-code
  isolation. Their runtime producers reject named fatal/kernel/storage
  diagnostics from the complete bounded console before evidence can pass; CI
  reviews that logic but does not execute the VMs.
- `make wucios-lovelace-network-smoke` is a separately explicit live guest
  Internet-NAT test. It retrieves only the exact locked Alpine digest sidecar
  for its bounded HTTPS probe and is never an offline-target prerequisite.
- `make wucios-lovelace-hostile-smoke` is the canonical host-local KVM and
  bubblewrap layered-control-presence check. It requires a securely configured,
  usable `/dev/kvm`, a non-root operator, and exact root-owned,
  non-setuid/non-setgid `/usr/bin/qemu-system-x86_64`, `/usr/bin/qemu-img`, and
  `/usr/bin/bwrap` executables. It exercises only fixed benign fixtures with
  volatile storage and no network, persistence, host share, or device
  passthrough. CI reviews this contract but does not run it; its runtime result
  remains `NOT_MEASURED` until a local artifact-backed run passes. A pass is
  gated on observing the exact QEMU security state before dispatch and that
  QEMU PID/start-time/executable identity disappearing after normal supervisor
  exit. This host-local normal-unwind observation is not perfect-isolation
  evidence, arbitrary-malware safety, cleanup-after-crash evidence, or release
  authority.
- `make wucios-lovelace-hostile-payload-smoke` is a separate host-local KVM and
  bubblewrap gate for the exact committed 44-byte benign fixture. It requires
  supervisor and guest exact-byte checks, guest read-only enforcement and write
  rejection, and normal-unwind payload/overlay cleanup. CI reviews but does not
  run this gate. It cannot satisfy the ordinary hostile-cell gate, validate an
  operator-selected sample, or establish containment or malware safety.
- Lovelace hostile mode requires a usable KVM device, trusted outer
  bubblewrap namespaces, non-root QEMU, volatile storage, no guest NIC or host
  share, exact read-only runtime/boot bindings, QEMU sandbox flags, and bounded
  resources. The supervisor fails closed without those gates, and CI does not
  claim they are available.
- Named Lovelace persistent overlays are local state under `build/wuci-lab/`.
  CI unit-tests their binding and failure behavior with fixtures but does not
  claim an artifact-backed persistence round trip.
