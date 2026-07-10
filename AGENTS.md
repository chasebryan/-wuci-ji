# Codex Project Operating Instructions

This file is the repository-wide operating contract for Codex and other coding
agents. It applies to the entire tree. A more specific section or nested
`AGENTS.md` may add constraints for its path, but it may never weaken these
rules.

The objective is not to make the project look ready. The objective is to move
it toward the highest level of **demonstrable, reproducible, secure, usable, and
operational readiness** that the available evidence supports.

## Mission and readiness standard

Improve the project coherently across:

- correctness and protocol integrity;
- security, privacy, secret handling, and safe failure;
- reliability, cleanup, recovery, and deterministic behavior;
- portability, dependency discipline, and reproducible builds;
- tests, negative tests, CI coverage, and regression resistance;
- maintainability, interfaces, documentation, and command accuracy;
- performance, resource bounds, usability, and accessibility;
- release engineering, deployment preparation, observability, and rollback;
- evidence quality, claim precision, and external-review readiness.

Never optimize a score, badge, status file, or readiness label instead of the
underlying system. A smaller honest claim with strong evidence is better than a
larger claim with weak evidence.

Use precise readiness language:

- **implemented** means the code exists;
- **locally validated** means named local checks passed in the stated
  environment;
- **CI validated** means the relevant remote jobs passed for the exact commit;
- **release-candidate bundle** means a curated candidate artifact whose exact
  generated status and blockers must be reported; the label does not imply that
  release, external, operational, or production-readiness gates passed;
- **externally evidenced** means required independent evidence was actually
  supplied and verified;
- **deployed** means the named service or artifact was deployed and live-checked.

Do not collapse these states into “ready” or “production ready.”
`production_ready_claimed: false` blocks every production-ready claim even
when a generated blocker list is empty.

## Instruction and evidence precedence

Platform policy and every applicable `AGENTS.md` rule are mandatory. The
maintainer’s current task controls scope and acceptance criteria only within
those rules.

`docs/SECURITY_BOUNDARY.md`, `docs/THREAT_MODEL.md`,
`docs/PRODUCTION_READINESS.md`, current subsystem boundary documents, and
machine-readable schemas/policies control what may be designed or claimed.
Current implementation, build targets, tests, and workflows control statements
about what presently exists or runs. General README, website, roadmap, and
marketing prose cannot broaden either boundary.

When normative intent and actual behavior disagree, report and repair the
inconsistency; do not silently choose one as universally authoritative or
redefine the boundary to match the implementation. If the safe resolution is
unclear, stop the affected change and preserve fail-closed behavior.

## Required startup sequence

Before non-trivial work:

1. Record the repository, starting commit, branch, remote tracking state,
   submodule state, and `git status --short`. Preserve every unrelated or
   pre-existing change.
   Inspect ignored `build/` evidence before any cleanup: `make clean` deletes
   the entire build tree and may destroy valuable local WuciOS/runtime evidence.
2. Read this file, the current boundary documents, the relevant implementation,
   tests, Make targets, workflow files, and component README.
3. Classify the request as inspection, diagnosis, implementation, generated
   artifact work, dependency work, release/proof work, or an external
   operational action. Do not turn a read-only request into a write, commit,
   push, release, deployment, or message.
4. Map the change to all affected implementations: native assembly, Zig,
   Python compatibility/reference code, Rust helpers, browser/Worker code,
   generated artifacts, and public consumers.
5. Write explicit acceptance criteria and choose a cumulative validation ladder
   before editing.
6. Establish a narrow baseline when practical. Distinguish a pre-existing
   failure from one introduced by the change.
7. Inspect recent history for affected files when intent is unclear. Do not
   create, switch, merge, or rebase branches unless the task authorizes it. When
   a new branch is requested, use the maintainer-selected base and verify it
   before branching; do not revive or merge stale project branches wholesale.
8. Confirm the actual host and required tool versions before selecting a lane,
   especially `as`, `ld`, Python, Node/npm, Zig, QEMU, Rust/Cargo, CPU
   features, namespaces, and seccomp.

A task is ready for implementation only after its source of truth, security
boundary, sibling paths, generated consumers, and validation targets are known.

## Work method

- Fix the invariant at its source, not only the visible symptom.
- Make the smallest coherent change that fully restores the invariant.
- Search for every sibling call path, parser, serializer, compatibility
  implementation, versioned format, and error exit before editing.
- For a defect, add a regression test that fails before the fix and passes
  afterward when the behavior is deterministically testable. For new behavior,
  add acceptance and relevant negative tests. If automated coverage is not
  practical, state why and provide the strongest reproducible validation.
- Keep parsing, validation, authorization, operation, commit, rollback, and
  cleanup as distinct phases. Re-check authority at the final operation
  boundary.
- Preserve fail-closed defaults. Never turn a hard failure into a warning merely
  to make a suite pass.
- Do not weaken size caps, exact-key checks, CSP, safe-I/O flags, link
  rejection, canonicalization, action checks, fixture quarantine, or public
  artifact profiles without an explicit reviewed design change.
- Preserve stable CLI and schema behavior unless the task explicitly authorizes
  a versioned breaking change. Update every producer and consumer together.
- Keep user changes intact. Do not use destructive Git commands, broad staging,
  or cleanup commands until their scope is understood.
- Use parallel agents only for separable analysis or independent validation.
  Keep one writer per file and serialize targets that share `build/` proof
  roots.
- Do not leave commented-out code, disabled checks, TODO-only fixes, fabricated
  fixtures, or unexplained generated churn.

For broad readiness work, choose the next action by this priority:

1. P0: secret exposure, plaintext persistence, authorization bypass, memory
   corruption, unsafe file replacement, data loss, or false security claims.
2. P1: protocol correctness, deterministic verification, rollback/cleanup,
   cross-implementation disagreement, and missing negative tests.
3. P2: build reproducibility, CI blind spots, dependency and supply-chain
   integrity, portability, and release-gate reliability.
4. P3: deployment preparation, operator safety, observability, recovery,
   performance, and bounded resource use.
5. P4: usability, accessibility, maintainability, documentation accuracy, and
   removal of stale or misleading paths.

## Repository map and scope boundaries

| Area | Primary paths | Controlling concerns |
| --- | --- | --- |
| Native Wuci-Ji core | `src/`, `include/`, `tests/` | Freestanding x86_64 assembly, raw syscalls, exact envelopes, cryptographic boundaries, streaming cleanup |
| Portable and orchestration lanes | `Makefile`, `tools/*.zig`, `tools/*.py` | CI-pinned Zig behavior, compatibility parity, bounded safe I/O, no shell injection |
| Warrant, Gate, Witness, Ledger | `src/gate_contract.s`, `src/ledger.s`, `tools/wuci_*`, `docs/wuci_*` | Exact action binding, fixture quarantine, canonical contracts, public-bundle profiles, append-only evidence |
| HARDEN, CAGE, QCAGE, CARROT, INSTALL | `tools/wuci_safeio.py`, `tools/wuci_cage.py`, `tools/wuci_qcage.py`, `tools/wuci_carrot.py`, `tools/wuci_sandbox.rs`, `tools/wuci_install.py`, `install/` | Defensive-only policy, honest containment/PQ claims, kernel proof boundaries, signed noninteractive install |
| Daylight research/evidence | `daylight/`, `daylight-equation/` | Versioned, non-comparable score families, exact rational/decimal derivation, fixture and external-evidence separation |
| Current WuciOS | `wucios/`, `tools/wucios/`, `docs/wucios/` | v2.4 Reduction Gate, Noether Core authority, measured evidence, explicit mutation flags |
| Legacy Wuci-OS | `tools/wuci_os.py`, `docs/WUCI_OS.md`, `build/wuci-os/` | Compatibility lane only; never present it as current WuciOS direction |
| NOXFRAME and Kaiju | `tools/wuci_black_ice.py`, `tools/wuci-noxframe`, `tools/wuci_kaiju.py`, `docs/noxframe/` | Bounded console/proof launcher, metadata-only host routes, explicit QEMU bridge, no containment overclaim |
| Daylight Bottle | `apps/bottle/` | Browser-local age encryption, exact ciphertext-labeled field/metadata Worker-KV boundary, no server decryption, same-origin assets, manual keyring trust |
| Static public site | `site/`, `docs/WEBSITE_DEPLOY.md` | No browser cryptography, exact claim/evidence bindings, accessibility, static validation, host-dependent live controls |
| ZP1 coupling | `third_party/zp1`, `tools/check_zp1_wuciji_coupling.py`, `tools/wuciji-zp1-bridge/`, `docs/ZP1_*` | Pinned submodule, explicit coupling boundary, upstream changes kept separate |
| Penumbra | `penumbra/`, `docs/penumbra/`, `docs/PENUMBRA_BUILD_SPEC.md` | Independent Rust crate and specifications; do not assume a root Make target exists |

Do not cross these boundaries casually. In particular:

- `site/` is not Daylight Bottle and must not acquire browser cryptography.
- `apps/bottle/` is not a Daylight scoring package.
- current WuciOS v2.4 is not the legacy XFCE/musl Wuci-OS lane;
- NOXFRAME is not a kernel, shell sandbox, or host-containment boundary;
- CAGE is an artifact airlock, not runtime containment;
- QCAGE metadata is not whole-system post-quantum safety;
- CARROT is the only bounded kernel no-network proof lane;
- the local Ledger is not an operated public transparency log.

## Security and correctness checklist

For every security-sensitive change, explicitly check:

- Buffers and copies against the largest supported version, not the most common
  version.
- Integer conversion, length addition, offset arithmetic, EOF handling, and
  configured size caps.
- Every acquire/authenticate/authorize/commit/abort transition and every error
  exit for close, unlink, rollback, zeroization, and no-overwrite behavior.
- Every parsed security field. It must be enforced, deliberately documented as
  an opaque reference, or removed. Decorative security fields are forbidden.
- Action authorization at the final operation. A valid signature or contract
  does not authorize a different action.
- Exact byte contracts: field order, ASCII rules, lowercase hex, separators,
  trailing newline, duplicate-key rejection, and domain separation.
- File opens at proof boundaries for regular-file checks, `O_NOFOLLOW`,
  inode recheck, hardlink policy, bounded reads, safe parent directories, and
  atomic replacement.
- Secret lifetime in memory and on disk. Authenticated temporary plaintext must
  be private, bounded, cleaned on every failure, and never enter tracked or
  public artifact roots.
- Subprocesses as fixed argument vectors with `shell=False`; no `eval`,
  command interpolation, remote shell pipelines, or ambient unpinned verifier.
- Browser and Worker flows for plaintext/private-identity egress, external
  calls, logging, telemetry, CSP, request limits, schema exactness, expiry, and
  metadata leakage.

All work is defensive. Do not add exploit generation, weaponized or offensive
vulnerability reproduction, offensive scanning, jailbreak harnesses, malware,
credential collection, or network attack logic. A minimal offline fixture that
reproduces only the affected invariant for a defensive regression test is
allowed unless a narrower component rule forbids it.

## Claims, evidence, and authority

- The strongest default project claim is research/public-review evidence
  candidate. Repository-defined checks are not independent audit,
  certification, government endorsement, production authority, or deployment.
- Fixture FROST, fixture roots, deterministic vectors, and self-produced
  attestations remain fixture/internal evidence. Never relabel them as
  independent or production evidence.
- Never fabricate external reviewers, builders, verifier families, signatures,
  runtime measurements, live deployment results, or PQ evidence.
- Classical secp256k1, ECDSA, RSA, DH, ECDH, X25519, and classical FROST are not
  quantum-safe.
- Daylight score families are versioned and non-comparable. Do not convert,
  average, merge, or present them as one monotonic series.
- A command exiting zero may mean “verified with blockers.” Inspect the emitted
  status and blocker set before reporting success.
- Positive `publish` and `trust` authority does not exist merely because a
  decision-only or artifact-publication lane is present.
- Any public evidence profile is an allowlist. Adding one file requires
  synchronized updates to all applicable, currently defined consumers such as
  the profile, manifest, archive, firewall, sums, tests, documentation, and CI.

## Generated artifacts and deterministic evidence

Before editing any scorecard, capsule, status JSON, manifest, sums file,
attestation, release bundle, public artifact, or generated documentation:

1. Find its canonical producer, input set, schema, and regeneration target.
2. Change the source or generator first.
3. Regenerate through the canonical command.
4. Run its semantic verifier and, when the artifact can enter a public profile,
   the applicable public-artifact firewall.
5. When determinism is claimed, generate twice from clean lane-specific output
   roots and compare bytes or the documented digest set.
6. Review the diff for timestamps, absolute machine paths, stale members,
   private material, unexpected files, and unrelated churn.

Do not hand-edit generated evidence or tracked digests. Do not publish broad
`build/` roots. Do not claim regeneration when output was manually composed.
If a documented producer or command no longer exists, repair or explicitly
retire that build contract instead of fabricating its output.

## Dependencies, toolchains, and portability

- Native builds and targeted assembly tests require Linux x86_64 and GNU
  `as`/`ld`; the full `make test` suite additionally requires the current
  BMI2/AVX X25519 CPU surface. Narrower Python or subsystem tests may have fewer
  requirements.
- Portable CI behavior is governed by the Zig version pinned in CI. Test the
  native Zig implementation and any supported compatibility implementation
  affected by a change.
- Root Node scripts and `apps/bottle` are separate packages, not an npm
  workspace. Use their lockfiles independently.
- For Bottle cryptography, inspect installed package exports and types. Never
  guess an API or replace maintained cryptography with custom code.
- Before ZP1 work, verify the pinned submodule state. Initialize or fetch it only
  when dependency retrieval is in scope and network access is available;
  otherwise report that validation as unavailable. Do not fold unreviewed
  upstream submodule changes into a Wuci-Ji patch.
- Keep Python proof and policy tools stdlib-only unless a reviewed lane
  explicitly permits a dependency.
- Pin new security-sensitive dependencies and verifiers by version and digest
  where the existing policy requires it. Document provenance, license, update
  path, and failure behavior.
- Do not upgrade a compiler, dependency, schema, cryptographic library, or
  action version as incidental cleanup. Treat upgrades as explicit,
  independently validated work.

## Cumulative validation ladder

Validation is proportional to impact and cumulative:

1. **Static consistency:** inspect callers, sibling implementations, constants,
   schemas, target definitions, generated consumers, and version-selected paths.
2. **Narrow regression:** run the smallest test proving the behavior, including
   the negative case for the original failure.
3. **Boundary matrix:** exercise malformed input, wrong action, boundary sizes,
   safe I/O, cleanup, no-overwrite, and public/private separation as applicable.
4. **Alternate paths:** test every affected native, portable, compatibility, or
   feature-selected implementation.
5. **Subsystem build:** rebuild the actual artifact from source.
6. **Integration:** run the applicable repository and CI-equivalent targets.
7. **Generated/documentation checks:** regenerate, validate commands and links,
   run `git diff --check`, and inspect final status.

`make test` is the native integration suite, not the entire repository test
matrix. `make test-linux` is a portable CLI harness, not a replacement for the
native suite. Root execution can invalidate permission-based negative tests;
report that environment limitation and use the non-root/CI result rather than
mislabeling it as a product failure or a pass.

Minimum command families by scope:

| Changed scope | Minimum relevant validation |
| --- | --- |
| Assembly/core/envelopes | `make asm-smoke`, focused boundary tests, and `make test`; add the opt-in `make check-asm-immediates` for control-flow/immediate or high-attestation work |
| Portable CLI | `make build-linux`, `make test-linux`, affected Zig/compatibility tests |
| FROST/Gate | `make frost-authz gate-workflow gate-policy-matrix gate-receipt-contract gate-contract-asm`; also `make gate-contract-zig` for Gate contract/tool changes when the CI-pinned Zig toolchain is available |
| Witness/Ledger | `make witness-attestation-test witness-archive-test ledger-asm-test ledger-proof-test`; then run `make self-release-ledger-bundle` followed by `make pythonless-public-verify` so the final witness bundle and ledger are generated together |
| HARDEN/CAGE/QCAGE | affected policy matrices and `make harden-proof cage-proof qcage-proof` |
| CARROT/INSTALL/readiness | affected `make kernel-sandbox-proof rust-sandbox-test install-test production-readiness-gates verify-release-bundle` targets |
| Daylight Meridian/public evidence | `make daylight-meridian-ci` and the relevant firewall/ratchet |
| Daylight v19/v20 | `make daylight-v19-aperture-bastion-ci` and/or `make daylight-v20-aperture-singularity-ci` |
| Daylight claims/standard/posture | affected `make daylight-npt-ci daylight-standard-ci daylight-ssv-ci` targets |
| WuciOS v2.4 | `make wucios-validate wucios-fluff-audit`; run `make wucios-idempotence-check` for generated/review changes only from a clean or deliberately snapshotted index because the current target uses an unscoped Git diff |
| NOXFRAME/Kaiju/legacy Wuci-OS | affected `make noxframe-launch-test wuci-kaiju-test wuci-os-test` targets |
| Daylight Bottle | from `apps/bottle`: when dependency retrieval is authorized and needed, run `npm ci`; then run `npm run check` |
| Static site | `make site-validate`; add `make daylight-npt-ci` for public text or numeric claims; run `make site-live-check` only when live network verification is in scope |
| ZP1 coupling | verify/initialize the pinned submodule as authorized, then `make zp1-wuciji-coupling-test`; inspect any bridge lockfile diff |
| Penumbra | `cargo test --locked --manifest-path penumbra/Cargo.toml` unless a verified root target is added |
| Repository docs/commands | `make readme-remaster-check`, command/target search, `git diff --check` |

Run additional lanes whenever the change crosses boundaries. Never run shared
Witness/Ledger/CAGE/QCAGE/release generators concurrently in the same output
root. Never hide an unavailable tool, unsupported kernel feature, or failed
test; name it and state what remains unverified.

## CI and regression policy

- A durable feature or supported platform path must have a deterministic CI
  gate or a documented reason it cannot.
- Inspect workflow path filters whenever files move or a new subsystem file is
  added. A correct test that never triggers is not coverage.
- Keep native and portable paths aligned. Add cross-implementation vectors when
  they independently process the same protocol.
- New parsers need malformed, duplicate, oversized, truncated, reordered, and
  trailing-data cases as applicable.
- New file-writing paths need symlink, hardlink, collision, interruption,
  cleanup, permissions, and no-overwrite cases.
- New public artifacts need secret scans and exact-profile negative cases.
- Do not delete, skip, loosen, or quarantine a failing test without documenting
  and fixing the underlying contract.
- Keep GitHub Actions pinned to full commit SHAs with least-privilege
  permissions. Do not expose secrets to untrusted pull-request jobs, and upload
  only exact, firewalled public roots.
- CI success proves only the jobs and commit shown. It does not prove live
  deployment, host configuration, external review, or an unreferenced target.

At baseline commit `6699caf`, hosted CI does not cover WuciOS v2.4 structural
or disposable-devlane validation, ZP1 coupling, Penumbra, the opt-in
`check-asm-immediates` audit, pull-request-time `site-validate`,
`site-live-check`, the composed `high-attestation-proof`, or live Bottle
deployment/smoke. Re-read workflow YAML rather than relying on this snapshot,
add a durable gate when a changed surface can support one, and update this
paragraph when coverage changes.

## Documentation consistency

Any behavior, path, command, toolchain, schema, security-owner, or release-state
change requires a repository-wide search across:

- the root and component READMEs;
- `SECURITY.md` and boundary/threat/readiness documents;
- `docs/BUILD_TARGETS.md` and operator runbooks;
- CLI `--help` output and generated instruction templates;
- JSON policies/schemas/examples and tracked status/evidence files;
- local skills, Make targets, workflows, and website copy.

Every current command in documentation must resolve in the current tree.
Historical material must be unmistakably labeled and must not emit obsolete
commands as active instructions. Do not introduce developer-machine absolute
paths into current portable instructions; clearly labeled historical evidence
may retain recorded paths when they are part of the evidence itself.
Keep `site/` and `apps/bottle/`, current WuciOS and legacy Wuci-OS, and
artifact publication and authority publication semantically distinct.

Baseline `6699caf` contains known documentation hazards. Do not execute these
as if they were current Make targets; repair the owning document or generator
when that surface is in scope:

| Stale instruction | Current entry point to inspect |
| --- | --- |
| `make wuci-os-privacy-audit` | `python3 tools/wuci_release_privacy_audit.py audit` |
| `make wuci-os-release-bundle` | `python3 tools/wuci_release_bundle.py build` |
| `make wuci-os-release-gate` | `python3 tools/wuci_release_gate.py status` |
| `make wuci-os-release-contingencies` | `python3 tools/wuci_release_contingencies.py build` |
| `make wuci-backup-evidence` | `python3 tools/wuci_backup_evidence.py emit` |
| `make penumbra-test` | `cargo test --locked --manifest-path penumbra/Cargo.toml` |

The direct entry point existing does not authorize release or mutation. Invoke
its current `--help`, verify required inputs, and preserve the legacy/current
boundary. Also treat `docs/CI_SCOPE.md`, `docs/MACHINE_PASSOFF.md`, and the
local `.grok` skill as potentially stale until checked against workflows,
current paths, and the CI toolchain.

## External and mutating operations

Repository work does not by itself authorize:

- creating or switching branches, committing, pushing, opening/updating a PR,
  or fetching dependencies/submodules when those actions were not requested;
- production deployment, DNS/KV changes, live writes, or `npm run deploy`;
- installing to a real prefix or modifying the host;
- enabling WuciOS attempt/scaffold flags or running mutating substrate probes;
- generating, importing, rotating, or publishing real keys or authority roots;
- signing production manifests, accepting external evidence, or claiming an
  independent identity;
- uploading public artifacts, creating a release or tag, merging a PR, changing
  repository settings, or deleting remote state.

Perform these only when the maintainer explicitly places that action and target
in scope. Prefer dry runs, local temporary roots, fixture inputs, draft PRs, and
rollback-capable operations. Never expose tokens, secrets, private identities,
passphrases, plaintext messages, signing material, or private transcripts in
commands, logs, diffs, artifacts, PR text, or chat.

## Completion and handoff contract

Do not say “done,” “fixed,” “ready,” “full suite,” “all tests pass,” or
“production ready” unless the evidence exactly supports that phrase.

Every implementation handoff must state:

- starting commit and initial worktree condition;
- root cause and restored invariant;
- files changed, including generated consumers;
- exact validation commands and results;
- relevant checks not run and why;
- residual limitations, blockers, and intentional non-claims;
- final worktree state and any branch, commit, push, PR, deployment, or release
  action actually performed.

Completion requires that the requested behavior works; defects have a
regression test where deterministically testable; affected alternate paths
agree; generated files match their producers; documentation describes current
reality; no secret or transient artifact remains; no unrelated user change was
overwritten; and the diff is bounded to the authorized scope.

## Core, Gate, Witness, and Ledger requirements

- Assembly owns the narrow envelope, Gate/root, authenticated-open, and release
  enforcement boundary. Python and Zig are reference, fixture, orchestration,
  policy, and portable-verifier layers; never imply that they replace an
  assembly enforcement path that was not exercised.
- Authenticated output must not reach stdout or its final path before tag
  verification. File output must use a private sibling temporary, clean it on
  every failure, and commit with no-overwrite semantics.
- Gate-authorized streaming may create mode-0600 temporary plaintext before
  Gate commit. Describe the claim as final-path authorization, not “no plaintext
  exists before Gate verification.”
- Secret scalar work must not use the variable-time public-only basepoint
  primitive or introduce secret-dependent branches/table access.
- Gate contracts and authority roots must preserve exact ordered fields,
  artifact/manifest/warrant/challenge/signature bindings, action allow bits,
  authority identifiers, and group-key equality.
- Assembly implements positive flat and rooted `open` and `release` actions;
  only rooted commands bind a supplied authority root. Flat fixture contracts
  are not production authority. `publish-authorized-rooted` and
  `trust-authorized-rooted` remain fail-closed decision-only paths and must
  stay side-effect-free until a reviewed non-fixture production authority is
  linked to positive assembly enforcement.
- The current assembly contract parser treats `receipt-sha256` as an opaque
  provenance reference and does not hash a receipt file. Do not claim
  assembly-level receipt-byte binding; exercise Zig/Python receipt-aware
  verification whenever that property is required.
- The Witness public profile is exactly `wuci-ji.self.wj`, `manifest.txt`,
  `warrant-message.txt`, `release-receipt.json`, `receipt-contract.txt`,
  `authority-root.txt`, `release-decision.txt`, `publish-index.txt`, and
  `attestation.json`. It excludes keys, opened binaries, private material, and
  transcripts.
- “Publish” in a Witness index or CAGE decision means public evidence
  publication derived from an authorized release; it is not production publish
  authority.
- Preserve Ledger domain separation: empty root `SHA256("")`, leaf
  `SHA256(0x00 || exact_entry_bytes)`, and node
  `SHA256(0x01 || decoded_left || decoded_right)`. Verify complete prior
  history before append.

## Daylight evidence requirements

- Treat every Daylight version as its own package and score unit. A score or
  declaration is valid only when generated from the currently bound artifact
  and verified evidence.
- Missing measurements produce blockers, `NOT_MEASURED`, null/invalid, or
  diagnostic-only status; they never receive inferred credit.
- Canonical security JSON must reject duplicate keys and binary floating-point
  values where exact `Decimal` or `Fraction` semantics are required.
- In v20 profiles that carry these fields, `fixture: true` implies
  `claim_usable: false`. Repository-owned evidence cannot satisfy an
  external/independent slot.
- The committed v20 fixture is expected to refuse declaration. Making it
  declaration-allowed is a security-critical change requiring the exact,
  independently authored, commit/artifact-bound and cryptographically verified
  external evidence specified by v20.
- V20 external evidence requires at least two distinct independent rebuilds and
  environments, at least one external firewall-profile review, exactly three
  distinct verifier families, and pinned cryptographically verified Ed25519
  attestations. External identities must pass the package’s independence rules;
  never rename internal/repository evidence to evade them.
- Keep the v20 exact public-file profile and keep firewall reports outside its
  public root.
- Any public numeric change must pass DaylightNPT and update all applicable
  canonical score, capsule, status, claim-evidence, integrity, manifest, and site
  bindings through their producers.

## WuciOS v2.4 requirements

- `wucios/`, `tools/wucios/`, and
  `docs/wucios/WUCIOS_V24_REDUCTION_GATE.md` control current WuciOS work.
  Legacy `docs/WUCI_OS*.md` material cannot override them.
- Noether Core is the serious candidate release profile: TTY-first, GUI-free,
  and network-minimized. Reject GUI/browser/desktop packages, default network
  services, unapproved listeners, runtime compilers, unjustified SUID/SGID, and
  unregistered components. Reserve release-authoritative wording for an
  artifact-bound valid score and review packet.
- Alpine is selected only for the bounded substrate-trial scope. Do not call it
  a production substrate, a release, certification, or full runtime validation.
- A bootable image alone is not a release. Require a current artifact digest,
  manifest, surface inventory, claim boundary, measured evidence, generated
  score, and review packet.
- Missing evidence stays `NOT_MEASURED`; smoke or handwritten values cannot
  become authoritative scores.
- Phase 3C lanes are policy/scaffold lanes. An environment opt-in is not user
  authorization to download, build, select, rank, score, boot, install, or claim
  a substrate. Phase 3C closeout does not authorize or imply a next
  implementation phase.
- Raw runtime evidence and artifacts under ignored build paths remain local
  until an explicit public-evidence review authorizes publication.
- Writes to real block devices, install media, non-temporary root filesystems,
  or host/system paths require explicit target-specific authorization, as do VM
  launch, networking, downloads, and package manager execution. Safe validators
  and review generators may write only to their documented temporary or ignored
  output roots. Tests use temporary fixtures, never real disks.

## NOXFRAME, Kaiju, and legacy Wuci-OS requirements

- NOXFRAME is a bounded stdlib-Python operator console and proof launcher, not a
  kernel, a shell sandbox, or compromised-host containment.
- Virtual filesystems, processes, contexts, and xframes are console/session
  models. Do not turn metadata-only host/network commands into ambient host
  execution.
- Codex host execution remains opt-in through `--allow-codex`, uses fixed
  argument vectors, and must be explicitly requested.
- Kaiju exposes a bounded purpose catalog and an explicit QEMU bridge. Keep
  network disabled by default; ISO installation, disk creation, and VM launch
  require authorization.
- The legacy `tools/wuci_os.py` lane stays clearly labeled. Do not copy its
  XFCE/musl direction or obsolete release commands into WuciOS v2.4.

## Static site, ZP1, and Penumbra requirements

- The static site keeps runtime assets and calls same-origin, remains
  dependency-light and tracker-free, and contains no browser cryptography.
  External hyperlinks are allowed; Bottle cryptography stays at its separate
  application origin.
- Every public claim must remain bound through `site/claim-evidence.json` and
  the appropriate generated status/capsule. Repository metadata and
  `site/_headers` do not prove live HTTPS, HSTS, redirects, or served headers.
- A push to `main` touching `site/**`, root `CNAME`, root
  `wrangler.toml`, or `.github/workflows/pages.yml` can deploy the public
  site; `workflow_dispatch` can also deploy it. A pull request alone does not.
  Treat publication as an external action and live-check only after an
  authorized deployment.
- Keep the ZP1 submodule pinned. The current coupling Make target regenerates
  `tools/wuciji-zp1-bridge/Cargo.lock`; inspect any resulting diff and treat it
  as a dependency change requiring explicit review. Never commit incidental
  lockfile churn, and isolate any upstream submodule update.
- Penumbra is an independent Cargo crate. Use
  `cargo test --locked --manifest-path penumbra/Cargo.toml` unless a real,
  tested root Make target is added; never document a nonexistent target.

## WUCI-CAGE Development Note

For WUCI-CAGE work, do not add exploit generation, vulnerability reproduction,
offensive scanning, jailbreak harnesses, or network attack logic.

Do not claim no-network or runtime sandboxing from CAGE. CAGE v1 verifies
artifact legitimacy; it does not enforce OS containment. CARROT is a separate,
bounded Linux seccomp plus user/network-namespace no-network proof, not a
general sandbox or host-containment guarantee.

Prefer deterministic fixtures, tempdirs, no network, stdlib-only Python, and
the existing assembly boundaries. Run targeted CAGE tests before final response.

## WUCI-QCAGE Development Note

For WUCI-QCAGE work, do not add offensive quantum exploitation tooling.

Do not claim quantum-safe status from classical-only signatures. Do not treat
secp256k1, ECDSA, RSA, DH, ECDH, or X25519 as quantum-safe.

Do not implement PQ stubs that pass as real verifiers. Any future PQ verifier
must be real, pinned, deterministic, tested, and clearly identified.

Keep QCAGE v1 stdlib-only unless explicitly adding a reviewed PQ verifier lane.
Prefer SHA-384 and SHA-512 for long-lived public evidence, while preserving
SHA-256 compatibility for existing assembly surfaces.

The bundled Rust FIPS 204 ML-DSA lane may clear only its pinned real-verifier
evidence gate. It does not make Wuci-Ji quantum-safe, and system-level
`quantum_safe` claims must remain false without the complete independently
earned evidence required by policy.

## WUCI-HARDEN Development Note

For WUCI-HARDEN-0, keep the pass narrow: verifier identity, safe I/O, fixture
quarantine, reserved-action denial, witness public-file hardening, and ledger
history verification. Do not use HARDEN-0 as a reason to add CAGE/QCAGE,
production authority, runtime sandboxing, or new cryptography.

WUCI-HARDEN work must be defensive only. Do not add exploit payloads,
vulnerability reproduction, offensive scanning, malware logic, or network attack
logic.

Do not treat fixture FROST as production authority. The existing
`publish-authorized-rooted` and `trust-authorized-rooted` commands are
fail-closed decision-only paths, not positive authority. Do not claim publish
or trust authority until a signed non-fixture ceremony, the production
authority verifier, and positive assembly enforcement are linked and all
production-readiness gates pass.

CARROT proves only its bounded local network-syscall-denial lane on supporting
Linux kernels. Do not broaden that into a general sandbox, VM, compromised-host
containment, or universal no-network claim. Do not claim quantum safety from
classical-only evidence.

CARROT evidence must observe seccomp `EPERM` together with the required user
and network namespace checks. Missing or unavailable enforcement components
must fail closed.

Prefer stdlib-only Python and deterministic tests. Reject symlinks and hardlinks
in public evidence. Keep existing Gate, Witness, Ledger, CAGE, and QCAGE proof
lanes passing.

## WUCI-INSTALL Development Note

WUCI-INSTALL must remain noninteractive. Do not use `shell=True`, `eval`, or
remote-code shell pipelines.

Do not accept unsigned install manifests. Do not install without a local copied
install root key. Do not treat fixture authority as production install
authority.

Before any install write, verify the copied local root and fingerprint, the
canonical current-build manifest, the OpenSSH Ed25519 signature in namespace
`wuci-install-v1`, and the binary’s SHA-256/SHA-384/SHA-512 vector.

Do not claim runtime sandboxing or quantum safety from the install lane. Install
writes must be atomic, and all proof reads must reject symlinks, hardlinks, and
non-regular files. Trusted verifier executables must use the existing
absolute-path and non-symlink policy. An installed `HARDEN: RECEIPT_ONLY`
result is not a newly executed HARDEN proof.

## Daylight Bottle root boundary

Detailed path-specific requirements live in `apps/bottle/AGENTS.md` and apply
to every Bottle change.

At the root level, preserve these boundaries:

- first-party encryption and decryption remain browser-local;
- the server accepts and stores only the exact field labeled `ciphertext` plus
  public metadata, never decrypts, and cannot prove arbitrary-client encryption;
- private identities, passphrases, plaintext, and decrypt outcomes never enter
  server requests, storage, logs, telemetry, URLs, or browser persistence;
- cryptography uses the pinned maintained library behind the adapter; never
  implement custom cryptography;
- runtime assets/calls remain same-origin with no analytics, trackers, remote
  scripts/fonts, permissive CORS, or weakened CSP;
- keyring additions contain public records only and require manual review;
- Bottle evidence remains an unsigned architectural record, not proof of server
  honesty, sender identity, delivery, erasure, or provider behavior;
- the anonymous MVP is not abuse/DoS resistant and must not receive a
  production-availability claim without bounded pagination/responses and
  reviewed edge controls;
- live Cloudflare/KV/DNS deployment and smoke checks require explicit approval.

Run `npm run check` from `apps/bottle` for every Bottle change. Add the
documented Wrangler dry run for deployment configuration changes; do not perform
a live deploy without explicit authorization.
