# WuciOS Dev Lane Probe 1 - Disposable Developer Profile Planning

## 1. Purpose

Define planning requirements for a future disposable developer profile in the
WuciOS development/general-usage lane.

This probe is non-validation, non-release, and planning-only. It does not
install packages, enable network access, modify runtime evidence, change Alpine
score state, reinterpret runtime gates, or claim readiness.

The purpose is to describe what a safe general-use developer preview would
eventually need before any separately authorized implementation work begins.

## 2. Authority Boundary

This document belongs to the WuciOS development lane under
`devlanes/wucios-general/`. It may reference prior validation evidence only as
input context under the lane evidence-import policy.

This probe does not:

- Change, replace, or expand completed validation evidence.
- Reclassify Gate, Witness, Ledger, CAGE, QCAGE, or Alpine evidence.
- Authorize package-manager use, repository access, or update behavior.
- Authorize network access, network testing, or network policy changes.
- Authorize image release, external review, or runtime validation.
- Claim production readiness, external validation, or complete runtime
  validation.

Any future work that installs packages, uses a package repository, enables
network access, modifies runtime evidence, builds a preview image, or validates
runtime behavior requires a separate authorization path.

## 3. Non-goals

- No package installation.
- No package-manager probe.
- No repository trust decision.
- No network enablement.
- No network connectivity test.
- No runtime gate reinterpretation.
- No Alpine score modification.
- No release artifact.
- No external-validation claim.
- No production-readiness claim.
- No full-runtime-validation claim.
- No validation evidence modification.
- No service/init correctness claim.
- No long-running stability claim.

## 4. Disposable Developer Profile Concept

The future profile should be disposable by design. A developer preview should
operate from a copied or generated development root, with all writes confined to
an explicitly designated temporary or preview-only workspace.

Expected properties:

- Source inputs are treated as read-only planning inputs unless a later task
  explicitly authorizes mutation.
- Runtime validation evidence is never edited by the profile.
- Generated files, package experiments, build outputs, caches, and logs live in
  preview-only locations.
- Cleanup behavior is documented before any experiment runs.
- The profile can be discarded without affecting validation artifacts, authority
  manifests, or baseline lane documents.
- Any future evidence produced by the profile is labeled as development-lane
  observation unless a separate validation procedure says otherwise.

The profile should improve developer ergonomics while preserving a strict
separation between development convenience and validation authority.

## 5. Package/Tooling Inventory Categories

The inventory should group future tooling needs by function before any package
selection or installation occurs:

- Shell and base utilities: interactive shell, file inspection, process
  inspection, permissions inspection, and environment inspection.
- Text inspection and editing: terminal editor support, pagers, diff viewing,
  and search tools.
- Source-control workflow: local repository inspection, commit preparation, and
  patch review.
- Scripting workflow: shell scripting and stdlib-first Python workflow planning.
- Build and compile workflow: compiler, linker, make-like orchestration, and
  header/library inspection.
- Documentation workflow: local manual pages, Markdown editing, changelog work,
  and release-note drafting without release claims.
- Archive and compression workflow: tar, gzip, xz, zip, and extraction planning.
- Hash and integrity workflow: SHA-256 compatibility plus SHA-384 and SHA-512
  support for longer-lived public evidence.
- Test workflow: deterministic local tests, tempdirs, fixtures, and no-network
  test design.
- Package-manager workflow: deferred until separately authorized.
- Network workflow: deferred until separately authorized.
- Service/init workflow: research-only until separately authorized.

## 6. Candidate Tooling List

The following tools are candidates for future review only. Listing them here is
not installation approval, package availability proof, repository trust, or
runtime validation.

- Shell/base: `busybox`, `ash`, `bash`, `coreutils`, `findutils`, `diffutils`,
  `grep`, `sed`, `awk`, `less`, `util-linux`, `procps`.
- Editors/viewers: `vi`, `vim`, `nano`, `less`, `file`.
- Source control: `git`, local patch tools, local diff tools.
- Scripting: POSIX shell, Python 3 with stdlib-first expectations.
- Build tooling: `make`, `gcc`, `g++`, `binutils`, `musl-dev`, `pkgconf`.
- Documentation: `mandoc` or equivalent local manpage support, Markdown lint or
  formatting helpers if later authorized.
- Archive/compression: `tar`, `gzip`, `xz`, `zip`, `unzip`.
- Hash/integrity: `sha256sum`, `sha384sum`, `sha512sum`, `openssl dgst` only if
  already authorized by the future profile.
- Test support: deterministic fixture runners, tempdir helpers, local-only test
  scripts.

## 7. Excluded Tooling List

The following tooling remains excluded from this probe:

- Exploit generation, vulnerability reproduction, offensive scanning,
  jailbreak harnesses, malware logic, or network attack logic.
- Offensive quantum exploitation tooling.
- Network scanners, packet capture workflows, remote enumeration tools, or
  service attack tooling.
- Remote-code shell pipelines, `eval`-style install helpers, or interactive
  installers.
- Unsigned install manifests or installer paths that lack a local copied install
  root key.
- Production authority tooling, publish authority tooling, or trust authority
  tooling without assembly-enforced commands.
- PQ verifier stubs that pass as real verifiers.
- Fixture FROST as production authority.
- Any tooling whose purpose is to mutate validation evidence or inflate prior
  gate meaning.

## 8. Preview Success Criteria

A future disposable developer preview can be considered ready for review only if
all of the following are documented before implementation:

- The preview root or workspace is explicitly disposable.
- Source inputs, generated outputs, caches, and logs have separate paths.
- Runtime validation evidence is protected from profile writes.
- Package categories are reviewed before package names are authorized.
- Package installation, repository use, and network behavior each have a
  separate authorization decision.
- Test expectations are deterministic, local, tempdir-based, and no-network.
- Evidence labels distinguish development observations from validation evidence.
- Cleanup and rollback expectations are written down.
- Known exclusions remain visible in the profile documentation.

## 9. Failure Conditions

The probe fails, or must be returned for revision, if future work:

- Installs packages without separate authorization.
- Enables or tests network access without separate authorization.
- Changes validation evidence, authority manifests, gate classifications, or
  Alpine score state.
- Treats development convenience as validation evidence.
- Claims release readiness, production readiness, external validation, complete
  runtime validation, boot correctness, init correctness, service correctness,
  repository trust, or update correctness.
- Adds offensive security tooling or quantum exploitation tooling.
- Uses fixture authority as production authority.
- Adds PQ verifier placeholders that can be mistaken for real verification.
- Uses interactive installation, `shell=True`, `eval`, or remote-code shell
  pipelines in install-lane-adjacent work.

## 10. Evidence Handling Policy

This probe does not create or modify validation evidence.

Future disposable-profile observations, if separately authorized, should be
stored outside validation evidence paths and labeled as development-lane
planning or development-lane observation. They must not be merged into Gate,
Witness, Ledger, CAGE, QCAGE, install, or Alpine evidence without a separate
validated procedure.

Public evidence reads should reject symlinks and hardlinks where the relevant
lane policy requires that behavior. Development convenience files must not
weaken existing proof-lane expectations.

## 11. Next Actions

- Review this planning probe for wording and authority-boundary correctness.
- Keep the probe uncommitted until reviewed.
- Draft a separate disposable-root layout plan.
- Draft package-category review notes before selecting any packages.
- Draft package-manager and network authorization questions as separate future
  tasks.
- Draft evidence-labeling rules for development-lane observations.
- Run only targeted, deterministic local checks when future implementation work
  is separately authorized.

## 12. Final Classification

WUCIOS_DEV_LANE_PROBE_1_PLANNING_READY
