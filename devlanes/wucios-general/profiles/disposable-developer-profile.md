# WuciOS Dev Lane Probe 2 - Disposable Developer Profile Design

## 1. Purpose

Define a design-only disposable developer profile shape for future WuciOS
development/general-usage work.

This document translates Probe 1 planning into a proposed profile layout and
policy surface. It does not implement the profile, install packages, execute a
package manager, enable network access, modify validation evidence, reinterpret
runtime gates, change Alpine score state, release an artifact, or claim
operational approval.

## 2. Authority Boundary

This profile design belongs to the WuciOS development lane under
`devlanes/wucios-general/`. It may use existing lane documents as input context,
but it must not change their authority.

The design is non-validation and non-release. It does not change Gate, Witness,
Ledger, CAGE, QCAGE, install, or Alpine evidence. It does not create production
trust, publish trust, package repository trust, update trust, network trust, or
runtime authority.

Any future work that builds this profile, copies a root, runs tools, executes a
package manager, enables network access, records runtime observations, or
prepares a preview artifact requires a separate task and review.

## 3. Relationship to Probe 1

Probe 1 defined the planning boundary for a future disposable developer
profile. This Probe 2 document narrows that planning into a proposed profile
shape.

Probe 2 carries forward these Probe 1 constraints:

- The profile remains disposable and preview-bound.
- Validation evidence remains outside the write surface.
- Package-manager behavior remains deferred.
- Network behavior remains deferred.
- Tooling names remain candidate inputs, not package approval.
- Development-lane observations, if later authorized, must stay distinct from
  validation evidence.

## 4. Relationship to base-dev-profile.md

`base-dev-profile.md` defines broad candidate categories for a minimal
developer-usable environment. This disposable profile is a proposed future
overlay that keeps those categories but adds preview-bound placement and
persistence rules.

The base profile remains the category source for shell, editor, compiler,
source-control, scripting, documentation, archive, hash, package-manager,
network, and service/init planning. Probe 2 does not widen those categories and
does not authorize package selection.

## 5. Relationship to general-usage-profile.md

`general-usage-profile.md` defines a conservative direction for basic system
use. This disposable profile treats that direction as user-experience context,
not as a release target.

The proposed profile may later inform shell usability, filesystem layout,
temporary work locations, logging placement, and documentation flow. It does
not claim boot behavior, service behavior, update behavior, network behavior,
security posture, or long-running operation.

## 6. Disposable Profile Concept

The disposable profile is a future preview-bound development workspace with a
clearly separated source input area, writable work area, generated-output area,
and optional observation area.

Proposed concept:

- Read-only inputs: lane documents, source snapshots, and prior evidence
  references used only as planning context.
- Disposable work root: a future copied or generated workspace that may be
  discarded after use.
- Preview-bound writes: generated files, editor scratch files, logs, caches,
  test outputs, and observations live only under preview-specific paths.
- Explicit cleanup: future implementation should define what is removed,
  retained, or summarized before the workspace is discarded.
- No authority transfer: output from the disposable profile remains
  development-lane material unless a separate validation procedure says
  otherwise.

## 7. Proposed Profile Directory/File Layout

The following layout is proposed for a future design review. It is not created
by this document.

```text
devlanes/wucios-general/profiles/disposable/
  README.md
  profile-policy.md
  layout.md
  candidate-tooling.md
  session-expectations.md
  persistence-policy.md
  network-policy.md
  evidence-policy.md
  handoff.md
```

Future preview-bound runtime paths, if separately authorized, should be
documented before use:

```text
<preview-root>/
  inputs/
  workspace/
  outputs/
  logs/
  caches/
  observations/
  cleanup/
```

Proposed path intent:

- `inputs/`: copied or referenced planning inputs, with provenance recorded.
- `workspace/`: disposable development work area.
- `outputs/`: generated files intended for review.
- `logs/`: preview-bound logs from future local actions.
- `caches/`: disposable caches that can be removed without authority impact.
- `observations/`: development-lane notes only, never validation evidence.
- `cleanup/`: future cleanup notes, manifests, or discard records.

## 8. Candidate Developer Tooling Categories

Candidate categories remain descriptive. They do not approve package names,
repository use, or package-manager execution.

- Shell/base utilities: proposed interactive shell, file inspection, process
  inspection, environment inspection, and permission inspection.
- Text tooling: candidate editor, pager, diff viewer, and search workflow.
- Source-control tooling: candidate local repository inspection and patch
  review workflow.
- Scripting tooling: future POSIX shell and stdlib-first Python workflow.
- Build tooling: candidate compiler, linker, make-like orchestration, and
  header/library inspection.
- Documentation tooling: candidate manpage, Markdown, changelog, and local doc
  workflow.
- Archive/hash tooling: candidate tar, gzip, xz, zip, SHA-256, SHA-384, and
  SHA-512 workflow.
- Test tooling: proposed deterministic local tests, tempdirs, fixtures, and
  no-network test design.
- Package tooling: deferred until a separate package-manager task exists.
- Network tooling: deferred until a separate network task exists.
- Service/init tooling: research-only until a separate service/init task
  exists.

## 9. Candidate Shell/Session Expectations

Future shell/session design should be predictable, local, and preview-bound.

Candidate expectations:

- A clear prompt marker that identifies the disposable profile context.
- A documented working directory under the disposable workspace.
- Environment variables scoped to the preview-bound session.
- PATH ordering documented before any future implementation.
- Read-only input paths separated from writable output paths.
- Logs and command transcripts, if later authorized, written under
  preview-bound log paths.
- No implicit package-manager execution during shell startup.
- No implicit network action during shell startup.
- No mutation of validation evidence from shell helpers.

## 10. Network Posture

The proposed network posture is deferred. Probe 2 does not enable network
access, test connectivity, configure repositories, fetch packages, or claim
network behavior.

Future network work must be split into a separate authorization path that
defines:

- Whether network access is in scope.
- Which commands or tools may use it.
- Which paths may record network-related observations.
- How repository trust and update behavior would be reviewed.
- How to keep development observations separate from validation evidence.

## 11. Persistence Posture

The proposed persistence posture is disposable by default for future preview
work.

Candidate persistence rules:

- Source inputs are not modified by profile activity.
- Workspace files are temporary unless explicitly promoted by review.
- Outputs are review artifacts, not validation evidence.
- Logs and caches are preview-bound and may be discarded.
- Observations are development-lane notes unless a separate validation process
  exists.
- Cleanup records should document retained files and discarded files.

## 12. Evidence Posture

This design does not create, edit, move, relabel, or replace validation
evidence.

Future evidence-related handling should follow these rules:

- Validation evidence paths are outside the writable surface.
- Development observations are labeled as development-lane observations.
- Observations do not change Gate, Witness, Ledger, CAGE, QCAGE, install, or
  Alpine classifications.
- Public evidence reads should reject symlinks and hardlinks where lane policy
  requires that behavior.
- Classical signatures are not described as quantum-safe.
- Fixture authority is not described as production authority.

## 13. Allowed Future Actions

Allowed future actions, subject to separate review, are limited to design and
local preparation:

- Draft the proposed disposable profile subdocuments.
- Refine the future directory/file layout.
- Define candidate environment variables and shell prompt markers.
- Define cleanup and discard policy.
- Define preview-bound output and observation labels.
- Draft deterministic local test expectations.
- Draft separate package-manager authorization questions.
- Draft separate network authorization questions.
- Draft Probe 3 implementation boundaries without implementing them in Probe 2.

## 14. Disallowed Actions

The following actions are outside Probe 2:

- Installing packages.
- Executing a package manager.
- Enabling or testing network access.
- Fetching remote resources.
- Modifying runtime validation evidence.
- Reinterpreting runtime gates.
- Changing Alpine score state.
- Creating release artifacts.
- Claiming production-readiness, external-validation, full-runtime-validation,
  security-validation, boot-correctness, service-correctness, update-correctness,
  package-manager-correctness, or network-correctness.
- Adding exploit generation, vulnerability reproduction, offensive scanning,
  jailbreak harnesses, malware logic, network attack logic, or offensive
  quantum exploitation tooling.
- Treating fixture FROST as production authority.
- Adding PQ verifier placeholders that can be mistaken for real verification.
- Using `shell=True`, `eval`, remote-code shell pipelines, interactive install
  flows, or unsigned install manifests in install-lane-adjacent work.

## 15. Preview Success Criteria

The future disposable profile design can proceed to later review only when:

- The profile remains design-only at this checkpoint.
- The proposed write surface is preview-bound and disposable.
- Source inputs, workspace files, outputs, logs, caches, observations, and
  cleanup records have distinct path purposes.
- Validation evidence remains outside writable profile paths.
- Package-manager behavior and network behavior remain deferred.
- Candidate tooling categories are reviewed without package execution.
- Persistence rules distinguish temporary files from review outputs.
- Evidence posture distinguishes development observations from validation
  evidence.
- Disallowed actions remain explicit.

## 16. Failure Conditions

Probe 2 fails or must be revised if it:

- Implements the disposable profile.
- Installs packages or executes a package manager.
- Enables, configures, or tests network access.
- Modifies validation evidence or Alpine score state.
- Reinterprets runtime gates.
- Claims release status, operational approval, production-readiness,
  external-validation, or full-runtime-validation.
- Treats candidate tooling as approved tooling.
- Treats future observations as validation evidence.
- Adds offensive security or offensive quantum tooling.
- Uses fixture authority as production authority.

## 17. Probe 3 Handoff

Probe 3 should remain separately scoped. A candidate handoff would be a
disposable-root layout plan or profile subdocument draft, still design-only
unless a later task explicitly authorizes implementation.

Probe 3 should answer:

- Which proposed files should be created first.
- Which preview-bound paths need stricter naming.
- Which environment variables are candidate-only.
- Which cleanup records are needed before any local action.
- Which package-manager and network questions must remain separate.

Probe 3 must preserve the same non-validation and non-release authority
boundary unless its task explicitly narrows or changes scope.

## 18. Final Classification

WUCIOS_DEV_LANE_PROBE_2_DISPOSABLE_PROFILE_DESIGN_READY
