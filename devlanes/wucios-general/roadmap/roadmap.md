# WuciOS Development Lane Roadmap

## Phase 0 - Lane separation and authority

Objective: establish the development/general-usage lane separately from the
runtime-validation gate chain.

Allowed work: create lane documentation, authority manifest, profile stubs,
evidence policy, and roadmap.

Forbidden claims: production readiness, external validation, full runtime
validation, score mutation, or reinterpretation of completed gates.

Completion evidence: branch exists as `wucios-dev-general-lane`; lane files
exist under `devlanes/wucios-general/`; authority manifest records the lane
classification.

## Phase 1 - Developer profile design

Objective: define the minimum developer-facing package and workflow categories.

Allowed work: plan shell, editor, source-control, scripting, documentation,
archive, and hash tooling categories without installing anything.

Forbidden claims: package-manager correctness, network readiness, service
readiness, or developer preview readiness.

Completion evidence: reviewed developer profile, planned package categories,
and unresolved authorization notes for package-manager and network behavior.

## Phase 2 - Disposable development rootfs experiments

Objective: plan experiments against disposable rootfs copies only.

Allowed work: define copy rules, tempdir layout, cleanup expectations, and
non-production smoke observations.

Forbidden claims: mutation of validation rootfs evidence, persistent runtime
correctness, or production system behavior.

Completion evidence: disposable-experiment plan that identifies source inputs,
copy boundaries, and evidence output location.

## Phase 3 - Toolchain/package planning

Objective: identify candidate development package groups and dependency
questions.

Allowed work: map toolchain, build, scripting, editor, documentation, archive,
and hash needs against available source context.

Forbidden claims: package availability correctness, package-manager correctness,
network repository correctness, or installation success.

Completion evidence: package-planning document with unresolved risks and
authorization requirements.

## Phase 4 - Controlled package-manager probe, separately authorized

Objective: design a separate authorization path for any package-manager probe.

Allowed work: draft probe scope, offline/online distinction, evidence format,
and rollback expectations.

Forbidden claims: enabling package installation without authorization,
repository trust, update correctness, or general OS readiness.

Completion evidence: approved probe plan or explicit decision to defer package
manager probing.

## Phase 5 - Network boundary and update-policy design

Objective: define how network behavior and update policy should be governed.

Allowed work: document proposed network boundaries, authorization gates,
repository policy, update cadence, and audit evidence requirements.

Forbidden claims: tested network behavior, network security validation, update
correctness, external validation, or production readiness.

Completion evidence: reviewed network and update-policy design with open
questions tracked.

## Phase 6 - Init/service model research

Objective: research the init and service model needed for developer and
general-usage previews.

Allowed work: compare candidate init/service expectations, service lifecycle
needs, logging integration, and failure modes.

Forbidden claims: init correctness, service behavior correctness, bootability,
or long-running stability.

Completion evidence: service-model research note with candidate paths and
required validation still marked incomplete.

## Phase 7 - Developer preview image

Objective: define criteria for a non-production developer preview image.

Allowed work: assemble preview requirements, artifact checklist, development
workflow expectations, and evidence recording plan.

Forbidden claims: production readiness, external validation, full runtime
validation, or general-usage readiness.

Completion evidence: developer-preview criteria and artifact manifest, subject
to separate build authorization.

## Phase 8 - General-usage preview

Objective: define conservative basic-system workflows for non-production use.

Allowed work: plan shell usability, filesystem expectations, account model,
logging, update policy, network policy, and service policy.

Forbidden claims: production readiness, external validation, security
validation, boot correctness, or long-running stability.

Completion evidence: general-usage preview criteria with explicit unresolved
validation requirements.

## Phase 9 - External review readiness

Objective: prepare materials for possible future external review without
claiming that review has occurred.

Allowed work: organize docs, manifests, evidence references, open questions,
and review checklist.

Forbidden claims: external validation, external certification, production
readiness, or full runtime validation.

Completion evidence: external-review readiness checklist that clearly states
external validation remains `NO`.
