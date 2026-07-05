# Hoare Contract

Hoare Contract defines preconditions and postconditions for WuciOS build, boot, audit, review, and score generation.

## Build Preconditions

- Substrate candidate is declared.
- Profile is declared.
- Component register exists.
- Denylists and allowlists exist.
- No claim of selected substrate exists unless a measured decision exists.

## Build Postconditions

- Artifact path and hash are recorded, or artifact fields remain `NOT_MEASURED`.
- Package manifest is generated, or marked `NOT_MEASURED`.
- Enabled services and listening ports are generated, or marked `NOT_MEASURED`.
- Noether Core disqualifiers fail the build or review gate.

## Review Preconditions

- Profiles, substrates, component register, budgets, and non-claim boundary parse as structured data.

## Review Postconditions

- Review packet exists.
- Missing values are explicit.
- Non-claims are included.
- Score is invalid unless artifact-bound and complete.
