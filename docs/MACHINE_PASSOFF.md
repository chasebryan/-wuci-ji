# Machine Passoff Pattern

Updated: 2026-06-28

This is the continuation pattern for another machine or agent picking up
Wuci-Ji / Daylight work from the current `main` branch.

## Boundary First

Keep these claims unchanged unless linked evidence and tests prove otherwise:

```text
ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalReviewClaim = 0
OfficialEndorsementClaim = 0
```

- Do not add exploit generation, vulnerability reproduction, offensive
  scanning, jailbreak harnesses, malware logic, or network attack logic.
- Do not describe CAGE as OS containment.
- Do not describe classical signatures as quantum-safe.
- Do not treat fixture FROST or fixture authority roots as production
  authority.

## Fresh Machine Bootstrap

Start from the pushed repository state:

```sh
git clone https://github.com/chasebryan/-wuci-ji
cd -wuci-ji
git fetch origin main
git checkout main
git pull --ff-only origin main
git status --short --branch
git rev-parse HEAD
```

If the worktree is dirty before new work starts, stop and understand those
changes first. Do not normalize or revert unrelated work without explicit
direction.

## Read Order

Read these files before editing:

1. [README.md](../README.md)
2. [BUILD_NOTES.md](../BUILD_NOTES.md)
3. [docs/SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md)
4. [docs/PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)
5. [docs/BUILD_TARGETS.md](BUILD_TARGETS.md)
6. [daylight-equation/SCORECARD.md](../daylight-equation/SCORECARD.md)
7. [daylight-equation/research/daylight-v06-cap-removal-plan.md](../daylight-equation/research/daylight-v06-cap-removal-plan.md)

The Daylight cap-removal plan is the current continuation anchor.

## Host Selection

On macOS or another non-Linux host with Zig installed:

```sh
make build-linux
make daylight-v06-cap-removal-test
make wuci-daylight-bridge-test
make wjnext-model-test
```

On native Linux x86_64 with GNU `as`/`ld`:

```sh
make clean
make test
make daylight-v06-cap-removal-test
make production-readiness-gates
```

On Linux with user-mode QEMU available:

```sh
make clean
make test-linux
```

If a Daylight Rust lane fails because crates are not cached locally, allow one
normal dependency-resolution pass on an authorized networked machine, then
return to the offline commands.

## Minimum Continuation Checks

Before starting a new implementation slice, run:

```sh
make daylight-v06-cap-removal-test
make daylight-v06-peer-review-score-test
make daylight-v06-authority-verifier-test
make production-readiness-gates
make wuci-daylight-bridge-test
make daylight-v06-1000-claim-gate-test
```

Expected state:

```text
Daylight_v0.6_peer_review_evaluation_score = 8250 / 10000
Daylight_v0.6_research_score = 975 / 1000
ScoreIncreaseAuthorized = 0
```

The 1000 claim gate should remain blocked. The cap-removal test should pass by
proving that the current blockers are explicit and fail closed.

## Current Continuation Point

The current local slice adds fail-closed decision-only publish/trust Gate
support and keeps the Daylight cap-removal boundary active:

```text
Continue assembly-backed publish/trust Gate work without enabling production claims.
```

It added:

- `publish-authorized-rooted <authority> <artifact> <contract>`
- `trust-authorized-rooted <authority> <artifact> <contract>`
- fail-closed assembly publish and trust decision paths
- rooted Gate tests for valid publish/trust evidence and tampering
- updated cap-removal evidence showing publish/trust are not production authority
- `tools/daylight_cap_removal.py`
- `daylight-equation/research/daylight-v06-cap-removal-plan.v1.json`

That slice does not raise the score. It proves that fixture authority cannot satisfy publish/trust authority, and it keeps the 10,000-point model capped at
8250 because positive production publish/trust authority, runtime
containment, integrated public authority, and external review remain blocked.

## Next Bounded Slice

Continue from the production-authority cap. The next engineering target is:

```text
Prepare positive production publish/trust authority prerequisites without enabling production claims.
```

Recommended order:

1. Treat `publish-authorized-rooted` and `trust-authorized-rooted` as
   implemented only for fail-closed decisions: each verifies authority,
   artifact, and flat contract evidence, then prints an unauthorized decision.
   Neither command may install, execute, decrypt, write plaintext, or create
   production authority.
2. Keep fixture roots rejected:

   ```text
   authority/wuci-root.fixture.txt
   authority/wuci-release-root.fixture.txt
   production: false
   allow-trust: false
   allow-publish: false
   ```

3. The next implementation target is production-authority acceptance, but only
   after signed Golden Lock ceremony evidence and policy-linked negative tests
   exist. Decision-only publish/trust support is not a production claim.
4. Keep these files together when production authority changes:

   ```text
   docs/wuci_gate_boundary.json
   docs/wuci_production_authority_policy.json
   docs/PRODUCTION_READINESS.md
   src/gate_contract.s
   tests/wuci_gate_boundary.py
   tests/wuci_production_authority.py
   tests/daylight_cap_removal.py
   ```

The cap-removal verifier must continue to fail closed until all linked evidence
exists. If a command becomes implemented, update the plan and tests in the same
commit so the score boundary remains explicit.

## Publish Pattern

Before pushing from another machine:

```sh
git status --short --branch
git config --get user.name
git config --get user.email
gh auth status
git diff --check
```

Use `chasebryan` identity for this repository. Push only after the relevant
proof targets pass and the remote is current:

```sh
git fetch origin main
git status --short --branch
git add <explicit files>
git commit -m "<terse change summary>"
git push origin main
gh run list --branch main --limit 5
```

If CI starts, watch it:

```sh
gh run watch <run-id> --exit-status
```

Successful handoff means:

- `origin/main` points at the pushed commit.
- local worktree is clean.
- the latest `main` CI run is passing or any failure is documented as the next
  blocker.
