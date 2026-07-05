# WuciOS Disposable Developer Profile Foundation Batch 2 Validation

## Scope

Foundation Batch 2 adds deterministic dry-run evidence support for the
disposable developer profile foundation and a local stability gate for that
evidence.

Validation is local-only. The evidence is non-runtime planning evidence. It is
generated under ignored `build/wucios/` paths and is not committed by this
batch.

## Added Behavior

- The dry-run planner accepts `--evidence-dir <repo-relative-path>`.
- Evidence mode writes only under the selected evidence directory.
- Evidence mode writes stable files:
  - `dry-run-plan.txt`
  - `dry-run-summary.json`
  - `evidence-index.json`
- The stability validator runs two evidence generations and compares the stable
  outputs.

## Non-Claims

- No profile was created.
- No install was performed.
- No package manager was executed.
- No network behavior was enabled.
- No host config was mutated by the planner.
- No isolation enforcement was added.
- No production readiness is claimed.
- No runtime validation is claimed.
- No external validation is claimed.
- No working disposable developer profile is claimed.

## Expected Evidence Directories

Manual reviewer evidence:

```text
build/wucios/devlanes/disposable-profile-foundation-batch-2/manual-check/
```

Stability validator evidence:

```text
build/wucios/devlanes/disposable-profile-foundation-batch-2/run-1/
build/wucios/devlanes/disposable-profile-foundation-batch-2/run-2/
```

## Commands Used

```sh
git status --short
git status --short devlanes/wucios-general
git rev-parse HEAD
git rev-parse origin/wucios-dev-general-lane
sh devlanes/wucios-general/tools/validate-disposable-developer-profile.sh
sh devlanes/wucios-general/tools/validate-disposable-profile-scaffold.sh
sh devlanes/wucios-general/tools/plan-disposable-profile-dry-run.sh
sh devlanes/wucios-general/tools/plan-disposable-profile-dry-run.sh --evidence-dir build/wucios/devlanes/disposable-profile-foundation-batch-2/manual-check
sh devlanes/wucios-general/tools/validate-disposable-profile-dry-run-stability.sh
python3 -m json.tool devlanes/wucios-general/scaffolds/disposable-developer-profile/contract-manifest.json
git diff --check
```

The forbidden-claim check for generated evidence is performed by:

```sh
sh devlanes/wucios-general/tools/validate-disposable-profile-dry-run-stability.sh
```

For source-review grep checks, avoid treating validator denylist data as a
positive claim. The Batch 2 source files can be checked with a split-pattern
form:

```sh
pattern='production'' ready'
pattern="$pattern"'|externally'' validated'
pattern="$pattern"'|runtime'' validated'
pattern="$pattern"'|ready for'' installation'
pattern="$pattern"'|secure by'' default'
pattern="$pattern"'|full isolation'' proven'
pattern="$pattern"'|developer profile'' implemented'
pattern="$pattern"'|operational'' readiness'
grep -RniE "$pattern" \
  devlanes/wucios-general/tools/plan-disposable-profile-dry-run.sh \
  devlanes/wucios-general/tools/validate-disposable-profile-dry-run-stability.sh \
  devlanes/wucios-general/profiles/disposable-profile-foundation-batch-2-validation.md && exit 1 || true
```

## Expected Local Result

- Probe 3 profile validator passes.
- Scaffold validator passes.
- Dry-run planner prints a plan without writing files when no evidence
  directory is supplied.
- Evidence mode writes stable local evidence under the selected ignored build
  path.
- Stability validator reports stable evidence.
- `git diff --check` is clean.

## Classification

WUCIOS_DEV_LANE_DISPOSABLE_PROFILE_FOUNDATION_BATCH_2_LOCAL_VALIDATION_RECORDED

Post-push target:

WUCIOS_DEV_LANE_DISPOSABLE_PROFILE_FOUNDATION_BATCH_2_PUSHED
