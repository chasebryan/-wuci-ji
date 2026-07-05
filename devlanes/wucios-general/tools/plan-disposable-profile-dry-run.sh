#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
MANIFEST="$SCAFFOLD/contract-manifest.json"
CONTRACT="$SCAFFOLD/profile-contract.md"
README="$SCAFFOLD/README.md"
SCAFFOLD_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-scaffold.sh"
EVIDENCE_DIR=

LANE_REL="devlanes/wucios-general"
SCAFFOLD_REL="$LANE_REL/scaffolds/disposable-developer-profile"
MANIFEST_REL="$SCAFFOLD_REL/contract-manifest.json"
CONTRACT_REL="$SCAFFOLD_REL/profile-contract.md"
README_REL="$SCAFFOLD_REL/README.md"
PLANNER_REL="$LANE_REL/tools/plan-disposable-profile-dry-run.sh"
PLANNER_CANONICAL_COMMAND="sh $PLANNER_REL --evidence-dir <evidence-dir>"

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

require_file() {
	file=$1
	label=$2
	if [ ! -f "$file" ]; then
		fail "$label missing: $file"
	fi
}

print_item() {
	label=$1
	value=$2
	printf '  - %s: %s\n' "$label" "$value"
}

usage() {
	printf 'usage: sh %s [--evidence-dir repo-relative-path]\n' "$PLANNER_REL" >&2
	exit 2
}

validate_evidence_dir_arg() {
	dir=$1
	case "$dir" in
		'' | -* | /* | *'/../'* | '../'* | *'/..' | '..')
			fail "evidence directory must be a repo-relative path without parent traversal"
			;;
	esac
}

write_evidence() {
	out_dir=$1
	mkdir -p "$out_dir" || fail "could not create evidence directory: $out_dir"

	cat > "$out_dir/dry-run-plan.txt" <<EOF
Disposable developer profile dry-run plan
Mode: local dry-run evidence only
Planner command: $PLANNER_CANONICAL_COMMAND
Source lane: $LANE_REL
Scaffold path: $SCAFFOLD_REL
Source contract path: $CONTRACT_REL
Contract manifest path: $MANIFEST_REL
Scaffold README path: $README_REL
Current status: not implemented

Non-claim boundary:
- No install behavior was performed.
- No profile creation behavior was performed.
- No runtime behavior was performed.
- No package-manager execution was performed.
- No network behavior was performed.
- No host configuration was changed.
- No isolation enforcement was added.
- This evidence is local dry-run evidence only.

Intended future inputs:
- reviewed_design_notes
- candidate_layout_decisions
- preview_bound_path_names
- cleanup_policy
- separate_package_manager_authorization
- separate_network_authorization

Intended future outputs:
- profile_subdocuments
- reviewed_layout_notes
- preview_bound_file_naming_rules
- cleanup_records
- local_reviewer_commands

Future plan outline:
1. Keep Probe 3 and scaffold validators passing.
2. Review the contract manifest before adding behavior.
3. Define preview-bound input, workspace, output, log, cache, observation, and cleanup paths.
4. Keep package-manager and network decisions in separate reviewed tasks.
5. Add local-only generated artifacts only under an explicitly marked non-runtime path.
6. Record any future observations as development-lane material unless another reviewed procedure applies.
EOF

	cat > "$out_dir/dry-run-summary.json" <<EOF
{
  "schema": "wucios-dev-lane-disposable-profile-dry-run-summary-v1",
  "mode": "local_dry_run_evidence_only",
  "planner_command": "$PLANNER_CANONICAL_COMMAND",
  "source_lane": "$LANE_REL",
  "scaffold_path": "$SCAFFOLD_REL",
  "source_contract_path": "$CONTRACT_REL",
  "contract_manifest_path": "$MANIFEST_REL",
  "current_status": "not_implemented",
  "performed_actions": {
    "install_behavior": false,
    "profile_creation_behavior": false,
    "runtime_behavior": false,
    "package_manager_execution": false,
    "network_behavior": false,
    "host_configuration_change": false,
    "isolation_enforcement": false
  },
  "non_claim_boundary": [
    "local dry-run evidence only",
    "no install behavior performed",
    "no profile creation behavior performed",
    "no runtime behavior performed",
    "no package-manager execution performed",
    "no network behavior performed",
    "no host configuration change performed",
    "no isolation enforcement added"
  ],
  "intended_future_inputs": [
    "reviewed_design_notes",
    "candidate_layout_decisions",
    "preview_bound_path_names",
    "cleanup_policy",
    "separate_package_manager_authorization",
    "separate_network_authorization"
  ],
  "intended_future_outputs": [
    "profile_subdocuments",
    "reviewed_layout_notes",
    "preview_bound_file_naming_rules",
    "cleanup_records",
    "local_reviewer_commands"
  ]
}
EOF

	cat > "$out_dir/evidence-index.json" <<EOF
{
  "schema": "wucios-dev-lane-disposable-profile-evidence-index-v1",
  "mode": "local_dry_run_evidence_only",
  "planner_command": "$PLANNER_CANONICAL_COMMAND",
  "source_contract_path": "$CONTRACT_REL",
  "scaffold_path": "$SCAFFOLD_REL",
  "files": [
    {
      "path": "dry-run-plan.txt",
      "kind": "text_plan"
    },
    {
      "path": "dry-run-summary.json",
      "kind": "summary_json"
    },
    {
      "path": "evidence-index.json",
      "kind": "index_json"
    }
  ],
  "stable_comparison": true,
  "current_status": "not_implemented",
  "claim_boundary": "local dry-run evidence only; no install, profile creation, runtime, package-manager, network, host-configuration, or isolation-enforcement behavior was performed"
}
EOF
}

case "$#" in
	0)
		;;
	2)
		if [ "$1" != "--evidence-dir" ]; then
			usage
		fi
		validate_evidence_dir_arg "$2"
		EVIDENCE_DIR=$2
		;;
	*)
		usage
		;;
esac

require_file "$SCAFFOLD_VALIDATOR" "scaffold validator"
require_file "$MANIFEST" "contract manifest"
require_file "$CONTRACT" "profile contract"
require_file "$README" "scaffold README"

printf '%s\n' 'Disposable developer profile dry-run planner'
printf '%s\n' 'Mode: dry-run only'
printf '%s\n' 'Action: validate scaffold contract, then print a proposed plan'
if [ -n "$EVIDENCE_DIR" ]; then
	printf '%s\n' 'Writes: selected evidence directory only'
else
	printf '%s\n' 'Writes: none'
fi
printf '%s\n' 'Network: none'
printf '%s\n' 'Package actions: none'
printf '%s\n' 'Host configuration changes: none'
if [ -n "$EVIDENCE_DIR" ]; then
	printf 'Evidence output: %s\n' "$EVIDENCE_DIR"
fi
printf '\n'

if ! sh "$SCAFFOLD_VALIDATOR"; then
	fail "scaffold validator failed; dry-run plan not printed"
fi

printf '\n'
printf '%s\n' 'Proposed disposable developer profile plan'
print_item "source lane" "$LANE_DIR"
print_item "scaffold" "$SCAFFOLD"
print_item "contract manifest" "$MANIFEST"
print_item "contract document" "$CONTRACT"
print_item "profile behavior" "not implemented"
print_item "profile creation" "not performed"
print_item "package manager" "not executed"
print_item "network" "not enabled"
print_item "isolation enforcement" "not added"
print_item "host configuration" "not changed"
print_item "runtime execution" "not performed"

printf '\n'
printf '%s\n' 'Future plan outline'
printf '%s\n' '  1. Keep Probe 3 and scaffold validators passing.'
printf '%s\n' '  2. Review the contract manifest before adding behavior.'
printf '%s\n' '  3. Define preview-bound input, workspace, output, log, cache, observation, and cleanup paths.'
printf '%s\n' '  4. Keep package-manager and network decisions in separate reviewed tasks.'
printf '%s\n' '  5. Add local-only generated artifacts only under an explicitly marked non-runtime path.'
printf '%s\n' '  6. Record any future observations as development-lane material unless another reviewed procedure applies.'

printf '\n'
if [ -n "$EVIDENCE_DIR" ]; then
	write_evidence "$REPO_ROOT/$EVIDENCE_DIR"
	printf '%s\n' 'Dry-run planner complete: evidence files written and no host settings changed.'
	printf 'Evidence files written under: %s\n' "$EVIDENCE_DIR"
else
	printf '%s\n' 'Dry-run planner complete: no files written and no host settings changed.'
fi
