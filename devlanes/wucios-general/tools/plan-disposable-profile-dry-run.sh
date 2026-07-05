#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
MANIFEST="$SCAFFOLD/contract-manifest.json"
CONTRACT="$SCAFFOLD/profile-contract.md"
README="$SCAFFOLD/README.md"
PLAN_VOCABULARY_CONTRACT="$SCAFFOLD/plan-vocabulary-contract.json"
SCAFFOLD_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-scaffold.sh"
INPUT_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-plan-input.sh"
EVIDENCE_DIR=
INPUT_FILE=
INPUT_PROFILE_ID="none"
CONTRACT_MANIFEST_SCHEMA=
CONTRACT_MANIFEST_SCHEMA_VERSION=
PROFILE_CONTRACT_ID=
PLANNER_MODE=
FOUNDATION_ONLY=
DRY_RUN_ONLY=
INPUT_SCHEMA_ID=
EVIDENCE_CONTRACT_ID=
EVIDENCE_SUMMARY_SCHEMA=
EVIDENCE_INDEX_SCHEMA=
PLAN_VOCABULARY_CONTRACT_ID=
PLAN_SUMMARY_SCHEMA=

LANE_REL="devlanes/wucios-general"
SCAFFOLD_REL="$LANE_REL/scaffolds/disposable-developer-profile"
MANIFEST_REL="$SCAFFOLD_REL/contract-manifest.json"
CONTRACT_REL="$SCAFFOLD_REL/profile-contract.md"
README_REL="$SCAFFOLD_REL/README.md"
PLAN_VOCABULARY_CONTRACT_REL="$SCAFFOLD_REL/plan-vocabulary-contract.json"
PLANNER_REL="$LANE_REL/tools/plan-disposable-profile-dry-run.sh"
INPUT_VALIDATOR_REL="$LANE_REL/tools/validate-disposable-profile-plan-input.sh"

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

manifest_value() {
	key=$1
	python3 - "$MANIFEST" "$key" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    value = json.load(handle)

for part in sys.argv[2].split("."):
    value = value[part]

if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

print_item() {
	label=$1
	value=$2
	printf '  - %s: %s\n' "$label" "$value"
}

usage() {
	printf 'usage: sh %s [--input repo-relative-input.json] [--evidence-dir repo-relative-path]\n' "$PLANNER_REL" >&2
	exit 2
}

validate_repo_relative_arg() {
	value=$1
	label=$2
	case "$value" in
		'' | -* | /* | *'/../'* | '../'* | *'/..' | '..')
			fail "$label must be a repo-relative path without parent traversal"
			;;
	esac
}

validate_evidence_dir_arg() {
	dir=$1
	validate_repo_relative_arg "$dir" "evidence directory"
}

validate_input_arg() {
	input=$1
	validate_repo_relative_arg "$input" "input file"
	if [ ! -f "$REPO_ROOT/$input" ]; then
		fail "input file missing: $input"
	fi
}

planner_command_for_evidence() {
	if [ -n "$INPUT_FILE" ]; then
		printf 'sh %s --input %s --evidence-dir <evidence-dir>\n' "$PLANNER_REL" "$INPUT_FILE"
	else
		printf 'sh %s --evidence-dir <evidence-dir>\n' "$PLANNER_REL"
	fi
}

write_evidence() {
	out_dir=$1
	planner_command=$(planner_command_for_evidence)
	mkdir -p "$out_dir" || fail "could not create evidence directory: $out_dir"

	cat > "$out_dir/dry-run-plan.txt" <<EOF
Disposable developer profile dry-run plan
Mode: local dry-run evidence only
Planner command: $planner_command
Source lane: $LANE_REL
Scaffold path: $SCAFFOLD_REL
Source contract path: $CONTRACT_REL
Contract manifest path: $MANIFEST_REL
Contract manifest schema: $CONTRACT_MANIFEST_SCHEMA
Contract manifest schema version: $CONTRACT_MANIFEST_SCHEMA_VERSION
Profile contract id: $PROFILE_CONTRACT_ID
Planner mode: $PLANNER_MODE
Foundation only: $FOUNDATION_ONLY
Dry-run only: $DRY_RUN_ONLY
Input schema id: $INPUT_SCHEMA_ID
Evidence contract id: $EVIDENCE_CONTRACT_ID
Plan vocabulary contract path: $PLAN_VOCABULARY_CONTRACT_REL
Plan vocabulary contract id: $PLAN_VOCABULARY_CONTRACT_ID
Scaffold README path: $README_REL
Plan input path: ${INPUT_FILE:-none}
Plan input profile id: $INPUT_PROFILE_ID
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
  "schema": "$EVIDENCE_SUMMARY_SCHEMA",
  "mode": "local_dry_run_evidence_only",
  "planner_command": "$planner_command",
  "contract_manifest_schema": "$CONTRACT_MANIFEST_SCHEMA",
  "contract_manifest_schema_version": "$CONTRACT_MANIFEST_SCHEMA_VERSION",
  "profile_contract_id": "$PROFILE_CONTRACT_ID",
  "planner_mode": "$PLANNER_MODE",
  "foundation_only": $FOUNDATION_ONLY,
  "dry_run_only": $DRY_RUN_ONLY,
  "input_schema_id": "$INPUT_SCHEMA_ID",
  "evidence_contract_id": "$EVIDENCE_CONTRACT_ID",
  "plan_vocabulary_contract_id": "$PLAN_VOCABULARY_CONTRACT_ID",
  "source_lane": "$LANE_REL",
  "scaffold_path": "$SCAFFOLD_REL",
  "source_contract_path": "$CONTRACT_REL",
  "contract_manifest_path": "$MANIFEST_REL",
  "plan_input_path": "${INPUT_FILE:-none}",
  "plan_input_profile_id": "$INPUT_PROFILE_ID",
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
  "schema": "$EVIDENCE_INDEX_SCHEMA",
  "mode": "local_dry_run_evidence_only",
  "planner_command": "$planner_command",
  "contract_manifest_schema": "$CONTRACT_MANIFEST_SCHEMA",
  "contract_manifest_schema_version": "$CONTRACT_MANIFEST_SCHEMA_VERSION",
  "profile_contract_id": "$PROFILE_CONTRACT_ID",
  "planner_mode": "$PLANNER_MODE",
  "foundation_only": $FOUNDATION_ONLY,
  "dry_run_only": $DRY_RUN_ONLY,
  "input_schema_id": "$INPUT_SCHEMA_ID",
  "evidence_contract_id": "$EVIDENCE_CONTRACT_ID",
  "plan_vocabulary_contract_id": "$PLAN_VOCABULARY_CONTRACT_ID",
  "source_contract_path": "$CONTRACT_REL",
  "scaffold_path": "$SCAFFOLD_REL",
  "plan_input_path": "${INPUT_FILE:-none}",
  "plan_input_profile_id": "$INPUT_PROFILE_ID",
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
    },
    {
      "path": "plan-summary.json",
      "kind": "plan_summary_json"
    }
  ],
  "stable_comparison": true,
  "current_status": "not_implemented",
  "claim_boundary": "local dry-run evidence only; no install, profile creation, runtime, package-manager, network, host-configuration, or isolation-enforcement behavior was performed"
}
EOF

	cat > "$out_dir/plan-summary.json" <<EOF
{
  "schema": "$PLAN_SUMMARY_SCHEMA",
  "contract_manifest_schema_version": "$CONTRACT_MANIFEST_SCHEMA_VERSION",
  "profile_contract_id": "$PROFILE_CONTRACT_ID",
  "planner_mode": "$PLANNER_MODE",
  "plan_vocabulary_contract_id": "$PLAN_VOCABULARY_CONTRACT_ID",
  "dry_run_only": $DRY_RUN_ONLY,
  "foundation_only": $FOUNDATION_ONLY,
  "execution_status": "not_executed",
  "planned_actions": [
    {
      "phase": "document_boundary",
      "action_kind": "document_boundary",
      "result": "boundary_documented"
    },
    {
      "phase": "input_boundary",
      "action_kind": "validate_input",
      "result": "input_contract_checked"
    },
    {
      "phase": "profile_request_summary",
      "action_kind": "summarize_requested_profile",
      "result": "request_summary_recorded"
    },
    {
      "phase": "evidence_metadata",
      "action_kind": "emit_dry_run_evidence",
      "result": "dry_run_metadata_written"
    },
    {
      "phase": "manifest_binding",
      "action_kind": "record_manifest_binding",
      "result": "manifest_identifiers_recorded"
    },
    {
      "phase": "execution_report",
      "action_kind": "report_no_execution",
      "result": "no_execution_reported"
    }
  ]
}
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--evidence-dir)
			if [ "$#" -lt 2 ]; then
				usage
			fi
			validate_evidence_dir_arg "$2"
			EVIDENCE_DIR=$2
			shift 2
			;;
		--input)
			if [ "$#" -lt 2 ]; then
				usage
			fi
			validate_input_arg "$2"
			INPUT_FILE=$2
			shift 2
			;;
		*)
			usage
			;;
	esac
done

require_file "$SCAFFOLD_VALIDATOR" "scaffold validator"
require_file "$MANIFEST" "contract manifest"
require_file "$CONTRACT" "profile contract"
require_file "$README" "scaffold README"
require_file "$PLAN_VOCABULARY_CONTRACT" "plan vocabulary contract"
if [ -n "$INPUT_FILE" ]; then
	require_file "$INPUT_VALIDATOR" "input validator"
fi

CONTRACT_MANIFEST_SCHEMA=$(manifest_value schema) || fail "could not read manifest schema"
CONTRACT_MANIFEST_SCHEMA_VERSION=$(manifest_value schema_version) || fail "could not read manifest schema version"
PROFILE_CONTRACT_ID=$(manifest_value profile_contract_id) || fail "could not read profile contract id"
PLANNER_MODE=$(manifest_value planner_contract.planner_mode) || fail "could not read planner mode"
FOUNDATION_ONLY=$(manifest_value foundation_only) || fail "could not read foundation-only flag"
DRY_RUN_ONLY=$(manifest_value dry_run_only) || fail "could not read dry-run-only flag"
INPUT_SCHEMA_ID=$(manifest_value input_contract.schema) || fail "could not read input schema id"
EVIDENCE_CONTRACT_ID=$(manifest_value evidence_contract.id) || fail "could not read evidence contract id"
EVIDENCE_SUMMARY_SCHEMA=$(manifest_value evidence_contract.summary_schema) || fail "could not read evidence summary schema"
EVIDENCE_INDEX_SCHEMA=$(manifest_value evidence_contract.index_schema) || fail "could not read evidence index schema"
PLAN_VOCABULARY_CONTRACT_ID=$(manifest_value plan_vocabulary_contract.id) || fail "could not read plan vocabulary contract id"
PLAN_SUMMARY_SCHEMA=$(manifest_value plan_vocabulary_contract.plan_summary_schema) || fail "could not read plan summary schema"

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
if [ -n "$INPUT_FILE" ]; then
	printf 'Plan input: %s\n' "$INPUT_FILE"
fi
printf '\n'

if ! WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 sh "$SCAFFOLD_VALIDATOR"; then
	fail "scaffold validator failed; dry-run plan not printed"
fi

if [ -n "$INPUT_FILE" ]; then
	if ! sh "$INPUT_VALIDATOR" "$INPUT_FILE"; then
		fail "plan input validation failed; dry-run plan not printed"
	fi
	INPUT_PROFILE_ID=$(python3 - "$REPO_ROOT/$INPUT_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.load(handle)["profile_id"])
PY
)
fi

printf '\n'
printf '%s\n' 'Proposed disposable developer profile plan'
print_item "source lane" "$LANE_DIR"
print_item "scaffold" "$SCAFFOLD"
print_item "contract manifest" "$MANIFEST"
print_item "contract document" "$CONTRACT"
print_item "contract manifest schema" "$CONTRACT_MANIFEST_SCHEMA"
print_item "contract manifest schema version" "$CONTRACT_MANIFEST_SCHEMA_VERSION"
print_item "profile contract id" "$PROFILE_CONTRACT_ID"
print_item "planner mode" "$PLANNER_MODE"
print_item "foundation only" "$FOUNDATION_ONLY"
print_item "dry-run only" "$DRY_RUN_ONLY"
print_item "input schema id" "$INPUT_SCHEMA_ID"
print_item "evidence contract id" "$EVIDENCE_CONTRACT_ID"
print_item "plan vocabulary contract id" "$PLAN_VOCABULARY_CONTRACT_ID"
print_item "plan input" "${INPUT_FILE:-none}"
print_item "plan input validator" "$INPUT_VALIDATOR_REL"
print_item "plan input profile id" "$INPUT_PROFILE_ID"
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
