#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
MANIFEST="$SCAFFOLD/contract-manifest.json"
CONTRACT="$SCAFFOLD/profile-contract.md"
README="$SCAFFOLD/README.md"
SCAFFOLD_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-scaffold.sh"

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

require_file "$SCAFFOLD_VALIDATOR" "scaffold validator"
require_file "$MANIFEST" "contract manifest"
require_file "$CONTRACT" "profile contract"
require_file "$README" "scaffold README"

printf '%s\n' 'Disposable developer profile dry-run planner'
printf '%s\n' 'Mode: dry-run only'
printf '%s\n' 'Action: validate scaffold contract, then print a proposed plan'
printf '%s\n' 'Writes: none'
printf '%s\n' 'Network: none'
printf '%s\n' 'Package actions: none'
printf '%s\n' 'Host configuration changes: none'
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
printf '%s\n' 'Dry-run planner complete: no files written and no host settings changed.'
