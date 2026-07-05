#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
PROFILE="$SCRIPT_DIR/../profiles/disposable-developer-profile.md"
failures=0

pass() {
	printf 'PASS: %s\n' "$1"
}

fail() {
	printf 'FAIL: %s\n' "$1"
	failures=$((failures + 1))
}

check_absent_phrase() {
	phrase=$1
	if grep -F -i -q "$phrase" "$PROFILE"; then
		fail "forbidden claim phrase present: $phrase"
	else
		pass "forbidden claim phrase absent: $phrase"
	fi
}

check_required_text() {
	label=$1
	text=$2
	if grep -F -q "$text" "$PROFILE"; then
		pass "$label"
	else
		fail "$label missing"
	fi
}

printf '%s\n' 'Probe 3 disposable developer profile contract validator'
printf 'Target: %s\n' "$PROFILE"

if [ ! -f "$PROFILE" ]; then
	fail "Probe 2 disposable developer profile document is missing"
	printf '%s\n' 'FAIL: disposable developer profile contract failed'
	exit 1
fi

pass "Probe 2 disposable developer profile document exists"

check_absent_phrase "production ready"
check_absent_phrase "production-ready"
check_absent_phrase "externally validated"
check_absent_phrase "runtime validated"
check_absent_phrase "full runtime validated"
check_absent_phrase "ready for installation"
check_absent_phrase "installation ready"
check_absent_phrase "secure by default"
check_absent_phrase "security complete"
check_absent_phrase "full isolation proven"
check_absent_phrase "full isolation"
check_absent_phrase "developer profile implemented"
check_absent_phrase "profile is implemented"
check_absent_phrase "ready for developer use"
check_absent_phrase "developer ready"
check_absent_phrase "runtime ready"
check_absent_phrase "host mutation impossible"
check_absent_phrase "host mutation prevented"

check_required_text "title present" "# WuciOS Dev Lane Probe 2 - Disposable Developer Profile Design"
check_required_text "authority boundary section present" "## 2. Authority Boundary"
check_required_text "network posture section present" "## 10. Network Posture"
check_required_text "persistence posture section present" "## 11. Persistence Posture"
check_required_text "evidence posture section present" "## 12. Evidence Posture"
check_required_text "disallowed actions section present" "## 14. Disallowed Actions"
check_required_text "final classification present" "WUCIOS_DEV_LANE_PROBE_2_DISPOSABLE_PROFILE_DESIGN_READY"

check_required_text "design-only boundary present" "design-only"
check_required_text "non-validation boundary present" "non-validation and non-release"
check_required_text "no implementation boundary present" "It does not implement the profile"
check_required_text "no package installation boundary present" "install packages"
check_required_text "no package-manager boundary present" "Executing a package manager."
check_required_text "no network enablement boundary present" "enable network access"
check_required_text "no validation evidence mutation boundary present" "modify validation evidence"
check_required_text "no runtime gate reinterpretation boundary present" "Reinterpreting runtime gates."
check_required_text "no Alpine score mutation boundary present" "Changing Alpine score state."
check_required_text "network deferred boundary present" "The proposed network posture is deferred."
check_required_text "package and network deferred boundary present" "Package-manager behavior and network behavior remain deferred."
check_required_text "disposable write surface boundary present" "The proposed write surface is preview-bound and disposable."
check_required_text "source mutation boundary present" "Source inputs are not modified by profile activity."
check_required_text "validation evidence outside write surface boundary present" "Validation evidence remains outside writable profile paths."
check_required_text "development observation boundary present" "Development observations are labeled as development-lane observations."
check_required_text "candidate tooling boundary present" "Candidate categories remain descriptive."

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile contract satisfied'
	exit 0
fi

printf 'FAIL: disposable developer profile contract failed with %d failure(s)\n' "$failures"
exit 1
