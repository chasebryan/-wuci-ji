#!/bin/sh

set -u

if [ "$#" -ne 1 ]; then
	printf '%s\n' 'FAIL: usage: sh devlanes/wucios-general/tools/validate-disposable-profile-plan-input.sh input.json' >&2
	exit 2
fi

INPUT=$1

if [ ! -f "$INPUT" ]; then
	printf 'FAIL: input file missing: %s\n' "$INPUT" >&2
	exit 1
fi

python3 - "$INPUT" <<'PY'
import json
import re
import sys

path = sys.argv[1]
failures = []

SUPPORTED_SCHEMA = "wucios.disposable_profile.plan_input.v1"
REQUIRED_FIELDS = {
    "schema_version": str,
    "profile_id": str,
    "profile_purpose": str,
    "allowed_scope": list,
    "requested_outputs": list,
    "non_claims_acknowledged": list,
}
REQUIRED_SCOPE = {
    "local_only",
    "dry_run_only",
    "repo_local",
    "non_runtime",
    "non_installing",
    "non_profile_creating",
    "non_host_mutating",
}
ALLOWED_OUTPUTS = {
    "dry_run_plan",
    "dry_run_summary",
    "evidence_index",
}
REQUIRED_NON_CLAIMS = {
    "no_profile_creation",
    "no_package_install",
    "no_runtime_execution",
    "no_host_config_mutation",
    "no_network_enablement",
    "no_external_review_result",
    "no_production_readiness",
    "no_installation_readiness",
    "no_developer_use_approval",
}
DISALLOWED_TRUE_FIELDS = {
    "runtime_behavior_requested",
    "runtime_execution_requested",
    "profile_creation_requested",
    "profile_setup_requested",
    "package_install_requested",
    "package_manager_execution_requested",
    "host_config_mutation_requested",
    "host_mutation_requested",
    "network_enablement_requested",
    "isolation_enforcement_requested",
    "production_readiness_claim",
    "external_validation_claim",
    "runtime_validation_claim",
    "installation_readiness_claim",
    "developer_use_claim",
    "operational_readiness_claim",
}
KNOWN_FIELDS = set(REQUIRED_FIELDS) | DISALLOWED_TRUE_FIELDS
FORBIDDEN_PHRASES = [
    "production" + " ready",
    "externally" + " validated",
    "runtime" + " validated",
    "ready for" + " installation",
    "secure by" + " default",
    "full isolation" + " proven",
    "developer profile" + " implemented",
    "operational" + " readiness",
]


def fail(message):
    failures.append(message)


try:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
except json.JSONDecodeError as exc:
    print(f"FAIL: invalid JSON: {exc}", file=sys.stderr)
    sys.exit(1)
except OSError as exc:
    print(f"FAIL: could not read input: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(data, dict):
    fail("input root must be a JSON object")
else:
    compact = json.dumps(data, sort_keys=True).lower()
    for phrase in FORBIDDEN_PHRASES:
        if phrase in compact:
            fail(f"forbidden claim phrase present: {phrase}")

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in data:
            fail(f"required field missing: {field}")
        elif not isinstance(data[field], expected_type):
            fail(f"required field has wrong type: {field}")

    for field in sorted(set(data) - KNOWN_FIELDS):
        fail(f"unsupported field present: {field}")

    schema = data.get("schema_version")
    if schema is not None and schema != SUPPORTED_SCHEMA:
        fail(f"unsupported schema_version: {schema}")

    profile_id = data.get("profile_id")
    if isinstance(profile_id, str):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", profile_id):
            fail("profile_id must be a short local identifier")

    profile_purpose = data.get("profile_purpose")
    if isinstance(profile_purpose, str):
        lowered = profile_purpose.lower()
        for token in ("install", "runtime execution", "host config", "network enable"):
            if token in lowered:
                fail(f"profile_purpose contains unsupported action wording: {token}")

    allowed_scope = data.get("allowed_scope")
    if isinstance(allowed_scope, list):
        scope_set = set(allowed_scope)
        if any(not isinstance(item, str) for item in allowed_scope):
            fail("allowed_scope must contain only strings")
        if scope_set != REQUIRED_SCOPE:
            missing = sorted(REQUIRED_SCOPE - scope_set)
            extra = sorted(scope_set - REQUIRED_SCOPE)
            if missing:
                fail("allowed_scope missing required boundary: " + ", ".join(missing))
            if extra:
                fail("allowed_scope contains unsupported boundary: " + ", ".join(extra))

    requested_outputs = data.get("requested_outputs")
    if isinstance(requested_outputs, list):
        output_set = set(requested_outputs)
        if not requested_outputs:
            fail("requested_outputs must not be empty")
        if any(not isinstance(item, str) for item in requested_outputs):
            fail("requested_outputs must contain only strings")
        unsupported = sorted(output_set - ALLOWED_OUTPUTS)
        if unsupported:
            fail("requested_outputs contains unsupported output: " + ", ".join(unsupported))

    non_claims = data.get("non_claims_acknowledged")
    if isinstance(non_claims, list):
        non_claim_set = set(non_claims)
        if any(not isinstance(item, str) for item in non_claims):
            fail("non_claims_acknowledged must contain only strings")
        missing = sorted(REQUIRED_NON_CLAIMS - non_claim_set)
        if missing:
            fail("non_claims_acknowledged missing boundary: " + ", ".join(missing))

    for field in sorted(DISALLOWED_TRUE_FIELDS):
        if bool(data.get(field)):
            fail(f"disallowed request or claim field is true: {field}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    print("FAIL: disposable profile plan input rejected")
    sys.exit(1)

print(f"PASS: disposable profile plan input accepted: {path}")
PY
