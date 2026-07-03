# DaylightSSV v1

DaylightSSV v1 is the Daylight System Security Validator v1. It is a
deterministic, local-only score validator for evidence-derived system security
posture.

It is not a security certificate.

## Purpose

DaylightSSV v1 computes an evidence-derived local system posture score. It
explains score deductions with reasons and gives an English warning level.

The score is generated from local runtime and repository evidence that the
validator can safely observe without exploitation, credential access, remote
probing, remediation, upload, or telemetry.

## Non-purpose

DaylightSSV v1 is not a penetration-testing tool. It is not an exploitation
tool. It is not a vulnerability scanner that attacks services. It is not a
certification system. It is not a production security guarantee.

Forbidden wording:

```text
DaylightSSV v1 certifies the system is secure.
DaylightSSV v1 proves the system is secure.
DaylightSSV v1 replaces external audit.
DaylightSSV v1 is a government-approved score.
DaylightSSV v1 proves production readiness.
DaylightSSV v1 proves post-quantum security.
```

Allowed wording:

```text
DaylightSSV v1 computes an evidence-derived local system posture score.
DaylightSSV v1 explains score deductions with reasons.
DaylightSSV v1 gives an English warning level.
```

## Safety Rules

DaylightSSV v1 is local host only and read-only by default.

```text
local host only
read-only collection only
no exploitation
no password cracking
no credential dumping
no private key printing
no token printing
no destructive remediation
no external network calls by default
no scanning other machines
no privilege escalation attempts
no silent upload/telemetry
no score without evidence
```

Unavailable access becomes `unknown`, and unknown relevant checks earn no
credit. The validator must not fake evidence.

## Score Formula

The final public score is a one-decimal score on this bounded scale:

```text
0.0 / 100.0 through 100.0 / 100.0
```

No hundredths are valid public output.

Top-level domain weights are fixed:

```text
identity_privilege_control: 12.0
update_install_integrity: 12.0
cryptography_secrets_handling: 11.0
network_exposure: 12.0
file_process_runtime_integrity: 11.0
configuration_hardening: 10.0
logging_auditability: 8.0
backup_recovery_posture: 7.0
dependency_supply_chain_integrity: 9.0
daylight_evidence_reproducibility: 8.0
```

The total is mechanically validated:

```text
12 + 12 + 11 + 12 + 11 + 10 + 8 + 7 + 9 + 8 = 100
```

Severity weights:

```text
critical = 8
high = 5
medium = 3
low = 1
```

Result values:

```text
pass = 1.0
partial = 0.5
fail = 0.0
unknown = 0.0
```

Evidence quality values:

```text
strong = 1.0
medium = 0.75
weak = 0.50
missing = 0.0
```

Formula:

```text
check_value = result_value * evidence_quality

domain_score =
  sum(severity_weight * check_value)
  /
  sum(severity_weight)

domain_points = domain_weight * domain_score

raw_score = sum(domain_points)

final_score = raw_score rounded HALF_UP to one decimal
```

The implementation uses Python `Decimal` and `ROUND_HALF_UP`, not binary float
math.

Illustrative rounding examples only:

```text
74.65 -> 74.7
74.64 -> 74.6
```

## Reasons

Every score deduction must have a reason. The loss formula is:

```text
check_loss =
  domain_weight * severity_weight * (1 - check_value)
  /
  sum(domain severity weights)
```

Reasons are sorted by loss descending, then domain id, then check id.

## Warning Levels

Base warning levels:

```text
93.0-100.0 = Low warning - strong evidence posture
85.0-92.9 = Guarded - mostly controlled, review remaining issues
75.0-84.9 = Elevated - notable hardening gaps
65.0-74.9 = High - significant security gaps
50.0-64.9 = Severe - major exposure or missing evidence
0.0-49.9 = Critical - immediate review required
```

Override rules:

```text
any critical failed check -> at least Critical
exposed secret found -> at least Critical
remote unauthenticated admin path found -> at least Critical
any high-severity failed check -> at least High
evidence coverage below 80% -> at least Elevated
```

The numeric score and warning are related, but the warning may become more
severe when a single high-impact condition is observed.

## Report Schema

The report schema id is:

```text
daylight.ssv.v1.report
```

The report includes:

```text
schema
tool
version
result
score
warning
summary
domains
findings
reasons
non_claim_boundary
```

The validator rejects reports with an out-of-range score, more than one decimal
place in the final score, missing reasons for a non-perfect score, missing
warning level, invalid domain weights, or check values outside the closed
interval from zero to one.

## How To Run

```sh
PYTHONPATH=daylight/ssv/v1 python3 -m daylight_ssv audit \
  --out build/daylight/ssv-v1/daylight-ssv.report.json
```

Other supported commands:

```sh
python3 -m daylight_ssv audit --json
python3 -m daylight_ssv audit --pretty
python3 -m daylight_ssv explain <finding-id>
python3 -m daylight_ssv check-model
python3 -m daylight_ssv list-domains
python3 -m daylight_ssv validate-report <report.json>
```

Make targets:

```sh
make daylight-ssv
make daylight-ssv-test
make daylight-ssv-report
make daylight-ssv-ci
```

Exit codes:

```text
0 = completed audit and produced valid report
1 = completed audit but warning level is Severe or Critical
2 = tool/config/internal error
```

Exit code `1` does not mean the tool failed. It means the observed posture
warning is severe enough for a caller to fail a CI posture gate.

## Interpretation

Read the score with the reasons. A high score must not hide a critical failure,
and a low score may reflect missing evidence rather than confirmed compromise.
DaylightSSV v1 reports only what it can safely verify from available runtime and
repository evidence.

## Limitations

DaylightSSV v1 does not perform exploitation, password cracking, packet sending,
remote probing, privileged inventory, or remediation. It summarizes process and
account evidence without usernames, command lines, hostnames, secrets, tokens,
private keys, or absolute local paths.

The SSV report is evidence-derived and local. It is not external audit evidence.
It is not a post-quantum verifier. It is not runtime containment.

## Non-claim Boundary

Required caveat:

```text
DaylightSSV v1 produces an evidence-derived local system security posture score. It does not certify security, production readiness, audit status, post-quantum security, agency endorsement, or mathematical finality. It reports what the validator could safely verify from available runtime and repository evidence.
```

The report boundary flags are all false:

```text
certifies_security
certifies_production_readiness
certifies_audit_status
certifies_post_quantum_security
implies_agency_endorsement
proves_mathematical_finality
```

## Core Principles

```text
NoEvidence -> NoCredit
UnknownRelevantCheck -> CountAsZero
NotApplicable + NoProof -> Unknown
CriticalFailure -> WarningOverride
ScoreWithoutReasons -> Reject
ScoreOutsideRange -> Reject
MoreThanOneDecimal -> Reject
ManualScore -> Reject
```

## DaylightNPT Boundary

The examples in `daylight/ssv/v1/examples/` are fixtures for validating the
SSV model. They are not public claims about a real host. The illustrative math
examples in this document are explicitly non-claim examples for the scoring
model and rounding behavior.

