# WuciOS General Usage Profile

Purpose: define a conservative, non-production direction for using WuciOS as a
basic system environment.

This profile is planning-only. It does not claim production readiness, external
validation, full runtime validation, or security validation.

## Direction

- Readable shell: provide a predictable interactive shell experience for basic
  inspection and development workflows.
- Predictable filesystem layout: document expected locations for user files,
  local tools, logs, configuration, and temporary work.
- User account model: future work; no complete account-management model is
  claimed.
- Package policy: future work; package installation and repository behavior
  require separate authorization.
- Logging policy: future work; define what should be logged and where logs
  should live.
- Update policy: future work; no update correctness or network update behavior
  is claimed.
- Service policy: future work; no init or service behavior is claimed.
- Network policy: future work; network behavior requires separate authorization.
- Security posture notes: development usability is not security validation, and
  validation gate evidence must not be inflated into production claims.
- Non-production warning: this profile is for conservative development and
  general-usage planning only.
