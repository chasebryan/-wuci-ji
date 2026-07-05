# Evidence Import Policy

This policy controls how the WuciOS Development Lane may reference prior
validation evidence. Evidence may be cited as input context only. It must not be
modified, reclassified, or expanded by this lane.

## Allowed References

- Gate 2 rootless file sanity
- Gate 3 runtime crossing policy
- Gate 4 limited runtime smoke
- Gate 4A closeout
- Gate 5 read-only boundary probe
- Alpine v3.24.1 aports source snapshot

## Required Restrictions

Gate 4 proves only limited runtime smoke under the selected rootless Podman
method.

Gate 5 proves only tested read-only boundary behavior under the selected
rootless Podman method.

Neither Gate 4 nor Gate 5 proves bootability, init correctness,
package-manager correctness, service behavior, network behavior, long-running
stability, external validation, or production readiness.

The development lane must never cite these gates as proof of full OS readiness.

The Alpine v3.24.1 aports source snapshot may be referenced for planning and
documentation context. It must not be treated as authorization for package
installation, network access, production trust, or external validation.
