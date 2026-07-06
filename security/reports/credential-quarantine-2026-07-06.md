# Wuci-Ji Credential Quarantine Ledger

## Purpose

Record repository-scope cleanup performed for `CAN-R01-003`,
`CAN-R01-010`, and `CAN-R01-011` without exposing credential values.

## Quarantined Paths

- `.wrangler/`
  - handling: moved out of repository scope
  - quarantine path: `/tmp/wuci-ji-security-quarantine-20260706/wrangler`
  - reason: ignored Wrangler account/cache/config material was inside the scan scope

- `external-ssd-export-20260705/`
  - handling: moved out of repository scope
  - quarantine path: `/home/wj/wuci-ji-security-quarantine-20260706/external-ssd-export-20260705`
  - reason: local backup/export tree contained app configuration, session stores, and credential-named files

## Notes

- Credential values were not printed, copied into this report, or tested for liveness.
- This repository cleanup does not rotate credentials. Account owners still need to rotate or revoke any potentially exposed real credentials out of band.
- Quarantine directories were set to mode `0700`.
