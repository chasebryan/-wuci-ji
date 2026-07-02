# Aperture Bastion Pass Report — Wuci-Ji v2

- Pass name: Wuci-Ji v2 — Aperture Bastion
- Date: 2026-07-01
- Repo commit before changes: `fad0cdcfc63d724e957071e09a6dd679a50af583` (branch `main`, clean)
- Repo commit after changes: not committed by this pass; all changes are in
  the working tree on top of `fad0cdc`. Nothing existing under
  `daylight/v15*`–`v18*` was overwritten.

## Files added

```text
daylight/v19-aperture-bastion/README.md
daylight/v19-aperture-bastion/examples/example-subject.bin
daylight/v19-aperture-bastion/examples/expected-capsule.v19.json
daylight/v19-aperture-bastion/schema/aperture-review-capsule.v19.schema.json
daylight/v19-aperture-bastion/specs/daylight-v19-aperture-review-capsule.md
daylight/v19-aperture-bastion/src/__init__.py
daylight/v19-aperture-bastion/src/canonical_json.py
daylight/v19-aperture-bastion/src/pathsafe.py
daylight/v19-aperture-bastion/src/claims.py
daylight/v19-aperture-bastion/src/profile.py
daylight/v19-aperture-bastion/src/evidence_refs.py
daylight/v19-aperture-bastion/src/capsule.py
daylight/v19-aperture-bastion/src/public_artifact.py
daylight/v19-aperture-bastion/src/firewall.py
daylight/v19-aperture-bastion/src/cli.py
daylight/v19-aperture-bastion/tests/__init__.py
daylight/v19-aperture-bastion/tests/test_canonical_json.py
daylight/v19-aperture-bastion/tests/test_claims.py
daylight/v19-aperture-bastion/tests/test_capsule.py
daylight/v19-aperture-bastion/tests/test_evidence_refs.py
daylight/v19-aperture-bastion/tests/test_public_artifact.py
daylight/v19-aperture-bastion/tests/test_firewall.py
daylight/v19-aperture-bastion/tests/test_cli.py
.github/workflows/daylight-v19-aperture-bastion.yml
docs/WUCI_JI_V2_APERTURE_BASTION.md
docs/APERTURE_BASTION_SECURITY_BOUNDARY.md
docs/APERTURE_BASTION_PASS_REPORT.md
```

## Files modified

```text
Makefile              (v19 variables, .PHONY line, seven targets, three aliases; nothing removed)
README.md             (one new section between v18 and System Shape; existing sections preserved)
docs/BUILD_TARGETS.md (new v19 section after the v18 section)
docs/CI_SCOPE.md      (one bullet for the new CI lane)
```

Everything is Python 3 standard library. No third-party dependencies were
added. No new cryptographic primitives were implemented; hashing uses
`hashlib` SHA-256 / SHA3-512 only.

## Commands run (this environment, Python 3.12.13, Linux x86_64)

Baseline before changes, at `fad0cdc`:

| Command | Result |
| --- | --- |
| `make daylight-v18-bastion-test` | PASS (45 tests) |
| `make daylight-v18-bastion-transition-test` | PASS (24 tests) |
| `make daylight-meridian-test` | PASS (106 tests) |
| `make daylight-meridian-public-artifact-test` | PASS |
| `make daylight-public-artifact-firewall` | PASS |
| `make site-validate` | PASS (`999999687 AM+` status unchanged) |

After changes, with the v19 layer in the working tree:

| Command | Result |
| --- | --- |
| `make daylight-v19-aperture-bastion-test` | PASS (87 tests, 0 failures, 0 skips) |
| `make daylight-v19-aperture-bastion-ci` (also via alias `aperture-bastion-ci`) | PASS |
| `make daylight-v19-aperture-bastion-doctor` | PASS (10 checks) |
| `make daylight-v19-aperture-bastion-verify` | PASS (committed fixture capsule) |
| `make daylight-v19-aperture-bastion-capsule-demo` | PASS (v18 chain + ledger + v15 + v17 + policy refs, `--require-evidence`) |
| `make daylight-v19-aperture-bastion-public-artifact` | PASS (8 files) |
| `make daylight-v19-aperture-bastion-firewall` | PASS (report written outside root) |
| `make daylight-v18-bastion-test` | PASS (unchanged) |
| `make daylight-v18-bastion-transition-test` | PASS (unchanged) |
| `make daylight-meridian-test` | PASS (unchanged) |
| `make daylight-meridian-public-artifact-test` | PASS (unchanged) |
| `make daylight-public-artifact-firewall` | PASS — now also lints `daylight-v19-aperture-bastion.yml` |
| `make site-validate` | PASS (unchanged) |

## Tests passed / failed

- v19 Aperture Bastion suite: 87 passed, 0 failed, 0 skipped in this
  environment (the symlink/hardlink tests self-skip only on filesystems
  without those features; they ran here).
- No previously existing test was modified, skipped, or broken.
- Nothing in this report is asserted beyond what the commands above printed.

## Known limitations

1. The firewall is a pinned deny-list plus structural rules (symlinks,
   hardlinks, hidden components, unexpected files, sums drift). A secret in
   a novel format that matches no rule passes. It reduces accident risk; it
   does not make leaks impossible.
2. External attestation handling is a negative gate only: it refuses
   self-signed closure behind perfect Meridian scores. It verifies no
   signatures; signed external evidence remains Solstice's lane.
3. Meridian scorecard checks are fail-closed consistency gates (manual-edit
   markers, contribution-sum equality, perfect-score external closure), not
   a re-implementation of the Meridian verifier. Full re-derivation stays
   with `make daylight-meridian-verify`.
4. `repo_commit`/`repo_dirty_state` come from a `git` subprocess (no shell);
   outside git they record `unknown`. Fixture capsules record `fixture` so
   the committed example stays byte-stable.
5. Hardlink detection depends on `st_nlink`; on filesystems that do not
   report link counts the hardlink rule cannot fire.
6. Byte-reproducibility was verified in this environment (Linux, Python
   3.12); no cross-platform determinism claim is made.
7. The GitHub Actions workflow passes the repo's `check-workflow` firewall
   lane locally but has not yet executed on GitHub's runners as of this
   pass.
8. The doctor pins the firewall profile digest; intentionally changing the
   rules requires updating that pin, which is the designed friction.

## Claim boundary

Aperture Bastion binds bytes to digests and refuses to publish private
material. It is not production cryptography, not runtime containment or
sandboxing, not host cleanliness proof, not FIPS validated, not government
validated, not externally certified, not whole-system post-quantum safe,
not an independent audit, and not a perfect Daylight score claim from
repository-owned evidence. The conservative Daylight scores are unchanged:
Meridian `998,900M / 1,000,000M` internal ceiling, Event Horizon
`999,999,687 AM+` undeclared. Every capsule carries these non-claims and
validation rejects any capsule that drops them.

## Next recommended work

1. Run the new workflow on GitHub Actions and confirm the uploaded artifact
   matches the local firewalled directory byte-for-byte.
2. Feed capsule digests into `tools/site_daylight_status.py` so the public
   site can reference the current review capsule without new claims.
3. Add an Aperture step to `docs/RELEASE_PROCESS.md` so release bundles ship
   with a capsule and firewall report.
4. Add capsule chaining (`previous_capsule_digest`) for an append-only
   review history, mirroring the v18 vector chain.
5. Consider an independent Rust capsule-digest verifier, following the v17
   triangulation pattern, to move capsule verification toward
   multi-implementation agreement.
