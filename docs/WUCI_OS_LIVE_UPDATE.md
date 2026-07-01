# Wuci-OS Live Update (no reflash)

Date: 2026-07-01

`wuci-selfupdate` updates a running Wuci-OS system from the repository the machine
already carries — no new ISO, no reinstall. It regenerates the Wuci overlay the
repository *presents* and syncs it onto the live root with per-file digest
measurement and verification.

```sh
wj selfupdate                  # preview: measure what the repo would change
wj selfupdate --apply          # apply changed files atomically, verify each by digest
wj selfupdate --pull           # git pull the source repo first, then measure
wj selfupdate --pull --apply   # git pull, then apply what changed
wj selfupdate --json           # machine-readable receipt
```

(`wuci-selfupdate` is the underlying command; `wj selfupdate` / `wj update` are
the operator shortcuts.)

## What "measureful" means here

The update is evidence-measured end to end, in keeping with the project doctrine:

1. **Presented state.** It rebuilds the overlay from the repo source into an
   isolated staging tree — the exact set of files the repository presents, each
   with a SHA-256/384/512 digest (`overlay_file_records`).
2. **Measure.** Every presented file is compared against the live root by content
   digest and classified `add` / `update` / `unchanged`. Preview writes nothing.
3. **Apply (atomic).** With `--apply`, each changed file is written to a temp file,
   `fsync`'d, `chmod`'d, and `rename`'d into place — never a partial file.
4. **Verify (fail-closed).** Immediately after writing, the file is re-read and its
   digest checked against the presented value. Any mismatch aborts the update.
5. **Receipt.** A JSON receipt (`schema: wuci-os-live-update-v1`) records the mode,
   an overlay fingerprint, per-file changes, and counts including how many files
   were applied and digest-verified.

Re-running an apply is a true no-op: build timestamps (`created_utc` in
`packages.json`) are normalized out of the comparison, and the build-only
`overlay-manifest.json` is not synced, so only genuine content changes ever count.

## Scope (and what it does not touch)

`wuci-selfupdate` updates the **Wuci overlay layer**:

- `/usr/local/bin/*` commands (`wj`, `INSTALL`, `wuci-*`, the Daylight launchers)
- `/usr/share/wuci-os/` including the Daylight v14C+ and v15 Meridian execution
  packages
- `os-release` identity, `/etc/profile.d/wuci-*`, autostart entries, and skel

It **never removes** files and **never touches** the kernel or base packages. Update
those with the distribution tool:

```sh
sudo xbps-install -Su
```

## Source repository

The updater builds from `WUCI_SOURCE` (default `/opt/wuci-os/source/wuci-ji`), the
repository checkout an installed Wuci-OS carries under `/opt`. `wuci-install-target-activate`
copies that source onto installed disks, so a fresh install can update itself. Point
`--source` / `WUCI_SOURCE` elsewhere to update from a different checkout.

Because the source is a normal git checkout, the loop is simply:

```sh
wj selfupdate --pull --apply
```

`git pull --ff-only` runs as the invoking user (who holds the git credentials);
the apply step escalates to root only to write into `/`.

## Direct CLI

The measurement/apply engine is also a `wuci_os.py` subcommand, usable from any
checkout without the baked wrapper:

```sh
python3 tools/wuci_os.py live-update --root / --json          # preview receipt
sudo python3 tools/wuci_os.py live-update --root / --apply     # apply + verify
```
