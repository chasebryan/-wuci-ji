# Daylight v15 Meridian — Offline Host Encryptor

`meridian-install` turns the cloned repository into an offline tool that gives any
machine an **evidence-gated, fail-closed** encryption layer built on Daylight v15
Meridian. It is additive and reversible: the host keeps working exactly as
before, gaining the Meridian authorization logic on top.

Everything runs offline — pure Python standard library, no network, no `pip`.

## What "Meridian logic" adds over a plain encrypted file

A Meridian Authorized Envelope (MAE) binds an **evidence base** (a frozen Daylight
v15 ledger + corpus) and a **policy** (minimum final score, required closed
obligations) to the ciphertext:

```
NoEvidence -> NoScore -> NoSeal
NoProof    -> NoClaim -> NoOpen
ManualScore -> Reject -> NoOpen
```

Opening is fail-closed: the bytes come back only when the host's Meridian evidence
still re-derives a verifying scorecard that satisfies the sealed policy *and*
reproduces the sealed authorization tag — and the caller holds the vault key.
Degrade or tamper with the evidence base and every sealed secret refuses to open.

## Honesty boundary (no overclaim)

- The v15 AEAD (`src/aead.py`) is a real RFC 8439 ChaCha20-Poly1305 / RFC 5869
  HKDF reference, proven against the published KATs, but it is **not constant
  time** and is **not production cryptography**.
- This is **not** full-disk encryption and **not** a production key-management
  product. The vault key is stored locally unless you choose passphrase mode.
- What Meridian adds is the evidence-derived, fail-closed **authorization** layer.
- A literal 1,000,000M policy floor is unsatisfiable from inside the repo by
  design — it requires genuine external attestation — so a vault refuses to be
  created with a floor its evidence cannot meet.

## Install

```sh
git clone <repo> && cd <repo>
./meridian-install                  # default: install CLI + create a vault
./meridian-install --autoseal       # also seal a profile of common secrets
sudo ./meridian-install --luks /dev/sdXN   # gate a LUKS volume by Meridian
./meridian-install --uninstall      # remove CLI/launchers (vault data kept)
```

Modes combine freely. Useful options: `--passphrase` (no key stored on disk),
`--remove-originals` (shred cleartext after sealing), `--min-score N`,
`--prefix DIR`, `--yes`.

The installer copies the package to `~/.local/share/daylight-meridian/pkg`,
installs a `daylight-meridian` launcher and `uninstall-meridian` to
`~/.local/bin`, and runs `doctor` (AEAD RFC-8439 KAT + scorecard verify) to prove
the install before doing anything else.

## Three modes

### 1. Evidence-gated vault

```sh
daylight-meridian vault init                 # create ~/.meridian-vault
daylight-meridian vault seal ~/.ssh/id_ed25519     # original kept by default
daylight-meridian vault list
daylight-meridian vault open id_ed25519.<id> --restore
daylight-meridian vault status               # evidence verifies? authorized?
```

A vault defaults to the internal-ceiling floor (998,900M), which the shipped seed
evidence satisfies, so it opens on a faithful install and fail-closes the instant
the evidence is degraded.

### 2. Auto-seal home profile

```sh
daylight-meridian vault autoseal             # seals a curated secret profile
daylight-meridian vault autoseal --target '~/.config/myapp/token' --remove-original
```

Seals existing files from a profile of common credential locations (`~/.ssh/*`,
`~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`, `~/.kube/config`, …).
Originals are kept unless `--remove-original` is given, so the host stays usable.

### 3. LUKS gated by Meridian

```sh
sudo ./meridian-install --luks /dev/sdb1
# later:
sudo meridian-luks-unlock                    # -> /dev/mapper/meridian-...
```

A real LUKS2 volume is formatted with a random key; that key is then **sealed
into the Meridian vault** and the plaintext is shredded. Unlocking pipes
`daylight-meridian vault open luks-<dev>` into `cryptsetup open --key-file -`, so
the LUKS key only materializes when the host's Daylight v15 evidence verifies and
satisfies the sealed policy. This path is destructive (it formats the device) and
is gated behind an explicit `FORMAT` confirmation and root.

## In Wuci-OS

The live OS bakes the same v15 Meridian package at
`/usr/share/wuci-os/daylight/v15-meridian` and ships `wuci-daylight-meridian`
(`status|verify|score|frontier|gate|doctor|vault …|test`). `wj meridian` and
`wj vault` are the operator shortcuts, and `wuci-daylight-status` reports whether
the Meridian scorecard verifies on the running system.
