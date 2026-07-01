# Daylight v15 Meridian Vault

Date: 2026-06-30

The Meridian Vault is the offline, host-side realization of Daylight v15
Meridian: an evidence-gated, fail-closed encrypt/decrypt store for ordinary
files and secrets on a machine you already run. It turns the
[Meridian Authorized Envelope](WUCI_DAYLIGHT_V15_MERIDIAN_ENVELOPE.md) (MAE) into
a usable vault — `vault init`, `seal`, `open`, `list`, `status`, `autoseal` —
without changing anything about the host's boot path, operating system, or
existing files.

This page is canonical for the vault: the primitive, its CLI, the `meridian-install`
offline installer (including the LUKS mode), and its use inside Wuci-OS.

Design and scores: [WUCI_DAYLIGHT_V15_MERIDIAN.md](WUCI_DAYLIGHT_V15_MERIDIAN.md).
Cipher and envelope: [WUCI_DAYLIGHT_V15_MERIDIAN_ENVELOPE.md](WUCI_DAYLIGHT_V15_MERIDIAN_ENVELOPE.md).
Artifact/CLI: [DAYLIGHT_V15_MERIDIAN_SOFTWARE_ARTIFACT.md](DAYLIGHT_V15_MERIDIAN_SOFTWARE_ARTIFACT.md).

## The law, enforced per file

```text
NoEvidence(x)  -> NoScore(x)  -> NoSeal(x)
NoProof(x)     -> NoClaim(x)  -> NoOpen(x)
ManualScore(x) -> Reject(x)   -> NoOpen(x)
```

A vault binds an **evidence base** (a frozen Daylight v15 ledger + corpus) and a
**policy** (minimum final score, required closed obligations). Sealing a file
succeeds only when that evidence re-derives a verifying scorecard satisfying the
policy. Opening is fail-closed: the bytes come back only when the host's Meridian
evidence still verifies and still satisfies the sealed policy, and the caller
holds the vault key. Degrade or tamper with the evidence and every entry refuses
to open.

## What it is

A vault is a self-contained directory (default `~/.meridian-vault`, override with
`--vault` or `MERIDIAN_VAULT`):

```text
vault.json            policy + key mode + pinned obligations digest
vault.key             32-byte AEAD caller key (keyfile mode, 0600), or
                      absent in passphrase mode (key derived via PBKDF2)
evidence/ledger.jsonl frozen Daylight v15 evidence ledger
evidence/corpus.jsonl frozen negative-evidence corpus
store/<name>.mae      one Meridian Authorized Envelope per sealed entry
index.json            entry registry (name, sizes, sha256, original path)
```

The vault is **never born unopenable**: `init` refuses unless the bound evidence
already verifies and meets the requested floor. The default floor is the honest
internal ceiling (998,900M); a 1,000,000M floor would require external
attestation the repo cannot self-issue, by design.

## Use

```sh
# Bind a vault to this host's shipped seed evidence (keyfile mode).
daylight-meridian vault init

# Or protect the key with a passphrase instead of a keyfile.
daylight-meridian vault init --passphrase-env MERIDIAN_PASS

# Show authorization status (does the evidence still verify and clear the floor?).
daylight-meridian vault status

# Seal a file. The original is KEPT by default; --remove-original wipes it.
daylight-meridian vault seal ~/.ssh/id_ed25519

# List entries, then open one back to a path or stdout.
daylight-meridian vault list
daylight-meridian vault open id_ed25519.<id> --out /tmp/key
daylight-meridian vault open id_ed25519.<id> --restore   # back to recorded path

# Seal a profile of common credential files in one pass (non-destructive).
daylight-meridian vault autoseal
```

On Wuci-OS the same surface is reachable as `wj vault ...` (see below).

## Install onto any host (`meridian-install`)

`meridian-install` (repo root) turns the cloned repository into an offline tool
that gives any machine this evidence-gated encryption layer. It runs entirely
offline — pure Python standard library, no network, no `pip`.

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
installs a `daylight-meridian` launcher and `uninstall-meridian` into
`~/.local/bin`, and runs `doctor` (AEAD RFC-8439 KAT + scorecard verify) to prove
the install before doing anything else.

### LUKS gated by Meridian

```sh
sudo ./meridian-install --luks /dev/sdb1
# later:
sudo meridian-luks-unlock                  # -> /dev/mapper/meridian-...
```

A real LUKS2 volume is formatted with a random key; that key is then **sealed into
the Meridian vault** and the plaintext is shredded. Unlocking pipes
`daylight-meridian vault open luks-<dev>` into `cryptsetup open --key-file -`, so
the LUKS key only materializes when the host's Daylight v15 evidence verifies and
satisfies the sealed policy. This path is destructive (it formats the device) and
is gated behind root and an explicit `FORMAT` confirmation.

## In Wuci-OS

The live OS bakes the same v15 Meridian package at
`/usr/share/wuci-os/daylight/v15-meridian` and ships `wuci-daylight-meridian`
(`status|verify|score|frontier|gate|doctor|vault …|test`). `wj meridian` and
`wj vault` are the operator shortcuts, and `wuci-daylight-status` reports whether
the Meridian scorecard verifies on the running system.

## Non-destructive by default

A vault is additive and reversible. Originals are kept unless you pass
`--remove-original` (which overwrites the cleartext before unlinking). Nothing
about the OS, boot path, or unrelated files is touched. Removing the vault
directory removes the vault; the host keeps working exactly as before.

## Boundary (no overclaim)

- The AEAD (`src/aead.py`) is a **research reference**: real, RFC-vector-checked
  ChaCha20-Poly1305 + HKDF-SHA256, but **not constant-time** and not
  side-channel hardened.
- This is **not full-disk encryption** and not a kernel keyring. The vault key
  lives locally unless you choose passphrase mode.
- What Meridian adds over a plain encrypted file is the evidence-derived,
  fail-closed **authorization** layer: data that refuses to open on a host whose
  Daylight v15 evidence does not verify.

Do not protect production secrets with the reference AEAD. The vault demonstrates
authorization gating; it is not a hardened secrets manager.

## Build / test lanes

```sh
make daylight-meridian-vault-test    # unit tests (src/vault.py)
make daylight-meridian-vault-demo    # init -> seal -> open roundtrip in build/
```

The vault roundtrip is also exercised by `make daylight-meridian-smoke` and the
composed `make daylight-meridian-ci`.
