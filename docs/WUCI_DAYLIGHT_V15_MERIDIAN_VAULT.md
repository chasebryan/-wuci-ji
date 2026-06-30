# Daylight v15 Meridian Vault

Date: 2026-06-30

The Meridian Vault is the offline, host-side realization of Daylight v15
Meridian: an evidence-gated, fail-closed encrypt/decrypt store for ordinary
files and secrets on a machine you already run. It turns the
[Meridian Authorized Envelope](WUCI_DAYLIGHT_V15_MERIDIAN_ENVELOPE.md) (MAE) into
a usable vault — `vault init`, `seal`, `open`, `list`, `status`, `autoseal` —
without changing anything about the host's boot path, operating system, or
existing files.

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

On Wuci-OS the same surface is reachable as `wj vault ...`.

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
