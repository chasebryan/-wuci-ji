# Daylight v18 Binaric Bastion

Daylight v18 Binaric Bastion is the binary-measurement substrate for Daylight
Horizon. It does not encrypt yet and it does not claim a clean host. It measures
binary state, binds it to policy and Event Horizon evidence, and refuses
unverified tamper transitions.

```text
No verified binary state -> no key.
No user-authorized tamper -> no transition.
No coherent evidence graph -> no plaintext.
```

v18.0 implements the Binaric Vector Format:

```sh
python3 -m src.cli measure --subject <path> --out <vector.json>
python3 -m src.cli verify-vector <vector.json>
python3 -m src.cli inspect-vector <vector.json>
```

The vector records:

- subject path, size, SHA-256, and SHA3-512
- executable metadata with `host_trust_level = H0-untrusted-host`
- a `whole_file` section digest
- Event Horizon scorecard digest
- policy digest
- optional previous-vector and user-verification digests
- canonical `vector_digest`

v18.1 implements the Binaric Transition Ledger:

```sh
python3 -m src.cli transition-propose --before before.json --after after.json --reason "user-approved update" --out transition.unsigned.json
python3 -m src.cli transition-sign --transition transition.unsigned.json --passphrase-env DAYLIGHT_BASTION_PASSPHRASE --out transition.signed.json
python3 -m src.cli transition-verify --before before.json --after after.json --transition transition.signed.json
python3 -m src.cli transition-ledger-init --out transition-ledger.jsonl
python3 -m src.cli transition-ledger-append --ledger transition-ledger.jsonl --transition transition.signed.json
python3 -m src.cli transition-ledger-verify --ledger transition-ledger.jsonl
python3 -m src.cli tamper-check --before before.json --after after.json --transition transition.signed.json --ledger transition-ledger.jsonl
```

A changed binary, policy, or Event Horizon binding is not accepted because a
marker field exists. It is accepted only when the local user ceremony signs the
exact before-to-after transition and that transition is present in the
append-only transition ledger.

```text
No user proof -> no transition.
No ledger inclusion -> no transition.
Chain break -> reject.
Contradiction -> reject.
```

## Boundaries

- No floats.
- No network.
- No symlink subjects.
- No path escape.
- No runtime containment claim.
- No production cryptography claim.
- No external certification claim.
- No whole-system post-quantum safety claim.
- No production identity claim.
- No hardware-backed attestation claim.
- No host cleanliness claim.

This layer is measurement-first. Later v18 layers can attach vault, PQ
authorization, tamper logs, and system capsule behavior to the vector graph.
