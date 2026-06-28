# Nightlight

Nightlight is the hidden adversarial companion to Daylight.

Daylight builds evidence. Nightlight tries to falsify that evidence. The pair
is meant to become a training battery: every Daylight improvement should survive
Nightlight pressure, and every useful Nightlight counterexample should become a
new deterministic regression or proof lane.

Nightlight is defensive only. It does not generate exploits, reproduce
vulnerabilities, scan networks, attempt jailbreaks, or add malware logic. It
attacks claims, not systems:

- invalid parser and envelope states must fail closed
- false production, runtime-containment, and quantum-safety claims must stay
  blocked
- tampered witness, CAGE, QCAGE, Gate, and ledger evidence must be rejected by
  existing proof lanes
- Daylight provider-backed evidence must keep its explicit non-production
  boundary

## Layout

```text
daylight-equation/.nightlight/
  README.md       This note.
  nightlight.sh   One-screen adversarial proof display.
  sparring.sh     Round-based Daylight vs Nightlight match driver.
```

## Quick Display

From the repository root:

```sh
bash daylight-equation/.nightlight/nightlight.sh
```

Useful variants:

```sh
bash daylight-equation/.nightlight/nightlight.sh --quick
bash daylight-equation/.nightlight/nightlight.sh --full
bash daylight-equation/.nightlight/nightlight.sh --quick --no-clear
```

`--quick` is the default display battery. It builds the artifact, prints visible
crypto surfaces, runs provider-backed Daylight evidence, then applies
Nightlight's fail-closed battery.

`--full` adds the broader Daylight/WUCI bridge, 1000-gate discipline tests, and
high-attestation proof. It is slower and intended for a more serious local
demonstration.

Logs are written under:

```text
build/nightlight/
```

## Sparring

Run a one-round sparring match:

```sh
bash daylight-equation/.nightlight/sparring.sh
```

Run repeated training rounds:

```sh
bash daylight-equation/.nightlight/sparring.sh --rounds 3
```

Run the heavy version:

```sh
bash daylight-equation/.nightlight/sparring.sh --full --rounds 1
```

The sparring structure is:

```text
Round 1: Daylight presents constructive evidence.
Round 2: Nightlight applies negative corpus and formal falsification pressure.
Round 3: WUCI Gate/CAGE/QCAGE defend the release-evidence boundary.
Round 4: Claim discipline gates keep unearned claims blocked.
Verdict: Daylight improves only if Nightlight still fails to falsify it.
```

## Extension Rule

When Nightlight grows, add only deterministic local checks:

- committed negative vectors
- tampered local evidence files in tempdirs
- parser mutation replay
- claim-gate rejection tests
- witness/CAGE/QCAGE/Gate policy matrices
- formal-model or SMT negated-obligation checks

Do not add network attack logic, exploit payloads, vulnerability reproduction,
offensive scanning, or runtime containment claims. Nightlight is a battery
against Daylight's proof claims, not an attack framework.
