# Daylight v15 Meridian Downgrade Rules

Claim states:

```text
sovereign > candidate > provisional > rejected
```

The Meridian execution package starts in `candidate` state at the internal ceiling.

Downgrade rules:

```text
If new evidence affects q_i and recomputed q_i < claimed q_i,
then claim_state must downgrade.

If scorecard digest verification fails,
then claim_state = rejected.

If the q-vector does not match the closed obligation set,
then claim_state = rejected.

If the obligation registry digest does not match,
then claim_state = rejected.

If any ledger entry lacks valid witness or transcript,
then claim_state = rejected.

If a self-signed external attestation is present
(external_signer_id absent or equal to the harness identity),
then claim_state = rejected.

If an external falsification entry is appended and unresolved,
then claim_state <= provisional.

Only new ledger evidence plus a successful harness execution may restore
claim_state. Manual override is forbidden.
```

The downgrade machine is monotonic with respect to negative evidence. A claim can
be restored only by new evidence, not by editing a scorecard, a q-value, or the
obligation registry.
