# Quorum And Blocker Boundary

The generated claim ledger records the v20.3 verifier-family quorum as
`PASS_EVIDENCE_MATCH`.

The boundary preserved by the run:

- exactly `3-of-3` verifier families are required for that quorum surface
- more or fewer verifier families do not close the quorum
- fixture vectors remain not claim-usable
- the quorum closes only the verifier-vector blocker
- the quorum does not raise the score
- the quorum does not declare Singularity

The v20 capsule keeps declaration blocked and keeps
`singularity_possible_without_external_validation` false.
