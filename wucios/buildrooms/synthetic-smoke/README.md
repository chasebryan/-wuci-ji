# Synthetic Smoke Buildroom

This directory defines the Phase 3C-A synthetic smoke buildroom.

The synthetic smoke image is not a substrate, not a WuciOS artifact, and not score eligible. It exists only to test rootless Podman or Buildah mechanics, local generated context handling, evidence capture, and cleanup under explicit L2 authorization.

Default Phase 3C-A execution is L1 backend detection only. L2 synthetic smoke requires `WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1` and a smoke-specific target.

The template uses `FROM scratch`, no `RUN`, no remote `ADD`, no network requirement, and no runtime command. The image must not be run.
