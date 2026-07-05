# Phase 3C-D Yocto Layer/Recipe Preparation

This directory contains policy-only preparation records for WuciOS v2.4 Euclid Trial Phase 3C-D.

In scope:

- `yocto_layer_recipe`

Phase 3C-D is a Yocto layer/recipe preparation layer. It does not run BitBake, initialize a Yocto build environment, clone or download layers, build Yocto, generate rootfs or image outputs, select a substrate, rank candidates, or score an artifact.

Generated L2 scaffolds, when explicitly authorized, are written only under ignored `build/wucios/` paths and are marked `NOT_EXECUTABLE`, `NOT_ARTIFACT`, `NOT_SCORE_ELIGIBLE`, `YOCTO_BUILD_FORBIDDEN`, `BITBAKE_FORBIDDEN`, and `L3_AUTHORIZATION_REQUIRED`.
