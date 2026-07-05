# Workspace Hub

Updated: 2026-07-04

This file makes Wuci-Ji the central coordination point for the accessible laptop
workspace and Codex/ChatGPT work artifacts.

## Canonical Anchor

| Role | Path |
| --- | --- |
| Main project | `/Users/chasebryan/Documents/-wuci-ji` |
| GitHub remote | `https://github.com/chasebryan/-wuci-ji` |
| Workspace inventory | [WORKSPACE_INVENTORY_2026-07-04.md](WORKSPACE_INVENTORY_2026-07-04.md) |

When a new work thread starts without a narrower repo instruction, start here:

```sh
cd /Users/chasebryan/Documents/-wuci-ji
git fetch origin main
git status --short --branch
```

If the worktree is dirty, understand those changes first. Do not normalize,
stash, move, or revert unrelated work without explicit direction.

## Operating Rule

Wuci-Ji is the focal point, not a dumping ground. Use this repo to track the
state of the user's work, link out to sibling projects, and hold machine-level
handoffs. Keep active repos in their canonical project roots unless a separate
relocation pass is approved.

## Codex And ChatGPT Work

Dated Codex folders are work logs and artifact stores. They are not canonical
homes for durable projects.

Use this promotion rule:

| Artifact type | Destination |
| --- | --- |
| A real project or tool | `/Users/chasebryan/Documents/<project-name>` |
| Wuci-Ji continuation, proof, or release work | this repository |
| Temporary analysis, scripts, and drafts | the current Codex `work/` folder |
| User-facing deliverables from a Codex thread | that thread's `outputs/` folder |
| Cross-project status, laptop organization, and future handoff | this file plus a dated inventory snapshot |

If a dated Codex session contains useful work, promote the surviving project or
link the artifact from here. Do not leave a project buried in a dated session
path as its only discoverable home.

## Project Lanes

| Lane | Canonical path | Notes |
| --- | --- | --- |
| Wuci-Ji / Daylight | `/Users/chasebryan/Documents/-wuci-ji` | Main project and workspace hub. |
| Latticra | `/Users/chasebryan/Documents/Latticra` | Large active repo; keep separate from Wuci-Ji. |
| Kaiju | `/Users/chasebryan/Documents/kaiju` | Active Documents root; Desktop clone is a review candidate. |
| Pharos | `/Users/chasebryan/Documents/pharos` | Active dirty repo; preserve in-flight work. |
| Warlock-Index | `/Users/chasebryan/Documents/warlock-index` | Canonical current root; `warlock-index.old` is a review candidate with dirty content. |
| Rainbow / Fyr | `/Users/chasebryan/Documents/fyr` | Active compiler/toolchain root. |
| newc | `/Users/chasebryan/Documents/newc` | Uncommitted project scaffold; review before any relocation. |
| l3 | `/Users/chasebryan/Documents/l3` | High-assurance Ada substrate. |
| pmgs | `/Users/chasebryan/Documents/pmgs` | Contains large capture artifacts; archive/offload needs project-aware review. |
| Codex sessions | `/Users/chasebryan/Documents/Codex` | Historical work logs; promote useful artifacts deliberately. |

## Organization Protocol

1. Refresh inventory before cleanup.
2. Keep active Git repos where they are unless relocation is explicitly approved.
3. Use exact hash checks before declaring any file a duplicate.
4. Prefer existing archive buckets such as `Documents/Organized Files`,
   `Documents/Code Drops`, `Documents/PDFs`, and existing archive destinations.
5. Treat `Downloads` and `Desktop` as safe-clutter queues, but keep project
   folders intact until reviewed.
6. Never delete user data as part of a broad organization pass. Archive or
   mark for review first.

## Current Review Queues

| Queue | Current items |
| --- | --- |
| Duplicate or legacy project roots | `/Users/chasebryan/-wuci-ji`, `/Users/chasebryan/Desktop/kaiju`, `/Users/chasebryan/Desktop/Latticra`, `/Users/chasebryan/l2`, `/Users/chasebryan/pharos`, `/Users/chasebryan/Latticra`, `/Users/chasebryan/latticra-library/*`, `/Users/chasebryan/projects_c++` |
| Dirty active repos | `/Users/chasebryan/Documents/newc`, `/Users/chasebryan/Documents/pharos`, `/Users/chasebryan/Documents/Projects/minaswan`, `/Users/chasebryan/Documents/warlock-index.old`, `/Users/chasebryan/Latticra`, `/Users/chasebryan/latticra-library/Latticra` |
| Large-file review | `/Users/chasebryan/Downloads/trisquel_12.0_amd64.iso`, `/Users/chasebryan/Documents/pmgs/meteor.iq`, `/Users/chasebryan/Documents/pmgs/captures/meteor-m2-4.iq`, `/Users/chasebryan/Documents/Latticra/assets/piper-voices/en_US-lessac-medium.onnx` |
| Codex promotion | Review `/Users/chasebryan/Documents/Codex/*/*/outputs` and surviving project folders. |

## Next Safe Pass

The next cleanup pass should be reversible:

1. Hash-match duplicate Wuci-Ji, Kaiju, Latticra, Pharos, and l2 roots against
   their Documents counterparts.
2. For exact duplicates, archive the non-canonical clone into an existing
   archive bucket or mark it for deletion after explicit approval.
3. For non-identical repos, write a short reconciliation note before moving
   anything.
4. Promote Codex artifacts that are still useful into their project roots, then
   record the promotion here.
5. Re-run the inventory and replace the dated snapshot with a newer one.
