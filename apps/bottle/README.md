# Daylight Bottle

Daylight Bottle is a browser-first encrypted message-in-a-bottle application
for `bottle.nosuchmachine.net`. A sender resolves a public recipient from the
static keyring and encrypts locally with `age-encryption`. The server stores
only ciphertext and public metadata. A recipient fetches candidate ciphertexts
and decrypts locally with a private identity that is never uploaded.

Daylight evidence describes what the server accepted; it does not provide
encryption secrecy or runtime containment.

## Architecture

```txt
public/keyring.json -> browser sender -> local age encryption
                                      -> POST ciphertext + public metadata
                                      -> Worker -> BOTTLES_KV

BOTTLES_KV -> Worker -> candidate ciphertexts -> browser recipient
                                                -> local age decryption
```

The production deployment is one Cloudflare Worker. Static assets, the keyring,
and `/api/*` share the same origin. No analytics, remote fonts, CDN scripts, or
third-party runtime calls are allowed. The Worker rejects drops whose keyname
and fingerprint do not match an active record in the bundled static keyring.
Workers KV is eventually consistent; an accepted bottle may take time to become
visible from another location, and the UI tells recipients to retry safely.
Candidate reads are capped at 8 KV keys per API request and fetched with one
bounded bulk read. When more candidates remain, the response carries an opaque
cursor in `X-Daylight-Next-Cursor`, and the UI requires the recipient to
re-import the private identity before fetching the next page. New drops are
refused once a recipient listing reaches 500 indexed bottles; this admission
ceiling is not transactional under KV's eventual consistency. The page and
response-byte limits remain authoritative if concurrent writes overshoot it.
The production Worker also applies a native Cloudflare burst limit of 12 drops
per minute for each hashed network-and-recipient pair before any KV write. The
same pair is limited to 60 inbox lookups per minute. Both limits are local to a
Cloudflare location and intentionally permissive, so they are abuse resistance
rather than exact global quotas.

## Toolchain

- Node.js: `22.23.1` for CI; supported versions are declared in `package.json`.
- npm: `11.8.0`.
- TypeScript: strict client, Worker, and test configurations.
- Tests: Vitest.
- Lint: ESLint with type-aware `typescript-eslint` strict and stylistic rules.
- Deployment: Wrangler `4.110.0`.

Install from the repository root:

```sh
cd apps/bottle
npm ci
```

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the Vite client and local in-memory API on `127.0.0.1`. |
| `npm run preview` | Preview built static assets; it does not provide the API. |
| `npm run lint` | Run strict, type-aware ESLint with zero warnings allowed. |
| `npm run typecheck` | Check client, Worker, tests, and tool configuration. |
| `npm test` | Run the deterministic unit and boundary tests once. |
| `npm run build` | Typecheck production code, build `dist`, and generate the versioned release manifest. |
| `npm run verify:bundle` | Verify required files, keyring fingerprints, asset/input hashes, size budgets, same-origin runtime URLs, CSP-compatible HTML, and headers. |
| `npm run check` | Run the full non-deploying local/CI release gate. |
| `npm run deploy:dry-run` | Rebuild, verify the bundle, and bundle Worker/assets without deploying. |
| `npm run deploy` | Run the complete gate, require the pinned production config and exact fetched `origin/main`, then perform a live Wrangler deployment. |

The Vite development API uses an in-memory store and resets when the process
stops. It is for local validation only and is not a claim of OS sandboxing or
durable storage.

## Project layout

- `src/crypto/`: the small adapter around the installed `age-encryption` API.
- `src/domain/`: versioned types and runtime validation.
- `src/ui/`: plain TypeScript views and DOM helpers.
- `worker/`: ciphertext-only HTTP API and KV storage adapter.
- `public/keyring.json`: manually curated public recipient directory.
- `public/_headers`: production static security headers.
- `scripts/verify-bundle.mjs`: post-build same-origin and CSP gate.
- `scripts/generate-release-manifest.mjs`: hashes the explicit Worker source
  closure and static artifacts, records the source commit, verifies source and
  built keyring equality, and applies the runtime bundle budget.
- `wrangler.toml`: Worker, static assets, custom domain, and KV binding.
- `DEPLOYMENT.md`: approved production setup, smoke, and rollback runbook.

## Keyring workflow

The MVP deliberately has no public key registration endpoint. The Create
Identity view generates a public `KeyRecord` that the site owner reviews and
manually adds to `public/keyring.json`. Never add a private identity,
passphrase, decrypted message, or other secret to the keyring or repository.

After every keyring change:

```sh
npm run check
```

Then follow `DEPLOYMENT.md`. A sender must verify the displayed recipient
fingerprint through an independent trusted channel before dropping a bottle.
An empty keyring remains deployable as a safe fail-closed state: the Worker
rejects all drops until an operator reviews and adds an active public record.
Identity generation, private-file backup verification, and public-record export
happen locally; deployment never creates or activates a production identity.

## Release manifest and performance budget

Every production build writes `dist/release-manifest.json` with schema
`nsm.daylight-bottle.release-manifest.v1`. It binds the Git commit and tree
state, package inputs, public keyring, security headers, Worker source,
Wrangler configuration, and every other deployed static artifact. The manifest
excludes itself to avoid a self-referential digest and also enforces these
runtime budgets:

- raw HTML, JavaScript, and CSS: at most 220 KiB;
- gzip HTML, JavaScript, and CSS: at most 80 KiB.

The manifest is self-published provenance. It helps an independent reviewer
compare bytes or a rebuild. The verifier rejects symlinks, multiply linked
files, changes to the explicit Worker source closure recorded by the build, and
any difference between the source and built keyring. The closure list is
maintained in source and is not proof that every transitive build input was
discovered. CI requires the manifest to bind its clean checkout before retaining
the bundle. The manifest is not a signature, an independent attestation, or
proof that the delivered app and manifest were not both replaced.

After validation, the `daylight-bottle` GitHub Actions workflow retains the
validated static `dist` bundle, release manifest, and Wrangler dry-run Worker
bundle for 30 days as
`daylight-bottle-validated-release-<commit>`. This gives reviewers a separate
CI-retained copy to compare with live bytes. The Worker bundle is retained for
review but is not yet part of the manifest subject. The artifact is unsigned
and is not independent proof that the production origin delivered those bytes.

## Security boundary

- Plaintext messages and private identities stay in the browser.
- The API accepts ciphertext and public metadata only.
- The API accepts new bottles only for active public keyring records.
- Production drops and inbox reads fail closed if their configured burst
  limiters are unavailable; rejected drops do not write to KV.
- Bottle storage contains ciphertext and public metadata. The platform rate
  limiters separately maintain short-lived counters keyed by hashes of network
  address plus recipient fingerprint; they are not exact accounting.
- The encrypted payload repeats the keyname and recipient fingerprint so local
  decryption can compare them with server metadata.
- Browser JavaScript delivery is part of the trust boundary.
- A compromised origin, browser, machine, extension, public key directory, or
  private identity can expose messages.
- Daylight evidence records provenance; it is not encryption and does not prove
  that a server never observed plaintext.

See the in-app Threat Model before changing any security claim.
