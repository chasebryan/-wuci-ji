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
third-party runtime calls are allowed.

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
| `npm run build` | Typecheck production code and build `dist`. |
| `npm run verify:bundle` | Verify required files, same-origin runtime URLs, CSP-compatible HTML, and headers. |
| `npm run check` | Run the full non-deploying local/CI release gate. |
| `npm run deploy:dry-run` | Rebuild, verify the bundle, and bundle Worker/assets without deploying. |
| `npm run deploy` | Run the complete gate, reject placeholder production config, then perform a live Wrangler deployment. |

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

## Security boundary

- Plaintext messages and private identities stay in the browser.
- The API accepts ciphertext and public metadata only.
- The encrypted payload repeats the keyname and recipient fingerprint so local
  decryption can compare them with server metadata.
- Browser JavaScript delivery is part of the trust boundary.
- A compromised origin, browser, machine, extension, public key directory, or
  private identity can expose messages.
- Daylight evidence records provenance; it is not encryption and does not prove
  that a server never observed plaintext.

See the in-app Threat Model before changing any security claim.
