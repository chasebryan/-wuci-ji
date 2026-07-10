# Daylight Bottle deployment

Daylight Bottle deploys as one Cloudflare Worker on the custom domain
`bottle.nosuchmachine.net`. The Worker serves the built frontend from `dist`,
runs the Worker code first for `/api/*`, and binds one Workers KV namespace as
`BOTTLES_KV`. This keeps the frontend, keyring, and API on one origin.

This runbook does not authorize an account login, DNS replacement, or live
deployment. Perform those account-bound steps only with the site owner's
approval.

## 1. Prerequisites

- `nosuchmachine.net` is an active zone in the target Cloudflare account.
- The operator can edit Workers, Workers KV, Custom Domains, and DNS for that
  zone.
- Cloudflare Network Error Logging is **Off** for `nosuchmachine.net`. When it
  is enabled, Cloudflare adds `NEL` and `Report-To` response headers that direct
  browsers to an external reporting endpoint, which conflicts with Daylight
  Bottle's no-third-party-runtime-calls boundary. See Cloudflare's
  [Network Error Logging documentation](https://developers.cloudflare.com/network-error-logging/).
- Node.js `22.23.1` and npm `11.8.0` are installed. The supported runtime range
  is also recorded in `package.json`.
- No private identity, message plaintext, passphrase, or private key is present
  in the checkout, environment, Wrangler variables, or KV seed data.
- `public/keyring.json` contains only manually reviewed public records whose
  private identities are held outside the repository. An empty keyring is a
  valid fail-closed deployment state: identity creation and the threat model
  remain available, while the Worker rejects every bottle drop.
- `wrangler.toml` includes the `DROP_RATE_LIMITER` and `READ_RATE_LIMITER`
  bindings. Drops permit 12 requests per 60 seconds for each hashed
  network-and-recipient pair. Inbox-list and evidence reads share 60 requests
  per 60 seconds for each hashed network address, so changing a fingerprint or
  bottle id cannot reset the read budget. These counters are local to a
  Cloudflare location. This is burst protection, not accurate accounting or a
  global daily quota; see Cloudflare's
  [Rate Limiting API limits](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/#accuracy).
  Its numeric namespace id must remain unique within the Cloudflare account
  unless counter sharing with another Worker is explicitly intended.

From the repository root, install exactly the locked dependencies and run the
complete local gate:

```sh
git fetch origin main
git rev-parse HEAD
git rev-parse refs/remotes/origin/main
git status --short
cd apps/bottle
node --version
npm --version
npm ci
npm run check
```

The two commit ids must match exactly and `git status --short` must be empty.
The live-deploy validator rejects a fork origin, an unfetched/unmerged commit,
or any dirty tree even if a local build succeeds.

`npm run check` runs real ESLint, all TypeScript environment checks, unit tests,
the production build, the same-origin bundle verifier, and a Wrangler dry-run.
It does not contact Cloudflare or deploy anything.

## 2. Authenticate deliberately

Wrangler authentication is account-bound. Do not sign in implicitly. Once the
site owner approves the account action, authenticate and confirm the target
account:

```sh
npx wrangler login
npx wrangler whoami
```

For noninteractive CI deployment, use a narrowly scoped
`CLOUDFLARE_API_TOKEN`; never commit it. The validation workflow in this
repository performs only a dry-run and needs no Cloudflare credentials.

## 3. Verify the pinned production KV binding

The production namespace is already pinned in `wrangler.toml`. After deliberate
authentication, list the account namespaces:

```sh
npx wrangler kv namespace list
```

Confirm that `20625e8d95504df28ba0e1bc94d97fc0` is the intended production
namespace in the account shown by `wrangler whoami`. A KV namespace id is
configuration, not a secret. Creating or rotating the namespace is a separate
approved migration: update `wrangler.toml`, the section-aware production config
validator, the rollback record, and the deployment review together.

Do not seed KV with plaintext or private identity material. The application
creates bottle keys itself using these forms:

```txt
bottle:<recipientFingerprint>:<storedAtEpochMs>:<bottleId>
bottle-id:<bottleId>
```

## 4. Check the custom-domain handoff

`wrangler.toml` declares `bottle.nosuchmachine.net` as a Cloudflare Custom
Domain. Cloudflare creates the DNS record and certificate when the Worker is
deployed. A Custom Domain cannot replace an existing CNAME without an explicit
handoff.

Inspect current DNS before changing anything:

```sh
dig bottle.nosuchmachine.net CNAME +short
dig bottle.nosuchmachine.net A +short
dig bottle.nosuchmachine.net AAAA +short
```

If any result belongs to an existing service, stop and record its DNS values,
deployment owner, and rollback path. Remove or replace existing DNS only after
the site owner approves the cutover.

## 5. Validate and deploy

Run the non-deploying release candidate checks again after the real KV id is in
place:

```sh
npm run check
npm run deploy:dry-run
```

Review the dry-run output. It must list the `BOTTLES_KV` binding and static
assets from `dist`, plus both rate-limit bindings. Inspect
`dist/release-manifest.json`; it must identify a
clean 40-character Git commit, verify through `npm run verify:bundle`, and stay
inside the recorded raw/gzip budgets. Then, with explicit approval for the live
Cloudflare write:

```sh
npm run deploy
npx wrangler deployments status
npx wrangler deployments list
```

`npm run deploy` refuses to contact Cloudflare unless the custom domain, assets,
KV, and rate-limit bindings match the pinned production sections. It also
refuses a release manifest that does not verify against the canonical upstream,
the exact fetched `origin/main` commit, the current clean Git tree, recorded
source closure, built assets, or byte-identical source and built keyring.

Record the new deployment id and the immediately previous deployment id in the
change record. Do not claim the deployment succeeded until the live checks
below pass.

## 6. Live smoke checks

Confirm DNS and the static application:

```sh
dig bottle.nosuchmachine.net A +short
dig bottle.nosuchmachine.net AAAA +short
curl --fail --silent --show-error https://bottle.nosuchmachine.net/ | grep -F "Daylight Bottle"
curl --fail --silent --show-error https://bottle.nosuchmachine.net/keyring.json
curl --fail --silent --show-error https://bottle.nosuchmachine.net/release-manifest.json
```

Confirm required headers on both a static response and an API response:

```sh
curl --silent --show-error --dump-header - --output /dev/null https://bottle.nosuchmachine.net/
curl --silent --show-error --dump-header - --output /dev/null \
  "https://bottle.nosuchmachine.net/api/bottles?recipientFingerprint=sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

Both responses must include the CSP, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, and `X-Content-Type-Options` values maintained in
`public/_headers` and the Worker. Neither response may include `NEL` or
`Report-To`; if either is present, turn off Cloudflare Network Error Logging for
the zone and repeat the checks. The API response should be `200` with schema
`nsm.daylight-bottle.list.response.v1`. Each request lists at most 8 candidate
KV keys and fetches them in one bounded bulk read; a page with additional
candidates includes an opaque
`X-Daylight-Next-Cursor` response header for the browser to submit on the next
locally authorized fetch. The Worker refuses new drops when its KV listing sees
500 unexpired indexed bottles for a recipient; eventual consistency means this
is an admission ceiling rather than a transactional hard bound. Pagination and
the response-byte budget remain authoritative even if concurrent writes briefly
overshoot that ceiling.

Confirm the live release manifest has schema
`nsm.daylight-bottle.release-manifest.v1`, its source commit matches the exact
commit approved for deployment, its canonical subject digest recomputes, and
its source-input digests match the checkout. The live checker does not trust a
self-consistent remote manifest as byte authority: a freshly rebuilt local
`dist/` tree defines every requested public artifact, exact expected content,
size/hash record, per-response read cap, and aggregate capture budget. The
consumed `_headers` artifact is bound locally and its resulting policy is
checked on live responses. JavaScript, CSS, HTML, JSON, image, and font paths
must return an extension-appropriate MIME type; `application/octet-stream` is
not accepted for JavaScript. This is deployment parity evidence, not proof of
an uncompromised origin.

From the repository root, run the deterministic policy tests and then the
explicit no-secret public readback. The live command binds the manifest,
checked-out source inputs, and exact bounded same-origin artifact bytes to the
checked-out commit; rejects redirects; requires the zero-fingerprint API probe
to return an empty versioned response; checks the static/API security headers;
and verifies that the live keyring, public observation, and status metadata
agree byte-for-byte:

```sh
make live-integrity-test
make live-integrity-check
```

The command never sends credentials, identity material, plaintext, or a real
recipient fingerprint, caps every response body, limits the locally defined
artifact capture to 20 aggregate seconds, and never prints bodies. It also
compares the canonical site's HTML, `app.js`, `styles.css`, and fixed public
JSON status/evidence responses directly with the checkout.

For a commit validated by GitHub Actions, the `daylight-bottle` workflow also
retains `daylight-bottle-validated-release-<commit>` for 30 days. Compare its
manifest, static bundle, and Wrangler dry-run Worker bundle with the live
deployment when available. The Worker bundle is not yet bound into the manifest
subject. This CI-retained artifact is unsigned and does not independently prove
which bytes the production origin delivered.

Finally, complete the browser acceptance path with a manually approved keyring
record:

1. Create an identity, download the private identity file, and verify the saved
   file locally in the Create Identity view.
2. Export and add only the displayed public `KeyRecord` to `public/keyring.json`.
3. Re-run `npm run check`, deploy, and verify the displayed fingerprint through
   an independent trusted channel.
4. Drop a bottle while inspecting the POST body. It may contain only `schema`,
   `keyname`, `recipientFingerprint`, `ciphertext`, and `createdAtClient`.
5. Confirm the POST body contains no message plaintext, private identity,
   private key, or passphrase.
6. Import the matching private identity and open the bottle locally. Confirm no
   decrypt success or failure request is sent to the server.
7. Confirm developer tools show no third-party runtime requests.

## 7. Rollback

If a live smoke check fails, stop new bottle drops and roll back to the recorded
previous Worker version:

```sh
npx wrangler deployments list
npx wrangler rollback <previous-version-id> --message "Rollback failed Daylight Bottle deployment"
npx wrangler deployments status
```

Repeat all live smoke checks after rollback. Worker rollback does not revert KV
contents or a manually edited DNS record. Do not delete the KV namespace during
rollback; preserve ciphertext evidence and investigate separately. If this was
the first deployment and no previous Worker version exists, remove the Custom
Domain only through an approved Cloudflare change and restore the recorded DNS
configuration.

## Security and evidence boundary

Static responses use `public/_headers`; API responses set the same required
headers in the Worker. Do not loosen the CSP for remote fonts, analytics, CDN
scripts, or third-party runtime calls.

The Worker stores ciphertext and public metadata. It does not decrypt bottles
and has no private identity material. `plaintextSeenByServer: false` is an
architectural claim about the implemented request path, not a mathematical
proof. Malicious JavaScript delivery or a compromised browser, machine, public
key directory, or private identity can still expose messages.
