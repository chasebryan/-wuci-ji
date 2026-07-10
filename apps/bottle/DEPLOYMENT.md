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
- Node.js `22.23.1` and npm `11.8.0` are installed. The supported runtime range
  is also recorded in `package.json`.
- No private identity, message plaintext, passphrase, or private key is present
  in the checkout, environment, Wrangler variables, or KV seed data.

From the repository root, install exactly the locked dependencies and run the
complete local gate:

```sh
cd apps/bottle
node --version
npm --version
npm ci
npm run check
```

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

## 3. Create and bind production KV

Create one production namespace:

```sh
npx wrangler kv namespace create daylight-bottle-production
```

Copy the returned namespace id into `wrangler.toml` in place of
`replace-with-production-kv-namespace-id`. A KV namespace id is configuration,
not a secret, but verify that it belongs to the account shown by
`wrangler whoami` before deploying.

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
assets from `dist`. Then, with explicit approval for the live Cloudflare write:

```sh
npm run deploy
npx wrangler deployments status
npx wrangler deployments list
```

`npm run deploy` refuses to contact Cloudflare while the KV id is missing,
still a placeholder, or not a 32-character namespace id.

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
```

Confirm required headers on both a static response and an API response:

```sh
curl --silent --show-error --dump-header - --output /dev/null https://bottle.nosuchmachine.net/
curl --silent --show-error --dump-header - --output /dev/null \
  "https://bottle.nosuchmachine.net/api/bottles?recipientFingerprint=sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

Both responses must include the CSP, `Referrer-Policy`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, and `X-Content-Type-Options` values maintained in
`public/_headers` and the Worker. The API response should be `200` with schema
`nsm.daylight-bottle.list.response.v1`.

Finally, complete the browser acceptance path with a manually approved keyring
record:

1. Create an identity and download the private identity file.
2. Add only the displayed public `KeyRecord` to `public/keyring.json`.
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
