# Wuci-Ji Website Deploy

The website source is in `site/`. Deploy only the generated
`build/site-dist/` tree from the repository root.

## Production: Cloudflare Pages

The canonical site at `https://nosuchmachine.net/` is served by Cloudflare
Pages project `wuci-ji`. `npm run build` validates the source and creates a
deterministic upload tree with `site-inventory.json`. It excludes the build-only
validator and source files shadowed by `_redirects`, while preserving
`_headers` and `_redirects` as consumed Pages configuration.

The global HTML response policy includes `Cache-Control: no-transform` so the
edge cannot inject Cloudflare Web Analytics or other transformed markup. More
specific static-asset and evidence rules detach that cache header before
applying their own cache policy. Do not enable browser analytics or remove
`no-transform` without an explicit privacy/CSP review.

Authenticate and verify the target before publishing:

```sh
npm run cloudflare:whoami
WRANGLER_WRITE_LOGS=false WRANGLER_SEND_METRICS=false \
  npx --no-install wrangler pages deployment list --project-name wuci-ji
```

Publish only from a clean, committed checkout:

```sh
make site-validate
git status --short
npm run deploy
```

The deploy command rebuilds and validates `build/site-dist/` before upload. A
dirty checkout or a failed `make site-validate` remains a release stop
condition.

After every production deployment, verify:

```sh
make site-live-check
```

The expected hosted state is a valid HTTPS certificate, canonical
`https://nosuchmachine.net/`, HTTP redirected to HTTPS, `www` redirected to the
apex domain, `/.well-known/security.txt` served as public text, and all
release-specific live markers present. Repository files cannot prove the live
host state by themselves.

`make site-live-check` is intentionally stricter than `make site-validate`: it
checks the deployed public host and fails if HTTP still serves `200 OK`, HSTS is
missing, browser-like HTML differs from the committed page, an analytics beacon
is injected, discovery files, `codemeta.json`, `hosting-requirements.json`, or
`claim-evidence.json` are unavailable, or the official Wuci-Ji assets are not
live.

`site/app.js` includes a browser-side fallback that redirects
`http://nosuchmachine.net/` and `http://www.nosuchmachine.net/` visits to the
canonical HTTPS apex URL. This improves browser behavior if a host setting
regresses, but it is not a replacement for a server-side 301/308 redirect,
HSTS, or Cloudflare Always Use HTTPS.

Use these settings:

```text
Framework preset: None / Static HTML
Root directory: /
Build command: npm run build
Build output directory: build/site-dist
Production branch: main
Node version: 22
```

`npm run build` validates the static site, fails closed on symlinks, hardlinks,
unknown public MIME types, redirect-shadow drift, and fixed file/byte budgets,
then stages the exact Pages upload tree. `site/validate.mjs`,
`site/daylight-grok-audit.html`, and the duplicate `site/security.txt` are not
uploaded: the latter two routes are served by explicit redirects.

The repository includes `.nvmrc`, `.node-version`, `package.json`, and
`package-lock.json` so the root build has a concrete Node/npm setup.

## Retired secondary publisher

The repository GitHub Pages workflow and both Pages `CNAME` files were removed
on 2026-07-10. Cloudflare Pages project `wuci-ji` is the only repository-defined
publisher for the canonical origin. A push to `main` does not deploy the site;
publishing remains a deliberate account-bound Wrangler action.

Repository files cannot disable an already configured GitHub Pages setting.
Disable Pages in the repository settings. Until that account-level follow-up is
complete, `make live-integrity-check` requires the former secondary URL to
return `404`/`410` or redirect directly to `https://nosuchmachine.net/`; an HTTP
downgrade or a separately served copy fails the check.

## Daylight evidence binding

The headline AM+ number on the site is bound to committed Daylight evidence so
it cannot silently drift. `site/daylight-status.json` is generated from
`daylight/v17-singularity/examples/current-scorecard.v17.json`, and the build
validator fails if the number displayed in `index.html` (or any
`data-am-plus` hook) disagrees with it, or if the status file's score and
scorecard digest disagree with the committed scorecard.

```sh
make site-daylight-status        # regenerate site/daylight-status.json from evidence
make site-validate               # check staleness, then run the site validator
```

When the v17 scorecard changes, run `make site-daylight-status` and update the
displayed number; the build refuses a stale site until they match.

## Discoverability and HTTPS metadata

The static artifact includes:

```text
site/sitemap.xml
site/robots.txt
site/site.webmanifest
site/codemeta.json
site/hosting-requirements.json
site/claim-evidence.json
site/llms.txt
site/humans.txt
site/.well-known/security.txt
site/noether-forge-status.json
site/aperture-status.json
site/daylight-status.json
```

`site/index.html` carries canonical HTTPS metadata, Open Graph/Twitter image
metadata, local microdata for the Wuci-Ji v2.2 Aperture Bastion source surface,
a CodeMeta JSON-LD pointer at `site/codemeta.json`, and an in-document
CSP/referrer policy as defense in depth alongside Cloudflare `_headers`.

`site/codemeta.json` is the machine-readable research software identity for
crawlers, archival tools, and research agents. The site validator checks that
it remains bound to the public repository, official imagery, Aperture capsule
digest, firewall profile, local validation handles, Apache-2.0 license, and
explicit non-claims.

`site/hosting-requirements.json` is the machine-readable deployment contract for
the public host. It states the canonical origin, required HTTP-to-HTTPS and
`www` redirects, required HSTS header, retired secondary-publisher state,
forbidden NEL/`Report-To` headers and analytics markers, required public paths,
and the host controls that must be enabled before the live gates can pass.

Run the deterministic fixture lane without network access, then explicitly run
the bounded public readback after an authorized deployment:

```sh
make live-integrity-test
make live-integrity-check
```

The live command sends no credentials or user content. It uses a fixed all-zero
recipient fingerprint that cannot be registered through the application,
rejects redirects, expects an empty list, and never prints response bodies.
Run `npm ci`, `npm run build`, and `npm run verify:bundle` in `apps/bottle`
first: the rebuilt `dist/` tree defines the complete Bottle artifact request
set, expected bytes, per-response caps, aggregate byte budget, and 20-second
artifact-fetch deadline. Remote manifest declarations do not expand that set.
JavaScript and CSS require browser-safe extension-specific MIME types, and an
octet-stream script fails.

The checker loads the generated `build/site-dist/site-inventory.json` and binds
every staged public file—including HTML, JavaScript, CSS, JSON, discovery text,
the generated inventory, and all media—by exact URL, status, MIME type, size,
and bytes. `_headers` and `_redirects` are bound through the exact inventory and
their resulting headers and redirect routes are checked instead of requesting
those consumed config files. The local tree is capped at 96 files, 4 MiB per
file, and 40 MiB total. Eight bounded workers share a 120-second site-artifact
deadline; remote content cannot add requests or raise a local byte cap.
The redirect parser refuses any absolute probe other than the exact HTTP apex,
HTTP `www`, and HTTPS `www` wildcard rules. Other redirect sources must be
literal same-origin paths; targets are checked only as response `Location`
values and are never followed or fetched. Clean HTML routes, raw `.html`
routes, directory indexes, and local wildcard collisions are considered when
the staged builder excludes redirect-shadowed source files.

`site/claim-evidence.json` maps each public website claim to the exact local
evidence files, evidence values, validation commands, and non-claims that bound
it. The validator cross-checks it against `site/aperture-status.json`,
`site/daylight-status.json`, and the official emblem bytes.

`site/_headers` additionally pins HSTS, CSP, plain-text content types, JSON
content types, and cache policy for hosts that support static header files.
This is a deployment signal, not proof that the public host is currently
serving those headers.

Cloudflare Pages also supports static HTML sites without a framework. For no
framework, Cloudflare documents a custom build command and a custom build output
directory; the build output directory is where the site content lives.

## Direct Wrangler Deploy Details

Authenticate once:

```sh
npm run cloudflare:login
npm run cloudflare:whoami
```

For the standard Cloudflare Pages direct upload:

```sh
npm run build
npm run deploy
```

The deploy script pins project `wuci-ji`, directory `build/site-dist/`, and deployment
branch `main`. For an evidence-bound manual deployment, Wrangler also accepts
explicit `--commit-hash`, `--commit-message`, and `--commit-dirty=false`
metadata. Record the resulting deployment ID and run `make site-live-check`.

```sh
COMMIT_SHA=$(git rev-parse HEAD)
WRANGLER_WRITE_LOGS=false WRANGLER_SEND_METRICS=false \
  npx --no-install wrangler pages deploy build/site-dist \
  --project-name wuci-ji --branch main \
  --commit-hash "$COMMIT_SHA" --commit-dirty=false
```

For token-based deploys, keep the token outside git:

```sh
export CLOUDFLARE_API_TOKEN="..."
export CLOUDFLARE_ACCOUNT_ID="..."
npm run deploy
```

## Local Preview

```sh
npm run preview
```

Then open:

```text
http://127.0.0.1:8788
```

## Required Files

```text
site/index.html
site/404.html
site/styles.css
site/app.js
site/_headers
site/_redirects
site/robots.txt
site/sitemap.xml
site/site.webmanifest
site/codemeta.json
site/hosting-requirements.json
site/claim-evidence.json
site/llms.txt
site/humans.txt
site/security.txt
site/.well-known/security.txt
site/noether-forge-status.json
site/aperture-status.json
site/daylight-status.json
site/assets/
```
