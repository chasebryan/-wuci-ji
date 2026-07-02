# Wuci-Ji Website Deploy

The website is a static site in `site/`. Deploy from the repository root.

## Cloudflare Pages Git Deploy

Use these settings:

```text
Framework preset: None / Static HTML
Root directory: /
Build command: npm run build
Build output directory: site
Production branch: main
Node version: 22
```

`npm run build` validates the static site and exits nonzero if required assets,
custom domain binding, headers, redirects, or local references are missing.

The repository includes `.nvmrc`, `.node-version`, `package.json`, and
`package-lock.json` so the root build has a concrete Node/npm setup.

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

Cloudflare Pages also supports static HTML sites without a framework. For no
framework, Cloudflare documents a custom build command and a custom build output
directory; the build output directory is where the site content lives.

## Direct Wrangler Deploy

Authenticate once:

```sh
npm run cloudflare:login
npm run cloudflare:whoami
```

For Cloudflare Pages direct upload:

```sh
npm run build
npm run deploy
```

The root `wrangler.toml` points Pages at `site/`. The deploy script pins the
deployment branch to `main`.

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
site/CNAME
site/404.html
site/styles.css
site/app.js
site/_headers
site/_redirects
site/assets/
```
