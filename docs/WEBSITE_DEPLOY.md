# Wuci-Ji Website Deploy

The website is a static site in `site/`. Deploy from the repository root.

## GitHub Pages Deploy

The repository includes `.github/workflows/pages.yml`. On pushes to `main`
that touch the site, the workflow runs `make site-validate`, uploads `site/`,
and deploys it through GitHub Pages.

Required repository settings:

```text
Pages source: GitHub Actions
Custom domain: nosuchmachine.net
Enforce HTTPS: enabled
```

Required DNS:

```text
nosuchmachine.net      A/AAAA or ALIAS/ANAME for GitHub Pages
www.nosuchmachine.net  CNAME to chasebryan.github.io
```

After each DNS or Pages settings change, verify:

```sh
make site-live-check
```

The expected hosted state is a valid HTTPS certificate, canonical
`https://nosuchmachine.net/`, HTTP redirected to HTTPS, `www` redirected to the
apex domain, and `/.well-known/security.txt` served as public text. GitHub
Pages controls certificate issuance and the Enforce HTTPS toggle; repository
files cannot prove that hosted setting by themselves.

`make site-live-check` is intentionally stricter than `make site-validate`: it
checks the deployed public host and fails if HTTP still serves `200 OK`, HSTS is
missing, discovery files, `codemeta.json`, `hosting-requirements.json`, or
`claim-evidence.json` are unavailable, or the official Wuci-Ji assets are not
live.

`site/app.js` includes a browser-side fallback that redirects
`http://nosuchmachine.net/` and `http://www.nosuchmachine.net/` visits to the
canonical HTTPS apex URL. This improves browser behavior if a host setting
regresses, but it is not a replacement for a server-side 301/308 redirect,
HSTS, or Cloudflare Always Use HTTPS.

## Cloudflare Pages Git Deploy

Cloudflare Pages is an alternate deploy path. Unlike GitHub Pages, it honors
`site/_headers` and `site/_redirects`, so those files are kept as checked
deployment metadata even when the active hosted path is GitHub Pages.

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
site/security.txt
site/.well-known/security.txt
site/aperture-status.json
site/daylight-status.json
```

`site/index.html` carries canonical HTTPS metadata, Open Graph/Twitter image
metadata, local microdata for the Wuci-Ji v2.2 Aperture Bastion source surface,
a CodeMeta JSON-LD pointer at `site/codemeta.json`, and in-document
CSP/referrer policy because GitHub Pages does not serve `_headers`.

`site/codemeta.json` is the machine-readable research software identity for
crawlers, archival tools, and research agents. The site validator checks that
it remains bound to the public repository, official imagery, Aperture capsule
digest, firewall profile, local validation handles, Apache-2.0 license, and
explicit non-claims.

`site/hosting-requirements.json` is the machine-readable deployment contract for
the public host. It states the canonical origin, required HTTP-to-HTTPS and
`www` redirects, required HSTS header, required public metadata paths, and the
host controls that must be enabled before `make site-live-check` can pass.

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
site/aperture-status.json
site/daylight-status.json
site/assets/
```
