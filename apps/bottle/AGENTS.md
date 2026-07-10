# Daylight Bottle Codex Instructions

These rules apply to `apps/bottle/**` and supplement the repository-wide
instructions in the root `AGENTS.md`. They may add constraints but never weaken
the root rules.

## Project mission

Build **Daylight Bottle**, a browser-first encrypted message-in-a-bottle app for `bottle.nosuchmachine.net`.

A sender using the first-party client encrypts a message locally in the browser
to a recipient keyname. The server stores the field labeled `ciphertext` and
public metadata without decrypting it. The recipient later identifies with the
matching local private identity and decrypts the message on their own machine.

The app must be honest about its limits: Daylight provides evidence/provenance, not secrecy. Encryption secrecy comes from recipient keys and local browser execution.

## Non-negotiable security rules

1. The first-party browser client must never send plaintext to the server.
2. Never send private keys, private identity files, passphrases, or decrypted message bodies to the server.
3. Never log plaintext, private keys, decrypted payloads, or identity material.
4. Never implement custom cryptography.
5. Use a maintained, existing public-key encryption library.
6. The sender encrypts to a public recipient key resolved from a public keyname.
7. The keyname is not a password and is not secret.
8. The server persists only the exact stored-bottle fields and never decrypts;
   arbitrary callers can still put plaintext into a string labeled
   `ciphertext`.
9. The recipient decrypts locally in the browser.
10. No analytics, trackers, remote fonts, third-party scripts, CDN scripts, or external runtime calls.
11. All app code must be served from the same origin.
12. All schemas must include explicit schema version strings.
13. Treat browser JavaScript delivery as part of the trust boundary.
14. State clearly in the UI that malicious JavaScript, a compromised browser, a compromised machine, swapped public keys, or stolen private keys can expose messages.

The API can reject explicit plaintext-bearing fields and accept only its exact
versioned request shape, but it cannot prove that an arbitrary caller’s
`ciphertext` string is genuinely encrypted. Never claim that the server can
prove arbitrary-client encryption or that hosting infrastructure has never
observed plaintext.

Private identities, passphrases, plaintext, and decrypted results must not enter
localStorage, sessionStorage, IndexedDB, cookies, URLs, evidence, logs, or
server requests. Decrypt success or failure remains local.

Keyring changes are security-sensitive. Commit only public key records and
require canonical fingerprint derivation, unique active keynames/fingerprints,
and manual review. Preserve the operator/UI requirement to verify recipient
fingerprints through an independent trusted channel; never claim that external
verification occurred without evidence.

Enforce request limits on bytes actually read, not a trusted
`Content-Length`. Keep repository-controlled API, HTML, and keyring responses
`no-store`. Keep NEL/`Report-To` disabled in deployment guidance and verify
their absence only during an authorized live check; repository files cannot
prove provider configuration. Do not add permissive CORS or loosen CSP. Hosting
may still observe IP addresses, timing, sizes, keynames, fingerprints, and
network metadata.

Bottle evidence is an unsigned architectural record. It does not prove server
honesty, encryption by arbitrary clients, sender identity, delivery,
availability, secure erasure, or retention behavior across provider backups.

The current anonymous MVP has no bounded pagination, response-size guarantee,
or reviewed abuse/rate control and is not abuse/DoS resistant. Before any
production-availability claim, add bounded pagination and response limits plus
reviewed edge abuse controls.

## Cryptography direction

Use `age-encryption` / Typage for the MVP unless the existing repository already has a superior audited browser public-key encryption dependency.

Do not guess library APIs from memory. Use the dependency pinned in
`package-lock.json`; when dependency retrieval is authorized and required,
run `npm ci`, then inspect the installed exports and TypeScript definitions
before changing the adapter.

Required crypto adapter interface:

```ts
export type GeneratedIdentity = {
  privateIdentity: string;
  publicRecipient: string;
};

export type KeyRecord = {
  schema: "nsm.daylight-bottle.key.v1";
  keyname: string;
  publicRecipient: string;
  fingerprint: string;
  createdAt: string;
  status: "active" | "revoked";
};

export type PlainBottlePayload = {
  schema: "nsm.daylight-bottle.payload.v1";
  keyname: string;
  recipientFingerprint: string;
  message: string;
  createdAt: string;
};

export async function generateIdentity(): Promise<GeneratedIdentity>;

export async function fingerprintKeyRecordInput(input: {
  keyname: string;
  publicRecipient: string;
}): Promise<string>;

export async function encryptBottlePayload(input: {
  payload: PlainBottlePayload;
  publicRecipient: string;
}): Promise<string>;

export async function decryptBottlePayload(input: {
  ciphertext: string;
  privateIdentity: string;
}): Promise<PlainBottlePayload>;
```

The encrypted payload must include the keyname and recipient fingerprint inside the ciphertext so the browser can verify decrypted content against server metadata.

## Product requirements

The app has four main views:

1. **Create Identity**

   * User enters a keyname.
   * Browser generates a local encryption identity.
   * Browser shows the public key record JSON.
   * Browser downloads the private identity file.
   * Browser explains that losing the private identity means bottles cannot be opened.
   * Browser explains that the private identity must not be uploaded or shared.

2. **Drop Bottle**

   * Sender selects or enters a recipient keyname.
   * Browser resolves the keyname from `/keyring.json`.
   * Browser shows recipient public key fingerprint before encryption.
   * Sender enters a message.
   * Browser encrypts locally.
   * Browser posts only ciphertext and public metadata to `/api/bottles`.
   * Server returns a bottle id and Daylight evidence record.

3. **Open Bottles**

   * Recipient selects keyname.
   * Recipient imports or pastes private identity locally.
   * Browser fetches candidate ciphertext bottles by recipient fingerprint.
   * Browser attempts local decrypt.
   * Browser shows successfully decrypted messages.
   * Browser does not report decrypt success/failure to the server.

4. **Threat Model**

   * Plain-English security boundary.
   * What is protected.
   * What is not protected.
   * Explanation that Daylight evidence is not encryption.
   * Explanation that server compromise after storage should reveal ciphertext only, not plaintext, assuming uncompromised JavaScript delivery and recipient devices.

## MVP key directory rule

For the first version, do not build public unauthenticated key registration.

Use a static keyring file:

```txt
/public/keyring.json
```

Format:

```json
{
  "schema": "nsm.daylight-bottle.keyring.v1",
  "updatedAt": "2026-07-07T00:00:00.000Z",
  "keys": []
}
```

The Create Identity view should generate a `KeyRecord` JSON block that the site owner can manually add to `keyring.json`.

This avoids keyname hijacking before accounts, signatures, or a transparency log exist.

## Bottle storage API

Implement a small server/API layer for storing ciphertext bottles.

Required endpoint:

```txt
POST /api/bottles
```

Request body:

```ts
type DropBottleRequest = {
  schema: "nsm.daylight-bottle.drop.v1";
  keyname: string;
  recipientFingerprint: string;
  ciphertext: string;
  createdAtClient: string;
};
```

Server behavior:

* Reject non-JSON requests.
* Reject requests over 256 KiB.
* Validate schema exactly.
* Validate keyname format.
* Validate recipient fingerprint format.
* Validate ciphertext is a non-empty string.
* Do not attempt to decrypt.
* Do not accept plaintext fields.
* Generate server-side `bottleId`.
* Generate server-side `storedAt`.
* Generate `ciphertextSha256`.
* Set default expiry to 30 days.
* Persist only the exact stored-bottle schema containing the field labeled
  `ciphertext` and public metadata.
* Return bottle id and evidence record.

Response body:

```ts
type DropBottleResponse = {
  schema: "nsm.daylight-bottle.drop.response.v1";
  bottleId: string;
  storedAt: string;
  expiresAt: string;
  evidence: DaylightBottleEvidence;
};
```

Required endpoint:

```txt
GET /api/bottles?recipientFingerprint=<fingerprint>
```

Response body:

```ts
type ListBottlesResponse = {
  schema: "nsm.daylight-bottle.list.response.v1";
  bottles: StoredBottlePublic[];
};
```

Return candidate bottles for the fingerprint. Include ciphertext because the browser must decrypt locally.

Required endpoint:

```txt
GET /api/bottles/:bottleId/evidence
```

Return the Daylight evidence record for a stored bottle.

## Storage model

If using Cloudflare Workers KV, use these keys:

```txt
bottle:<recipientFingerprint>:<storedAtEpochMs>:<bottleId>
bottle-id:<bottleId>
```

The stored value must be JSON:

```ts
type StoredBottle = {
  schema: "nsm.daylight-bottle.stored.v1";
  bottleId: string;
  keyname: string;
  recipientFingerprint: string;
  ciphertext: string;
  ciphertextSha256: string;
  storedAt: string;
  expiresAt: string;
  evidence: DaylightBottleEvidence;
};
```

Public list item:

```ts
type StoredBottlePublic = {
  schema: "nsm.daylight-bottle.public.v1";
  bottleId: string;
  keyname: string;
  recipientFingerprint: string;
  ciphertext: string;
  ciphertextSha256: string;
  storedAt: string;
  expiresAt: string;
};
```

## Daylight evidence record

Every accepted bottle must produce this record:

```ts
type DaylightBottleEvidence = {
  schema: "nsm.daylight-bottle.evidence.v1";
  event: "bottle.accepted";
  bottleId: string;
  keyname: string;
  recipientFingerprint: string;
  ciphertextSha256: string;
  storedAt: string;
  expiresAt: string;
  serverOrigin: "bottle.nosuchmachine.net";
  storagePolicy: "ciphertext-only";
  plaintextSeenByServer: false;
};
```

Important: `plaintextSeenByServer: false` is a design claim from the app architecture, not a mathematical proof. The threat model page must say this.

## Keyname rules

Normalize keynames as lowercase trimmed strings.

Allowed keyname pattern:

```txt
^[a-z0-9][a-z0-9._/-]{2,63}$
```

Reject keynames containing:

```txt
..
//
spaces
control characters
leading slash
trailing slash
```

Examples of valid keynames:

```txt
daylight/chase
aperture.alice
nsm/operator-7
```

## Fingerprint rules

Use SHA-256 over this exact canonical string:

```txt
nsm.daylight-bottle.key.v1
<keyname>
<publicRecipient>
```

Then encode as lowercase hex prefixed with:

```txt
sha256:
```

Example shape:

```txt
sha256:0123456789abcdef...
```

## UI requirements

Use plain HTML/CSS/TypeScript. Avoid React unless the existing repo already uses React.

Required UI copy:

```txt
Daylight Bottle encrypts messages locally in your browser.

The first-party client encrypts before sending. The server stores the ciphertext field and cannot decrypt a correctly encrypted bottle unless the delivered JavaScript, your browser, your machine, or your private identity is compromised.

Your keyname is public. Your private identity is secret.
```

Required warning near identity download:

```txt
Save this private identity file. If you lose it, bottles encrypted to this key cannot be opened. If someone else gets it, they can open your bottles.
```

Required warning near keyring:

```txt
Verify the recipient fingerprint before dropping a bottle. A swapped public key means the wrong person can decrypt the message.
```

## HTTP security headers

Add these headers for all app responses:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

Do not loosen CSP to make dependencies work. Bundle dependencies locally.

## Repository expectations

Use TypeScript strict mode.

Create or update these scripts:

```json
{
  "scripts": {
    "dev": "...",
    "build": "...",
    "test": "...",
    "typecheck": "...",
    "lint": "..."
  }
}
```

Use Vitest for unit tests unless the repo already uses another test runner.

Test these cases:

1. Keyname normalization accepts valid names.
2. Keyname normalization rejects invalid names.
3. Fingerprint generation is deterministic.
4. Encrypt/decrypt round trip works.
5. Decrypt verifies decrypted payload schema.
6. Decrypt rejects mismatched recipient fingerprint.
7. Server rejects oversized bottle requests.
8. Server rejects malformed JSON.
9. Server rejects plaintext fields in bottle request.
10. Server persists only the exact ciphertext-and-metadata schema and rejects
    unknown fields.
11. UI does not call external origins.
12. Build succeeds.

## Acceptance criteria

The work is complete only when:

1. A user can create an identity in the browser.
2. The user can download the private identity file.
3. The user can copy a public key record for `/public/keyring.json`.
4. A sender can select a keyname from the keyring.
5. The sender can encrypt a message locally.
6. The network request to `/api/bottles` contains ciphertext, not plaintext.
7. The recipient can import the private identity locally.
8. The recipient can fetch candidate bottles.
9. The recipient can decrypt matching bottles locally.
10. The first-party client never transmits plaintext or private identity
    material; the API rejects explicit plaintext fields, never decrypts, and
    persists only the exact stored-bottle schema.
11. Threat model page exists.
12. Security headers are configured.
13. Tests pass.
14. Typecheck passes.
15. Production build passes.
16. `DEPLOYMENT.md` explains how to deploy to `bottle.nosuchmachine.net`.

## Do not implement yet

Do not implement these in the MVP unless explicitly requested later:

* Public self-service key registration.
* Password-only encryption.
* Social login.
* Accounts.
* Email notifications.
* Push notifications.
* Sender authentication.
* Read receipts.
* Server-side decryption.
* Server-side private key backup.
* Analytics.
* Admin dashboard.
* Paid plans.
