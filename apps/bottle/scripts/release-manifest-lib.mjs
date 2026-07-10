import { createHash } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";

const KEYNAME_PATTERN = /^[a-z0-9][a-z0-9._/-]{2,63}$/;
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/;
const AGE_RECIPIENT_PATTERN = /^age1[a-z0-9]{20,511}$/;
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export const WORKER_SOURCE_PATHS = Object.freeze([
  "public/keyring.json",
  "src/crypto/fingerprint.ts",
  "src/domain/types.ts",
  "src/domain/validation.ts",
  "worker/index.ts"
]);

export async function collectRegularFiles(directory, label = "artifact tree") {
  const rootMetadata = await lstat(directory);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
    throw new Error(`${label} root must be a real directory.`);
  }

  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(
      `${encodeURIComponent(entry.name)}${entry.isDirectory() ? "/" : ""}`,
      directory
    );
    const entryLabel = `${label} entry ${entry.name}`;
    const metadata = await lstat(url);
    if (metadata.isSymbolicLink()) {
      throw new Error(`${entryLabel} must not be a symbolic link.`);
    }
    if (metadata.isDirectory()) {
      output.push(...await collectRegularFiles(url, entryLabel));
      continue;
    }
    assertRegularSingleLink(metadata, entryLabel);
    output.push(url);
  }
  return output;
}

export async function readRegularFile(url, label) {
  const metadata = await lstat(url);
  if (metadata.isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link.`);
  }
  assertRegularSingleLink(metadata, label);
  return readFile(url);
}

export async function buildSourceClosure(appRoot, sourcePaths) {
  const files = [];
  for (const path of [...sourcePaths].sort()) {
    const content = await readRegularFile(new URL(path, appRoot), `Worker source ${path}`);
    files.push({ path, bytes: content.byteLength, sha256: sha256(content) });
  }
  return {
    schema: "nsm.daylight-bottle.worker-source-closure.v1",
    sha256: sha256(Buffer.from(JSON.stringify(files))),
    files
  };
}

export function assertSameBytes(left, right, label) {
  if (!Buffer.from(left).equals(Buffer.from(right))) {
    throw new Error(`${label} must be byte-for-byte identical.`);
  }
}

export function assertValidKeyring(input) {
  const keyring = expectRecord(input, "keyring");
  assertExactFields(keyring, ["schema", "updatedAt", "keys"], "keyring");
  if (keyring.schema !== "nsm.daylight-bottle.keyring.v1" || !Array.isArray(keyring.keys)) {
    throw new Error("Keyring has an unsupported schema or keys value.");
  }
  expectCanonicalTimestamp(keyring.updatedAt, "keyring updatedAt");

  const fingerprints = new Set();
  const activeKeynames = new Set();
  for (const candidate of keyring.keys) {
    const key = expectRecord(candidate, "key record");
    assertExactFields(
      key,
      ["schema", "keyname", "publicRecipient", "fingerprint", "createdAt", "status"],
      "key record"
    );
    if (key.schema !== "nsm.daylight-bottle.key.v1") {
      throw new Error("Key record has an unsupported schema.");
    }

    const keyname = expectString(key.keyname, "keyname");
    assertNormalizedKeyname(keyname);
    const publicRecipient = expectString(key.publicRecipient, "publicRecipient");
    if (!AGE_RECIPIENT_PATTERN.test(publicRecipient)) {
      throw new Error(`Keyring record ${keyname} has an invalid age public recipient.`);
    }
    const fingerprint = expectString(key.fingerprint, "fingerprint");
    if (!FINGERPRINT_PATTERN.test(fingerprint)) {
      throw new Error(`Keyring record ${keyname} has an invalid fingerprint.`);
    }
    expectCanonicalTimestamp(key.createdAt, `keyring record ${keyname} createdAt`);
    if (key.status !== "active" && key.status !== "revoked") {
      throw new Error(`Keyring record ${keyname} has an invalid status.`);
    }
    if (fingerprints.has(fingerprint)) {
      throw new Error(`Keyring contains duplicate fingerprint ${fingerprint}.`);
    }
    fingerprints.add(fingerprint);
    if (key.status === "active") {
      if (activeKeynames.has(keyname)) {
        throw new Error(`Keyring contains multiple active records for ${keyname}.`);
      }
      activeKeynames.add(keyname);
    }

    const canonical = `nsm.daylight-bottle.key.v1\n${keyname}\n${publicRecipient}`;
    const expectedFingerprint = `sha256:${sha256(Buffer.from(canonical))}`;
    if (fingerprint !== expectedFingerprint) {
      throw new Error(`Keyring fingerprint mismatch for ${keyname}.`);
    }
  }

  return keyring;
}

export function normalizeGitRepositoryUrl(input) {
  if (typeof input !== "string") {
    return undefined;
  }
  const value = input.trim().replace(/\.git$/, "");
  const match = value.match(
    /^(?:https:\/\/github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/
  );
  return match ? `https://github.com/${match[1]}/${match[2]}` : undefined;
}

export function assertBundleSourceMetadata(source) {
  const record = expectRecord(source, "release manifest source");
  const repository = record.repository;
  const commit = record.commit;
  const treeState = record.treeState;
  const repositoryIsValid =
    repository === "unknown" ||
    (typeof repository === "string" && normalizeGitRepositoryUrl(repository) === repository);
  const commitIsValid =
    commit === "unknown" || (typeof commit === "string" && /^[0-9a-f]{40}$/.test(commit));

  if (!repositoryIsValid || !commitIsValid || !["clean", "dirty", "unknown"].includes(treeState)) {
    throw new Error("Built release manifest source metadata is invalid.");
  }
  return record;
}

export function assertCurrentCleanSource(
  manifest,
  currentCommit,
  currentTreeStatus,
  currentRepository,
  approvedMainCommit
) {
  assertCleanSourceSnapshot(
    manifest,
    currentCommit,
    currentTreeStatus,
    currentRepository
  );
  if (approvedMainCommit !== currentCommit) {
    throw new Error(
      "The verified release manifest must bind the exact fetched origin/main commit."
    );
  }
}

export function assertCleanSourceSnapshot(
  manifest,
  currentCommit,
  currentTreeStatus,
  currentRepository
) {
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    manifest.schema !== "nsm.daylight-bottle.release-manifest.v1" ||
    typeof manifest.source !== "object" ||
    manifest.source === null ||
    manifest.source.treeState !== "clean" ||
    currentTreeStatus !== "" ||
    currentRepository !== "https://github.com/chasebryan/-wuci-ji" ||
    manifest.source.repository !== currentRepository ||
    typeof currentCommit !== "string" ||
    !/^[0-9a-f]{40}$/.test(currentCommit) ||
    manifest.source.commit !== currentCommit
  ) {
    throw new Error(
      "The verified release manifest must bind the canonical origin and current HEAD from a clean Git tree."
    );
  }
}

export function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function assertRegularSingleLink(metadata, label) {
  if (!metadata.isFile()) {
    throw new Error(`${label} must be a regular file.`);
  }
  if (metadata.nlink > 1) {
    throw new Error(`${label} must not have multiple hard links.`);
  }
}

function assertNormalizedKeyname(keyname) {
  if (
    !KEYNAME_PATTERN.test(keyname) ||
    keyname.includes("..") ||
    keyname.includes("//") ||
    keyname.includes(" ") ||
    hasControlCharacter(keyname) ||
    keyname.startsWith("/") ||
    keyname.endsWith("/")
  ) {
    throw new Error(`Keyring keyname ${keyname} is not canonical.`);
  }
}

function hasControlCharacter(value) {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f);
  });
}

function expectCanonicalTimestamp(input, label) {
  const value = expectString(input, label);
  const parsed = new Date(value);
  if (
    !ISO_TIMESTAMP_PATTERN.test(value) ||
    Number.isNaN(parsed.getTime()) ||
    parsed.toISOString() !== value
  ) {
    throw new Error(`${label} must be a valid canonical UTC ISO timestamp.`);
  }
  return value;
}

function expectRecord(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value;
}

function expectString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string.`);
  }
  return value;
}

function assertExactFields(record, fields, label) {
  const expected = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) {
      throw new Error(`${label} contains unexpected field ${key}.`);
    }
  }
  for (const field of expected) {
    if (!Object.hasOwn(record, field)) {
      throw new Error(`${label} is missing field ${field}.`);
    }
  }
}
