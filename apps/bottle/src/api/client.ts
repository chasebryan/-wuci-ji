import type {
  DropBottleRequest,
  DropBottleResponse,
  Keyring,
  ListBottlesResponse
} from "../domain/types";
import {
  assertFingerprint,
  parseDropBottleRequest,
  parseDropBottleResponse,
  parseKeyring,
  parseListBottlesResponse
} from "../domain/validation";
import { fingerprintKeyRecordInput, sha256Hex } from "../crypto/fingerprint";

type Fetcher = typeof fetch;

export async function loadKeyring(fetcher: Fetcher = fetch): Promise<Keyring> {
  const response = await fetcher("/keyring.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Could not load keyring: ${response.status}`);
  }
  const keyring = parseKeyring(await response.json());
  await verifyKeyringFingerprints(keyring);
  return keyring;
}

export async function dropBottle(
  request: DropBottleRequest,
  fetcher: Fetcher = fetch
): Promise<DropBottleResponse> {
  const validatedRequest = parseDropBottleRequest(request);
  const body = JSON.stringify(validatedRequest);
  const response = await fetcher("/api/bottles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });

  const parsed = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(getApiError(parsed, `Drop failed: ${response.status}`));
  }
  const dropResponse = parseDropBottleResponse(parsed);
  if (dropResponse.evidence.keyname !== validatedRequest.keyname) {
    throw new Error("Drop response keyname does not match the request.");
  }
  if (dropResponse.evidence.recipientFingerprint !== validatedRequest.recipientFingerprint) {
    throw new Error("Drop response recipient fingerprint does not match the request.");
  }
  const expectedCiphertextHash = await sha256Hex(validatedRequest.ciphertext);
  if (dropResponse.evidence.ciphertextSha256 !== expectedCiphertextHash) {
    throw new Error("Drop response ciphertext hash does not match the uploaded ciphertext.");
  }
  return dropResponse;
}

export async function listBottles(
  recipientFingerprint: string,
  fetcher: Fetcher = fetch
): Promise<ListBottlesResponse> {
  const fingerprint = assertFingerprint(recipientFingerprint);
  const response = await fetcher(
    `/api/bottles?recipientFingerprint=${encodeURIComponent(fingerprint)}`,
    { cache: "no-store" }
  );

  const parsed = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(getApiError(parsed, `Bottle lookup failed: ${response.status}`));
  }
  const listResponse = parseListBottlesResponse(parsed);
  for (const bottle of listResponse.bottles) {
    if (bottle.recipientFingerprint !== fingerprint) {
      throw new Error("Bottle response contains a different recipient fingerprint.");
    }
    const expectedCiphertextHash = await sha256Hex(bottle.ciphertext);
    if (bottle.ciphertextSha256 !== expectedCiphertextHash) {
      throw new Error(`Ciphertext integrity check failed for bottle ${bottle.bottleId}.`);
    }
  }
  return listResponse;
}

function getApiError(parsed: unknown, fallback: string): string {
  if (typeof parsed === "object" && parsed !== null && "error" in parsed) {
    const error = (parsed as { error?: unknown }).error;
    if (typeof error === "string") {
      return error;
    }
  }
  return fallback;
}

async function verifyKeyringFingerprints(keyring: Keyring): Promise<void> {
  for (const key of keyring.keys) {
    const expected = await fingerprintKeyRecordInput({
      keyname: key.keyname,
      publicRecipient: key.publicRecipient
    });
    if (key.fingerprint !== expected) {
      throw new Error(`Keyring fingerprint mismatch for ${key.keyname}.`);
    }
  }
}
