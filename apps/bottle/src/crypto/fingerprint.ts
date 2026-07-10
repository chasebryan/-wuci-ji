import { SCHEMAS } from "../domain/types";
import { normalizeKeyname } from "../domain/validation";

const textEncoder = new TextEncoder();

export async function fingerprintKeyRecordInput(input: {
  keyname: string;
  publicRecipient: string;
}): Promise<string> {
  const keyname = normalizeKeyname(input.keyname);
  if (input.publicRecipient.length === 0) {
    throw new Error("Public recipient must not be empty.");
  }

  const canonical = [SCHEMAS.key, keyname, input.publicRecipient].join("\n");
  return `sha256:${await sha256Hex(canonical)}`;
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? textEncoder.encode(input) : input;
  const digestInput: Uint8Array<ArrayBuffer> = new Uint8Array(bytes.byteLength);
  digestInput.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", digestInput);
  return bytesToHex(new Uint8Array(digest));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
