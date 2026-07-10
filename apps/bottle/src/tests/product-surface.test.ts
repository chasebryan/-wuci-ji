import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { identityCeremonyPresentation } from "../ui/CreateIdentity";
import { shouldMarkIdentityInvalid } from "../ui/OpenBottles";
import {
  clearNavigationGuard,
  confirmNavigationAway,
  setNavigationGuard
} from "../ui/navigationGuard";

describe("trust-first product surface", () => {
  it("keeps the identity backup ceremony and explicit clearing controls visible", async () => {
    const source = await readFile(join(process.cwd(), "src/ui/CreateIdentity.ts"), "utf8");

    expect(source).toContain("verifyPrivateIdentityMatchesKeyRecord");
    expect(source).toContain("Verify the Saved Identity");
    expect(source).toContain("Download Public Key Record");
    expect(source).toContain("Confirm Start Over");
    expect(source).toContain("Read the Manual Keyring Procedure");
    expect(source).toContain("not proof of secure memory erasure");
    expect(source).toContain('addEventListener("beforeunload"');
    expect(source).toContain("setNavigationGuard");
    expect(source).toContain("publicActions[0]?.focus()");
  });

  it("keeps generation and public export gated through the ceremony phases", () => {
    expect(identityCeremonyPresentation("idle")).toEqual({
      generateDisabled: false,
      keynameReadOnly: false,
      publicRecordHidden: true,
      publicActionsDisabled: true,
      startOverDisabled: false
    });
    expect(identityCeremonyPresentation("awaiting-backup")).toEqual({
      generateDisabled: true,
      keynameReadOnly: true,
      publicRecordHidden: true,
      publicActionsDisabled: true,
      startOverDisabled: false
    });
    expect(identityCeremonyPresentation("verifying-backup")).toEqual({
      generateDisabled: true,
      keynameReadOnly: true,
      publicRecordHidden: true,
      publicActionsDisabled: true,
      startOverDisabled: true
    });
    expect(identityCeremonyPresentation("verified")).toEqual({
      generateDisabled: true,
      keynameReadOnly: true,
      publicRecordHidden: false,
      publicActionsDisabled: false,
      startOverDisabled: false
    });
  });

  it("blocks navigation until the active identity ceremony confirms release", () => {
    clearNavigationGuard();
    const removeBlockingGuard = setNavigationGuard(() => false);
    expect(confirmNavigationAway()).toBe(false);
    removeBlockingGuard();
    expect(confirmNavigationAway()).toBe(true);

    const removeConfirmingGuard = setNavigationGuard(() => true);
    expect(confirmNavigationAway()).toBe(true);
    removeConfirmingGuard();
    clearNavigationGuard();
  });

  it("requires recipient confirmation and exposes portable evidence actions", async () => {
    const source = await readFile(join(process.cwd(), "src/ui/DropBottle.ts"), "utf8");

    expect(source).toContain("confirm-recipient-fingerprint");
    expect(source).toContain("separate trusted channel");
    expect(source).toContain("Open Evidence");
    expect(source).toContain("Copy Evidence URL");
    expect(source).toContain("Download Evidence JSON");
    expect(source).toContain("Retry Keyring Load");
    const meterSource = source.match(/const messageMeter[\s\S]*?const messageField/)?.[0] ?? "";
    expect(meterSource).not.toContain("aria-live");
  });

  it("masks pasted identities and exposes the self-published release boundary", async () => {
    const openSource = await readFile(join(process.cwd(), "src/ui/OpenBottles.ts"), "utf8");
    const mainSource = await readFile(join(process.cwd(), "src/main.ts"), "utf8");

    expect(openSource).toContain('type: "password"');
    expect(openSource).toContain("clipboard history may retain secrets");
    expect(openSource).toContain("Fetch Next Candidate Page");
    expect(mainSource).toContain("/release-manifest.json");
    expect(mainSource).toContain("not independent attestation");
    expect(mainSource).toContain("confirmNavigationAway");
  });

  it("attributes only local identity failures to the private identity control", () => {
    expect(shouldMarkIdentityInvalid("identity")).toBe(true);
    expect(shouldMarkIdentityInvalid("selection")).toBe(false);
    expect(shouldMarkIdentityInvalid("lookup")).toBe(false);
  });
});
