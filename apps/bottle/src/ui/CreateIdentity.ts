import {
  fingerprintKeyRecordInput,
  generateIdentity,
  verifyPrivateIdentityMatchesKeyRecord
} from "../crypto/ageAdapter";
import { SCHEMAS, type KeyRecord } from "../domain/types";
import {
  MAX_PRIVATE_IDENTITY_BYTES,
  normalizeKeyname,
  safeKeynameForFilename
} from "../domain/validation";
import {
  copyButton,
  downloadTextFile,
  h,
  labeledField,
  renderJsonBlock,
  setBusy,
  setStatus,
  statusRegion,
  warning
} from "./dom";
import { setNavigationGuard } from "./navigationGuard";

export type IdentityCeremonyPhase =
  | "idle"
  | "generating"
  | "awaiting-backup"
  | "verifying-backup"
  | "verified";

export type IdentityCeremonyPresentation = {
  generateDisabled: boolean;
  keynameReadOnly: boolean;
  publicRecordHidden: boolean;
  publicActionsDisabled: boolean;
  startOverDisabled: boolean;
};

export function identityCeremonyPresentation(
  phase: IdentityCeremonyPhase
): IdentityCeremonyPresentation {
  return {
    generateDisabled: phase !== "idle",
    keynameReadOnly: phase !== "idle",
    publicRecordHidden: phase !== "verified",
    publicActionsDisabled: phase !== "verified",
    startOverDisabled: phase === "generating" || phase === "verifying-backup"
  };
}

export function renderCreateIdentity(container: HTMLElement): void {
  const keynameInput = h("input", {
    attrs: {
      id: "identity-keyname",
      name: "keyname",
      autocomplete: "off",
      autocapitalize: "none",
      spellcheck: "false",
      minlength: "3",
      maxlength: "64",
      required: "",
      placeholder: "daylight/chase"
    }
  });
  const submit = h("button", { text: "Generate Identity", attrs: { type: "submit" } });
  const status = statusRegion();
  const output = h("div", {
    className: "output-stack",
    attrs: { "aria-label": "Generated identity results" }
  });
  const form = h("form", { className: "panel-form" }, [
    labeledField(
      "Public keyname",
      keynameInput,
      "Use 3–64 lowercase letters, digits, '.', '_', '/', or '-'. Do not use '..', '//', spaces, or a leading or trailing slash. The keyname is public."
    ),
    submit
  ]);
  let phase: IdentityCeremonyPhase = "idle";
  let publicActions: HTMLButtonElement[] = [];
  let publicRecordSection: HTMLElement | null = null;
  let approvalSection: HTMLElement | null = null;
  let privateIdentity: string | null = null;
  let ceremonyRevision = 0;
  let removeNavigationGuard: (() => void) | null = null;
  let startOverAction: HTMLButtonElement | null = null;
  let cancelStartOverAction: HTMLButtonElement | null = null;
  let confirmStartOverAction: HTMLButtonElement | null = null;
  let startOverConfirmation: HTMLElement | null = null;

  const handleBeforeUnload = (event: BeforeUnloadEvent): void => {
    if (phase !== "idle") {
      event.preventDefault();
      // Required for browsers that still gate beforeunload prompts on returnValue.
      // eslint-disable-next-line @typescript-eslint/no-deprecated
      event.returnValue = "";
    }
  };

  const releaseLeaveGuard = (): void => {
    removeNavigationGuard?.();
    removeNavigationGuard = null;
    window.removeEventListener("beforeunload", handleBeforeUnload);
  };

  const clearActiveCeremony = (): void => {
    ceremonyRevision += 1;
    privateIdentity = null;
    phase = "idle";
    releaseLeaveGuard();
  };

  const armLeaveGuard = (): void => {
    if (removeNavigationGuard) {
      return;
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    removeNavigationGuard = setNavigationGuard(() => {
      if (phase === "idle") {
        return true;
      }
      const confirmed = window.confirm(
        "Leave this identity ceremony? The generated identity and in-page public record will be cleared. Continue only after saving the private identity and any public record you need."
      );
      if (confirmed) {
        clearActiveCeremony();
      }
      return confirmed;
    });
  };

  const syncCeremony = (): void => {
    const presentation = identityCeremonyPresentation(phase);
    submit.disabled = presentation.generateDisabled;
    keynameInput.readOnly = presentation.keynameReadOnly;
    for (const action of publicActions) {
      action.disabled = presentation.publicActionsDisabled;
    }
    if (publicRecordSection) {
      publicRecordSection.hidden = presentation.publicRecordHidden;
    }
    if (approvalSection) {
      approvalSection.hidden = presentation.publicRecordHidden;
    }
    if (startOverAction) {
      startOverAction.disabled = presentation.startOverDisabled;
    }
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (phase !== "idle") {
      setStatus(
        status,
        "Finish or explicitly start over from the active identity ceremony before generating another identity.",
        "error"
      );
      return;
    }
    keynameInput.removeAttribute("aria-invalid");
    output.replaceChildren();
    const activeRevision = ++ceremonyRevision;
    phase = "generating";
    armLeaveGuard();
    syncCeremony();
    setBusy(form, true);
    setBusy(output, true);
    setStatus(status, "Generating an age identity locally in this browser...");

    try {
      const keyname = normalizeKeyname(keynameInput.value);
      keynameInput.value = keyname;
      const generated = await generateIdentity();
      if (activeRevision !== ceremonyRevision) {
        return;
      }
      privateIdentity = generated.privateIdentity;
      const fingerprint = await fingerprintKeyRecordInput({
        keyname,
        publicRecipient: generated.publicRecipient
      });
      if (activeRevision !== ceremonyRevision) {
        return;
      }
      const keyRecord: KeyRecord = {
        schema: SCHEMAS.key,
        keyname,
        publicRecipient: generated.publicRecipient,
        fingerprint,
        createdAt: new Date().toISOString(),
        status: "active"
      };

      const download = h("button", {
        text: "Download Private Identity",
        attrs: { type: "button" }
      });
      download.addEventListener("click", () => {
        if (privateIdentity === null) {
          return;
        }
        downloadTextFile(
          `${privateIdentity}\n`,
          `daylight-bottle-${safeKeynameForFilename(keyname)}-identity.txt`
        );
        setStatus(
          status,
          "Private identity download requested. Your browser cannot prove the file was saved; verify the saved file below.",
          "info"
        );
      });

      const serializedKeyRecord = JSON.stringify(keyRecord, null, 2);
      const copyPublicRecord = copyButton(serializedKeyRecord, "Copy Public Key Record");
      const downloadPublicRecord = h("button", {
        className: "button-secondary button-compact",
        text: "Download Public Key Record",
        attrs: { type: "button" }
      });
      publicActions = [copyPublicRecord, downloadPublicRecord];
      downloadPublicRecord.addEventListener("click", () => {
        downloadTextFile(
          `${serializedKeyRecord}\n`,
          `daylight-bottle-${safeKeynameForFilename(keyname)}-public-key.json`
        );
      });

      const backupInput = h("input", {
        attrs: {
          id: "verify-identity-file",
          name: "verifyIdentityFile",
          type: "file",
          accept: ".txt,text/plain"
        }
      });
      const backupStatus = statusRegion();
      backupInput.addEventListener("change", async () => {
        const file = backupInput.files?.[0];
        backupInput.removeAttribute("aria-invalid");
        if (!file || privateIdentity === null) {
          return;
        }
        const verificationRevision = ceremonyRevision;
        phase = "verifying-backup";
        if (startOverConfirmation) {
          startOverConfirmation.hidden = true;
        }
        if (cancelStartOverAction) {
          cancelStartOverAction.disabled = true;
        }
        if (confirmStartOverAction) {
          confirmStartOverAction.disabled = true;
        }
        syncCeremony();
        backupInput.disabled = true;
        setStatus(backupStatus, "Verifying the saved identity locally...");
        if (file.size > MAX_PRIVATE_IDENTITY_BYTES) {
          backupInput.value = "";
          backupInput.disabled = false;
          backupInput.setAttribute("aria-invalid", "true");
          phase = "awaiting-backup";
          syncCeremony();
          if (cancelStartOverAction) {
            cancelStartOverAction.disabled = false;
          }
          if (confirmStartOverAction) {
            confirmStartOverAction.disabled = false;
          }
          setStatus(backupStatus, "That file is too large to be a Daylight Bottle identity.", "error");
          return;
        }

        try {
          const savedIdentity = await file.text();
          if (verificationRevision !== ceremonyRevision) {
            return;
          }
          await verifyPrivateIdentityMatchesKeyRecord({
            privateIdentity: savedIdentity,
            keyname,
            expectedPublicRecipient: keyRecord.publicRecipient,
            expectedFingerprint: keyRecord.fingerprint
          });
          if (verificationRevision !== ceremonyRevision) {
            return;
          }
          phase = "verified";
          syncCeremony();
          setStatus(
            backupStatus,
            "Saved identity verified locally. The public key record is now ready for the manual approval process.",
            "success"
          );
          publicActions[0]?.focus();
        } catch (error) {
          if (verificationRevision !== ceremonyRevision) {
            return;
          }
          phase = "awaiting-backup";
          syncCeremony();
          backupInput.setAttribute("aria-invalid", "true");
          setStatus(
            backupStatus,
            error instanceof Error ? error.message : "The saved identity could not be verified.",
            "error"
          );
        } finally {
          if (verificationRevision === ceremonyRevision) {
            backupInput.value = "";
            backupInput.disabled = phase === "verified";
            if (cancelStartOverAction) {
              cancelStartOverAction.disabled = false;
            }
            if (confirmStartOverAction) {
              confirmStartOverAction.disabled = false;
            }
            syncCeremony();
          }
        }
      });

      const startOver = h("button", {
        className: "button-secondary",
        text: "Start Over",
        attrs: { type: "button" }
      });
      startOverAction = startOver;
      const cancelStartOver = h("button", {
        className: "button-secondary button-compact",
        text: "Cancel",
        attrs: { type: "button" }
      });
      cancelStartOverAction = cancelStartOver;
      const confirmStartOver = h("button", {
        text: "Confirm Start Over",
        attrs: { type: "button" }
      });
      confirmStartOverAction = confirmStartOver;
      const startOverConfirmationElement = h("div", {
        className: "start-over-confirmation",
        attrs: {
          hidden: "",
          role: "group",
          "aria-label": "Confirm starting over"
        }
      }, [
        warning(
          "Starting over removes access to this generated identity from the page. Continue only after verifying the saved private file."
        ),
        h("div", { className: "action-group" }, [cancelStartOver, confirmStartOver])
      ]);
      startOverConfirmation = startOverConfirmationElement;
      startOver.addEventListener("click", () => {
        startOver.disabled = true;
        startOverConfirmationElement.hidden = false;
        confirmStartOver.focus();
      });
      cancelStartOver.addEventListener("click", () => {
        startOverConfirmationElement.hidden = true;
        startOver.disabled = false;
        startOver.focus();
      });
      confirmStartOver.addEventListener("click", () => {
        clearActiveCeremony();
        publicActions = [];
        publicRecordSection = null;
        approvalSection = null;
        startOverAction = null;
        cancelStartOverAction = null;
        confirmStartOverAction = null;
        startOverConfirmation = null;
        output.replaceChildren();
        syncCeremony();
        setStatus(
          status,
          "The identity ceremony was cleared from this page. This is not proof of secure memory erasure.",
          "info"
        );
        keynameInput.focus();
      });

      publicRecordSection = h("section", { className: "result-section", attrs: { hidden: "" } }, [
        h("div", { className: "result-heading" }, [
          h("h3", { text: "3. Export the Public Key Record" }),
          h("div", { className: "action-group" }, publicActions)
        ]),
        h("p", {
          text: "Only this public record may leave your device. It contains no private identity material."
        }),
        renderJsonBlock(keyRecord, "Public key record JSON")
      ]);
      approvalSection = h("section", { className: "result-section", attrs: { hidden: "" } }, [
        h("h3", { text: "4. Request Manual Keyring Approval" }),
        h("p", {
          text: "Key activation is currently closed and operator-only. If the site owner has invited a record, deliver only the exported public JSON through an authenticated channel you already trust. The owner must review it before adding it to /keyring.json; this app has no public registration endpoint."
        }),
        h("details", {}, [
          h("summary", { text: "Read the Manual Keyring Procedure" }),
          h("ol", {}, [
            h("li", { text: "Transfer only the exported public JSON through an authenticated channel you already trust." }),
            h("li", { text: "The site owner recomputes its fingerprint and checks the schema, keyname, status, and directory uniqueness." }),
            h("li", { text: "The owner edits /keyring.json, runs the complete release gate, deploys, and verifies the live fingerprint before announcing activation." }),
            h("li", { text: "Never send the private identity, its file, or its contents to the owner." })
          ])
        ])
      ]);

      output.replaceChildren(
        warning(
          "Save this private identity file. If you lose it, bottles encrypted to this key cannot be opened. If someone else gets it, they can open your bottles."
        ),
        h("section", { className: "result-section" }, [
          h("h3", { text: "1. Save the Private Identity" }),
          h("p", {
            text: "Keep this local. Do not upload it, paste it into support requests, or share it. A download request does not prove the file was saved."
          }),
          download
        ]),
        h("section", { className: "result-section" }, [
          h("h3", { text: "2. Verify the Saved Identity" }),
          h("p", {
            text: "Re-import the file you saved. Verification happens locally and does not upload the identity."
          }),
          labeledField(
            "Saved private identity file",
            backupInput,
            "Public-record actions unlock only after this file derives the expected public recipient and fingerprint."
          ),
          backupStatus
        ]),
        publicRecordSection,
        approvalSection,
        startOver,
        startOverConfirmationElement
      );
      phase = "awaiting-backup";
      syncCeremony();
      setStatus(
        status,
        "Identity generated locally. Save and verify the private file before exporting the public record. No identity material was uploaded.",
        "success"
      );
    } catch (error) {
      if (activeRevision !== ceremonyRevision) {
        return;
      }
      clearActiveCeremony();
      syncCeremony();
      keynameInput.setAttribute("aria-invalid", "true");
      keynameInput.focus();
      setStatus(status, error instanceof Error ? error.message : "Identity generation failed.", "error");
    } finally {
      syncCeremony();
      setBusy(form, false);
      setBusy(output, false);
    }
  });

  container.replaceChildren(
    h("section", { className: "view" }, [
      h("h2", { text: "Create Identity" }),
      h("p", {
        text: "Generate a local age identity and a public key record for the static keyring."
      }),
      warning("Your keyname is public. Your private identity is secret."),
      form,
      status,
      output
    ])
  );
}
