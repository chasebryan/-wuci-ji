import { listBottlePage, loadKeyring } from "../api/client";
import {
  decryptBottlePayloadForRecipient,
  verifyPrivateIdentityMatchesKeyRecord
} from "../crypto/ageAdapter";
import type { KeyRecord, PlainBottlePayload, StoredBottlePublic } from "../domain/types";
import { MAX_PRIVATE_IDENTITY_BYTES } from "../domain/validation";
import {
  copyButton,
  formatFingerprint,
  h,
  labeledField,
  setBusy,
  setStatus,
  statusRegion,
  timeElement,
  warning
} from "./dom";

const textEncoder = new TextEncoder();

export type OpenFailureStage = "selection" | "identity" | "lookup";

export function shouldMarkIdentityInvalid(stage: OpenFailureStage): boolean {
  return stage === "identity";
}

export async function renderOpenBottles(container: HTMLElement): Promise<void> {
  const keySelect = h("select", {
    attrs: {
      id: "open-keyname",
      name: "recipientFingerprint",
      required: "",
      disabled: ""
    }
  });
  const recipientDetails = h("div", {
    className: "recipient-details",
    attrs: { "aria-live": "polite", "aria-atomic": "true" }
  });
  const identityInput = h("input", {
    className: "private-identity-input",
    attrs: {
      id: "private-identity",
      name: "privateIdentity",
      type: "password",
      autocomplete: "off",
      autocapitalize: "none",
      spellcheck: "false",
      required: "",
      placeholder: "Paste AGE-SECRET-KEY-1... here, or import the private identity file."
    }
  });
  const revealIdentity = h("button", {
    className: "button-secondary button-compact",
    text: "Show Identity",
    attrs: {
      type: "button",
      "aria-controls": "private-identity",
      "aria-pressed": "false"
    }
  });
  revealIdentity.addEventListener("click", () => {
    const reveal = identityInput.type === "password";
    identityInput.type = reveal ? "text" : "password";
    revealIdentity.textContent = reveal ? "Hide Identity" : "Show Identity";
    revealIdentity.setAttribute("aria-pressed", reveal ? "true" : "false");
  });
  const identityField = labeledField(
    "Private identity",
    identityInput,
    "Prefer file import. Pasted values are masked, but clipboard history may retain secrets. The identity stays in this browser, is cleared before lookup, and is never uploaded."
  );
  identityField.append(revealIdentity);
  const fileInput = h("input", {
    attrs: {
      id: "identity-file",
      name: "identityFile",
      type: "file",
      accept: ".txt,text/plain"
    }
  });
  const status = statusRegion();
  const output = h("div", {
    className: "output-stack",
    attrs: { "aria-label": "Locally opened bottles" }
  });
  const submit = h("button", {
    text: "Fetch and Open Bottles",
    attrs: { type: "submit", disabled: "" }
  });
  const form = h("form", { className: "panel-form", attrs: { "aria-busy": "true" } }, [
    labeledField(
      "Recipient key record",
      keySelect,
      "Revoked records remain available here so their historical bottles can still be opened."
    ),
    recipientDetails,
    identityField,
    labeledField(
      "Import identity file",
      fileInput,
      `Plain-text identity files are limited to ${formatBytes(MAX_PRIVATE_IDENTITY_BYTES)}.`
    ),
    submit
  ]);

  let availableKeys: KeyRecord[] = [];
  let busy = true;
  let nextCursor: string | undefined;
  let cursorFingerprint: string | undefined;

  const selectedKey = (): KeyRecord | undefined =>
    availableKeys.find((key) => key.fingerprint === keySelect.value);

  const syncControls = (): void => {
    const selected = selectedKey();
    keySelect.disabled = busy || availableKeys.length === 0;
    identityInput.readOnly = busy;
    fileInput.disabled = busy;
    submit.disabled = busy || selected === undefined;
    submit.textContent =
      selected && cursorFingerprint === selected.fingerprint && nextCursor
        ? "Fetch Next Candidate Page"
        : "Fetch and Open Bottles";
    setBusy(form, busy);
  };

  const updateRecipientDetails = (): void => {
    const selected = selectedKey();
    if (!selected) {
      recipientDetails.replaceChildren(h("p", { className: "muted", text: "Choose the public key record that matches your private identity." }));
      syncControls();
      return;
    }

    const children: Node[] = [];
    if (selected.status === "revoked") {
      children.push(
        warning("This key is revoked for new bottles, but its matching private identity can still open historical bottles.")
      );
    }
    children.push(
      h("dl", { className: "metadata-list" }, [
        h("dt", { text: "Keyname" }),
        h("dd", { text: selected.keyname }),
        h("dt", { text: "Status" }),
        h("dd", { text: selected.status }),
        h("dt", { text: "Fingerprint" }),
        h("dd", {}, [
          h("div", { className: "inline-copy" }, [
            h("code", { className: "code-value fingerprint", text: formatFingerprint(selected.fingerprint) }),
            copyButton(selected.fingerprint, "Copy Fingerprint")
          ])
        ])
      ])
    );
    recipientDetails.replaceChildren(...children);
    syncControls();
  };

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    identityInput.removeAttribute("aria-invalid");
    fileInput.removeAttribute("aria-invalid");
    if (!file) {
      return;
    }

    identityInput.value = "";
    if (file.size > MAX_PRIVATE_IDENTITY_BYTES) {
      fileInput.value = "";
      fileInput.setAttribute("aria-invalid", "true");
      setStatus(
        status,
        `The identity file is ${formatBytes(file.size)}, above the ${formatBytes(MAX_PRIVATE_IDENTITY_BYTES)} limit.`,
        "error"
      );
      fileInput.focus();
      return;
    }

    try {
      const privateIdentity = await file.text();
      fileInput.value = "";
      if (textEncoder.encode(privateIdentity).byteLength > MAX_PRIVATE_IDENTITY_BYTES) {
        throw new Error(`The decoded identity exceeds the ${formatBytes(MAX_PRIVATE_IDENTITY_BYTES)} limit.`);
      }
      identityInput.value = privateIdentity;
      identityInput.type = "password";
      revealIdentity.textContent = "Show Identity";
      revealIdentity.setAttribute("aria-pressed", "false");
      setStatus(status, "Private identity imported locally. It has not been uploaded.", "success");
    } catch (error) {
      identityInput.value = "";
      fileInput.value = "";
      fileInput.setAttribute("aria-invalid", "true");
      setStatus(status, error instanceof Error ? error.message : "Could not read the identity file.", "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const selected = selectedKey();
    const privateIdentity = identityInput.value;
    identityInput.value = "";
    identityInput.type = "password";
    revealIdentity.textContent = "Show Identity";
    revealIdentity.setAttribute("aria-pressed", "false");
    fileInput.value = "";
    keySelect.removeAttribute("aria-invalid");
    identityInput.removeAttribute("aria-invalid");
    output.replaceChildren();
    busy = true;
    syncControls();
    setBusy(output, true);
    setStatus(status, "Checking the private identity locally...");
    let failureStage: OpenFailureStage = "selection";

    try {
      if (!selected) {
        keySelect.setAttribute("aria-invalid", "true");
        keySelect.focus();
        throw new Error("Choose a recipient key record.");
      }
      failureStage = "identity";
      if (privateIdentity.trim().length === 0) {
        identityInput.setAttribute("aria-invalid", "true");
        identityInput.focus();
        throw new Error("Paste or import the private identity for this key record.");
      }
      if (textEncoder.encode(privateIdentity).byteLength > MAX_PRIVATE_IDENTITY_BYTES) {
        identityInput.setAttribute("aria-invalid", "true");
        identityInput.focus();
        throw new Error(`The private identity exceeds the ${formatBytes(MAX_PRIVATE_IDENTITY_BYTES)} limit.`);
      }

      await verifyPrivateIdentityMatchesKeyRecord({
        privateIdentity,
        keyname: selected.keyname,
        expectedPublicRecipient: selected.publicRecipient,
        expectedFingerprint: selected.fingerprint
      });

      failureStage = "lookup";
      setStatus(status, "Identity matched locally. Fetching candidate ciphertext bottles...");
      const requestCursor =
        cursorFingerprint === selected.fingerprint ? nextCursor : undefined;
      const page = await listBottlePage(selected.fingerprint, fetch, requestCursor);
      const response = page.response;
      nextCursor = page.nextCursor;
      cursorFingerprint = selected.fingerprint;
      if (response.bottles.length === 0) {
        setStatus(
          status,
          nextCursor
            ? "This candidate page contained no unexpired bottles. More pages remain; re-import the identity to fetch the next page."
            : "No candidate ciphertext bottles were returned. A recently accepted bottle may take a short time to become visible; re-import the identity and retry."
        );
        return;
      }

      const opened: Array<{ bottle: StoredBottlePublic; payload: PlainBottlePayload }> = [];
      let failed = 0;
      for (const bottle of response.bottles) {
        try {
          if (
            bottle.keyname !== selected.keyname ||
            bottle.recipientFingerprint !== selected.fingerprint
          ) {
            throw new Error("Bottle metadata does not match the selected key record.");
          }
          const payload = await decryptBottlePayloadForRecipient({
            ciphertext: bottle.ciphertext,
            privateIdentity,
            expectedKeyname: selected.keyname,
            expectedRecipientFingerprint: selected.fingerprint
          });
          opened.push({ bottle, payload });
        } catch {
          failed += 1;
          // Decrypt outcomes remain local and are never sent back to the server.
        }
      }

      if (opened.length === 0) {
        setStatus(
          status,
          nextCursor
            ? `None of the ${response.bottles.length} candidate bottle(s) on this page opened locally. More pages remain; re-import the identity to continue. The server was not told the result.`
            : `None of the ${response.bottles.length} candidate bottle(s) opened locally. The server was not told the result.`,
          "error"
        );
        return;
      }

      const clear = h("button", {
        className: "button-secondary button-compact",
        text: "Clear Opened Messages",
        attrs: { type: "button" }
      });
      clear.addEventListener("click", () => {
        output.replaceChildren();
        setStatus(status, "Decrypted messages cleared from this page.");
      });

      const resultNodes: Node[] = [
        h("div", { className: "result-heading" }, [
          h("h3", { text: `Opened ${opened.length} bottle(s)` }),
          clear
        ])
      ];
      if (failed > 0) {
        resultNodes.push(
          warning(
            `${failed} candidate bottle(s) failed metadata validation or decryption locally. That result was not reported to the server.`
          )
        );
      }
      if (nextCursor) {
        resultNodes.push(
          warning(
            "More candidate pages remain. Re-import the private identity and use Fetch Next Candidate Page to continue; pagination does not reveal local decrypt results to the server."
          )
        );
      }
      resultNodes.push(
        ...opened.map(({ bottle, payload }) =>
          h("article", { className: "message-item" }, [
            h("header", { className: "message-header" }, [
              h("h3", { text: `Bottle ${bottle.bottleId}` }),
              h("p", { className: "message-timestamps" }, [
                "Created ",
                timeElement(payload.createdAt),
                " · stored ",
                timeElement(bottle.storedAt)
              ])
            ]),
            h("p", { className: "message-body", text: payload.message }),
            h("dl", { className: "metadata-list" }, [
              h("dt", { text: "Ciphertext SHA-256" }),
              h("dd", {}, [h("code", { className: "code-value", text: bottle.ciphertextSha256 })]),
              h("dt", { text: "Expires at" }),
              h("dd", {}, [timeElement(bottle.expiresAt)])
            ])
          ])
        )
      );
      output.replaceChildren(...resultNodes);
      setStatus(
        status,
        nextCursor
          ? `Opened ${opened.length} bottle(s) locally on this page; more candidate pages remain.`
          : failed > 0
            ? `Opened ${opened.length} bottle(s) locally; ${failed} candidate(s) did not open.`
            : `Opened ${opened.length} bottle(s) locally.`,
        "success"
      );
    } catch (error) {
      if (shouldMarkIdentityInvalid(failureStage)) {
        identityInput.setAttribute("aria-invalid", "true");
        identityInput.focus();
      } else {
        identityInput.removeAttribute("aria-invalid");
      }
      setStatus(
        status,
        `${error instanceof Error ? error.message : "Could not open bottles."} The private identity was cleared from the form.`,
        "error"
      );
    } finally {
      busy = false;
      syncControls();
      setBusy(output, false);
    }
  });

  keySelect.addEventListener("change", () => {
    nextCursor = undefined;
    cursorFingerprint = undefined;
    keySelect.removeAttribute("aria-invalid");
    updateRecipientDetails();
    if (selectedKey()) {
      setStatus(status, "Key record selected. Import its matching private identity to continue.");
    }
  });

  container.replaceChildren(
    h("section", { className: "view" }, [
      h("h2", { text: "Open Bottles" }),
      h("p", {
        className: "view-intro",
        text: "Fetch candidate ciphertexts by fingerprint and try decryption locally. The server is not told which bottles open."
      }),
      warning("Your private identity must not be uploaded or shared."),
      form,
      status,
      output
    ])
  );
  form.hidden = true;

  const loadKeyRecords = async (focusAfterLoad = false): Promise<void> => {
    busy = true;
    availableKeys = [];
    form.hidden = true;
    output.replaceChildren();
    syncControls();
    setStatus(status, "Loading /keyring.json...");
    try {
      const keyring = await loadKeyring();
      availableKeys = keyring.keys;
      nextCursor = undefined;
      cursorFingerprint = undefined;
      keySelect.replaceChildren(
        h("option", { text: "Choose a key record…", attrs: { value: "" } }),
        ...availableKeys.map((key) =>
          h("option", {
            text: `${key.keyname} — ${key.status} — ${shortFingerprint(key.fingerprint)}`,
            attrs: { value: key.fingerprint }
          })
        )
      );

      busy = false;
      updateRecipientDetails();
      if (availableKeys.length === 0) {
        const createIdentityAction = h("a", {
          className: "button-link",
          text: "Create an Identity",
          attrs: { href: "#create" }
        });
        form.hidden = true;
        output.replaceChildren(
          h("section", { className: "empty-state" }, [
            h("h3", { text: "No approved recipient records yet" }),
            h("p", {
              text: "Opening requires a public keyring record that can be matched to your private identity. Create and verify an identity, then request manual owner approval of its public record."
            }),
            h("div", { className: "action-group" }, [
              createIdentityAction,
              h("a", {
                className: "button-link button-secondary",
                text: "Read the Manual Keyring Procedure",
                attrs: { href: "#threat" }
              })
            ])
          ])
        );
        setStatus(status, "Waiting for the first manually approved public recipient record.");
        if (focusAfterLoad) {
          createIdentityAction.focus();
        }
        return;
      }

      form.hidden = false;
      setStatus(status, `Loaded ${availableKeys.length} recipient key record(s). Choose one to continue.`, "success");
      if (focusAfterLoad) {
        keySelect.focus();
      }
    } catch (error) {
      busy = false;
      syncControls();
      const message = error instanceof Error ? error.message : "Could not load keyring.";
      const retry = h("button", { text: "Retry Keyring Load", attrs: { type: "button" } });
      retry.addEventListener("click", () => {
        void loadKeyRecords(true);
      });
      output.replaceChildren(
        h("section", {
          className: "empty-state empty-state-error",
          attrs: { role: "group", "aria-labelledby": "open-keyring-error-title" }
        }, [
          h("h3", { text: "Recipient directory unavailable", attrs: { id: "open-keyring-error-title" } }),
          h("p", {
            text: "No private identity was read. Retry the same-origin public keyring before selecting or importing an identity."
          }),
          retry
        ])
      );
      setStatus(status, message, "error");
      if (focusAfterLoad) {
        retry.focus();
      }
    }
  };

  await loadKeyRecords();
}

function shortFingerprint(fingerprint: string): string {
  return `${fingerprint.slice(0, 15)}…${fingerprint.slice(-8)}`;
}

function formatBytes(bytes: number): string {
  return `${Math.ceil(bytes / 1024)} KiB`;
}
