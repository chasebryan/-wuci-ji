import { listBottles, loadKeyring } from "../api/client";
import {
  decryptBottlePayloadForRecipient,
  verifyPrivateIdentityMatchesKeyRecord
} from "../crypto/ageAdapter";
import type { KeyRecord, PlainBottlePayload, StoredBottlePublic } from "../domain/types";
import { MAX_PRIVATE_IDENTITY_BYTES } from "../domain/validation";
import {
  copyButton,
  h,
  labeledField,
  setBusy,
  setStatus,
  statusRegion,
  timeElement,
  warning
} from "./dom";

const textEncoder = new TextEncoder();

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
  const identityInput = h("textarea", {
    className: "private-identity-input",
    attrs: {
      id: "private-identity",
      name: "privateIdentity",
      rows: "5",
      autocomplete: "off",
      autocapitalize: "none",
      spellcheck: "false",
      required: "",
      placeholder: "Paste AGE-SECRET-KEY-1... here, or import the private identity file."
    }
  });
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
    labeledField(
      "Private identity",
      identityInput,
      "This value stays in this browser, is cleared from the form before lookup, and is never uploaded."
    ),
    labeledField(
      "Import identity file",
      fileInput,
      `Plain-text identity files are limited to ${formatBytes(MAX_PRIVATE_IDENTITY_BYTES)}.`
    ),
    submit
  ]);

  let availableKeys: KeyRecord[] = [];
  let busy = true;

  const selectedKey = (): KeyRecord | undefined =>
    availableKeys.find((key) => key.fingerprint === keySelect.value);

  const syncControls = (): void => {
    keySelect.disabled = busy || availableKeys.length === 0;
    identityInput.readOnly = busy;
    fileInput.disabled = busy;
    submit.disabled = busy || selectedKey() === undefined;
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
            h("code", { className: "code-value fingerprint", text: selected.fingerprint }),
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
    if (!file) {
      return;
    }

    identityInput.value = "";
    if (file.size > MAX_PRIVATE_IDENTITY_BYTES) {
      fileInput.value = "";
      identityInput.setAttribute("aria-invalid", "true");
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
      setStatus(status, "Private identity imported locally. It has not been uploaded.", "success");
    } catch (error) {
      identityInput.value = "";
      fileInput.value = "";
      identityInput.setAttribute("aria-invalid", "true");
      setStatus(status, error instanceof Error ? error.message : "Could not read the identity file.", "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const selected = selectedKey();
    const privateIdentity = identityInput.value;
    identityInput.value = "";
    fileInput.value = "";
    keySelect.removeAttribute("aria-invalid");
    identityInput.removeAttribute("aria-invalid");
    output.replaceChildren();
    busy = true;
    syncControls();
    setBusy(output, true);
    setStatus(status, "Checking the private identity locally...");

    try {
      if (!selected) {
        keySelect.setAttribute("aria-invalid", "true");
        keySelect.focus();
        throw new Error("Choose a recipient key record.");
      }
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

      setStatus(status, "Identity matched locally. Fetching candidate ciphertext bottles...");
      const response = await listBottles(selected.fingerprint);
      if (response.bottles.length === 0) {
        setStatus(status, "No candidate ciphertext bottles were returned for this fingerprint.");
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
          `None of the ${response.bottles.length} candidate bottle(s) opened locally. The server was not told the result.`,
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
        failed > 0
          ? `Opened ${opened.length} bottle(s) locally; ${failed} candidate(s) did not open.`
          : `Opened ${opened.length} bottle(s) locally.`,
        "success"
      );
    } catch (error) {
      identityInput.setAttribute("aria-invalid", "true");
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

  try {
    setStatus(status, "Loading /keyring.json...");
    const keyring = await loadKeyring();
    availableKeys = keyring.keys;
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
      setStatus(status, "The static keyring has no recipient records yet.", "error");
      return;
    }

    setStatus(status, `Loaded ${availableKeys.length} recipient key record(s). Choose one to continue.`, "success");
  } catch (error) {
    busy = false;
    syncControls();
    setStatus(status, error instanceof Error ? error.message : "Could not load keyring.", "error");
  }
}

function shortFingerprint(fingerprint: string): string {
  return `${fingerprint.slice(0, 15)}…${fingerprint.slice(-8)}`;
}

function formatBytes(bytes: number): string {
  return `${Math.ceil(bytes / 1024)} KiB`;
}
