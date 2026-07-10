import { dropBottle, loadKeyring } from "../api/client";
import { encryptBottlePayload } from "../crypto/ageAdapter";
import { SCHEMAS, type DropBottleRequest, type KeyRecord, type PlainBottlePayload } from "../domain/types";
import { MAX_DROP_BODY_BYTES, normalizeKeyname } from "../domain/validation";
import {
  copyButton,
  h,
  labeledField,
  renderJsonBlock,
  setBusy,
  setStatus,
  statusRegion,
  timeElement,
  warning
} from "./dom";

const textEncoder = new TextEncoder();

export async function renderDropBottle(container: HTMLElement): Promise<void> {
  const keySelect = h("select", {
    attrs: {
      id: "drop-keyname",
      name: "recipientFingerprint",
      required: "",
      disabled: ""
    }
  });
  const messageInput = h("textarea", {
    attrs: {
      id: "drop-message",
      name: "message",
      rows: "8",
      required: "",
      placeholder: "Write the bottle message here. It will be encrypted locally before upload."
    }
  });
  const status = statusRegion();
  const recipientDetails = h("div", {
    className: "recipient-details",
    attrs: { "aria-live": "polite", "aria-atomic": "true" }
  });
  const output = h("div", { className: "output-stack", attrs: { "aria-label": "Bottle result" } });
  const submit = h("button", {
    text: "Encrypt and Drop Bottle",
    attrs: { type: "submit", disabled: "" }
  });
  const form = h("form", { className: "panel-form", attrs: { "aria-busy": "true" } }, [
    labeledField("Recipient keyname", keySelect, "Choose explicitly, then verify the displayed fingerprint through a trusted channel."),
    recipientDetails,
    labeledField("Message", messageInput, "The message is encrypted in this browser before any request is sent."),
    submit
  ]);

  let activeKeys: KeyRecord[] = [];
  let busy = true;

  const selectedKey = (): KeyRecord | undefined =>
    activeKeys.find((key) => key.fingerprint === keySelect.value);

  const syncControls = (): void => {
    keySelect.disabled = busy || activeKeys.length === 0;
    messageInput.readOnly = busy;
    submit.disabled = busy || selectedKey() === undefined;
    setBusy(form, busy);
  };

  const updateRecipientDetails = (): void => {
    const selected = selectedKey();
    if (!selected) {
      recipientDetails.replaceChildren(h("p", { className: "muted", text: "Choose a recipient to inspect its public key and fingerprint." }));
      syncControls();
      return;
    }

    recipientDetails.replaceChildren(
      warning(
        "Verify the recipient fingerprint before dropping a bottle. A swapped public key means the wrong person can decrypt the message."
      ),
      h("dl", { className: "metadata-list" }, [
        h("dt", { text: "Keyname" }),
        h("dd", { text: selected.keyname }),
        h("dt", { text: "Public recipient" }),
        h("dd", {}, [h("code", { className: "code-value", text: selected.publicRecipient })]),
        h("dt", { text: "Fingerprint" }),
        h("dd", {}, [
          h("div", { className: "inline-copy" }, [
            h("code", { className: "code-value fingerprint", text: selected.fingerprint }),
            copyButton(selected.fingerprint, "Copy Fingerprint")
          ])
        ])
      ])
    );
    syncControls();
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const selected = selectedKey();
    keySelect.removeAttribute("aria-invalid");
    messageInput.removeAttribute("aria-invalid");
    output.replaceChildren();
    busy = true;
    syncControls();
    setBusy(output, true);
    setStatus(status, "Encrypting locally...");

    try {
      if (!selected) {
        keySelect.setAttribute("aria-invalid", "true");
        keySelect.focus();
        throw new Error("Choose an active recipient from the keyring.");
      }

      const message = messageInput.value;
      if (message.length === 0) {
        messageInput.setAttribute("aria-invalid", "true");
        messageInput.focus();
        throw new Error("Message must not be empty.");
      }
      const plaintextBytes = textEncoder.encode(message).byteLength;
      if (plaintextBytes > MAX_DROP_BODY_BYTES) {
        messageInput.setAttribute("aria-invalid", "true");
        messageInput.focus();
        throw new Error(
          `The message is ${formatBytes(plaintextBytes)}, already above the ${formatBytes(MAX_DROP_BODY_BYTES)} request limit before encryption. Shorten it and try again.`
        );
      }

      const payload: PlainBottlePayload = {
        schema: SCHEMAS.payload,
        keyname: normalizeKeyname(selected.keyname),
        recipientFingerprint: selected.fingerprint,
        message,
        createdAt: new Date().toISOString()
      };
      const ciphertext = await encryptBottlePayload({
        payload,
        publicRecipient: selected.publicRecipient
      });
      const request: DropBottleRequest = {
        schema: SCHEMAS.drop,
        keyname: selected.keyname,
        recipientFingerprint: selected.fingerprint,
        ciphertext,
        createdAtClient: payload.createdAt
      };
      const requestBytes = textEncoder.encode(JSON.stringify(request)).byteLength;
      if (requestBytes > MAX_DROP_BODY_BYTES) {
        messageInput.setAttribute("aria-invalid", "true");
        messageInput.focus();
        throw new Error(
          `The encrypted request is ${formatBytes(requestBytes)}, above the ${formatBytes(MAX_DROP_BODY_BYTES)} limit. Shorten the message and try again.`
        );
      }

      setStatus(status, "Uploading ciphertext and public metadata...");
      const response = await dropBottle(request);
      const serializedEvidence = JSON.stringify(response.evidence, null, 2);
      output.replaceChildren(
        h("section", { className: "result-section" }, [
          h("div", { className: "result-heading" }, [
            h("h3", { text: "Bottle Accepted" }),
            copyButton(serializedEvidence, "Copy Evidence")
          ]),
          h("dl", { className: "metadata-list" }, [
            h("dt", { text: "Bottle id" }),
            h("dd", { text: response.bottleId }),
            h("dt", { text: "Stored at" }),
            h("dd", {}, [timeElement(response.storedAt)]),
            h("dt", { text: "Expires at" }),
            h("dd", {}, [timeElement(response.expiresAt)])
          ]),
          h("h3", { text: "Daylight Evidence" }),
          renderJsonBlock(response.evidence, "Daylight bottle evidence JSON")
        ])
      );
      messageInput.value = "";
      setStatus(status, "Bottle dropped. This app sent ciphertext and public metadata, not the message text.", "success");
    } catch (error) {
      setStatus(status, error instanceof Error ? error.message : "Bottle drop failed.", "error");
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
      setStatus(status, "Recipient selected. Verify its fingerprint before encrypting.");
    }
  });

  container.replaceChildren(
    h("section", { className: "view" }, [
      h("h2", { text: "Drop Bottle" }),
      h("p", {
        className: "view-intro",
        text: "Select a public recipient from /keyring.json, verify the fingerprint, and encrypt locally."
      }),
      form,
      status,
      output
    ])
  );

  try {
    setStatus(status, "Loading /keyring.json...");
    const keyring = await loadKeyring();
    activeKeys = keyring.keys.filter((key) => key.status === "active");
    keySelect.replaceChildren(
      h("option", { text: "Choose a recipient…", attrs: { value: "" } }),
      ...activeKeys.map((key) =>
        h("option", { text: key.keyname, attrs: { value: key.fingerprint } })
      )
    );

    busy = false;
    updateRecipientDetails();
    if (activeKeys.length === 0) {
      setStatus(status, "The static keyring has no active recipients yet.", "error");
      return;
    }

    setStatus(status, `Loaded ${activeKeys.length} active recipient key(s). Choose one to continue.`, "success");
  } catch (error) {
    busy = false;
    syncControls();
    setStatus(status, error instanceof Error ? error.message : "Could not load keyring.", "error");
  }
}

function formatBytes(bytes: number): string {
  return `${Math.ceil(bytes / 1024)} KiB`;
}
