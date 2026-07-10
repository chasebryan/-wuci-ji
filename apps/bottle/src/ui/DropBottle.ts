import { dropBottle, loadKeyring } from "../api/client";
import { encryptBottlePayload } from "../crypto/ageAdapter";
import { SCHEMAS, type DropBottleRequest, type KeyRecord, type PlainBottlePayload } from "../domain/types";
import { MAX_DROP_BODY_BYTES, normalizeKeyname } from "../domain/validation";
import {
  copyButton,
  downloadTextFile,
  formatFingerprint,
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
const LARGE_MESSAGE_WARNING_BYTES = 160 * 1024;
export const MAX_SERIALIZED_PAYLOAD_BYTES = 180 * 1024;

export type MessageMeterPresentation = {
  text: string;
  warning: boolean;
};

export function messageMeterPresentation(bytes: number): MessageMeterPresentation {
  const warning = bytes >= LARGE_MESSAGE_WARNING_BYTES;
  return {
    text: warning
      ? `${formatByteCount(bytes)} of plaintext · large message: encryption overhead may exceed the ${formatBytes(MAX_DROP_BODY_BYTES)} request limit`
      : `${formatByteCount(bytes)} of plaintext · encryption adds overhead; final request limit ${formatBytes(MAX_DROP_BODY_BYTES)}`,
    warning
  };
}

export function serializedPayloadByteLength(payload: PlainBottlePayload): number {
  return textEncoder.encode(JSON.stringify(payload)).byteLength;
}

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
  const initialMessageMeter = messageMeterPresentation(0);
  const messageMeter = h("p", {
    className: "message-meter",
    text: initialMessageMeter.text,
    attrs: { id: "drop-message-meter" }
  });
  const messageField = labeledField(
    "Message",
    messageInput,
    "The message is encrypted in this browser before any request is sent. Encryption adds size, so the API limit is checked against the final ciphertext request."
  );
  messageInput.setAttribute(
    "aria-describedby",
    [messageInput.getAttribute("aria-describedby"), messageMeter.id].filter(Boolean).join(" ")
  );
  messageField.append(messageMeter);
  const fingerprintConfirmation = h("input", {
    attrs: {
      id: "confirm-recipient-fingerprint",
      name: "confirmRecipientFingerprint",
      type: "checkbox",
      disabled: ""
    }
  });
  const fingerprintConfirmationRow = h("label", {
    className: "check-row",
    attrs: { for: "confirm-recipient-fingerprint" }
  }, [
    fingerprintConfirmation,
    h("span", {
      text: "I compared the complete fingerprint through a separate trusted channel."
    })
  ]);
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
    fingerprintConfirmationRow,
    messageField,
    submit
  ]);

  let activeKeys: KeyRecord[] = [];
  let busy = true;

  const selectedKey = (): KeyRecord | undefined =>
    activeKeys.find((key) => key.fingerprint === keySelect.value);

  const syncControls = (): void => {
    keySelect.disabled = busy || activeKeys.length === 0;
    messageInput.readOnly = busy;
    fingerprintConfirmation.disabled = busy || selectedKey() === undefined;
    submit.disabled = busy || selectedKey() === undefined || !fingerprintConfirmation.checked;
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
            h("code", { className: "code-value fingerprint", text: formatFingerprint(selected.fingerprint) }),
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
      if (!fingerprintConfirmation.checked) {
        fingerprintConfirmation.focus();
        throw new Error("Confirm that you independently verified the complete recipient fingerprint.");
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
      const payloadBytes = serializedPayloadByteLength(payload);
      if (payloadBytes > MAX_SERIALIZED_PAYLOAD_BYTES) {
        messageInput.setAttribute("aria-invalid", "true");
        messageInput.focus();
        throw new Error(
          `The message produces a ${formatBytes(payloadBytes)} serialized payload, above the ${formatBytes(MAX_SERIALIZED_PAYLOAD_BYTES)} conservative client limit before encryption. Shorten it and try again.`
        );
      }
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
      const evidencePath = `/api/bottles/${encodeURIComponent(response.bottleId)}/evidence`;
      const evidenceUrl = new URL(evidencePath, window.location.origin).toString();
      const downloadEvidence = h("button", {
        className: "button-secondary button-compact",
        text: "Download Evidence JSON",
        attrs: { type: "button" }
      });
      downloadEvidence.addEventListener("click", () => {
        downloadTextFile(`${serializedEvidence}\n`, `daylight-bottle-${response.bottleId}-evidence.json`);
      });
      output.replaceChildren(
        h("section", { className: "result-section" }, [
          h("div", { className: "result-heading" }, [
            h("h3", { text: "Bottle Accepted" }),
            h("div", { className: "action-group" }, [
              h("a", {
                className: "button-link button-secondary button-compact",
                text: "Open Evidence",
                attrs: { href: evidencePath, target: "_blank", rel: "noopener" }
              }),
              copyButton(evidenceUrl, "Copy Evidence URL"),
              downloadEvidence
            ])
          ]),
          h("dl", { className: "metadata-list" }, [
            h("dt", { text: "Bottle id" }),
            h("dd", { text: response.bottleId }),
            h("dt", { text: "Stored at" }),
            h("dd", {}, [timeElement(response.storedAt)]),
            h("dt", { text: "Expires at" }),
            h("dd", {}, [timeElement(response.expiresAt)])
          ]),
          h("p", {
            className: "muted",
            text: "Storage is eventually consistent. A recipient in another location may need to wait briefly and retry before this accepted bottle appears."
          }),
          h("p", {
            className: "muted",
            text: "Before displaying this receipt, the client verified its schema, request metadata, timestamps, and ciphertext digest. That does not prove server honesty."
          }),
          h("h3", { text: "Daylight Evidence" }),
          renderJsonBlock(response.evidence, "Daylight bottle evidence JSON")
        ])
      );
      messageInput.value = "";
      fingerprintConfirmation.checked = false;
      updateMessageMeter();
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
    fingerprintConfirmation.checked = false;
    updateRecipientDetails();
    if (selectedKey()) {
      setStatus(status, "Recipient selected. Verify its fingerprint before encrypting.");
    }
  });

  fingerprintConfirmation.addEventListener("change", () => {
    syncControls();
    if (fingerprintConfirmation.checked) {
      setStatus(status, "Fingerprint verification confirmed locally. The confirmation is not uploaded.");
    }
  });

  const updateMessageMeter = (): void => {
    const bytes = textEncoder.encode(messageInput.value).byteLength;
    const presentation = messageMeterPresentation(bytes);
    messageMeter.textContent = presentation.text;
    messageMeter.classList.toggle("message-meter-warning", presentation.warning);
    messageInput.removeAttribute("aria-invalid");
  };
  messageInput.addEventListener("input", updateMessageMeter);

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
  form.hidden = true;

  const loadRecipients = async (focusAfterLoad = false): Promise<void> => {
    busy = true;
    activeKeys = [];
    form.hidden = true;
    output.replaceChildren();
    syncControls();
    setStatus(status, "Loading /keyring.json...");
    try {
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
        const createIdentityAction = h("a", {
          className: "button-link",
          text: "Create an Identity",
          attrs: { href: "#create" }
        });
        form.hidden = true;
        output.replaceChildren(
          h("section", { className: "empty-state" }, [
            h("h3", { text: "No approved recipients yet" }),
            h("p", {
              text: "The static keyring has no active public records. Create an identity, verify its private backup, and request manual owner approval before anyone can drop a bottle to it."
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
      setStatus(status, `Loaded ${activeKeys.length} active recipient key(s). Choose one to continue.`, "success");
      if (focusAfterLoad) {
        keySelect.focus();
      }
    } catch (error) {
      busy = false;
      syncControls();
      const message = error instanceof Error ? error.message : "Could not load keyring.";
      const retry = h("button", { text: "Retry Keyring Load", attrs: { type: "button" } });
      retry.addEventListener("click", () => {
        void loadRecipients(true);
      });
      output.replaceChildren(
        h("section", {
          className: "empty-state empty-state-error",
          attrs: { role: "group", "aria-labelledby": "drop-keyring-error-title" }
        }, [
          h("h3", { text: "Recipient directory unavailable", attrs: { id: "drop-keyring-error-title" } }),
          h("p", {
            text: "No message was encrypted or uploaded. Retry the same-origin public keyring when you are ready."
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

  await loadRecipients();
}

function formatBytes(bytes: number): string {
  return `${Math.ceil(bytes / 1024)} KiB`;
}

function formatByteCount(bytes: number): string {
  return bytes < 1024 ? `${bytes} byte${bytes === 1 ? "" : "s"}` : formatBytes(bytes);
}
