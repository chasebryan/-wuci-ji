import {
  fingerprintKeyRecordInput,
  generateIdentity
} from "../crypto/ageAdapter";
import { SCHEMAS, type KeyRecord } from "../domain/types";
import { normalizeKeyname, safeKeynameForFilename } from "../domain/validation";
import {
  copyButton,
  h,
  labeledField,
  renderJsonBlock,
  setBusy,
  setStatus,
  statusRegion,
  warning
} from "./dom";

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

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    keynameInput.removeAttribute("aria-invalid");
    submit.disabled = true;
    keynameInput.readOnly = true;
    setBusy(form, true);
    setBusy(output, true);
    setStatus(status, "Generating an age identity locally in this browser...");

    try {
      const keyname = normalizeKeyname(keynameInput.value);
      keynameInput.value = keyname;
      const generated = await generateIdentity();
      const fingerprint = await fingerprintKeyRecordInput({
        keyname,
        publicRecipient: generated.publicRecipient
      });
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
        downloadPrivateIdentity(
          generated.privateIdentity,
          `daylight-bottle-${safeKeynameForFilename(keyname)}-identity.txt`
        );
        setStatus(status, "Private identity download started. Keep the file secret and backed up.", "success");
      });

      const serializedKeyRecord = JSON.stringify(keyRecord, null, 2);

      output.replaceChildren(
        warning(
          "Save this private identity file. If you lose it, bottles encrypted to this key cannot be opened. If someone else gets it, they can open your bottles."
        ),
        h("section", { className: "result-section" }, [
          h("h3", { text: "1. Save the Private Identity" }),
          h("p", {
            text: "Keep this local. Do not upload it, paste it into support requests, or share it."
          }),
          download
        ]),
        h("section", { className: "result-section" }, [
          h("div", { className: "result-heading" }, [
            h("h3", { text: "2. Copy the Public Key Record" }),
            copyButton(serializedKeyRecord, "Copy Public Key Record")
          ]),
          h("p", {
            text: "After saving the private identity, send this public JSON block to the site owner for manual addition to /keyring.json."
          }),
          renderJsonBlock(keyRecord, "Public key record JSON")
        ])
      );
      setStatus(status, "Identity generated locally. No identity material was uploaded.", "success");
    } catch (error) {
      keynameInput.setAttribute("aria-invalid", "true");
      keynameInput.focus();
      setStatus(status, error instanceof Error ? error.message : "Identity generation failed.", "error");
    } finally {
      submit.disabled = false;
      keynameInput.readOnly = false;
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

function downloadPrivateIdentity(privateIdentity: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([privateIdentity, "\n"], { type: "text/plain" }));
  const link = h("a", {
    attrs: { href: url, download: filename, "aria-hidden": "true", tabindex: "-1" }
  });
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
