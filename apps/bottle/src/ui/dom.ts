export type ViewRenderer = (container: HTMLElement) => void | Promise<void>;

type Child = Node | string | number | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tagName: K,
  options: {
    className?: string;
    text?: string;
    attrs?: Record<string, string>;
  } = {},
  children: Child[] = []
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tagName);
  if (options.className) {
    element.className = options.className;
  }
  if (options.text !== undefined) {
    element.textContent = options.text;
  }
  if (options.attrs) {
    for (const [name, value] of Object.entries(options.attrs)) {
      element.setAttribute(name, value);
    }
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) {
      continue;
    }
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}

export function renderJsonBlock(value: unknown, label = "JSON output"): HTMLPreElement {
  return h("pre", {
    className: "json-output",
    text: JSON.stringify(value, null, 2),
    attrs: { "aria-label": label, tabindex: "0" }
  });
}

export function statusRegion(): HTMLParagraphElement {
  return h("p", {
    className: "status status-info",
    attrs: {
      role: "status",
      "aria-live": "polite",
      "aria-atomic": "true"
    }
  });
}

export function setStatus(
  element: HTMLElement,
  message: string,
  kind: "info" | "success" | "error" = "info"
): void {
  element.setAttribute("role", kind === "error" ? "alert" : "status");
  element.setAttribute("aria-live", kind === "error" ? "assertive" : "polite");
  element.setAttribute("aria-atomic", "true");
  element.className = `status status-${kind}`;
  element.textContent = message;
}

export function setBusy(element: HTMLElement, busy: boolean): void {
  element.setAttribute("aria-busy", busy ? "true" : "false");
  element.classList.toggle("is-busy", busy);
}

export function labeledField(
  labelText: string,
  field: HTMLElement,
  helpText?: string
): HTMLElement {
  const id = field.id;
  const label = h("label", {
    className: "field-label",
    text: labelText,
    attrs: id ? { for: id } : {}
  });
  const children: Child[] = [label, field];
  if (helpText) {
    const helpId = id ? `${id}-help` : "";
    if (helpId) {
      const describedBy = field.getAttribute("aria-describedby");
      field.setAttribute("aria-describedby", [describedBy, helpId].filter(Boolean).join(" "));
    }
    children.push(h("small", { className: "field-help", text: helpText, attrs: helpId ? { id: helpId } : {} }));
  }
  return h("div", { className: "field" }, children);
}

export function warning(text: string): HTMLElement {
  return h("p", { className: "warning", text, attrs: { role: "note" } });
}

export function copyButton(value: string, label: string): HTMLButtonElement {
  const button = h("button", {
    className: "button-secondary button-compact",
    text: label,
    attrs: { type: "button", "aria-label": label }
  });
  const originalLabel = label;

  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await writeClipboard(value);
      button.textContent = "Copied";
      button.setAttribute("aria-label", `${originalLabel}: copied`);
    } catch {
      button.textContent = "Copy unavailable";
      button.setAttribute("aria-label", `${originalLabel}: clipboard unavailable`);
    } finally {
      window.setTimeout(() => {
        button.textContent = originalLabel;
        button.setAttribute("aria-label", originalLabel);
        button.disabled = false;
      }, 1800);
    }
  });

  return button;
}

export function downloadTextFile(value: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([value], { type: "text/plain;charset=utf-8" }));
  const link = h("a", {
    attrs: { href: url, download: filename, "aria-hidden": "true", tabindex: "-1" }
  });
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function formatFingerprint(fingerprint: string): string {
  const prefix = "sha256:";
  if (!fingerprint.startsWith(prefix)) {
    return fingerprint;
  }
  const digest = fingerprint.slice(prefix.length);
  return `${prefix}${digest.match(/.{1,8}/g)?.join(" ") ?? digest}`;
}

async function writeClipboard(value: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // A user gesture can still permit the local document.execCommand fallback.
    }
  }

  const fallback = h("textarea", {
    className: "clipboard-fallback",
    attrs: {
      readonly: "",
      "aria-hidden": "true",
      tabindex: "-1"
    }
  });
  fallback.value = value;
  document.body.append(fallback);
  fallback.select();
  const copied = document.execCommand("copy");
  fallback.remove();
  if (!copied) {
    throw new Error("Clipboard write was not available.");
  }
}

export function timeElement(value: string): HTMLTimeElement {
  const parsed = new Date(value);
  const text = Number.isNaN(parsed.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short"
      }).format(parsed);
  return h("time", { text, attrs: { datetime: value, title: value } });
}
