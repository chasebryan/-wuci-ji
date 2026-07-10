import { renderCreateIdentity } from "./ui/CreateIdentity";
import { renderDropBottle } from "./ui/DropBottle";
import { renderOpenBottles } from "./ui/OpenBottles";
import { renderThreatModel } from "./ui/ThreatModel";
import { h, type ViewRenderer } from "./ui/dom";
import { clearNavigationGuard, confirmNavigationAway } from "./ui/navigationGuard";

type ViewId = "create" | "drop" | "open" | "threat";

const views: Array<{ id: ViewId; label: string; render: ViewRenderer }> = [
  { id: "create", label: "Create Identity", render: renderCreateIdentity },
  { id: "drop", label: "Drop Bottle", render: renderDropBottle },
  { id: "open", label: "Open Bottles", render: renderOpenBottles },
  { id: "threat", label: "Threat Model", render: renderThreatModel }
];

const root = document.querySelector<HTMLElement>("#app");
if (!root) {
  throw new Error("Missing #app root.");
}

const viewRoot = h("main", {
  className: "view-root",
  attrs: { id: "main", tabindex: "-1", "aria-busy": "false" }
});
const nav = h("nav", { className: "tabs", attrs: { "aria-label": "Daylight Bottle views" } });
const links = new Map<ViewId, HTMLAnchorElement>();
const initialView = readViewFromHash();
let currentViewId: ViewId = initialView;
const shortCommit = /^[0-9a-f]{40}$/.test(__DAYLIGHT_SOURCE_COMMIT__)
  ? __DAYLIGHT_SOURCE_COMMIT__.slice(0, 12)
  : "unavailable";

for (const view of views) {
  const link = h("a", {
    text: view.label,
    attrs: { href: `#${view.id}` }
  });
  link.addEventListener("click", (event) => {
    if (view.id !== currentViewId && !confirmNavigationAway()) {
      event.preventDefault();
    }
  });
  links.set(view.id, link);
  nav.append(link);
}

const skipLink = h("a", {
  className: "skip-link",
  text: "Skip to main content",
  attrs: { href: "#main" }
});
skipLink.addEventListener("click", (event) => {
  event.preventDefault();
  viewRoot.focus();
});

root.replaceChildren(
  h("div", { className: "app-shell" }, [
    skipLink,
    h("header", { className: "app-header" }, [
      h("div", { className: "header-copy" }, [
        h("p", { className: "eyebrow", text: "No Such Machine" }),
        h("h1", { text: "Daylight Bottle" }),
        h("p", {
          className: "lead",
          text: "Daylight Bottle encrypts messages locally in your browser."
        }),
        h("p", {
          className: "boundary-copy",
          text: "The server stores ciphertext only. It cannot decrypt your bottle unless the delivered JavaScript, your browser, your machine, or your private identity is compromised."
        }),
        h("p", {
          className: "boundary-copy strong",
          text: "Your keyname is public. Your private identity is secret."
        })
      ]),
      nav
    ]),
    viewRoot,
    h("footer", { className: "app-footer" }, [
      h("div", {}, [
        h("p", { className: "app-footer-title", text: `Build ${shortCommit} · ${__DAYLIGHT_TREE_STATE__} source tree` }),
        h("p", {
          text: "The same-origin release manifest binds source metadata, asset hashes, the keyring, security headers, and size budgets. It is self-published provenance—not independent attestation or proof of uncompromised delivery."
        })
      ]),
      h("a", {
        className: "button-link button-secondary button-compact",
        text: "Inspect Release Manifest",
        attrs: { href: "/release-manifest.json", target: "_blank", rel: "noopener" }
      })
    ])
  ])
);

let activationId = 0;
if (window.location.hash !== `#${initialView}`) {
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${initialView}`);
}
void activateView(initialView, false);

window.addEventListener("hashchange", () => {
  const viewId = readViewFromHash();
  if (viewId === currentViewId) {
    if (window.location.hash !== `#${viewId}`) {
      window.history.replaceState(
        null,
        "",
        `${window.location.pathname}${window.location.search}#${viewId}`
      );
    }
    return;
  }
  if (viewId !== currentViewId && !confirmNavigationAway()) {
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${window.location.search}#${currentViewId}`
    );
    return;
  }
  if (window.location.hash !== `#${viewId}`) {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${viewId}`);
  }
  void activateView(viewId, true);
});

async function activateView(viewId: ViewId, focusHeading: boolean): Promise<void> {
  const view = views.find((candidate) => candidate.id === viewId);
  if (!view) {
    return;
  }

  clearNavigationGuard();
  currentViewId = viewId;

  const currentActivation = ++activationId;
  for (const [id, link] of links.entries()) {
    link.classList.toggle("active", id === viewId);
    if (id === viewId) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  }

  document.title = `${view.label} · Daylight Bottle`;
  viewRoot.setAttribute("aria-busy", "true");
  const renderPromise = Promise.resolve(view.render(viewRoot));

  if (focusHeading) {
    window.requestAnimationFrame(() => {
      if (currentActivation !== activationId) {
        return;
      }
      const heading = viewRoot.querySelector<HTMLHeadingElement>("h2");
      if (heading) {
        heading.tabIndex = -1;
        heading.focus();
      } else {
        viewRoot.focus();
      }
    });
  }

  try {
    await renderPromise;
  } finally {
    if (currentActivation === activationId) {
      viewRoot.setAttribute("aria-busy", "false");
    }
  }
}

function readViewFromHash(): ViewId {
  const candidate = window.location.hash.slice(1);
  return views.some((view) => view.id === candidate) ? (candidate as ViewId) : "create";
}
