import { h } from "./dom";

export function renderThreatModel(container: HTMLElement): void {
  container.replaceChildren(
    h("section", { className: "view threat-model" }, [
      h("h2", { text: "Threat Model" }),
      h("p", {
        className: "view-intro",
        text: "Daylight Bottle protects message content with recipient encryption. It does not make the browser, server, sender, delivery path, or metadata automatically trustworthy."
      }),
      section("What this protects", [
        "A correctly delivered browser app encrypts message content to a recipient public key before upload.",
        "The server stores ciphertext and public metadata. A later server compromise should reveal ciphertext only, assuming JavaScript delivery and recipient devices were not compromised.",
        "Opening a bottle happens locally with the recipient private identity, and decrypt success or failure is not sent back to the server."
      ]),
      section("What can expose message content", [
        "Malicious JavaScript delivery can read messages or private identities before encryption or after decryption.",
        "A compromised browser, machine, extension, clipboard, backup, or stolen private identity can expose messages.",
        "A swapped public key can make the sender encrypt to the wrong person.",
        "Anyone holding the matching private identity can open matching bottles. There is no server-side recovery if that identity is lost."
      ]),
      section("Sender identity is not authenticated", [
        "There are no accounts or sender signatures in this MVP. Anyone can submit a ciphertext bottle to a listed recipient.",
        "A decrypted message does not prove who wrote or sent it. Treat identity claims inside messages as unverified."
      ]),
      section("What recipient registration checks", [
        "The server checks that submitted keyname and fingerprint metadata match an active public keyring record.",
        "The age ciphertext is opaque to the server, so this registration check cannot prove that the ciphertext was encrypted to that record's public recipient.",
        "Unrelated or malformed ciphertext can pass the metadata check and later fail local decryption. The browser does not report that result to the server."
      ]),
      section("Metadata the server can observe", [
        "Keynames, recipient fingerprints, ciphertext sizes, bottle ids, storage times, expiry times, and request timing are public or operational metadata.",
        "Opening begins with a fingerprint lookup, so the server can observe which public fingerprint was queried and when. It is not told which candidate ciphertexts decrypted successfully.",
        "Drop burst protection hashes the request network address together with the recipient fingerprint. Inbox-list and evidence reads share a coarser counter derived only from the network address, so rotating lookup identifiers does not reset the read budget. These counters are short-lived and location-local; their derived keys are not bottle content and are not written to bottle storage.",
        "Hosting infrastructure may also observe ordinary connection metadata such as network addresses even though this app includes no analytics or trackers."
      ]),
      section("Availability and server behavior", [
        "Encryption does not force the server to accept, retain, return, order, or deliver a bottle.",
        "Production drop and inbox-read requests use location-local burst protection. A shared network can be temporarily limited, distributed traffic can bypass a single location's counter, and these are not exact global quotas.",
        "Each lookup returns at most eight candidate bottles plus an opaque continuation header, and each recipient has a 500-bottle admission ceiling. The ceiling is eventually consistent rather than transactional; bounded pages remain the protection against oversized reads.",
        "The current KV storage is eventually consistent, so an accepted bottle can take time to appear in another location.",
        "A faulty or malicious server can delete, withhold, duplicate, replay, or replace ciphertext and metadata. Authenticated age encryption should prevent altered ciphertext from decrypting as a valid message.",
        "An expiry timestamp is a service retention boundary, not proof that every copy, backup, or prior response has been securely erased."
      ]),
      section("Why the keyname is public", [
        "The keyname only selects a public key record from /keyring.json.",
        "It is not a password, not a shared secret, and not enough to open a bottle."
      ]),
      section("Why the private identity is secret", [
        "The private identity decrypts bottles sent to its matching public recipient.",
        "If it is lost, matching bottles cannot be opened. If it is stolen, another person can open matching bottles."
      ]),
      section("Manual keyring activation procedure", [
        "The recipient first downloads and locally verifies the private identity, then exports only the public key record JSON.",
        "The recipient transfers that public JSON to the site owner through an authenticated channel they already trust. The private identity must never be submitted.",
        "The owner recomputes the fingerprint, checks schema and keyname uniqueness, manually edits /keyring.json, runs the complete release gate, and verifies the deployed fingerprint before announcing activation.",
        "This application has no key-registration or key-record submission endpoint and cannot approve its own key record."
      ]),
      section("Why Daylight evidence is not encryption", [
        "The evidence record describes what this server says it accepted and stored: bottle id, timestamps, recipient fingerprint, ciphertext hash, and storage policy.",
        "The current evidence JSON is not a recipient signature or independent proof of server honesty. A compromised server can issue misleading records.",
        "The field plaintextSeenByServer: false is a design claim from this app architecture, not a mathematical proof."
      ]),
      section("Why JavaScript delivery matters", [
        "Browser cryptography depends on the code delivered by this origin.",
        "If the delivered JavaScript is changed maliciously, it can capture plaintext or identity material before the encryption library is used.",
        "Use a trusted browser and device, and treat unexpected application changes as a reason to stop before entering secrets."
      ]),
      section("What the release manifest proves—and does not prove", [
        "The same-origin release manifest binds a source commit, build inputs, keyring, security headers, runtime asset hashes, and explicit size budgets into one versioned record.",
        "A reviewer can independently rebuild or hash downloaded assets and compare them with that record.",
        "The manifest is self-published by this deployment. Malicious JavaScript or a compromised origin can replace both the app and its manifest, so the app cannot prove its own delivery integrity."
      ]),
      section("Why fingerprints must be verified", [
        "The fingerprint binds a public key record to a keyname and public recipient.",
        "A sender should compare the full displayed fingerprint through a separate trusted channel before dropping a bottle.",
        "A matching fingerprint checks the selected public record; it does not authenticate the sender of a later bottle."
      ])
    ])
  );
}

function section(title: string, items: string[]): HTMLElement {
  return h("section", { className: "threat-section" }, [
    h("h3", { text: title }),
    h("ul", {}, items.map((item) => h("li", { text: item })))
  ]);
}
