import { readdir, readFile } from "node:fs/promises";
import { extname, relative } from "node:path";

const root = new URL("../", import.meta.url);
const dist = new URL("dist/", root);
const requiredFiles = ["index.html", "keyring.json", "_headers"];

for (const file of requiredFiles) {
  await readFile(new URL(file, dist), "utf8");
}

for (const file of await runtimeFiles(dist)) {
  const content = await readFile(file, "utf8");
  const label = relative(dist.pathname, file.pathname);
  if (/(?:https?|wss?):\/\//i.test(content)) {
    throw new Error(`${label} contains an external runtime URL.`);
  }
}

const html = await readFile(new URL("index.html", dist), "utf8");
if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(html) || /<style\b/i.test(html) || /\sstyle=/i.test(html)) {
  throw new Error("Built HTML contains inline script or style that violates the production CSP.");
}

const headers = await readFile(new URL("_headers", dist), "utf8");
for (const required of [
  "default-src 'self'",
  "script-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "Referrer-Policy: no-referrer",
  "Permissions-Policy: geolocation=(), microphone=(), camera=()",
  "Cross-Origin-Opener-Policy: same-origin",
  "Cross-Origin-Resource-Policy: same-origin",
  "X-Frame-Options: DENY",
  "X-Content-Type-Options: nosniff"
]) {
  if (!headers.includes(required)) {
    throw new Error(`Built _headers is missing required policy: ${required}`);
  }
}

console.log("Verified same-origin bundle, CSP-compatible HTML, keyring, and security headers.");

async function runtimeFiles(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directory);
    if (entry.isDirectory()) {
      output.push(...await runtimeFiles(url));
    } else if ([".html", ".js", ".css"].includes(extname(entry.name))) {
      output.push(url);
    }
  }
  return output;
}
