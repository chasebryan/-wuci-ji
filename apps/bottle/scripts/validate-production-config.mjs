import { readFile } from "node:fs/promises";

const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
const namespaceId = config.match(/^id\s*=\s*"([^"]+)"\s*$/m)?.[1];

if (!namespaceId || !/^[0-9a-f]{32}$/.test(namespaceId)) {
  refuse(
    "Refusing live deployment: replace the BOTTLES_KV namespace placeholder with a 32-character production namespace id."
  );
}

for (const required of [
  'pattern = "bottle.nosuchmachine.net"',
  "custom_domain = true",
  "workers_dev = false",
  'directory = "./dist"',
  'run_worker_first = ["/api/*"]',
  'binding = "BOTTLES_KV"'
]) {
  if (!config.includes(required)) {
    refuse(`Refusing live deployment: wrangler.toml is missing ${required}.`);
  }
}

console.log("Verified production custom domain, assets route, and BOTTLES_KV namespace id.");

function refuse(message) {
  console.error(message);
  process.exit(1);
}
