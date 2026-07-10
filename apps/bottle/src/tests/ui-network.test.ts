import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const uiFiles = [
  "index.html",
  "src/styles.css",
  "src/main.ts",
  "src/api/client.ts",
  "src/crypto/ageAdapter.ts",
  "src/crypto/fingerprint.ts",
  "src/ui/CreateIdentity.ts",
  "src/ui/DropBottle.ts",
  "src/ui/OpenBottles.ts",
  "src/ui/ThreatModel.ts",
  "src/ui/dom.ts"
];

describe("UI network boundary", () => {
  it("does not call external origins or reference third-party runtime assets", async () => {
    for (const file of uiFiles) {
      const content = await readFile(join(process.cwd(), file), "utf8");
      expect(content, file).not.toMatch(/fetch\s*\(\s*["'`]https?:\/\//);
      expect(content, file).not.toMatch(/https:\/\/fonts\./);
      expect(content, file).not.toMatch(/cdn\./i);
      expect(content, file).not.toMatch(/<script[^>]+https?:\/\//i);
      expect(content, file).not.toMatch(/\b(?:XMLHttpRequest|WebSocket|EventSource)\s*\(/);
      expect(content, file).not.toMatch(/\bsendBeacon\s*\(/);
      expect(content, file).not.toMatch(/@import\s+url\s*\(\s*["']?https?:\/\//i);
      expect(content, file).not.toMatch(/url\s*\(\s*["']?\/\//i);
    }
  });

  it("loads CSS as a same-origin stylesheet instead of CSP-blocked dev injection", async () => {
    const html = await readFile(join(process.cwd(), "index.html"), "utf8");
    const main = await readFile(join(process.cwd(), "src/main.ts"), "utf8");

    expect(html).toContain('<link rel="stylesheet" href="/src/styles.css" />');
    expect(html).not.toMatch(/<style\b|\sstyle=/i);
    expect(main).not.toMatch(/import\s+["']\.\/styles\.css["']/);
  });
});
