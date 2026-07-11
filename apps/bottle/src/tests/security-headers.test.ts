import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SECURITY_HEADERS } from "../../worker/index";

describe("security header parity", () => {
  it("keeps static and API policies aligned without CSP escape hatches", async () => {
    const staticHeaders = await readFile(join(process.cwd(), "public/_headers"), "utf8");

    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(staticHeaders, name).toContain(`${name}: ${value}`);
    }
    expect(staticHeaders).toMatch(
      /(?:^|\n)\/release-manifest\.json\n {2}Cache-Control: no-store, no-transform(?:\n|$)/
    );
    expect(staticHeaders).toContain(
      "Cache-Control: public, max-age=31536000, immutable, no-transform"
    );
    expect(SECURITY_HEADERS["Content-Security-Policy"]).not.toMatch(/unsafe-(?:inline|eval)/);
    expect(SECURITY_HEADERS["Content-Security-Policy"]).not.toMatch(/https?:|data:|blob:/);
  });
});
