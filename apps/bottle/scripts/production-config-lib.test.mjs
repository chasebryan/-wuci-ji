import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { assertProductionConfig, parseTomlSubset } from "./production-config-lib.mjs";

const validConfig = `name = "daylight-bottle"
main = "worker/index.ts"
compatibility_date = "2026-07-09"
workers_dev = false

[version_metadata]
binding = "CF_VERSION_METADATA"

[[routes]]
pattern = "bottle.nosuchmachine.net"
custom_domain = true

[assets]
directory = "./dist"
run_worker_first = ["/api/*"]

[[kv_namespaces]]
binding = "BOTTLES_KV"
id = "20625e8d95504df28ba0e1bc94d97fc0"

[[ratelimits]]
name = "DROP_RATE_LIMITER"
namespace_id = "263356768422848"

[ratelimits.simple]
limit = 12
period = 60

[[ratelimits]]
name = "READ_RATE_LIMITER"
namespace_id = "173331705833598"

[ratelimits.simple]
limit = 60
period = 60
`;

describe("production Wrangler config", () => {
  it("parses and accepts the exact approved binding sections", () => {
    const parsed = assertProductionConfig(validConfig);
    expect(parsed.kv_namespaces[0].binding).toBe("BOTTLES_KV");
    expect(parsed.version_metadata.binding).toBe("CF_VERSION_METADATA");
    expect(parsed.ratelimits[0].simple).toEqual({ limit: 12, period: 60 });
    expect(parsed.ratelimits[1].simple).toEqual({ limit: 60, period: 60 });
  });

  it("accepts the checked-in Wrangler configuration", async () => {
    const source = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
    expect(() => assertProductionConfig(source)).not.toThrow();
  });

  it("does not accept required text from comments or the wrong section", () => {
    expect(() =>
      assertProductionConfig(validConfig.replace('binding = "BOTTLES_KV"', '# binding = "BOTTLES_KV"'))
    ).toThrow(/KV binding|kv_namespaces/);
    expect(() =>
      assertProductionConfig(
        validConfig
          .replace("[ratelimits.simple]\nlimit = 12\nperiod = 60", "[ratelimits.simple]")
          .replace('directory = "./dist"', 'directory = "./dist"\nlimit = 12\nperiod = 60')
      )
    ).toThrow(/rate-limit request count/);
  });

  it("rejects duplicate keys and unsupported syntax deterministically", () => {
    expect(() =>
      parseTomlSubset(
        validConfig.replace("workers_dev = false", "workers_dev = false\nworkers_dev = true")
      )
    ).toThrow(/Duplicate/);
    expect(() =>
      parseTomlSubset(validConfig.replace("workers_dev = false", "workers_dev = false || true"))
    ).toThrow(
      /Unsupported/
    );
  });
});
