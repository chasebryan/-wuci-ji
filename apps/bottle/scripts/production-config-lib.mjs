const EXPECTED_KV_NAMESPACE_ID = "20625e8d95504df28ba0e1bc94d97fc0";
const EXPECTED_DROP_RATE_LIMIT_NAMESPACE_ID = "263356768422848";
const EXPECTED_READ_RATE_LIMIT_NAMESPACE_ID = "173331705833598";

export function assertProductionConfig(source) {
  const config = parseTomlSubset(source);
  expectEqual(config.name, "daylight-bottle", "Worker name");
  expectEqual(config.main, "worker/index.ts", "Worker entrypoint");
  expectEqual(config.workers_dev, false, "workers.dev exposure");
  if (typeof config.compatibility_date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(config.compatibility_date)) {
    throw new Error("Worker compatibility_date must be a canonical date.");
  }

  const route = expectSingleTable(config.routes, "routes");
  expectEqual(route.pattern, "bottle.nosuchmachine.net", "custom-domain route");
  expectEqual(route.custom_domain, true, "custom-domain mode");

  const assets = expectTable(config.assets, "assets");
  expectEqual(assets.directory, "./dist", "static asset directory");
  expectJsonEqual(assets.run_worker_first, ["/api/*"], "Worker-first API routes");

  const kv = expectSingleTable(config.kv_namespaces, "kv_namespaces");
  expectEqual(kv.binding, "BOTTLES_KV", "KV binding");
  expectEqual(kv.id, EXPECTED_KV_NAMESPACE_ID, "production KV namespace id");

  const limiters = expectTableArray(config.ratelimits, "ratelimits", 2);
  const limiter = expectNamedTable(limiters, "DROP_RATE_LIMITER", "drop rate-limit binding");
  expectEqual(
    limiter.namespace_id,
    EXPECTED_DROP_RATE_LIMIT_NAMESPACE_ID,
    "drop rate-limit namespace id"
  );
  const simple = expectTable(limiter.simple, "ratelimits.simple");
  expectEqual(simple.limit, 12, "drop rate-limit request count");
  expectEqual(simple.period, 60, "drop rate-limit period");

  const readLimiter = expectNamedTable(limiters, "READ_RATE_LIMITER", "read rate-limit binding");
  expectEqual(
    readLimiter.namespace_id,
    EXPECTED_READ_RATE_LIMIT_NAMESPACE_ID,
    "read rate-limit namespace id"
  );
  const readSimple = expectTable(readLimiter.simple, "read ratelimits.simple");
  expectEqual(readSimple.limit, 60, "read rate-limit request count");
  expectEqual(readSimple.period, 60, "read rate-limit period");

  return config;
}

export function parseTomlSubset(source) {
  if (typeof source !== "string") {
    throw new Error("Wrangler configuration must be text.");
  }
  const root = Object.create(null);
  let current = root;

  for (const [index, rawLine] of source.split(/\r?\n/).entries()) {
    const lineNumber = index + 1;
    const line = stripComment(rawLine).trim();
    if (line.length === 0) {
      continue;
    }

    const arrayHeader = line.match(/^\[\[([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\]\]$/);
    if (arrayHeader) {
      current = createSection(root, arrayHeader[1].split("."), true, lineNumber);
      continue;
    }
    const tableHeader = line.match(/^\[([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\]$/);
    if (tableHeader) {
      current = createSection(root, tableHeader[1].split("."), false, lineNumber);
      continue;
    }

    const assignment = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!assignment) {
      throw new Error(`Unsupported Wrangler TOML syntax on line ${lineNumber}.`);
    }
    const key = assignment[1];
    if (Object.hasOwn(current, key)) {
      throw new Error(`Duplicate Wrangler TOML key ${key} on line ${lineNumber}.`);
    }
    current[key] = parseValue(assignment[2].trim(), lineNumber);
  }

  return root;
}

function createSection(root, path, arraySection, lineNumber) {
  let current = root;
  for (let index = 0; index < path.length; index += 1) {
    const part = path[index];
    const last = index === path.length - 1;
    const existing = current[part];

    if (Array.isArray(existing)) {
      if (existing.length === 0) {
        throw new Error(`Wrangler TOML section ${path.join(".")} has no parent on line ${lineNumber}.`);
      }
      if (last) {
        if (!arraySection) {
          throw new Error(`Wrangler TOML table ${path.join(".")} conflicts with an array table.`);
        }
        const entry = Object.create(null);
        existing.push(entry);
        return entry;
      }
      current = existing.at(-1);
      continue;
    }

    if (last) {
      if (existing !== undefined) {
        throw new Error(`Duplicate Wrangler TOML section ${path.join(".")} on line ${lineNumber}.`);
      }
      if (arraySection) {
        const entry = Object.create(null);
        current[part] = [entry];
        return entry;
      }
      const table = Object.create(null);
      current[part] = table;
      return table;
    }

    if (existing === undefined) {
      current[part] = Object.create(null);
    } else if (typeof existing !== "object" || existing === null) {
      throw new Error(`Wrangler TOML section ${path.join(".")} conflicts with a value.`);
    }
    current = current[part];
  }
  throw new Error("Wrangler TOML section path must not be empty.");
}

function stripComment(line) {
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && character === "#") {
      return line.slice(0, index);
    }
  }
  return line;
}

function parseValue(value, lineNumber) {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  if (/^-?\d+$/.test(value)) {
    const number = Number(value);
    if (!Number.isSafeInteger(number)) {
      throw new Error(`Wrangler TOML integer is outside the safe range on line ${lineNumber}.`);
    }
    return number;
  }
  if (value.startsWith('"') || value.startsWith("[")) {
    try {
      return JSON.parse(value);
    } catch {
      throw new Error(`Unsupported Wrangler TOML value on line ${lineNumber}.`);
    }
  }
  throw new Error(`Unsupported Wrangler TOML value on line ${lineNumber}.`);
}

function expectSingleTable(value, label) {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new Error(`Production Wrangler config must contain exactly one ${label} entry.`);
  }
  return expectTable(value[0], label);
}

function expectTableArray(value, label, count) {
  if (!Array.isArray(value) || value.length !== count) {
    throw new Error(`Production Wrangler config must contain exactly ${count} ${label} entries.`);
  }
  return value.map((entry) => expectTable(entry, label));
}

function expectNamedTable(tables, name, label) {
  const matching = tables.filter((table) => table.name === name);
  if (matching.length !== 1) {
    throw new Error(`Production Wrangler config must contain exactly one ${label}.`);
  }
  return matching[0];
}

function expectTable(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Production Wrangler config is missing the ${label} table.`);
  }
  return value;
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} does not match the approved production value.`);
  }
}

function expectJsonEqual(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} does not match the approved production value.`);
  }
}
