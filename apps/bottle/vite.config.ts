import type { IncomingMessage, ServerResponse } from "node:http";
import { execFileSync } from "node:child_process";
import { defineConfig, type Plugin } from "vite";
import { MAX_DROP_BODY_BYTES } from "./src/domain/validation";
import { SECURITY_HEADERS, createMemoryBottleStorage, handleRequest } from "./worker/index";

const sourceCommit = gitOutput(["rev-parse", "HEAD"]) ?? "unknown";
const treeStatus = gitOutput(["status", "--porcelain=v1", "--untracked-files=all"]);
const treeState = treeStatus === undefined ? "unknown" : treeStatus === "" ? "clean" : "dirty";

export default defineConfig({
  define: {
    __DAYLIGHT_SOURCE_COMMIT__: JSON.stringify(sourceCommit),
    __DAYLIGHT_TREE_STATE__: JSON.stringify(treeState)
  },
  plugins: [daylightBottleApiDevPlugin()],
  publicDir: "public",
  build: {
    outDir: "dist",
    emptyOutDir: true
  },
  server: {
    headers: SECURITY_HEADERS,
    host: "127.0.0.1",
    port: 5173,
    strictPort: false
  },
  preview: {
    headers: SECURITY_HEADERS,
    host: "127.0.0.1",
    port: 4173,
    strictPort: false
  }
});

function gitOutput(args: string[]): string | undefined {
  try {
    return execFileSync("git", args, {
      cwd: new URL("../../", import.meta.url),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return undefined;
  }
}

function daylightBottleApiDevPlugin(): Plugin {
  const store = createMemoryBottleStorage();

  return {
    name: "daylight-bottle-api-dev",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith("/api/")) {
          next();
          return;
        }

        try {
          const origin = `http://${req.headers.host ?? "127.0.0.1:5173"}`;
          const body = await readRequestBody(req);
          const headers = new Headers();
          for (const [name, value] of Object.entries(req.headers)) {
            if (Array.isArray(value)) {
              for (const item of value) {
                headers.append(name, item);
              }
            } else if (value !== undefined) {
              headers.set(name, value);
            }
          }

          const requestInit: RequestInit = { headers };
          if (req.method) {
            requestInit.method = req.method;
          }
          if (body.length > 0 && req.method !== "GET" && req.method !== "HEAD") {
            const requestBody: Uint8Array<ArrayBuffer> = new Uint8Array(body.length);
            requestBody.set(body);
            requestInit.body = requestBody;
          }

          const response = await handleRequest(
            new Request(new URL(req.url, origin), requestInit),
            { __TEST_STORE__: store }
          );
          await writeResponse(res, response);
        } catch (error) {
          const response = localErrorResponse(
            error instanceof RequestBodyTooLargeError ? 413 : 500,
            error instanceof RequestBodyTooLargeError
              ? "Bottle request body is too large."
              : "Local API error."
          );
          await writeResponse(res, response);
        }
      });
    }
  };
}

async function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  const contentLength = req.headers["content-length"];
  if (contentLength && /^\d+$/.test(contentLength.trim())) {
    const advertisedLength = Number(contentLength);
    if (!Number.isSafeInteger(advertisedLength) || advertisedLength > MAX_DROP_BODY_BYTES) {
      req.resume();
      throw new RequestBodyTooLargeError();
    }
  }

  const body = Buffer.allocUnsafe(MAX_DROP_BODY_BYTES);
  let totalBytes = 0;
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (totalBytes + buffer.byteLength > MAX_DROP_BODY_BYTES) {
      req.resume();
      throw new RequestBodyTooLargeError();
    }
    buffer.copy(body, totalBytes);
    totalBytes += buffer.byteLength;
  }
  return body.subarray(0, totalBytes);
}

function localErrorResponse(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }, null, 2), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

async function writeResponse(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, name) => {
    res.setHeader(name, value);
  });
  res.end(Buffer.from(await response.arrayBuffer()));
}

class RequestBodyTooLargeError extends Error {
  constructor() {
    super("Bottle request body is too large.");
  }
}
