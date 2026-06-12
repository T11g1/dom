import "dotenv/config";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "http";
import { createServer as createHttpsServer } from "https";
import { readFileSync, realpathSync } from "fs";
import { timingSafeEqual } from "crypto";
import { pathToFileURL } from "url";
import { createAgent, BudgetExceededError, isSandboxEnabled, type AgentEvent } from "./agent.js";
import { listSessions, getSession } from "./sessions.js";
import { parseModelFromPrompt } from "./models.js";
import { resolveOutputDir } from "./sandbox.js";
import { logToolEvent } from "./audit.js";
import { isOverBudget, getMaxCostUsd, getSessionTotalUsd } from "./budget.js";

const PORT = Number(process.env.AGENT_WEB_PORT) || 3333;
const CORS_ORIGIN = process.env.AGENT_CORS_ORIGIN || "http://localhost:3333";
const RATE_LIMIT = Number(process.env.AGENT_RATE_LIMIT) || 10;
const RATE_WINDOW_MS = 60_000;
// Hard cap on a single request body. The prompt cap is 100k chars; this bounds
// the raw bytes we'll buffer before parsing, so a huge POST can't OOM us.
const MAX_BODY_BYTES = Number(process.env.AGENT_MAX_BODY_BYTES) || 1_000_000;
// Bound the rate-limit map so a source-rotating (e.g. IPv6) flood can't grow
// it without limit. Oldest entries are evicted when the cap is reached.
let MAX_RATE_BUCKETS = Number(process.env.AGENT_RATE_LIMIT_MAX_IPS) || 10_000;
// Only trust X-Forwarded-For when explicitly behind a known reverse proxy.
// Default: use the raw socket address (XFF is client-spoofable otherwise).
let TRUST_PROXY = process.env.AGENT_TRUST_PROXY === "true";

const TLS_CERT = process.env.AGENT_TLS_CERT;
const TLS_KEY = process.env.AGENT_TLS_KEY;
const TLS_ENABLED = Boolean(TLS_CERT && TLS_KEY);

// ---------------------------------------------------------------------------
// Auth — bearer token, constant-time comparison
// ---------------------------------------------------------------------------

function isAuthorized(req: IncomingMessage): boolean {
  const header = req.headers["authorization"];
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const provided = header.slice("Bearer ".length).trim();

  // Read the token at call time so the module is import-safe (no top-level
  // exit) and testable. The server refuses to START without it (see startServer).
  const expected = process.env.AGENT_API_TOKEN;
  if (!expected) return false;

  // Lengths must match before timingSafeEqual; comparing buffers of unequal length throws
  if (provided.length !== expected.length) return false;

  try {
    return timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Rate limiter — sliding window, per-IP, in-memory
// ---------------------------------------------------------------------------

const rateBuckets = new Map<string, number[]>();

function clientIp(req: IncomingMessage): string {
  if (TRUST_PROXY) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.trim()) {
      // With a single trusted reverse proxy, the RIGHTMOST entry is the address
      // our proxy actually observed (leftmost entries are client-spoofable).
      const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
      if (parts.length) return parts[parts.length - 1];
    }
  }
  return req.socket.remoteAddress ?? "unknown";
}

/**
 * Returns null if request is allowed.
 * Returns retryAfterSeconds (number) if the request is rate-limited.
 */
function checkRateLimit(ip: string): number | null {
  const now = Date.now();
  const cutoff = now - RATE_WINDOW_MS;

  let bucket = rateBuckets.get(ip);
  if (bucket) {
    // Touch: re-insert so this key becomes most-recent. Map iteration is
    // insertion order, so eviction from the front (below) then drops the
    // least-recently-ACTIVE bucket — true LRU, not FIFO. Without this, a flood
    // of new source IPs could evict an actively-limited client's bucket and
    // reset its count to zero (a rate-limit bypass).
    rateBuckets.delete(ip);
    rateBuckets.set(ip, bucket);
  } else {
    // Bound the map: evict the least-recently-active ~10% at capacity so a
    // flood from many distinct source addresses can't grow it without limit.
    if (rateBuckets.size >= MAX_RATE_BUCKETS) {
      const evict = Math.max(1, Math.floor(MAX_RATE_BUCKETS * 0.1));
      let n = 0;
      for (const k of rateBuckets.keys()) {
        rateBuckets.delete(k);
        if (++n >= evict) break;
      }
    }
    bucket = [];
    rateBuckets.set(ip, bucket);
  }

  // Drop timestamps outside the window
  while (bucket.length > 0 && bucket[0] < cutoff) bucket.shift();

  if (bucket.length >= RATE_LIMIT) {
    // Retry-After: when the oldest timestamp falls out of the window
    const retryAfterMs = bucket[0] + RATE_WINDOW_MS - now;
    return Math.max(1, Math.ceil(retryAfterMs / 1000));
  }

  bucket.push(now);
  return null;
}

// Periodic cleanup so empty/idle buckets don't accumulate forever (memory leak)
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [ip, bucket] of rateBuckets) {
    while (bucket.length > 0 && bucket[0] < cutoff) bucket.shift();
    if (bucket.length === 0) rateBuckets.delete(ip);
  }
}, RATE_WINDOW_MS).unref();

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function setCors(res: ServerResponse) {
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function sendJson(res: ServerResponse, status: number, data: unknown) {
  setCors(res);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

class BodyTooLargeError extends Error {
  readonly code = "BODY_TOO_LARGE";
  constructor() {
    super("Request body too large");
    this.name = "BodyTooLargeError";
  }
}

function readBody(req: IncomingMessage, maxBytes: number = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) {
        // Stop buffering immediately and tear down the connection so a
        // multi-gigabyte POST can't exhaust memory.
        reject(new BodyTooLargeError());
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function sendSseEvent(res: ServerResponse, event: string, data: unknown) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ---------------------------------------------------------------------------
// Input sanitization for POST /agent
// ---------------------------------------------------------------------------

const MAX_PROMPT_LEN = 100_000;
const MAX_SESSION_ID_LEN = 128;
const SESSION_ID_PATTERN = /^[A-Za-z0-9-]+$/;

/** A session id is safe iff it matches the charset and length bounds. Used by
 *  both POST /agent validation and the GET /sessions/:id route guard. */
function isValidSessionId(id: string): boolean {
  return typeof id === "string" && id.length > 0 && id.length <= MAX_SESSION_ID_LEN && SESSION_ID_PATTERN.test(id);
}

interface SanitizedAgentRequest {
  prompt: string;
  sessionId?: string;
  outputDir?: string;
}

interface ValidationFailure {
  rule: string;
  message: string;
}

function sanitizeAgentRequest(
  body: unknown,
): { ok: true; data: SanitizedAgentRequest } | { ok: false; failure: ValidationFailure } {
  if (body === null || typeof body !== "object") {
    return { ok: false, failure: { rule: "body_shape", message: "Request body must be a JSON object" } };
  }
  const raw = body as Record<string, unknown>;

  // --- prompt ---
  if (!("prompt" in raw)) {
    return { ok: false, failure: { rule: "prompt_missing", message: "Missing 'prompt' field" } };
  }
  if (typeof raw.prompt !== "string") {
    return { ok: false, failure: { rule: "prompt_type", message: "'prompt' must be a string" } };
  }
  // Strip null bytes before length checks
  const prompt = raw.prompt.replace(/\0/g, "");
  if (prompt.trim().length === 0) {
    return { ok: false, failure: { rule: "prompt_empty", message: "'prompt' must not be empty" } };
  }
  if (prompt.length > MAX_PROMPT_LEN) {
    return {
      ok: false,
      failure: { rule: "prompt_too_long", message: `'prompt' exceeds maximum length of ${MAX_PROMPT_LEN} characters` },
    };
  }

  // --- sessionId (optional) ---
  let sessionId: string | undefined;
  if (raw.sessionId !== undefined && raw.sessionId !== null) {
    if (typeof raw.sessionId !== "string") {
      return { ok: false, failure: { rule: "sessionId_type", message: "'sessionId' must be a string" } };
    }
    if (raw.sessionId.length > MAX_SESSION_ID_LEN) {
      return {
        ok: false,
        failure: { rule: "sessionId_too_long", message: `'sessionId' exceeds maximum length of ${MAX_SESSION_ID_LEN} characters` },
      };
    }
    if (!SESSION_ID_PATTERN.test(raw.sessionId)) {
      return {
        ok: false,
        failure: { rule: "sessionId_pattern", message: "'sessionId' must contain only letters, digits, and hyphens" },
      };
    }
    sessionId = raw.sessionId;
  }

  // --- outputDir (optional) ---
  let outputDir: string | undefined;
  if (raw.outputDir !== undefined && raw.outputDir !== null) {
    if (typeof raw.outputDir !== "string") {
      return { ok: false, failure: { rule: "outputDir_type", message: "'outputDir' must be a string" } };
    }
    if (raw.outputDir.includes("..")) {
      return {
        ok: false,
        failure: { rule: "outputDir_traversal", message: "'outputDir' must not contain '..' (path traversal not allowed)" },
      };
    }
    if (raw.outputDir.startsWith("/")) {
      return {
        ok: false,
        failure: { rule: "outputDir_absolute", message: "'outputDir' must not be an absolute path" },
      };
    }
    // resolveOutputDir() expands a leading '~' to $HOME, which would write
    // outside the project tree. Reject it here.
    if (raw.outputDir.startsWith("~")) {
      return {
        ok: false,
        failure: { rule: "outputDir_home_expansion", message: "'outputDir' must not start with '~' (home expansion not allowed)" },
      };
    }
    if (raw.outputDir.includes("\0")) {
      return {
        ok: false,
        failure: { rule: "outputDir_null_byte", message: "'outputDir' must not contain null bytes" },
      };
    }
    outputDir = raw.outputDir;
  }

  return { ok: true, data: { prompt, sessionId, outputDir } };
}

// ---------------------------------------------------------------------------
// Route: POST /agent — run agent with SSE streaming
// ---------------------------------------------------------------------------

async function handleAgent(req: IncomingMessage, res: ServerResponse) {
  let body: string;
  try {
    body = await readBody(req);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      sendJson(res, 413, { error: `Request body exceeds ${MAX_BODY_BYTES} bytes` });
    } else {
      sendJson(res, 400, { error: "Could not read request body" });
    }
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    sendJson(res, 400, { error: "Invalid JSON body" });
    return;
  }

  const result = sanitizeAgentRequest(parsed);
  if (!result.ok) {
    // Log metadata (never the prompt itself — it may be huge or contain secrets)
    const raw = (parsed ?? {}) as Record<string, unknown>;
    logToolEvent({
      sessionId: "http",
      phase: "pre",
      toolName: "http_validation",
      toolInput: {
        route: "POST /agent",
        rule: result.failure.rule,
        clientIp: clientIp(req),
        promptLen: typeof raw.prompt === "string" ? raw.prompt.length : -1,
        sessionIdProvided: raw.sessionId !== undefined,
        outputDirProvided: raw.outputDir !== undefined,
      },
      result: "denied",
      denyReason: result.failure.message,
    });
    sendJson(res, 400, { error: result.failure.message });
    return;
  }

  const { prompt, sessionId, outputDir } = result.data;

  // Budget check BEFORE opening the SSE stream so we can return a clean
  // 402 with a JSON body. Once we write SSE headers there's no going back.
  if (sessionId && isOverBudget(sessionId)) {
    sendJson(res, 402, {
      error: "Session over budget",
      budgetUsd: getMaxCostUsd(),
      sessionTotalUsd: Number(getSessionTotalUsd(sessionId).toFixed(6)),
    });
    return;
  }

  const resolvedDir = resolveOutputDir(
    outputDir || process.env.AGENT_OUTPUT_DIR || process.cwd(),
  );

  // Report which model will be used
  const { model } = parseModelFromPrompt(prompt);

  // SSE headers
  setCors(res);
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  sendSseEvent(res, "status", { model, outputDir: resolvedDir, sandbox: isSandboxEnabled() });

  try {
    const agent = createAgent({ prompt, outputDir: resolvedDir, sessionId });

    for await (const message of agent) {
      if (res.destroyed) break;

      // Docker sandbox emits AgentEvent (has .event), local SDK emits SDKMessage (has .type)
      if ("event" in message) {
        const evt = message as AgentEvent;
        // Forward Docker events directly as SSE — they're already in the right shape
        sendSseEvent(res, evt.event, evt.data);
      } else {
        const msg = message as Record<string, unknown>;
        switch (msg.type) {
          case "system":
            if (msg.subtype === "init") {
              sendSseEvent(res, "session", { sessionId: msg.session_id });
            }
            break;
          case "assistant": {
            const content = msg.message as Record<string, unknown> | undefined;
            const blocks = content?.content as Array<Record<string, unknown>> | undefined;
            if (!blocks) break;
            for (const block of blocks) {
              if ("text" in block && block.text) {
                sendSseEvent(res, "text", { text: block.text });
              } else if ("name" in block) {
                sendSseEvent(res, "tool", { name: block.name });
              }
            }
            break;
          }
          case "result":
            sendSseEvent(res, "result", {
              subtype: msg.subtype,
              turns: msg.num_turns,
              cost: msg.total_cost_usd,
              sessionId: msg.session_id,
            });
            break;
        }
      }
    }
  } catch (err) {
    // Log the detail server-side; never reflect raw err.message (host paths,
    // internal IDs, dependency internals) to the client.
    console.error("[agent] run error:", err);
    sendSseEvent(res, "error", {
      message: err instanceof BudgetExceededError ? err.message : "Internal error during agent run",
      ...(err instanceof BudgetExceededError ? { kind: "budget_exceeded", budgetUsd: err.budgetUsd } : {}),
    });
  }

  sendSseEvent(res, "done", {});
  res.end();
}

// ---------------------------------------------------------------------------
// Route: GET /sessions
// ---------------------------------------------------------------------------

async function handleListSessions(_req: IncomingMessage, res: ServerResponse) {
  try {
    const sessions = await listSessions();
    sendJson(res, 200, { sessions });
  } catch (err) {
    console.error("[sessions] list error:", err);
    sendJson(res, 500, { error: "Internal error" });
  }
}

// ---------------------------------------------------------------------------
// Route: GET /sessions/:id
// ---------------------------------------------------------------------------

async function handleGetSession(sessionId: string, res: ServerResponse) {
  try {
    const session = await getSession(sessionId);
    if (!session) {
      sendJson(res, 404, { error: "Session not found" });
      return;
    }
    sendJson(res, 200, { session });
  } catch (err) {
    console.error("[sessions] get error:", err);
    sendJson(res, 500, { error: "Internal error" });
  }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const SCHEME = TLS_ENABLED ? "https" : "http";

const requestHandler = async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", `${SCHEME}://localhost:${PORT}`);

  // CORS preflight
  if (req.method === "OPTIONS") {
    setCors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check — public, no auth
  if (url.pathname === "/health") {
    sendJson(res, 200, { status: "ok" });
    return;
  }

  // All other routes require bearer token auth
  if (!isAuthorized(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }

  // POST /agent — rate-limited per IP
  if (req.method === "POST" && url.pathname === "/agent") {
    const retryAfter = checkRateLimit(clientIp(req));
    if (retryAfter !== null) {
      setCors(res);
      res.setHeader("Retry-After", String(retryAfter));
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Rate limited. Try again in ${retryAfter} seconds.` }));
      return;
    }
    await handleAgent(req, res);
    return;
  }

  // GET /sessions
  if (req.method === "GET" && url.pathname === "/sessions") {
    await handleListSessions(req, res);
    return;
  }

  // GET /sessions/:id — validate the path param with the SAME rules as the
  // POST body. url.pathname is percent-decoded, so an un-validated `.+` would
  // let `..%2f..%2fetc` reach the filesystem-backed SDK lookup.
  const sessionMatch = url.pathname.match(/^\/sessions\/(.+)$/);
  if (req.method === "GET" && sessionMatch) {
    const id = sessionMatch[1];
    if (!isValidSessionId(id)) {
      sendJson(res, 400, { error: "Invalid session id" });
      return;
    }
    await handleGetSession(id, res);
    return;
  }

  // 404
  sendJson(res, 404, { error: "Not found" });
};

// Bootstrap is wrapped in startServer() and only invoked when this module is
// run directly — so importing it (e.g. from tests) doesn't exit the process,
// validate TLS, or bind a port.
/**
 * Validate required startup config. Throws (does not exit) so it's unit-testable;
 * startServer() turns a throw into a logged process.exit(1).
 *  - AGENT_API_TOKEN must be set (no auth = no server).
 *  - TLS cert+key must be both-set or both-unset (fail closed — never half-TLS).
 */
export function assertStartupConfig(opts?: { apiToken?: string; tlsCert?: string; tlsKey?: string }): void {
  const apiToken = opts && "apiToken" in opts ? opts.apiToken : process.env.AGENT_API_TOKEN;
  const tlsCert = opts && "tlsCert" in opts ? opts.tlsCert : TLS_CERT;
  const tlsKey = opts && "tlsKey" in opts ? opts.tlsKey : TLS_KEY;

  if (!apiToken) {
    throw new Error("AGENT_API_TOKEN must be set. Generate one with: openssl rand -hex 32");
  }
  if (Boolean(tlsCert) !== Boolean(tlsKey)) {
    throw new Error(
      "AGENT_TLS_CERT and AGENT_TLS_KEY must both be set, or neither. " +
      "To generate a self-signed dev cert: " +
      "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes",
    );
  }
}

export function startServer() {
  try {
    assertStartupConfig();
  } catch (err) {
    console.error("Error:", err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  const server = TLS_ENABLED
    ? createHttpsServer(
        { cert: readFileSync(TLS_CERT!), key: readFileSync(TLS_KEY!) },
        requestHandler,
      )
    : createHttpServer(requestHandler);

  server.listen(PORT, () => {
    console.log(`\nDom server on ${SCHEME}://localhost:${PORT}\n`);
    console.log("  POST /agent          { prompt, sessionId?, outputDir? } → SSE stream  [auth]");
    console.log("  GET  /sessions       List recent sessions  [auth]");
    console.log("  GET  /sessions/:id   Get session details  [auth]");
    console.log("  GET  /health         Health check  (public)");
    console.log("\n  Auth:        Authorization: Bearer <AGENT_API_TOKEN>");
    console.log(`  CORS origin: ${CORS_ORIGIN}`);
    console.log(`  Rate limit:  ${RATE_LIMIT} requests/minute per ${TRUST_PROXY ? "client (via X-Forwarded-For)" : "IP"} on POST /agent`);
    console.log(`  TLS:         ${TLS_ENABLED ? "enabled" : "disabled (HTTP)"}\n`);
    if (CORS_ORIGIN === "*") {
      console.warn("  Warning: CORS is set to allow all origins. Restrict this in production.\n");
    }
  });

  return server;
}

// Only auto-start when executed directly (node dist/server.js / tsx src/server.ts).
// Compare realpaths: under tsx, import.meta.url is realpath-resolved while
// process.argv[1] may be a symlink (e.g. a project under /tmp), so a raw compare
// would silently fail to start the server.
function isMainModule(): boolean {
  const invoked = process.argv[1];
  if (!invoked) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(invoked)).href;
  } catch {
    return import.meta.url === pathToFileURL(invoked).href;
  }
}
if (isMainModule()) {
  startServer();
}

// ---------------------------------------------------------------------------
// Exports for tests (the module is import-safe; nothing above binds a port).
// ---------------------------------------------------------------------------

export {
  sanitizeAgentRequest,
  isValidSessionId,
  isAuthorized,
  clientIp,
  checkRateLimit,
  readBody,
  BodyTooLargeError,
};

export const _internal = {
  rateBuckets,
  setMaxRateBucketsForTests: (n: number) => { MAX_RATE_BUCKETS = n; },
  setTrustProxyForTests: (b: boolean) => { TRUST_PROXY = b; },
};
