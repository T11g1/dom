import "dotenv/config";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "http";
import { createServer as createHttpsServer } from "https";
import { readFileSync } from "fs";
import { timingSafeEqual } from "crypto";
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

// Refuse to start without an auth token configured
const AGENT_API_TOKEN = process.env.AGENT_API_TOKEN;
if (!AGENT_API_TOKEN) {
  console.error("Error: AGENT_API_TOKEN must be set. Generate one with: openssl rand -hex 32");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// TLS — both cert+key must be set, or neither. Enforced before we start.
// ---------------------------------------------------------------------------

const TLS_CERT = process.env.AGENT_TLS_CERT;
const TLS_KEY = process.env.AGENT_TLS_KEY;

if (Boolean(TLS_CERT) !== Boolean(TLS_KEY)) {
  console.error(
    "Error: AGENT_TLS_CERT and AGENT_TLS_KEY must both be set, or neither. " +
    "To generate a self-signed dev cert: " +
    "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes",
  );
  process.exit(1);
}

const TLS_ENABLED = Boolean(TLS_CERT && TLS_KEY);

// ---------------------------------------------------------------------------
// Auth — bearer token, constant-time comparison
// ---------------------------------------------------------------------------

function isAuthorized(req: IncomingMessage): boolean {
  const header = req.headers["authorization"];
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const provided = header.slice("Bearer ".length).trim();

  // Lengths must match before timingSafeEqual; comparing buffers of unequal length throws
  const expected = AGENT_API_TOKEN!;
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
  if (!bucket) {
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

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
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
  const body = await readBody(req);

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
    const message = err instanceof Error ? err.message : String(err);
    sendSseEvent(res, "error", {
      message,
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
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
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
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
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

  // GET /sessions/:id
  const sessionMatch = url.pathname.match(/^\/sessions\/(.+)$/);
  if (req.method === "GET" && sessionMatch) {
    await handleGetSession(sessionMatch[1], res);
    return;
  }

  // 404
  sendJson(res, 404, { error: "Not found" });
};

// Create HTTP or HTTPS server based on env. If cert/key files can't be read,
// fail fast with the underlying fs error — better than a confused TLS handshake later.
const server = TLS_ENABLED
  ? createHttpsServer(
      {
        cert: readFileSync(TLS_CERT!),
        key: readFileSync(TLS_KEY!),
      },
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
  console.log(`  Rate limit:  ${RATE_LIMIT} requests/minute per IP on POST /agent`);
  console.log(`  TLS:         ${TLS_ENABLED ? "enabled" : "disabled (HTTP)"}\n`);
  if (CORS_ORIGIN === "*") {
    console.warn("  Warning: CORS is set to allow all origins. Restrict this in production.\n");
  }
});
