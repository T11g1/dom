import { appendFileSync, mkdirSync, existsSync, statSync, renameSync } from "fs";
import { dirname, join } from "path";
import { redactSecrets } from "./leak-detect.js";

// ---------------------------------------------------------------------------
// Audit log — JSON-lines append to ./logs/audit.log with size-based rotation.
// Records every tool call: phase (pre/post), result (allowed/denied/completed),
// and sanitized input. File contents are NEVER logged — only paths/commands.
// Bash commands are passed through the secret redactor so credentials embedded
// in flags or env-style assignments don't land on disk verbatim.
// ---------------------------------------------------------------------------

const LOG_DIR = "logs";
const LOG_FILE = join(LOG_DIR, "audit.log");
const LOG_BACKUP = join(LOG_DIR, "audit.log.1");
const MAX_BYTES = 10 * 1024 * 1024; // 10 MB

function isEnabled(): boolean {
  return process.env.AGENT_AUDIT_LOG !== "false";
}

/**
 * Whitelist of which fields from tool_input to persist per tool.
 * Anything not listed is dropped — keeps file contents, secrets, etc.
 * out of the log.
 */
const KEEP_FIELDS: Record<string, string[]> = {
  Bash: ["command"],
  Write: ["file_path"],
  Edit: ["file_path"],
  Read: ["file_path"],
  Glob: ["pattern", "path"],
  Grep: ["pattern", "path", "glob"],
  WebSearch: ["query"],
  WebFetch: ["url"],
  Agent: ["subagent_type", "description"],
  // Synthetic "tool" for HTTP request-validation events.
  // IMPORTANT: whitelist metadata only — never the prompt or file contents.
  http_validation: ["route", "rule", "clientIp", "promptLen", "sessionIdProvided", "outputDirProvided"],
};

function sanitizeToolInput(toolName: string, input: Record<string, unknown>): Record<string, unknown> {
  const keep = KEEP_FIELDS[toolName];
  if (keep) {
    const out: Record<string, unknown> = {};
    for (const k of keep) {
      if (k in input) out[k] = input[k];
    }
    // Bash commands may contain inline secrets (curl -H "Authorization: Bearer ...",
    // psql connection strings, --token flags). Pass them through the redactor.
    if (toolName === "Bash" && typeof out.command === "string") {
      out.command = redactSecrets(out.command);
    }
    return out;
  }
  // Unknown tool: log only the key names so we know what arrived,
  // never the values (they may contain content/secrets).
  return { _unknown_tool_input_keys: Object.keys(input) };
}

function ensureLogDir(): void {
  const dir = dirname(LOG_FILE);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function rotateIfNeeded(): void {
  try {
    if (!existsSync(LOG_FILE)) return;
    const { size } = statSync(LOG_FILE);
    if (size < MAX_BYTES) return;
    // renameSync overwrites destination on POSIX, so the old .1 is discarded.
    renameSync(LOG_FILE, LOG_BACKUP);
  } catch {
    // Rotation best-effort; don't block logging on failure.
  }
}

export interface AuditEntry {
  timestamp: string;
  sessionId: string;
  phase: "pre" | "post";
  toolName: string;
  toolInput: Record<string, unknown>;
  result: "allowed" | "denied" | "completed";
  denyReason?: string;
}

export function logToolEvent(params: {
  sessionId: string;
  phase: "pre" | "post";
  toolName: string;
  toolInput: Record<string, unknown>;
  result: "allowed" | "denied" | "completed";
  denyReason?: string;
}): void {
  if (!isEnabled()) return;

  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    sessionId: params.sessionId || "unknown",
    phase: params.phase,
    toolName: params.toolName,
    toolInput: sanitizeToolInput(params.toolName, params.toolInput),
    result: params.result,
    ...(params.denyReason ? { denyReason: params.denyReason } : {}),
  };

  try {
    ensureLogDir();
    rotateIfNeeded();
    appendFileSync(LOG_FILE, JSON.stringify(entry) + "\n");
  } catch {
    // Audit logging must never break agent execution — swallow errors.
  }
}

// Exposed for tests
export const _internal = { LOG_FILE, LOG_BACKUP, MAX_BYTES, sanitizeToolInput };
