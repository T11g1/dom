import { query, type Query } from "@anthropic-ai/claude-agent-sdk";
import type { SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import type { AgentRequest } from "./types.js";
import { parseModelFromPrompt } from "./models.js";
import { guardrailsHook, trackChangesHook, enforceReviewHook } from "./guardrails.js";
import { buildSystemPrompt, SUBAGENTS } from "./agent-config.js";
import { ensureBrainDir } from "./brain.js";
import { runInSandbox, isSandboxEnabled } from "./sandbox.js";
import {
  ensureClaudeConfigDir,
  isEncryptionEnabled,
  decryptSessionsNow,
  encryptSessionsNow,
} from "./session-crypt.js";
import { writeGoal, clearGoal } from "./goal.js";
import { addRunCost, isOverBudget, getMaxCostUsd } from "./budget.js";

// Ensure the SDK writes sessions into the project (./.dom-claude/), not ~/.claude/
ensureClaudeConfigDir();

// Ensure the brain directory exists so the curator has somewhere to write
// from the very first run, and so any startup misconfiguration (bad
// AGENT_BRAIN_DIR) fails loudly here rather than mid-Stop-hook.
ensureBrainDir();

/**
 * Pull the cost from a finished-run message (SDK result message OR docker
 * event). Returns 0 if the message isn't a result or doesn't carry cost.
 */
function extractRunCost(message: unknown): { sessionId?: string; costUsd?: number } {
  const m = message as Record<string, unknown> | null | undefined;
  if (!m || typeof m !== "object") return {};
  // Docker AgentEvent shape: { event: "result", data: { cost, sessionId } }
  if (m.event === "result") {
    const data = m.data as Record<string, unknown> | undefined;
    return {
      sessionId: typeof data?.sessionId === "string" ? data.sessionId : undefined,
      costUsd: typeof data?.cost === "number" ? data.cost : undefined,
    };
  }
  // SDK result message: { type: "result", total_cost_usd, session_id }
  if (m.type === "result") {
    return {
      sessionId: typeof m.session_id === "string" ? m.session_id : undefined,
      costUsd: typeof m.total_cost_usd === "number" ? m.total_cost_usd : undefined,
    };
  }
  return {};
}

// ---------------------------------------------------------------------------
// Local agent — runs in-process (dev mode, no Docker)
// ---------------------------------------------------------------------------

function buildLocalQuery(request: AgentRequest): Query {
  const { model, cleanPrompt } = parseModelFromPrompt(request.prompt);
  const maxTurns = Number(process.env.AGENT_MAX_TURNS) || 50;
  const outputDir = request.outputDir || process.env.AGENT_OUTPUT_DIR || process.cwd();

  // Persist the goal so the goal-verifier subagent can read it from cwd.
  // Per-session tracking is reset implicitly when the SDK assigns a new
  // session id (or when the prior session is reset by the Stop hook on
  // successful completion).
  writeGoal(outputDir, cleanPrompt);

  return query({
    prompt: cleanPrompt,
    options: {
      model,
      maxTurns,
      cwd: outputDir,
      systemPrompt: buildSystemPrompt(),
      permissionMode: "bypassPermissions",
      allowedTools: [
        "Read", "Write", "Edit", "Bash",
        "Glob", "Grep", "WebSearch", "WebFetch", "Agent",
      ],
      agents: SUBAGENTS,
      hooks: {
        PreToolUse: [{ hooks: [guardrailsHook] }],
        PostToolUse: [{ hooks: [trackChangesHook] }],
        Stop: [{ hooks: [enforceReviewHook] }],
      },
      persistSession: true,
      ...(request.sessionId ? { resume: request.sessionId } : {}),
    },
  });
}

/**
 * Wrap the SDK query so we (a) tap cost from result messages into the
 * per-session budget, (b) always clean up the .dom-goal file, and
 * (c) optionally re-encrypt session files when AGENT_SESSION_ENCRYPT is on.
 *
 * The wrapped result preserves the Query interface (AsyncGenerator plus
 * the SDK's Query methods like .interrupt()) so callers don't change.
 */
function createLocalAgent(request: AgentRequest): Query {
  const outputDir = request.outputDir || process.env.AGENT_OUTPUT_DIR || process.cwd();
  const encryptionOn = isEncryptionEnabled();

  // Decrypt BEFORE the SDK starts reading (listSessions, resume, etc.)
  if (encryptionOn) decryptSessionsNow();

  const inner = buildLocalQuery(request);

  async function* wrapped(): AsyncGenerator<SDKMessage, void, unknown> {
    try {
      for await (const msg of inner) {
        const { sessionId, costUsd } = extractRunCost(msg);
        if (sessionId && typeof costUsd === "number") addRunCost(sessionId, costUsd);
        yield msg;
      }
    } finally {
      clearGoal(outputDir);
      if (encryptionOn) {
        try { encryptSessionsNow(); } catch { /* don't let crypto break the run result */ }
      }
    }
  }

  // Preserve Query-specific methods by delegating to the inner Query.
  const gen = wrapped() as Query;
  const delegate = (name: keyof Query) => ((...args: unknown[]) =>
    (inner as unknown as Record<string, (...a: unknown[]) => unknown>)[name as string](...args));
  for (const method of [
    "interrupt", "rewindFiles", "setPermissionMode", "setModel",
    "setMaxThinkingTokens", "initializationResult", "supportedCommands",
    "supportedModels", "supportedAgents", "mcpServerStatus", "accountInfo",
    "reconnectMcpServer", "toggleMcpServer", "setMcpServers",
    "streamInput", "stopTask", "close",
  ] as const) {
    (gen as unknown as Record<string, unknown>)[method] = delegate(method);
  }
  return gen;
}

// ---------------------------------------------------------------------------
// Sandboxed agent — runs inside Docker container
// ---------------------------------------------------------------------------

export interface AgentEvent {
  event: string;
  data: Record<string, unknown>;
}

async function* createSandboxedAgent(request: AgentRequest): AsyncGenerator<AgentEvent> {
  const { model, cleanPrompt } = parseModelFromPrompt(request.prompt);
  const maxTurns = Number(process.env.AGENT_MAX_TURNS) || 50;
  const outputDir = request.outputDir || process.env.AGENT_OUTPUT_DIR || process.cwd();

  // The container mounts outputDir at /workspace; writing the goal here
  // makes it visible to the agent and goal-verifier inside the sandbox.
  writeGoal(outputDir, cleanPrompt);

  try {
    for await (const event of runInSandbox(
      { prompt: cleanPrompt, model, maxTurns, sessionId: request.sessionId },
      outputDir,
    )) {
      const { sessionId, costUsd } = extractRunCost(event);
      if (sessionId && typeof costUsd === "number") addRunCost(sessionId, costUsd);
      yield event;
    }
  } finally {
    clearGoal(outputDir);
  }
}

// ---------------------------------------------------------------------------
// Public API — picks local or sandboxed based on config
// ---------------------------------------------------------------------------

/**
 * Throws if the requested session has already exceeded AGENT_MAX_COST_USD.
 * Surfaces as a normal error so the consumer (CLI/HTTP) can render it cleanly.
 */
export class BudgetExceededError extends Error {
  readonly budgetUsd: number;
  constructor(sessionId: string, budgetUsd: number) {
    super(
      `Session ${sessionId} has exceeded AGENT_MAX_COST_USD=$${budgetUsd}. ` +
      `Start a new session or raise the budget.`,
    );
    this.name = "BudgetExceededError";
    this.budgetUsd = budgetUsd;
  }
}

export function createAgent(request: AgentRequest): Query | AsyncGenerator<AgentEvent> {
  if (request.sessionId && isOverBudget(request.sessionId)) {
    throw new BudgetExceededError(request.sessionId, getMaxCostUsd() ?? 0);
  }
  if (isSandboxEnabled()) {
    return createSandboxedAgent(request);
  }
  return createLocalAgent(request);
}

export { isSandboxEnabled };
export type { SDKMessage, Query };
