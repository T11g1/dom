import {
  listSessions as sdkListSessions,
  getSessionInfo as sdkGetSessionInfo,
} from "@anthropic-ai/claude-agent-sdk";
import type { SessionInfo } from "./types.js";
import {
  ensureClaudeConfigDir,
  isEncryptionEnabled,
  beginActiveRun,
  endActiveRun,
} from "./session-crypt.js";

// Ensure SDK reads/writes into the project-local ./.dom-claude/ dir.
ensureClaudeConfigDir();

/**
 * Bracket a read-only SDK call with decrypt-before / encrypt-after so
 * listSessions/getSessionInfo can open plaintext metadata and we reseal
 * once done.
 */
async function withDecryptedSessions<T>(fn: () => Promise<T>): Promise<T> {
  if (!isEncryptionEnabled()) return fn();
  // Share the run-level reference count so a listing during an active run
  // doesn't prematurely re-encrypt the tree out from under it. Re-encryption
  // failures are surfaced (not swallowed) by endActiveRun.
  beginActiveRun();
  try {
    return await fn();
  } finally {
    endActiveRun();
  }
}

/**
 * List recent agent sessions, newest first.
 */
export async function listSessions(limit = 20): Promise<SessionInfo[]> {
  return withDecryptedSessions(async () => {
    const sessions = await sdkListSessions();
    return sessions
      .sort((a, b) => b.lastModified - a.lastModified)
      .slice(0, limit)
      .map((s) => ({
        id: s.sessionId,
        title: s.customTitle || s.summary || s.firstPrompt || "Untitled",
        createdAt: s.createdAt ?? s.lastModified,
        lastPrompt: s.firstPrompt,
      }));
  });
}

/**
 * Get details for a single session by ID.
 */
export async function getSession(sessionId: string): Promise<SessionInfo | null> {
  return withDecryptedSessions(async () => {
    try {
      const s = await sdkGetSessionInfo(sessionId);
      if (!s) return null;
      return {
        id: s.sessionId,
        title: s.customTitle || s.summary || s.firstPrompt || "Untitled",
        createdAt: s.createdAt ?? s.lastModified,
        lastPrompt: s.firstPrompt,
      };
    } catch {
      return null;
    }
  });
}
