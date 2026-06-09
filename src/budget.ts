/**
 * Per-session cost budget. Cumulative USD spend is tracked in-process and
 * compared against AGENT_MAX_COST_USD (default: unset = unlimited).
 *
 * Enforcement is at session boundaries — we cannot mid-stream interrupt the
 * SDK in a portable way, so we:
 *   1. Sum cost from each finished run's result message.
 *   2. Refuse to *start* a new run for a session that's already over budget.
 *   3. Audit a `_budget_exceeded` event the first time a session crosses the
 *      threshold, so it surfaces in the audit log.
 *
 * State is in-memory; restarting the process resets all session totals. For
 * a long-lived production server this should be backed by persistent storage,
 * but in-memory matches Dom's other session tracking today.
 */

import { logToolEvent } from "./audit.js";

interface SessionBudget {
  totalUsd: number;
  exceededAuditedAt?: number;
  lastTouched: number;
}

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const budgets = new Map<string, SessionBudget>();

export function getMaxCostUsd(): number | null {
  const raw = process.env.AGENT_MAX_COST_USD;
  if (!raw) return null;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function getOrCreate(sessionId: string): SessionBudget {
  let b = budgets.get(sessionId);
  if (!b) {
    b = { totalUsd: 0, lastTouched: Date.now() };
    budgets.set(sessionId, b);
  } else {
    b.lastTouched = Date.now();
  }
  return b;
}

/**
 * Add the cost of a completed run to the session total. Audits a
 * `_budget_exceeded` event the first time the threshold is crossed.
 */
export function addRunCost(sessionId: string, costUsd: number): void {
  if (!sessionId || !Number.isFinite(costUsd) || costUsd <= 0) return;
  const max = getMaxCostUsd();
  const b = getOrCreate(sessionId);
  b.totalUsd += costUsd;

  if (max !== null && b.totalUsd > max && !b.exceededAuditedAt) {
    b.exceededAuditedAt = Date.now();
    logToolEvent({
      sessionId,
      phase: "post",
      toolName: "_budget_exceeded",
      toolInput: {
        sessionTotalUsd: Number(b.totalUsd.toFixed(6)),
        budgetUsd: max,
      },
      result: "denied",
      denyReason: `Session cumulative cost $${b.totalUsd.toFixed(4)} exceeded AGENT_MAX_COST_USD=$${max}.`,
    });
  }
}

/**
 * Return true if the session has crossed the configured budget.
 * Sessions with no recorded cost return false. No budget configured → false.
 */
export function isOverBudget(sessionId: string): boolean {
  const max = getMaxCostUsd();
  if (max === null) return false;
  const b = budgets.get(sessionId);
  if (!b) return false;
  return b.totalUsd > max;
}

export function getSessionTotalUsd(sessionId: string): number {
  return budgets.get(sessionId)?.totalUsd ?? 0;
}

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, b] of budgets) {
    if (b.lastTouched < cutoff) budgets.delete(id);
  }
}, 60 * 60 * 1000).unref();

// Test-only
export const _internal = { budgets };

export function _resetAllBudgetsForTests(): void {
  budgets.clear();
}
