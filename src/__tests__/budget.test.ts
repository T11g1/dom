import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  addRunCost,
  isOverBudget,
  getSessionTotalUsd,
  getMaxCostUsd,
  _resetAllBudgetsForTests,
} from "../budget.js";

// Silence the audit log for the duration of these tests.
process.env.AGENT_AUDIT_LOG = "false";

describe("budget", () => {
  beforeEach(() => _resetAllBudgetsForTests());

  it("no budget configured → never over budget", () => {
    delete process.env.AGENT_MAX_COST_USD;
    addRunCost("s", 100);
    assert.equal(isOverBudget("s"), false);
    assert.equal(getMaxCostUsd(), null);
  });

  it("accumulates cost per session", () => {
    process.env.AGENT_MAX_COST_USD = "1.00";
    addRunCost("s1", 0.25);
    addRunCost("s1", 0.30);
    assert.ok(Math.abs(getSessionTotalUsd("s1") - 0.55) < 1e-9);
    delete process.env.AGENT_MAX_COST_USD;
  });

  it("isOverBudget flips true after threshold crossed", () => {
    process.env.AGENT_MAX_COST_USD = "0.50";
    addRunCost("s2", 0.30);
    assert.equal(isOverBudget("s2"), false);
    addRunCost("s2", 0.30); // 0.60 > 0.50
    assert.equal(isOverBudget("s2"), true);
    delete process.env.AGENT_MAX_COST_USD;
  });

  it("ignores non-finite or zero/negative cost contributions", () => {
    process.env.AGENT_MAX_COST_USD = "1.00";
    addRunCost("s3", 0);
    addRunCost("s3", -1);
    addRunCost("s3", NaN);
    assert.equal(getSessionTotalUsd("s3"), 0);
    delete process.env.AGENT_MAX_COST_USD;
  });

  it("invalid AGENT_MAX_COST_USD is treated as unset", () => {
    process.env.AGENT_MAX_COST_USD = "garbage";
    assert.equal(getMaxCostUsd(), null);
    addRunCost("s4", 100);
    assert.equal(isOverBudget("s4"), false);
    delete process.env.AGENT_MAX_COST_USD;
  });
});
