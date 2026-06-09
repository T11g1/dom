import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeGoal, readGoal, clearGoal, GOAL_FILENAME } from "../goal.js";

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "dom-goal-test-"));
}

describe("goal", () => {
  it("write → read round-trips the prompt", () => {
    const dir = tmpDir();
    try {
      writeGoal(dir, "Build me a CLI for X");
      const got = readGoal(dir);
      assert.ok(got);
      assert.ok(got!.includes("Build me a CLI for X"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("writes with 0600 permissions", () => {
    const dir = tmpDir();
    try {
      writeGoal(dir, "x");
      const mode = statSync(join(dir, GOAL_FILENAME)).mode & 0o777;
      assert.equal(mode, 0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("clearGoal removes the file (and is idempotent)", () => {
    const dir = tmpDir();
    try {
      writeGoal(dir, "x");
      clearGoal(dir);
      assert.equal(existsSync(join(dir, GOAL_FILENAME)), false);
      // Calling again on a clean dir should not throw.
      clearGoal(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("readGoal returns null when the file is missing", () => {
    const dir = tmpDir();
    try {
      assert.equal(readGoal(dir), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
