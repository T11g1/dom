/**
 * Goal persistence — captures the user's original prompt so the goal-verifier
 * subagent can compare the generated output against the actual ask.
 *
 * The goal is written as a markdown file into the agent's working directory
 * (so subagents can Read it with a relative path). Filename is .dom-goal —
 * dotfile to discourage commits; users should add it to .gitignore.
 */

import { writeFileSync, readFileSync, existsSync, unlinkSync } from "fs";
import { join } from "path";

export const GOAL_FILENAME = ".dom-goal";

/**
 * Write the goal file into the given working directory.
 * Truncates anything previously there.
 */
export function writeGoal(cwd: string, prompt: string): void {
  const body =
    "# Dom — original user goal\n\n" +
    "This file was written by Dom at the start of the run. The goal-verifier\n" +
    "subagent reads it to check that the built output addresses what the user\n" +
    "asked for. Do not edit while a run is active.\n\n" +
    "---\n\n" +
    prompt.trim() +
    "\n";

  writeFileSync(join(cwd, GOAL_FILENAME), body, { mode: 0o600 });
}

/**
 * Read the goal file. Returns null if missing.
 */
export function readGoal(cwd: string): string | null {
  const goalPath = join(cwd, GOAL_FILENAME);
  if (!existsSync(goalPath)) return null;
  return readFileSync(goalPath, "utf-8");
}

/**
 * Best-effort cleanup. Safe to call when the file is already gone.
 */
export function clearGoal(cwd: string): void {
  try {
    unlinkSync(join(cwd, GOAL_FILENAME));
  } catch {
    /* already gone */
  }
}
