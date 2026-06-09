import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  guardrailsHook,
  trackChangesHook,
  enforceReviewHook,
  _internal,
  _resetAllSessionStateForTests,
  resetSessionState,
} from "../guardrails.js";

const { evaluate, isHostAllowed, getState } = _internal;

// Silence the audit log for the duration of these tests.
process.env.AGENT_AUDIT_LOG = "false";

describe("guardrails — destructive command detection", () => {
  it("blocks rm -rf /", () => {
    assert.ok(evaluate("Bash", { command: "rm -rf /" })?.startsWith("Blocked"));
  });
  it("blocks rm -rf ~", () => {
    assert.ok(evaluate("Bash", { command: "rm -rf ~" })?.startsWith("Blocked"));
  });
  it("blocks git push --force to main", () => {
    assert.ok(evaluate("Bash", { command: "git push --force origin main" })?.startsWith("Blocked"));
  });
  it("blocks DROP TABLE in any case", () => {
    assert.ok(evaluate("Bash", { command: "psql -c 'drop table users'" })?.startsWith("Blocked"));
  });
  it("blocks fork bomb", () => {
    assert.ok(evaluate("Bash", { command: ":(){ :|:& };:" })?.startsWith("Blocked"));
  });
  it("blocks nested shell wrapping rm -rf /", () => {
    assert.ok(evaluate("Bash", { command: "bash -c 'rm -rf /'" })?.startsWith("Blocked"));
  });
  it("blocks $(...) wrapping rm -rf /", () => {
    assert.ok(evaluate("Bash", { command: "echo $(rm -rf /tmp/x; rm -rf /)" })?.startsWith("Blocked"));
  });
  it("allows ordinary build commands", () => {
    assert.equal(evaluate("Bash", { command: "npm install" }), null);
    assert.equal(evaluate("Bash", { command: "git status" }), null);
  });
});

describe("guardrails — network policy", () => {
  it("allows curl to github.com", () => {
    assert.equal(evaluate("Bash", { command: "curl https://github.com/foo" }), null);
  });
  it("blocks curl to attacker.com", () => {
    assert.ok(evaluate("Bash", { command: "curl https://attacker.com/x" })?.startsWith("Blocked"));
  });
  it("blocks script-mode http calls in node -e", () => {
    assert.ok(evaluate("Bash", { command: "node -e 'fetch(\"https://x\")'" })?.startsWith("Blocked"));
  });
});

describe("guardrails — WebFetch host allowlist", () => {
  it("blocks WebFetch to an unknown host", () => {
    const result = evaluate("WebFetch", { url: "https://attacker.com/exfil" });
    assert.ok(result?.startsWith("Blocked"), `expected block, got: ${result}`);
  });
  it("allows WebFetch to github.com", () => {
    assert.equal(evaluate("WebFetch", { url: "https://github.com/owner/repo" }), null);
  });
  it("blocks malformed URLs", () => {
    assert.ok(evaluate("WebFetch", { url: "not-a-url" })?.startsWith("Blocked"));
  });
});

describe("guardrails — Write/Edit content leak detection", () => {
  it("blocks writing an Anthropic API key", () => {
    const result = evaluate("Write", {
      file_path: "/workspace/src/cfg.ts",
      content: "export const KEY = 'sk-ant-realsecrettoken1234567890abcdef';",
    });
    assert.ok(result?.startsWith("Blocked"), `expected block, got: ${result}`);
    assert.ok(result?.includes("anthropic_api_key"), "deny reason should name the pattern");
  });
  it("blocks Edit replacing with a postgres password", () => {
    const result = evaluate("Edit", {
      file_path: "/workspace/db.ts",
      new_string: "const url = 'postgres://app:hunter2@db/internal';",
    });
    assert.ok(result?.startsWith("Blocked"), `expected block, got: ${result}`);
  });
  it("allows clean config code referencing env vars", () => {
    assert.equal(
      evaluate("Write", {
        file_path: "/workspace/cfg.ts",
        content: "export const KEY = process.env.ANTHROPIC_API_KEY;",
      }),
      null,
    );
  });
});

describe("guardrails — tester subagent Bash allowlist", () => {
  it("denies arbitrary Bash inside tester", () => {
    const result = evaluate("Bash", { command: "git log" }, "tester");
    assert.ok(result?.startsWith("Blocked"));
  });
  it("allows npm test inside tester", () => {
    assert.equal(evaluate("Bash", { command: "npm test" }, "tester"), null);
  });
});

describe("guardrails — agent_id gating for per-subagent policy (L1 regression)", () => {
  it("hook with agent_id + agent_type='tester' enforces tester policy", async () => {
    const out = await guardrailsHook(
      {
        tool_name: "Bash",
        tool_input: { command: "git log" },
        session_id: "L1a",
        agent_id: "ag-1",
        agent_type: "tester",
      } as never,
      {} as never,
      {} as never,
    );
    assert.equal((out as { behavior?: string }).behavior, "deny");
  });

  it("hook with agent_type='tester' but no agent_id is treated as main-thread (no per-subagent policy)", async () => {
    const out = await guardrailsHook(
      {
        tool_name: "Bash",
        tool_input: { command: "git log" },
        session_id: "L1b",
        // agent_id missing — the SDK says agent_type can still be set on
        // the main thread of an --agent session; we must NOT enforce tester
        // Bash policy in that case.
        agent_type: "tester",
      } as never,
      {} as never,
      {} as never,
    );
    assert.deepEqual(out, {});
  });
});

describe("guardrails — host allowlist with extras", () => {
  it("respects ALLOWED_HOSTS env extras", () => {
    const prev = process.env.ALLOWED_HOSTS;
    process.env.ALLOWED_HOSTS = "extra.example.com";
    try {
      assert.equal(isHostAllowed("extra.example.com"), true);
      assert.equal(isHostAllowed("sub.extra.example.com"), true);
      assert.equal(isHostAllowed("unrelated.example.com"), false);
    } finally {
      if (prev === undefined) delete process.env.ALLOWED_HOSTS;
      else process.env.ALLOWED_HOSTS = prev;
    }
  });
});

describe("guardrails — session state isolation (C1 regression)", () => {
  beforeEach(() => _resetAllSessionStateForTests());

  it("Stop hook blocks when files changed without subagents", async () => {
    await trackChangesHook(
      { tool_name: "Write", tool_input: { file_path: "/x" }, session_id: "s1" } as never,
      {} as never,
      {} as never,
    );
    const stop = await enforceReviewHook({ session_id: "s1" } as never, {} as never, {} as never);
    assert.equal((stop as { decision?: string }).decision, "block");
  });

  it("Stop hook blocks when WebFetch was used (M3 regression)", async () => {
    await trackChangesHook(
      { tool_name: "WebFetch", tool_input: { url: "https://github.com/x" }, session_id: "s2" } as never,
      {} as never,
      {} as never,
    );
    const stop = await enforceReviewHook({ session_id: "s2" } as never, {} as never, {} as never);
    assert.equal((stop as { decision?: string }).decision, "block");
  });

  it("session A's flags do not leak into session B", async () => {
    await trackChangesHook(
      { tool_name: "Write", tool_input: { file_path: "/x" }, session_id: "A" } as never,
      {} as never,
      {} as never,
    );
    await trackChangesHook(
      { tool_name: "Agent", tool_input: { subagent_type: "code-reviewer" }, session_id: "A" } as never,
      {} as never,
      {} as never,
    );
    // Session B has no recorded activity — Stop should pass.
    const stop = await enforceReviewHook({ session_id: "B" } as never, {} as never, {} as never);
    assert.deepEqual(stop, {});
  });

  it("Stop passes once all five subagents have run (with files changed)", async () => {
    const sid = "all-good";
    await trackChangesHook(
      { tool_name: "Write", tool_input: { file_path: "/x" }, session_id: sid } as never,
      {} as never,
      {} as never,
    );
    for (const sub of ["code-reviewer", "tester", "eval", "goal-verifier", "brain-curator"] as const) {
      await trackChangesHook(
        { tool_name: "Agent", tool_input: { subagent_type: sub }, session_id: sid } as never,
        {} as never,
        {} as never,
      );
    }
    const stop = await enforceReviewHook({ session_id: sid } as never, {} as never, {} as never);
    assert.deepEqual(stop, {});
  });

  it("Stop block reason lists brain-curator when missing", async () => {
    const sid = "missing-brain";
    await trackChangesHook(
      { tool_name: "Write", tool_input: { file_path: "/x" }, session_id: sid } as never,
      {} as never,
      {} as never,
    );
    for (const sub of ["code-reviewer", "tester", "eval", "goal-verifier"] as const) {
      await trackChangesHook(
        { tool_name: "Agent", tool_input: { subagent_type: sub }, session_id: sid } as never,
        {} as never,
        {} as never,
      );
    }
    const stop = await enforceReviewHook({ session_id: sid } as never, {} as never, {} as never);
    const reason = (stop as { reason?: string }).reason ?? "";
    assert.match(reason, /brain-curator/);
  });

  it("loose subagent name does NOT satisfy the requirement (C4 regression)", async () => {
    const sid = "loose";
    await trackChangesHook(
      { tool_name: "Write", tool_input: { file_path: "/x" }, session_id: sid } as never,
      {} as never,
      {} as never,
    );
    // Fake an Agent dispatch with a description that contains "review"
    await trackChangesHook(
      { tool_name: "Agent", tool_input: { description: "review the import path" }, session_id: sid } as never,
      {} as never,
      {} as never,
    );
    const stop = await enforceReviewHook({ session_id: sid } as never, {} as never, {} as never);
    assert.equal(
      (stop as { decision?: string }).decision,
      "block",
      "loose description should NOT satisfy code-reviewer",
    );
  });

  it("resetSessionState clears flags between user prompts", async () => {
    const sid = "reset-me";
    await trackChangesHook(
      { tool_name: "Write", tool_input: { file_path: "/x" }, session_id: sid } as never,
      {} as never,
      {} as never,
    );
    resetSessionState(sid);
    const state = getState(sid);
    assert.equal(state.filesChanged, false);
    assert.equal(state.reviewerRan, false);
    assert.equal(state.brainCuratorRan, false);
  });
});

describe("guardrails — brain-curator path restriction", () => {
  it("allows Write under the brain dir", () => {
    const brainDir = process.env.AGENT_BRAIN_DIR || `${process.cwd()}/.dom-brain`;
    const result = evaluate(
      "Write",
      { file_path: `${brainDir}/user-prefs.md`, content: "harmless body" },
      "brain-curator",
    );
    assert.equal(result, null);
  });

  it("blocks Write outside the brain dir", () => {
    const result = evaluate(
      "Write",
      { file_path: "/workspace/src/index.ts", content: "console.log('x');" },
      "brain-curator",
    );
    assert.ok(result?.startsWith("Blocked"), `expected block, got: ${result}`);
    assert.match(result!, /brain-curator/);
  });

  it("blocks Edit outside the brain dir", () => {
    const result = evaluate(
      "Edit",
      { file_path: "/workspace/CLAUDE.md", new_string: "anything" },
      "brain-curator",
    );
    assert.ok(result?.startsWith("Blocked"));
  });

  it("only enforced for brain-curator, not for other subagents", () => {
    const result = evaluate(
      "Write",
      { file_path: "/workspace/src/index.ts", content: "console.log('x');" },
      "tester",
    );
    // tester is restricted on Bash, not on Write paths
    assert.equal(result, null);
  });

  it("blocks path traversal via '..' segments", () => {
    const brainDir = process.env.AGENT_BRAIN_DIR || `${process.cwd()}/.dom-brain`;
    const result = evaluate(
      "Write",
      { file_path: `${brainDir}/../escape.md`, content: "x" },
      "brain-curator",
    );
    assert.ok(result?.startsWith("Blocked"), `expected block, got: ${result}`);
    assert.match(result!, /outside the brain/);
  });

  it("rejects relative paths from brain-curator", () => {
    const result = evaluate(
      "Write",
      { file_path: "memory.md", content: "x" },
      "brain-curator",
    );
    assert.ok(result?.startsWith("Blocked"));
    assert.match(result!, /absolute paths/);
  });
});
