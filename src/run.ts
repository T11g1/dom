#!/usr/bin/env node
/**
 * Container entrypoint. Runs a single agent query inside the Docker sandbox.
 *
 * Usage: node run.js '{"prompt":"...","model":"claude-sonnet-4-6"}'
 *
 * Streams JSON-lines to stdout — one event per line.
 * The host process (sandbox.ts) reads these and forwards them to the CLI/HTTP client.
 */
import { query } from "@anthropic-ai/claude-agent-sdk";
import { guardrailsHook, trackChangesHook, enforceReviewHook } from "./guardrails.js";
import { buildSystemPrompt, SUBAGENTS } from "./agent-config.js";

interface RunRequest {
  prompt: string;
  model: string;
  maxTurns: number;
  sessionId?: string;
}

function emit(event: string, data: unknown) {
  process.stdout.write(JSON.stringify({ event, data }) + "\n");
}

async function main() {
  const input = process.argv[2];
  if (!input) {
    emit("error", { message: "No request JSON provided" });
    process.exit(1);
  }

  let request: RunRequest;
  try {
    request = JSON.parse(input);
  } catch {
    emit("error", { message: "Invalid request JSON" });
    process.exit(1);
  }

  const agent = query({
    prompt: request.prompt,
    options: {
      model: request.model,
      maxTurns: request.maxTurns,
      cwd: "/workspace",
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

  for await (const message of agent) {
    switch (message.type) {
      case "system": {
        if (message.subtype === "init") {
          const sessionId = (message as Record<string, unknown>).session_id;
          emit("session", { sessionId });
        }
        break;
      }
      case "assistant": {
        const content = (message as Record<string, unknown>).message as Record<string, unknown> | undefined;
        const blocks = content?.content as Array<Record<string, unknown>> | undefined;
        if (!blocks) break;
        for (const block of blocks) {
          if ("text" in block && block.text) {
            emit("text", { text: block.text });
          } else if ("name" in block) {
            emit("tool", { name: block.name });
          }
        }
        break;
      }
      case "result": {
        const r = message as Record<string, unknown>;
        emit("result", {
          subtype: r.subtype,
          turns: r.num_turns,
          cost: r.total_cost_usd,
          sessionId: r.session_id,
        });
        break;
      }
    }
  }

  emit("done", {});
}

main().catch((err) => {
  emit("error", { message: err instanceof Error ? err.message : String(err) });
  process.exit(1);
});
