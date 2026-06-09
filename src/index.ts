#!/usr/bin/env node
import "dotenv/config";
import { createAgent, isSandboxEnabled, type AgentEvent } from "./agent.js";
import type { SDKSystemMessage, SDKAssistantMessage, SDKResultMessage } from "@anthropic-ai/claude-agent-sdk";
import { listSessions } from "./sessions.js";
import { parseModelFromPrompt, MODEL_DEFAULT, MODEL_POWER } from "./models.js";
import { resolveOutputDir } from "./sandbox.js";
import kleur from "kleur";
import { createInterface } from "readline";

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

function printBanner() {
  console.log(kleur.cyan().bold("\n  Dom"));
  console.log(kleur.gray("  Autonomous coding agent\n"));
}

function printConfig(outputDir: string, sandboxed: boolean) {
  console.log(kleur.gray(`  Default model : ${MODEL_DEFAULT}`));
  console.log(kleur.gray(`  Opus prefix   : /opus <prompt>`));
  console.log(kleur.gray(`  Output dir    : ${outputDir}`));
  console.log(kleur.gray(`  Sandbox       : ${sandboxed ? kleur.green("Docker") : kleur.yellow("off (local)")}`));
  console.log(kleur.gray(`  Resume        : --resume <sessionId>`));
  console.log(kleur.gray(`  List sessions : --list-sessions`));
  console.log(kleur.gray("  Type 'exit' to quit.\n"));
}

// ---------------------------------------------------------------------------
// Unified event handler — works for both local SDK messages and Docker events
// ---------------------------------------------------------------------------

function handleSandboxEvent(event: AgentEvent, startTime: number): string | undefined {
  let sessionId: string | undefined;

  switch (event.event) {
    case "session":
      sessionId = event.data.sessionId as string;
      break;
    case "text":
      process.stdout.write(String(event.data.text));
      break;
    case "tool":
      console.log(kleur.yellow(`\n  [tool] ${event.data.name}`));
      break;
    case "result": {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const subtype = event.data.subtype as string;
      const turns = event.data.turns as number;
      const cost = event.data.cost as number;
      console.log("\n");
      if (subtype === "success") {
        console.log(kleur.green().bold("  Done!"));
      } else {
        console.log(kleur.red().bold(`  Finished: ${subtype}`));
      }
      console.log(kleur.gray(`  Turns: ${turns}  Cost: $${cost?.toFixed(4) ?? "?"}  Time: ${elapsed}s`));
      if (event.data.sessionId) {
        console.log(kleur.gray(`  Session: ${event.data.sessionId}`));
      }
      console.log();
      break;
    }
    case "error":
      console.error(kleur.red(`\n  Error: ${event.data.message}\n`));
      break;
    case "stderr":
      // Container stderr — show as dim text
      process.stderr.write(kleur.gray(String(event.data.text) + "\n"));
      break;
  }

  return sessionId;
}

function handleLocalMessage(message: { type: string } & Record<string, unknown>, startTime: number): string | undefined {
  let sessionId: string | undefined;

  switch (message.type) {
    case "system": {
      const sys = message as unknown as SDKSystemMessage;
      if (sys.subtype === "init") {
        sessionId = sys.session_id;
      }
      break;
    }
    case "assistant": {
      const asst = message as unknown as SDKAssistantMessage;
      if (!asst.message?.content) break;
      for (const block of asst.message.content) {
        if (block.type === "text") {
          process.stdout.write(block.text);
        } else if (block.type === "tool_use") {
          console.log(kleur.yellow(`\n  [tool] ${block.name}`));
        }
      }
      break;
    }
    case "result": {
      const result = message as unknown as SDKResultMessage;
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log("\n");
      if (result.subtype === "success") {
        console.log(kleur.green().bold("  Done!"));
      } else {
        console.log(kleur.red().bold(`  Finished: ${result.subtype}`));
      }
      console.log(kleur.gray(`  Turns: ${result.num_turns}  Cost: $${result.total_cost_usd?.toFixed(4) ?? "?"}  Time: ${elapsed}s`));
      console.log(kleur.gray(`  Session: ${result.session_id}`));
      console.log();
      break;
    }
  }

  return sessionId;
}

// ---------------------------------------------------------------------------
// Run agent
// ---------------------------------------------------------------------------

async function runAgent(prompt: string, outputDir: string, sessionId?: string) {
  const { model } = parseModelFromPrompt(prompt);
  const modelLabel = model === MODEL_POWER ? kleur.magenta("opus") : kleur.blue("sonnet");
  const modeLabel = isSandboxEnabled() ? kleur.green("docker") : kleur.yellow("local");
  console.log(kleur.gray(`\n  Model: `) + modelLabel + kleur.gray(`  Mode: `) + modeLabel);

  const startTime = Date.now();
  const agent = createAgent({ prompt, outputDir, sessionId });

  for await (const message of agent) {
    // AgentEvent from Docker has .event, SDK messages have .type
    if ("event" in message) {
      handleSandboxEvent(message as AgentEvent, startTime);
    } else {
      handleLocalMessage(message as { type: string } & Record<string, unknown>, startTime);
    }
  }
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

async function handleListSessions() {
  const sessions = await listSessions();
  if (sessions.length === 0) {
    console.log(kleur.gray("  No sessions found.\n"));
    return;
  }
  console.log(kleur.cyan().bold("\n  Recent Sessions\n"));
  for (const s of sessions) {
    const date = new Date(s.createdAt).toLocaleDateString();
    console.log(`  ${kleur.yellow(s.id.slice(0, 8))}  ${date}  ${s.title}`);
  }
  console.log();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  printBanner();

  const outputDir = resolveOutputDir(
    process.env.AGENT_OUTPUT_DIR || process.cwd(),
  );

  const args = process.argv.slice(2);

  if (args.includes("--list-sessions")) {
    await handleListSessions();
    process.exit(0);
  }

  let resumeSessionId: string | undefined;
  const resumeIdx = args.indexOf("--resume");
  if (resumeIdx !== -1 && args[resumeIdx + 1]) {
    resumeSessionId = args[resumeIdx + 1];
    args.splice(resumeIdx, 2);
  }

  printConfig(outputDir, isSandboxEnabled());

  const cliPrompt = args.join(" ").trim();
  if (cliPrompt) {
    await runAgent(cliPrompt, outputDir, resumeSessionId);
    process.exit(0);
  }

  // Interactive REPL
  const rl = createInterface({ input: process.stdin, output: process.stdout });

  const askPrompt = () => {
    rl.question(kleur.cyan("  > "), async (input) => {
      const trimmed = input.trim();
      if (!trimmed || trimmed === "exit" || trimmed === "quit") {
        console.log(kleur.gray("\n  Goodbye!\n"));
        rl.close();
        process.exit(0);
      }
      if (trimmed === "/sessions") {
        await handleListSessions();
        askPrompt();
        return;
      }
      try {
        await runAgent(trimmed, outputDir, resumeSessionId);
        resumeSessionId = undefined;
      } catch (err) {
        console.error(kleur.red(`\n  Error: ${err}\n`));
      }
      askPrompt();
    });
  };

  askPrompt();
}

main().catch((err) => {
  console.error(kleur.red(`Fatal: ${err}`));
  process.exit(1);
});
