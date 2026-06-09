export const MODEL_DEFAULT = "claude-sonnet-4-6";
export const MODEL_POWER = "claude-opus-4-8";
export const MODEL_FAST = "claude-haiku-4-5";

/**
 * Detects `/opus` prefix in a prompt and returns the appropriate model + cleaned prompt.
 *
 *   parseModelFromPrompt("/opus Build a React dashboard")
 *   → { model: "claude-opus-4-8", cleanPrompt: "Build a React dashboard" }
 *
 *   parseModelFromPrompt("Build a todo app")
 *   → { model: "claude-sonnet-4-6", cleanPrompt: "Build a todo app" }
 */
export function parseModelFromPrompt(prompt: string): {
  model: string;
  cleanPrompt: string;
} {
  const trimmed = prompt.trim();

  if (trimmed.startsWith("/opus ") || trimmed === "/opus") {
    return {
      model: MODEL_POWER,
      cleanPrompt: trimmed.slice("/opus ".length).trim() || trimmed,
    };
  }

  return {
    model: process.env.AGENT_MODEL || MODEL_DEFAULT,
    cleanPrompt: trimmed,
  };
}

/**
 * System prompt snippet that tells the agent to suggest switching to Opus
 * when it detects a task that would benefit from deeper reasoning.
 */
export const OPUS_SUGGESTION_HINT = `
When you encounter a task that involves complex architectural decisions, intricate multi-service design,
or deep reasoning about trade-offs, include a suggestion in your response like:

💡 **This task could benefit from Opus mode.** Re-send with the \`/opus\` prefix for deeper architectural reasoning.

Only suggest this for genuinely complex tasks — not for straightforward CRUD, simple scripts, or boilerplate.
Examples that warrant Opus: distributed system design, complex state machines, database schema design with
non-obvious normalization trade-offs, security-critical authentication flows, performance-critical algorithm choices.
`.trim();
