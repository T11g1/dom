export interface AgentConfig {
  model?: string;
  maxTurns?: number;
  outputDir?: string;
  systemPrompt?: string;
  sessionId?: string;
}

export interface AgentRequest {
  prompt: string;
  sessionId?: string;
  outputDir?: string;
}

export interface AgentEvent {
  type: "text" | "tool" | "result" | "error" | "model_suggestion" | "done";
  data: Record<string, unknown>;
}

export interface SessionInfo {
  id: string;
  title: string;
  createdAt: number;
  lastPrompt?: string;
  cost?: number;
  turns?: number;
}
