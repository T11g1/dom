# Dom — Capabilities & Architecture

A visual overview of what Dom does and how the pieces fit together.
Each diagram is a Mermaid block — renders natively on GitHub, Notion, VS Code, Obsidian.

---

## 1. What Dom Can Do (capabilities mindmap)

```mermaid
mindmap
  root((Dom))
    Build apps
      Stack-agnostic
      Natural-language prompts
      Iterative dev via sessions
    Interfaces
      CLI REPL
      HTTP API on :3333
      Telegram bot integration
    Model routing
      Sonnet 4.6 default
      Opus 4.8 with /opus
      Haiku 4.5 for subagents
    Safety
      Docker sandbox by default
      Pre/Post/Stop SDK hooks
      Mandatory code review
    Network
      Bash command allowlist
      Isolated Docker network
      HAProxy SNI egress filter
    Sessions
      Persist + resume
      AES-256-GCM at rest
      Auth-token-derived key
    Audit
      Every tool call logged
      JSON-lines, 10 MB rotation
      Sanitised input only
    Subagents
      code-reviewer
      tester
      eval
      goal-verifier
      brain-curator
```

---

## 2. System Architecture

End-to-end view: how a prompt flows from a client to executed code.

```mermaid
flowchart TB
    subgraph Clients
        CLI[CLI / REPL]
        TG[Telegram Bot]
        HTTP[HTTP Client / curl]
    end

    subgraph Entry["Entry Layer"]
        Index["src/index.ts<br/>CLI, REPL, --resume"]
        Server["src/server.ts<br/>HTTP API :3333<br/>Bearer auth + rate limit"]
    end

    subgraph Core["Core Agent"]
        Models["src/models.ts<br/>parseModelFromPrompt"]
        Config["src/agent-config.ts<br/>System prompt +<br/>subagent defs"]
        Agent["src/agent.ts<br/>createAgent()"]
    end

    subgraph Hooks["Guardrails — src/guardrails.ts"]
        Pre["PreToolUse<br/>block dangerous ops"]
        Post["PostToolUse<br/>track changes"]
        Stop["Stop<br/>enforce review"]
    end

    subgraph Exec["Execution Mode"]
        Local["Local<br/>AGENT_SANDBOX=false"]
        Docker["Docker Sandbox<br/>dom-sandbox image<br/>src/sandbox.ts + run.ts"]
    end

    subgraph Storage["Storage"]
        Sessions["Sessions<br/>./.dom-claude/<br/>(optional AES-256-GCM)"]
        Audit["Audit Log<br/>./logs/audit.log<br/>10 MB rotation"]
        Brain["Brain<br/>./.dom-brain/<br/>curated memory"]
        Projects["./projects/<br/>generated code"]
    end

    CLI --> Index
    TG --> Server
    HTTP --> Server
    Index --> Models
    Server --> Models
    Models --> Agent
    Config --> Agent
    Agent --> Pre
    Pre --> Local
    Pre --> Docker
    Local --> Post
    Docker --> Post
    Post --> Stop
    Stop --> Sessions
    Stop --> Audit
    Stop --> Brain
    Stop --> Projects
```

---

## 3. Hook Enforcement & Subagent Flow

The safety loop: how guardrails and subagents make Dom refuse to ship unreviewed code.

```mermaid
flowchart TB
    Start([Run starts]) --> Tool[Agent issues tool call]
    Tool --> PreCheck{PreToolUse}
    PreCheck -->|denied<br/>rm -rf, unknown host,<br/>protected path| Block[Block + audit 'denied']
    PreCheck -->|allowed| Exec[Execute tool]
    Exec --> PostHook[PostToolUse]
    PostHook --> WroteFile{Write/Edit used?}
    WroteFile -->|yes| FlagF[filesChanged = true]
    WroteFile -->|no| LoopCheck
    FlagF --> LoopCheck{More work?}
    LoopCheck -->|yes| Tool
    LoopCheck -->|no| StopHook{Stop hook}
    StopHook -->|read-only run| Done([Finish])
    StopHook -->|filesChanged &&<br/>!reviewerRan| Force[Force-run subagents]

    subgraph Subagents["Mandatory Subagents (Haiku 4.5)"]
        Reviewer["code-reviewer<br/>Read/Glob/Grep<br/>→ bug, security, quality"]
        Tester["tester<br/>Read/Write/Edit +<br/>Bash allowlisted runners<br/>→ pass / fail"]
        Eval["eval<br/>Read/Glob/Grep<br/>→ CRITICAL / WARNING"]
    end

    Force --> Reviewer
    Force --> Tester
    Force --> Eval
    Eval --> EvalGate{CRITICAL?}
    EvalGate -->|yes| Blocked[Block finish]
    EvalGate -->|no, WARNING ok| Done
```

---

## 4. Defense-in-Depth: Network Security

Three independent egress layers — each catches what the others miss.

```mermaid
flowchart TB
    Agent[Agent inside container] --> L1

    subgraph L1["Layer 1 — Bash Guardrails (PreToolUse)"]
        direction TB
        L1Desc["Blocks curl/wget/nc/ssh/socat<br/>to unknown hosts<br/>Allows package registries +<br/>GitHub"]
    end

    L1 -->|allowed| L2

    subgraph L2["Layer 2 — Docker Network"]
        direction TB
        L2Desc["dom-sandbox-net bridge<br/>isolates from other<br/>containers / host networks"]
    end

    L2 -->|production mode| L3

    subgraph L3["Layer 3 — HAProxy Egress Proxy (opt-in)"]
        direction TB
        L3Desc["TLS SNI allowlist<br/>HTTPS_PROXY env var<br/>haproxy/haproxy.cfg"]
    end

    L3 -->|HTTPS only,<br/>allowed SNIs| Internet((Internet))
    L1 -.denied.-> Blocked[Blocked + audit log]
```

---

## 5. HTTP API Surface

Public-facing endpoints, auth, and validation.

```mermaid
flowchart LR
    Client[Client / Telegram bot] -->|Bearer AGENT_API_TOKEN| Server[src/server.ts]

    Server --> Health["GET /health<br/>public, returns {status:'ok'}"]
    Server --> Sessions["GET /sessions<br/>auth required"]
    Server --> Session["GET /sessions/:id<br/>auth required"]
    Server --> Agent["POST /agent<br/>auth + rate limit (per IP)<br/>SSE stream"]

    Agent --> Validate{Input validation}
    Validate -->|prompt missing/>100k| R400[400 error]
    Validate -->|bad sessionId regex| R400
    Validate -->|outputDir escape| R400
    Validate -->|ok| Stream["SSE: status / session /<br/>text / tool / result /<br/>error / done"]

    Agent -.rate exceeded.-> R429["429 + Retry-After"]
```

---

## Talking Points (suggested for the presentation)

1. **What is Dom** — autonomous coding agent on top of `@anthropic-ai/claude-agent-sdk`, controllable from CLI, HTTP, or Telegram.
2. **Model routing** — cheap by default (Sonnet), powerful on demand (`/opus` → Opus 4.8), cheap-and-fast for review (Haiku).
3. **Safety story** — Docker sandbox + 3 hooks + mandatory review subagents. Code can't ship without `code-reviewer`, `tester`, and `eval` running.
4. **Defense in depth** — three independent network layers; each guards against a different failure mode.
5. **Operational hardening** — sessions encrypted at rest, audit log of every tool call, rate-limited HTTP API with bearer auth, TLS optional.
6. **Extensibility** — model routing + subagent definitions are stack-agnostic; new subagents (e.g. a security-auditor) can be added by extending `SUBAGENTS` in `agent-config.ts`.
