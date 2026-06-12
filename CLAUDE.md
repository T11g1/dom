# Dom — Autonomous Coding Agent

## What is this

Dom is an autonomous coding agent that builds applications from natural language prompts. It uses `@anthropic-ai/claude-agent-sdk` (NOT `claude-code-sdk` — renamed) and is controlled via CLI or HTTP API (designed for Telegram bot integration).

## Commands

```bash
npm run dev          # CLI mode (Docker sandbox, interactive REPL)
npm run dev:local    # CLI mode (no Docker, runs on host directly)
npm run serve        # HTTP API server on port 3333
npm run build        # Compile TypeScript to dist/
npm run docker:build # Build + Docker image (dom-sandbox)
npm run typecheck    # tsc --noEmit
npm test             # Run framework self-tests (node --test + tsx)
```

## Architecture

```
src/
  types.ts          Shared interfaces: AgentRequest, AgentEvent, SessionInfo
  models.ts         Model routing: Sonnet (default), Opus (/opus prefix), Haiku (subagents)
  agent-config.ts   System prompt + subagent definitions (shared by local + Docker modes)
  guardrails.ts     3 hooks: PreToolUse (block dangerous ops + WebFetch allowlist + Write/Edit leak scan), PostToolUse (track changes per session), Stop (enforce review)
  audit.ts          JSON-lines audit log for every tool call (./logs/audit.log, 10MB rotation, Bash command secrets redacted)
  leak-detect.ts    Secret-pattern library (provider keys, headers, DB URLs, PEM keys); shared by audit redaction and Write/Edit blocking
  goal.ts           Persist user's original prompt to .dom-goal in cwd so the goal-verifier subagent can read it
  budget.ts         Per-session cost tracking against AGENT_MAX_COST_USD; refuses new runs on exceeded sessions
  brain.ts          Long-lived markdown memory bank (./.dom-brain); loaded into system prompt every run, curated by brain-curator subagent
  sandbox.ts        Docker container + network lifecycle: spawns containers, streams JSON-line events
  agent.ts          Agent factory: createAgent() returns local Query or Docker AsyncGenerator; taps cost into budget; clears goal on finish
  sessions.ts       Session list/resume wrapping SDK functions (decrypt-before / encrypt-after when AGENT_SESSION_ENCRYPT=true)
  session-crypt.ts  AES-256-GCM bracket encryption for session files at rest (PBKDF2 from AGENT_API_TOKEN)
  run.ts            Docker container entrypoint (reads JSON from argv, streams events to stdout)
  index.ts          CLI: REPL, one-shot, /opus prefix, --resume, --list-sessions
  server.ts         HTTP: POST /agent (SSE), GET /sessions, GET /sessions/:id, GET /health
  __tests__/        node:test specs for guardrails, leak-detect, audit redaction, goal, budget, session-crypt
Dockerfile.agent          node:22-slim with git, python3, build-essential
docker-compose.egress.yml HAProxy egress proxy (production egress filtering)
haproxy/haproxy.cfg       HAProxy SNI allowlist config
```

## Model Tiers

| Context | Model | Why |
|---------|-------|-----|
| Default prompts | claude-sonnet-4-6 | Best speed/cost balance |
| `/opus` prefix | claude-opus-4-8 | Complex architecture tasks |
| code-reviewer subagent | claude-haiku-4-5 | Fast, cheap, read-only |
| Agent auto-suggests Opus | System prompt hint | When task is genuinely complex |

## Guardrails (src/guardrails.ts)

Three SDK hooks enforce safety. All state is **session-scoped** (keyed by SDK-provided `session_id`) so two simultaneous runs in the same host process cannot corrupt each other's tracking.

**PreToolUse — blocks before execution:**
- Destructive commands: catastrophic `rm` (token-aware — `rm -rf /`, `rm -fr /`, `rm -r -f /`, `rm --recursive --force /`, `rm -rf /*`, `~`, `.`, `./` are all caught regardless of flag order/long-form), `git push main`, `git push --force`, `DROP TABLE`, `mkfs`, `dd`, fork bombs, nested-shell wrappers, `$(...)` and backtick wrappers.
- Bash network: only package registries + GitHub allowed. **Every** host in a (possibly chained) command is checked — `curl ok.com && curl evil.com` no longer slips through on the first host. Hosts are lowercased before comparison. **Fails closed:** a recognized network tool (curl/wget/nc/ssh/...) whose target can't be parsed (URL in a variable/file/flag, listening socket) is blocked rather than allowed.
- **WebFetch host allowlist:** same allowlist as Bash. WebFetch is no longer a free egress channel — `WebFetch` to an unlisted host returns a deny reason.
- Filesystem path block: writes to `/etc`, `/usr`, `/bin`, `/sbin`, `/root`, `/var`, `/opt`, `/lib`, `/boot`, `.ssh`, `.bashrc`, `.zshrc`, `.gitconfig`. The path is `path.resolve()`d **before** matching, so `..` traversal and trailing-slash-less targets (`/root`) can't dodge the block.
- **Write/Edit content leak detection:** the file content (or Edit's `new_string`) is scanned by `leak-detect.ts`. Any match (API keys, Authorization headers, DB connection strings with creds, PEM private keys, generic `secret=…` assignments ≥16 chars) is blocked with a deny reason naming the matched pattern.

**PostToolUse — tracks per-session state:**
- Records when Write/Edit tools are used (`filesChanged`)
- Records when WebFetch is used (`webFetched`) — see Stop hook
- Records when a subagent ran, **matched against an exact-name allowlist** (`code-reviewer`, `tester`, `eval`, `goal-verifier`). Loose substring matches on descriptions no longer satisfy the Stop check.

**Stop — enforces review:**
- Fires when **either** files changed **or** WebFetch was used. (Previously: only files changed — a no-write WebFetch run could exfiltrate without ever triggering review.)
- Requires all four subagents (`code-reviewer`, `tester`, `eval`, `goal-verifier`) to have run. Missing ones are named in the block reason.
- On a successful pass, resets the session's tracking so the next user prompt in the same session starts with a clean slate.

## Sandbox Modes

`AGENT_SANDBOX` env var controls execution:
- `true` (default): Agent runs inside Docker container. Host volume mounted at /workspace.
- `false`: Agent runs in-process on host. Guardrails still active but no container isolation.

Docker mode: server.ts/index.ts on host spawns container via sandbox.ts. Container runs run.ts which streams JSON-line events back via stdout.

## HTTP API (src/server.ts)

All routes except `/health` require `Authorization: Bearer <AGENT_API_TOKEN>` header. Missing/invalid token returns `401 { "error": "Unauthorized" }`.

`POST /agent` is rate-limited per IP (sliding window, AGENT_RATE_LIMIT requests/minute). When exceeded: `429 { "error": "Rate limited. Try again in N seconds." }` with `Retry-After` header.

**Request body size cap** — POST /agent buffers at most `AGENT_MAX_BODY_BYTES` (default 1 MB); a larger body gets `413` and the connection is destroyed *before* buffering, so a huge/`/dev/zero` POST can't exhaust memory. The prompt-length check runs after, on the parsed JSON.

**POST /agent input validation** — body must be JSON with:
- `prompt` (required, string, non-empty after trim, ≤ 100,000 chars; null bytes are stripped before length check)
- `sessionId` (optional, string matching `^[A-Za-z0-9-]+$`, ≤ 128 chars)
- `outputDir` (optional, string, must not contain `..` or start with `/`)

**GET /sessions/:id** validates the path segment with the **same** `^[A-Za-z0-9-]+$` rule before the lookup — `url.pathname` is percent-decoded, so an unvalidated param (`..%2f..%2fetc`) could otherwise reach the filesystem-backed SDK call. Invalid ids get `400`.

**Error responses** never reflect raw `err.message` to clients (avoids leaking host paths / internal IDs): `/sessions` 500s and the SSE `error` event return a generic message and log the detail server-side. Intentional structured errors (validation `400`, budget `402`/`budget_exceeded`) keep their specific fields.

**Rate-limit identity** — keyed on `req.socket.remoteAddress` by default. Set `AGENT_TRUST_PROXY=true` only behind a trusted reverse proxy to key on the rightmost `X-Forwarded-For` hop. The bucket map is bounded (`AGENT_RATE_LIMIT_MAX_IPS`) so a source-rotating flood can't grow it without limit.

Validation failures return `400 { "error": "<specific message>" }` and are recorded in the audit log as a `http_validation` event with metadata only (never the prompt content).

| Method | Path | Auth | Rate-limited | Body | Response |
|--------|------|------|--------------|------|----------|
| POST | /agent | required | yes | `{ prompt, sessionId?, outputDir? }` | SSE stream (events: status, session, text, tool, result, error, done) |
| GET | /sessions | required | no | — | JSON array of sessions |
| GET | /sessions/:id | required | no | — | JSON session detail |
| GET | /health | public | no | — | `{ status: "ok" }` |

`/opus` prefix works via the API — Telegram bot forwards message as-is.

## Sessions

Sessions persist to disk via SDK's `persistSession: true`. Resume by passing `sessionId` to the API or `--resume <id>` in CLI. List with `GET /sessions` or `/sessions` in REPL.

## Subagents

| Name | Model | Tools | Purpose |
|------|-------|-------|---------|
| code-reviewer | haiku | Read, Glob, Grep | Reviews code for bugs, security, quality after builds. |
| tester | haiku | Read, Write, Edit, Bash (restricted), Glob, Grep | Writes focused unit tests, runs them, reports pass/fail. Bash is restricted by guardrail allowlist to `npm/pnpm/yarn test`, `npx vitest/jest/mocha/ava/tap`, `pytest`, `python -m pytest`, `go test`, `cargo test`, `(npm/pnpm/yarn/pip) install`, and `tsc --noEmit`. Anything else via Bash is denied. |
| eval | haiku | Read, Glob, Grep | Audits session for guardrail/style compliance. Returns CRITICAL/WARNING. Goal alignment is **out of scope** — `goal-verifier` handles that. |
| goal-verifier | haiku | Read, Glob, Grep | Reads `.dom-goal` from cwd and verifies the build satisfies the user's original prompt. Returns MISSING/WRONG/EXTRA/OK findings. |
| brain-curator | haiku | Read, Write, Edit, Glob, Grep | **Runs last.** Reads `./.dom-brain/*.md`, decides what (if anything) from this session is worth saving for future runs, overwrites contradicted memories, evicts dormant ones. Write/Edit restricted by guardrail to paths under the brain dir. Returns SAVED/UPDATED/EVICTED/NOTHING_SAVED bullets. |

All five are auto-triggered by the Stop hook when files were changed **or WebFetch was used**. Dom cannot finish without running all five. Subagent attribution uses exact-name matching, so a description like "test the import" cannot accidentally satisfy `tester`.

## Goal persistence (src/goal.ts)

Before every run, Dom writes the user's prompt (after `/opus`-prefix stripping) to `.dom-goal` in the agent's working directory (mode 0600). The file is:

- Read by the main agent at the start of its run (`SYSTEM_PROMPT` directs it).
- Read by `goal-verifier` at review time so it can compare implementation to ask.
- Removed in a `finally` block once the run completes (success, error, or interrupt).

This is the answer to "how does Dom stay goal-oriented?" — the goal is a file on disk, not a memory of conversation, and the goal-verifier subagent has read access to it via the normal Read tool.

Add `.dom-goal` to your project's `.gitignore` if you generate code into a tracked repo.

## Leak detection (src/leak-detect.ts)

A shared secret-pattern library used in two places:

1. **Audit redaction:** Bash `command` strings are passed through `redactSecrets` before logging, so credentials embedded in flags (`-H "Authorization: Bearer ..."`, `psql 'postgres://u:p@h/db'`, `--token=...`) never land in `./logs/audit.log` verbatim.
2. **Write/Edit blocking:** generated content is scanned by `detectSecrets`; any match blocks the write with a deny reason naming the matched pattern (so the main agent knows to switch to env-var references).

Patterns covered: Anthropic / OpenAI / GitHub / Slack / Stripe / AWS / Google API keys; `Authorization: Bearer` and `Basic` headers; `postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://` connection strings with embedded credentials; PEM `BEGIN PRIVATE KEY` blocks; generic `(api_key|secret|token|password|...)=<value>` assignments with values ≥16 chars.

## Cost budget (src/budget.ts)

Set `AGENT_MAX_COST_USD` to cap cumulative spend per session.

- After each finished run, the SDK's `total_cost_usd` (or the Docker `result` event's `cost`) is added to the session's running total.
- Once a session crosses the budget, the next `createAgent` for that session throws `BudgetExceededError` and the HTTP API returns `402 { error: "Session over budget", budgetUsd, sessionTotalUsd }`.
- A `_budget_exceeded` audit event is logged the first time a session crosses the threshold so it's easy to spot in the audit log.

This is a soft cap (mid-run interruption isn't portable with the SDK) — the agent finishes its current run, then the next prompt is refused.

## Shared brain (src/brain.ts)

Dom has a long-lived markdown memory bank at `./.dom-brain/` (override with `AGENT_BRAIN_DIR`). Each memory is a single `.md` file with YAML frontmatter (`name`, `description`, `type: user|feedback|project|reference`, `created`, `last_used`) and a markdown body. An index file `MEMORY.md` lists every entry for human inspection.

**Lifecycle of a memory:**
1. **Loaded at every run start.** `buildSystemPrompt()` concatenates the static `SYSTEM_PROMPT` template with `buildPromptSection()` from `brain.ts`. Newest entries (by `last_used`) are loaded first, capped at `AGENT_BRAIN_MAX_LOADED` (default 30) and ~60 KB of prompt section.
2. **Used by the main agent** as authoritative knowledge (the system prompt instructs it to treat memories as facts).
3. **Curated at Stop** by the `brain-curator` subagent (Haiku, Read/Write/Edit/Glob/Grep restricted to the brain dir):
   - **Save:** only durable lessons that generalize across future projects (user preferences, recurring constraints, external-system references).
   - **Overwrite, not append:** when a new memory contradicts an existing one, the curator replaces the file in place and annotates the description with `(updated YYYY-MM-DD)`.
   - **Evict dormant:** memories with `last_used` older than 30 days that aren't reinforced by the current session get rewritten as tombstones (body = `(evicted on YYYY-MM-DD: <reason>)`, description prefixed with `[EVICTED]`).
4. **Index refresh:** the curator rewrites `MEMORY.md` so the bullet list reflects the new state.

**Why a curator and not "save everything":** the brain loads into every system prompt. Without a strict curator, signal-to-noise collapses fast and Dom's prompt becomes its own bottleneck. The curator's job is to keep the brain small, accurate, and current — when in doubt, it saves nothing.

**Docker mode:** the host brain directory is bind-mounted into the container at `/brain` and `AGENT_BRAIN_DIR=/brain` is passed via the env file. The curator's writes inside the container persist to the host because of the mount, so memories accumulate across runs regardless of sandbox mode.

**Caps and tunables:**
- `AGENT_BRAIN_DIR` — directory location (default `./.dom-brain`).
- `AGENT_BRAIN_MAX_LOADED` — soft cap on how many entries get injected into the system prompt per run (default 30). Beyond this, oldest-by-`last_used` entries remain on disk but aren't loaded that run.
- `AGENT_BRAIN_MAX_ENTRIES` — hard cap on total entries (default 100). When exceeded, the curator must evict before saving.

**What this is NOT:** not a vector store, not RAG, not embeddings, not learning. It's a curated text file that humans can `cat` and `git diff`. Migrate to a hybrid system later if retrieval becomes the bottleneck — typically around 200–500 entries.

## Key Decisions

- Stack-agnostic: no framework baked into system prompt. Agent adapts to user's request.
- `bypassPermissions` is used because Docker provides the isolation boundary. Guardrails add defense-in-depth.
- WebSearch/WebFetch run on the main model (Sonnet), not Haiku. Cost difference is negligible; Sonnet writes better queries.
- code-reviewer, tester, and eval subagents are mandatory when files change, skipped otherwise.
- Eval blocks for CRITICAL violations only (guardrail bypasses, ignored instructions). Style issues warn but don't block.
- Tester focuses on 20% of tests that catch 80% of bugs — no coverage theater.

## Environment Variables (.env)

| Variable | Default | Purpose |
|----------|---------|---------|
| ANTHROPIC_API_KEY | (required) | API authentication |
| AGENT_MODEL | claude-sonnet-4-6 | Default model |
| AGENT_MAX_TURNS | 50 | Max agentic turns per run |
| AGENT_OUTPUT_DIR | ./projects | Where projects are built |
| AGENT_WEB_PORT | 3333 | HTTP server port |
| AGENT_SANDBOX | true | Docker mode on/off |
| AGENT_DOCKER_IMAGE | dom-sandbox | Docker image name |
| AGENT_API_TOKEN | (required) | Bearer token for HTTP API auth. Generate with `openssl rand -hex 32`. Server refuses to start if unset. |
| AGENT_CORS_ORIGIN | http://localhost:3333 | Allowed CORS origin. Set to client URL in production. `*` triggers a startup warning. |
| AGENT_RATE_LIMIT | 10 | Max requests/minute per IP on POST /agent (sliding window). 429 + Retry-After when exceeded. |
| AGENT_AUDIT_LOG | true | JSON-lines audit log of every tool call (./logs/audit.log). `false` disables. Bash `command` is passed through the secret redactor before logging. |
| AGENT_MAX_COST_USD | (empty = unlimited) | Per-session cost cap (USD). Refuses new runs on a session that's already crossed this. See "Cost budget". |
| AGENT_BRAIN_DIR | ./.dom-brain | Directory holding the markdown memory bank. See "Shared brain". |
| AGENT_BRAIN_MAX_LOADED | 30 | Soft cap on memories loaded into the system prompt per run (newest by `last_used` first). |
| AGENT_BRAIN_MAX_ENTRIES | 100 | Hard cap on total memories on disk. Curator must evict before adding when at cap. |
| AGENT_SESSION_ENCRYPT | false | When `true`, session files at rest are AES-256-GCM encrypted (bracket mode: plaintext only during active runs). Key derived from AGENT_API_TOKEN via PBKDF2→HKDF. |
| AGENT_SESSION_ENCRYPT_MIGRATE | false | One-time opt-in. When `true`, plaintext session files are accepted (and sealed on the next encrypt). When `false` (default) with encryption on, plaintext at rest is treated as a downgrade/tamper and **rejected** — independent of the seal marker. Set it once to migrate a pre-existing plaintext directory, then unset. |
| AGENT_TLS_CERT | (empty) | Path to a PEM-encoded TLS certificate. Set BOTH cert+key to serve HTTPS; leave BOTH empty for HTTP. Server exits if only one is set. |
| AGENT_TLS_KEY | (empty) | Path to a PEM-encoded TLS private key. See AGENT_TLS_CERT. |
| CLAUDE_CONFIG_DIR | ./.dom-claude | Where the SDK stores sessions. Default keeps them inside the project (not in ~/.claude/). Only override if you need the SDK's default location. |
| ALLOWED_HOSTS | (empty) | Extra allowed network hosts (comma-separated) |
| AGENT_EGRESS_PROXY | (empty) | When set (e.g. `http://dom-egress-proxy:8443`), injects `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` into the sandbox container so proxy-aware clients route through the SNI allowlist. Opt-in; raw sockets/DNS still bypass it. See "Network Security". |
| AGENT_TRUST_PROXY | false | When `true`, the rate limiter reads the rightmost `X-Forwarded-For` hop as the client IP (use only behind a trusted reverse proxy). Default uses the raw socket address. |
| AGENT_MAX_BODY_BYTES | 1000000 | Hard cap on POST /agent request body size (bytes). Oversized requests get `413` and the connection is torn down before buffering — prevents memory-exhaustion DoS. |
| AGENT_RATE_LIMIT_MAX_IPS | 10000 | Max distinct IPs tracked by the rate limiter. Oldest entries are evicted at the cap so a source-rotating flood can't grow the map unbounded. |

## Network Security (defense in depth)

Egress filtering uses three independent layers. Higher layers should not be relied on alone — they each protect against different failure modes.

| Layer | Where | What it enforces | What it does NOT enforce |
|-------|-------|------------------|--------------------------|
| 1. Bash guardrails | `src/guardrails.ts` PreToolUse hook | Blocks shell commands targeting unknown hosts (curl, wget, nc, ssh, socat, script-mode network calls) | Anything bypassing the Bash tool — a buggy SDK or non-Bash exfiltration vector |
| 2. Docker network | `dom-sandbox-net` (auto-created by `runInSandbox`) | Container isolation: the agent container can't reach other Docker networks/containers on the host | Public internet egress — by itself, the bridge network does NOT filter outbound to the internet |
| 3. HAProxy egress proxy | `docker-compose.egress.yml` + `haproxy/haproxy.cfg` | TLS SNI allowlist on outbound HTTPS. Containers with HTTPS_PROXY pointed at the proxy can ONLY reach allowed hostnames | HTTP (non-TLS), DNS, raw TCP — only HTTPS via SNI is filtered |

**Default mode** (just `npm run dev`): layers 1 + 2 are active. **The container has FULL internet egress** — the bridge network isolates containers from each other but does NOT filter outbound traffic to the internet. Layer 1 (the Bash host-allowlist) is the only egress filter in this mode, and it is best-effort defense-in-depth: it now checks *every* host in a chained command (not just the first), but it is still bypassable by anything that doesn't go through the Bash tool's parseable surface — raw sockets (`/dev/tcp`), DNS, non-allowlisted binaries, or a buggy SDK. **Do not treat default mode as network-contained.**

**Production mode**: bring up the egress proxy with `docker-compose -f docker-compose.egress.yml up -d`, then set `AGENT_EGRESS_PROXY=http://dom-egress-proxy:8443` on the host — `sandbox.ts` injects `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` into the container so proxy-aware HTTPS goes through the SNI allowlist. Edit `haproxy/haproxy.cfg` to change the allowed hostnames.

> ⚠️ **The egress proxy is NOT a verified hard boundary yet.** `haproxy/haproxy.cfg`'s backend is a placeholder (`server target 0.0.0.0:443` does not dynamically route by SNI, and `HTTPS_PROXY` clients speak HTTP CONNECT, which the current tcp/SNI frontend does not handle). It needs a rework (resolver + `do-resolve`/`set-dst`, or a CONNECT-aware frontend) and validation against a live container before you can rely on it. Even once working, `HTTPS_PROXY` only constrains proxy-aware clients — raw sockets and DNS bypass it; a true hard boundary needs an `internal` network where the proxy is the only route out.

The Docker network is created on first sandbox run and removed on process exit (best-effort — fails silently if other containers are still attached). If network creation fails, sandbox falls back to Docker's default bridge with a warning printed.

## TLS

By default Dom serves HTTP. To enable HTTPS, set BOTH `AGENT_TLS_CERT` and `AGENT_TLS_KEY` in `.env` to the paths of a PEM-encoded cert and private key. Setting only one is rejected at startup (server exits with an error).

**Self-signed cert for local dev** (run from the project root):

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Then in `.env`:

```
AGENT_TLS_CERT=./cert.pem
AGENT_TLS_KEY=./key.pem
AGENT_CORS_ORIGIN=https://localhost:3333
```

The startup banner prints the correct scheme (`https://...` when TLS is on, `http://...` otherwise).

**Production:** use a real CA-issued cert (Let's Encrypt, cloud provider's cert manager, etc.). Never commit `*.pem` files — add them to `.gitignore` if you store them in the project.

## Audit Log

Every tool call is appended as a JSON line to `./logs/audit.log`. Two entries per allowed call (pre + post); one entry for a denied call.

**Entry shape:**
```json
{
  "timestamp": "2026-04-15T10:00:00.000Z",
  "sessionId": "...",
  "phase": "pre" | "post",
  "toolName": "Bash",
  "toolInput": { "command": "npm install" },
  "result": "allowed" | "denied" | "completed",
  "denyReason": "..."
}
```

**Input sanitization:** `toolInput` only contains a whitelisted subset per tool — never file contents, never `new_string`/`old_string` for Edit. Write/Edit log only `file_path`. Bash logs `command`. Unknown tools log only the key names, never the values.

**Rotation:** When `audit.log` reaches 10 MB it's renamed to `audit.log.1` and a new file starts. Only one backup is kept — older backups are overwritten on the next rotation.

**Failure mode:** Audit failures never break agent execution. Logging errors are swallowed; the agent continues.

Disable by setting `AGENT_AUDIT_LOG=false`. `logs/` is in `.gitignore`.

## Session Encryption (at rest)

Sessions may contain sensitive prompts and generated code. When `AGENT_SESSION_ENCRYPT=true`, Dom encrypts session files on disk using **bracket encryption**:

- **After** a run finishes (or errors/interrupts): every file under `./.dom-claude/projects/**` is encrypted in place with AES-256-GCM.
- **Before** a resume or a `listSessions` / `getSession` call: files are decrypted so the SDK can read them.
- After the read/run completes, files are re-sealed.

**Why bracket and not per-write?** The SDK owns its session file I/O directly — it does not expose a pluggable storage hook. True encrypt-on-every-write would require monkey-patching `fs`, which is fragile. Bracket encryption limits the plaintext window to when the agent is actively running — the same window during which the data is in memory anyway.

**Key management:** the encryption key is derived from `AGENT_API_TOKEN` via PBKDF2-SHA256 (200k iterations, random 16-byte salt per file, 32-byte key), **then HKDF-Expand'd with a fixed domain label** (`dom-session-encryption-v2`). The PBKDF2 stretch is unchanged; the extra HKDF step cryptographically separates the at-rest key from the raw bearer token (and its other uses), so leaking `AGENT_API_TOKEN` does not directly yield the encryption key. No additional secret is needed. If `AGENT_API_TOKEN` changes, existing encrypted sessions become unreadable.

**File format (binary):** `DOMENC2` magic (7 bytes) | salt (16) | iv (12) | GCM auth tag (16) | ciphertext. Legacy `DOMENC1` (PBKDF2 key used directly, no HKDF) is still **readable** for backward compatibility; new writes are always `DOMENC2`.

**Downgrade / tamper detection (fail-closed):** with encryption enabled, a plaintext file at rest under the sessions root is treated as a downgrade/tamper signal (an attacker swapping ciphertext→plaintext, or a crash that left the tree unsealed): `readSessionFile` **throws**, and the decrypt sweep logs a loud `SECURITY:` warning and counts it as an error rather than silently ingesting it. This is **independent of the seal marker** — deleting `.dom-enc-marker` does NOT re-open silent acceptance. The only way to legitimately accept plaintext at rest is the explicit one-time `AGENT_SESSION_ENCRYPT_MIGRATE=true` opt-in (used when first enabling encryption on a directory that already holds plaintext sessions). The HMAC seal marker (`.dom-enc-marker`) is still written after a clean sweep as a positive "sealed" record. (A full per-file signed manifest remains the complete defense-in-depth follow-up; this closes the silent-acceptance and marker-deletion cases.)

**Concurrent runs (reference counting):** the decrypt→run→re-encrypt bracket is reference-counted (`beginActiveRun`/`endActiveRun`). The tree is decrypted on the first concurrent entrant and only re-encrypted when the **last** run/listing exits, so one run's `finally` can't re-seal files another run is still reading. Re-encryption errors are surfaced (logged), not swallowed.

**Local-mode only:** the bracket applies to the host's `./.dom-claude/` in local mode (and around `listSessions`/`getSession`). In Docker mode the SDK writes sessions *inside* the container and `.dom-claude/` is not mounted in, so at-rest session encryption does not apply there — rely on Docker volume / OS-level encryption for the container's storage.

**Graceful fallback:** existing unencrypted session files are still readable when no seal marker exists yet — the decrypt path checks the magic header and passes plaintext through. You can enable encryption on a directory that already has plaintext sessions; they get sealed (and the marker written) on the next run. Once sealed, the downgrade detection above applies.

**Session location:** Dom sets `CLAUDE_CONFIG_DIR=./.dom-claude` by default so sessions are stored inside the project, not in `~/.claude/`. This keeps encryption sweeps bounded to the project folder. `.dom-claude/` is in `.gitignore`.

**What this does NOT protect:** sensitive data in memory during an active run, audit log contents, files inside mounted Docker volumes, anything outside `./.dom-claude/`. Combine with Docker sandboxing and (ideally) OS-level volume encryption.

## Security Notes

- Never commit .env — it contains secrets (API key, auth token). It's in .gitignore.
- The sandbox container runs **non-root as the host UID** (`--user`), `--cap-drop ALL` with only `CHOWN`/`FOWNER` re-added (no `SETUID`/`SETGID`/`DAC_OVERRIDE`), `no-new-privileges`, and `--pids-limit 512`. Running as the host UID also makes bind-mounted `/workspace` and `/brain` writes work without permission-bypass caps.
- The guardrails regex patterns are defense-in-depth, not a substitute for Docker isolation. Always run with AGENT_SANDBOX=true in production.
- HTTP API requires bearer token (AGENT_API_TOKEN). Token is compared with timing-safe equality. Server refuses to start if unset.
- POST /agent is rate-limited per IP (AGENT_RATE_LIMIT/min, sliding window). 429 + Retry-After when exceeded.
- ANTHROPIC_API_KEY is passed to the Docker container via `--env-file` (mode 0600 temp file), not `-e` argv — keeps it out of `ps aux`.
- Session files are stored in `./.dom-claude/` (inside the project, not `~/.claude/`). Optionally encrypt at rest with AGENT_SESSION_ENCRYPT=true.
- See "Network Security" and "Session Encryption" above for details.
