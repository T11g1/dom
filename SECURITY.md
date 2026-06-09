# Security Policy

Dom is a security-focused autonomous coding agent. Reports of vulnerabilities — especially **guardrail bypasses, sandbox escapes, secret leaks, or auth/rate-limit weaknesses** — are taken seriously and handled privately.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.** Public disclosure before a fix is available puts other users at risk.

Use GitHub's private vulnerability reporting instead:

1. Go to https://github.com/T11g1/dom/security/advisories
2. Click **"Report a vulnerability"**
3. Fill in the report; only repo maintainers can see it

When reporting, please include:

- A description of the vulnerability and its impact.
- A minimal reproduction (prompt, env vars, expected vs actual behavior).
- The Dom version / commit hash you tested against (`git rev-parse HEAD`).
- Whether you ran in `AGENT_SANDBOX=true` (Docker) or `false` (local) mode.
- Any logs from `./logs/audit.log` that show the issue (sanitize secrets first).

You can expect an acknowledgement within **72 hours** and a status update within **7 days**.

## Scope

| In scope | Out of scope |
|---|---|
| Guardrail regex bypasses (destructive commands, network egress, leak detection) | Bugs in third-party dependencies — report those upstream (`@anthropic-ai/claude-agent-sdk`, `dotenv`, `kleur`) |
| Sandbox escapes (container break-outs, host-FS access) | Issues that require `AGENT_SANDBOX=false` AND an attacker already on the host |
| Auth bypasses on the HTTP API (`AGENT_API_TOKEN`, rate limiting) | Social engineering / typosquatting / dependency confusion |
| Secret leaks via audit log, brain, or generated output | Self-XSS / DoS via massive prompts (rate limit is your friend) |
| Session-encryption weaknesses (`AGENT_SESSION_ENCRYPT=true`) | Cost overruns from runaway agents (use `AGENT_MAX_COST_USD`) |
| `brain-curator` path-traversal / scope escapes | Generated user code's own bugs (Dom can't review every line it writes) |

## What "fixed" looks like

For each accepted report, Dom will:

1. Add a **regression test** in `src/__tests__/` that fails on the unpatched code and passes after the fix.
2. Land the fix in `main` and tag a patch release.
3. Credit the reporter in the release notes (with permission).
4. If the impact is significant, publish a `GHSA-` advisory after the patch is available.

## Defense-in-depth — known boundaries

Dom is built with these limits in mind. Reports about them are welcome but unlikely to be treated as vulnerabilities:

- **Docker isolation is the primary security boundary.** Guardrail regexes are defense-in-depth, not a replacement.
- **The brain is loaded into the system prompt every run.** A poisoned brain file is a vulnerability. The `brain-curator` is the gate; bugs in the curator are in scope.
- **WebFetch / Bash network calls go through the host allowlist.** Bypasses are in scope.
- **The HAProxy SNI egress proxy** is opt-in (`docker-compose.egress.yml`); reports about its policy are in scope when it's active.

## Coordinated disclosure

Please give us a reasonable window to fix before public disclosure — typically **90 days** from initial report, or sooner if a fix lands first. We'll work with you on a public-disclosure date.

Thank you for helping keep Dom safe.
