import { spawn, execFileSync } from "child_process";
import { mkdirSync, existsSync, writeFileSync, unlinkSync, mkdtempSync, rmSync } from "fs";
import { resolve, join } from "path";
import { homedir, tmpdir } from "os";
import type { AgentEvent } from "./agent.js";
import { getBrainDir, ensureBrainDir } from "./brain.js";

const DOCKER_IMAGE = process.env.AGENT_DOCKER_IMAGE || "dom-sandbox";
const SANDBOX_NETWORK = "dom-sandbox-net";
const CONTAINER_BRAIN_PATH = "/brain";

// Cached lazily — first runInSandbox() call decides which network to use
let resolvedNetworkPromise: Promise<string> | null = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function resolveOutputDir(dir: string): string {
  const resolved = dir.startsWith("~") ? dir.replace("~", homedir()) : resolve(dir);
  if (!existsSync(resolved)) {
    mkdirSync(resolved, { recursive: true });
  }
  return resolved;
}

export function isSandboxEnabled(): boolean {
  return process.env.AGENT_SANDBOX !== "false";
}

// ---------------------------------------------------------------------------
// Docker network — bridge isolation + (optional) HAProxy egress proxy
// ---------------------------------------------------------------------------
//
// What `dom-sandbox-net` actually enforces:
//   - Container isolation: containers on the network can talk to each other
//     but are isolated from containers on other networks.
//   - It does NOT filter egress to the public internet by itself. Bash-level
//     guardrails in src/guardrails.ts are the primary filter.
//
// For real egress filtering, run the egress-proxy compose stack:
//   docker-compose -f docker-compose.egress.yml up -d
// That brings up an HAProxy container that's the only egress point on this
// network and enforces a hostname allowlist.

function dockerCmd(args: string[]): string {
  return execFileSync("docker", args, { stdio: ["ignore", "pipe", "pipe"] }).toString().trim();
}

function networkExists(name: string): boolean {
  try {
    dockerCmd(["network", "inspect", name]);
    return true;
  } catch {
    return false;
  }
}

async function ensureNetwork(): Promise<string> {
  if (resolvedNetworkPromise) return resolvedNetworkPromise;

  resolvedNetworkPromise = (async () => {
    try {
      if (!networkExists(SANDBOX_NETWORK)) {
        dockerCmd([
          "network", "create",
          "--driver", "bridge",
          // Internal=false: containers can reach the internet (subject to
          // egress proxy if running). Internal=true would block all egress
          // including the Anthropic API — too restrictive for default mode.
          SANDBOX_NETWORK,
        ]);
      }
      return SANDBOX_NETWORK;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(
        `Warning: could not create Docker network '${SANDBOX_NETWORK}' (${msg.split("\n")[0]}). ` +
        `Falling back to default bridge network. Container isolation reduced.`,
      );
      return "bridge";
    }
  })();

  return resolvedNetworkPromise;
}

/**
 * Best-effort network removal on process exit.
 * Fails silently if other containers are still attached (Docker rejects).
 */
function removeNetwork() {
  try {
    if (networkExists(SANDBOX_NETWORK)) {
      execFileSync("docker", ["network", "rm", SANDBOX_NETWORK], {
        stdio: ["ignore", "ignore", "ignore"],
      });
    }
  } catch {
    // Network has active endpoints, doesn't exist, or docker is gone — ignore
  }
}

// Register cleanup once. .unref() so it doesn't keep the process alive.
let cleanupRegistered = false;
function registerNetworkCleanup() {
  if (cleanupRegistered) return;
  cleanupRegistered = true;
  process.on("exit", removeNetwork);
  process.on("SIGINT", () => { removeNetwork(); process.exit(130); });
  process.on("SIGTERM", () => { removeNetwork(); process.exit(143); });
}

// ---------------------------------------------------------------------------
// Run agent inside Docker — streams JSON-line events from the container
// ---------------------------------------------------------------------------

interface RunRequest {
  prompt: string;
  model: string;
  maxTurns: number;
  sessionId?: string;
}

export async function* runInSandbox(
  request: RunRequest,
  hostOutputDir: string,
): AsyncGenerator<AgentEvent> {
  const absDir = resolveOutputDir(hostOutputDir);
  const requestJson = JSON.stringify(request);

  // Ensure the sandbox network exists before launching the container.
  // First call creates it; subsequent calls are cached.
  registerNetworkCleanup();
  const network = await ensureNetwork();

  // Ensure the brain dir exists on the host before we mount it; bind-mounting
  // a missing source path creates it as root-owned, which causes the
  // curator's writes from inside the container to fail mysteriously.
  const hostBrainDir = ensureBrainDir();

  // Write API key to a temp env file with mode 0600 (owner-only).
  // Using --env-file instead of -e keeps the secret out of `ps aux` output.
  // mkdtempSync creates a 0700 dir; writeFileSync with mode 0600 locks the file.
  // Inside the container the brain lives at /brain; brain.ts respects
  // AGENT_BRAIN_DIR so we just point it there. Other Dom env vars that
  // should be visible inside the container go here too.
  const tmpDir = mkdtempSync(join(tmpdir(), "dom-env-"));
  const envFilePath = join(tmpDir, "agent.env");
  // Optional egress proxy. When AGENT_EGRESS_PROXY is set (e.g. to
  // http://dom-egress-proxy:8443 from docker-compose.egress.yml), point the
  // container's HTTP(S)_PROXY at it so well-behaved HTTP libraries route
  // through the SNI allowlist. NOTE: this only constrains proxy-aware clients —
  // raw sockets / DNS still bypass it. See "Network Security" in CLAUDE.md.
  const egressProxy = process.env.AGENT_EGRESS_PROXY;
  writeFileSync(
    envFilePath,
    `ANTHROPIC_API_KEY=${process.env.ANTHROPIC_API_KEY ?? ""}\n` +
    `AGENT_BRAIN_DIR=${CONTAINER_BRAIN_PATH}\n` +
    (process.env.AGENT_BRAIN_MAX_LOADED ? `AGENT_BRAIN_MAX_LOADED=${process.env.AGENT_BRAIN_MAX_LOADED}\n` : "") +
    (process.env.AGENT_BRAIN_MAX_ENTRIES ? `AGENT_BRAIN_MAX_ENTRIES=${process.env.AGENT_BRAIN_MAX_ENTRIES}\n` : "") +
    (egressProxy
      ? `HTTPS_PROXY=${egressProxy}\nHTTP_PROXY=${egressProxy}\n` +
        `NO_PROXY=localhost,127.0.0.1\n`
      : ""),
    { mode: 0o600 },
  );

  const cleanup = () => {
    try { unlinkSync(envFilePath); } catch { /* already gone */ }
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  };

  // Run as the host user (not root). With --user = host uid:gid, writes to the
  // bind-mounted /workspace and /brain "just work" (the process IS the owner),
  // and we no longer need root + DAC_OVERRIDE/SET[UG]ID to cross the mount.
  // getuid/getgid are POSIX-only; fall back to image default elsewhere.
  const userArgs =
    typeof process.getuid === "function" && typeof process.getgid === "function"
      ? ["--user", `${process.getuid()}:${process.getgid()}`]
      : [];

  const container = spawn("docker", [
    "run",
    "--rm",
    // Mount project directory
    "-v", `${absDir}:/workspace`,
    // Mount the brain so the in-container curator's writes persist to the host
    "-v", `${hostBrainDir}:${CONTAINER_BRAIN_PATH}`,
    // Pass API key via env file (not visible in `ps aux`)
    "--env-file", envFilePath,
    // Run non-root as the host user (see above)
    ...userArgs,
    // Resource limits
    "--memory", "2g",
    "--cpus", "2",
    "--pids-limit", "512",
    // Security — drop ALL caps and re-add only the file-ownership caps package
    // managers may need. The privilege-escalation caps SETUID/SETGID and the
    // permission-bypass cap DAC_OVERRIDE are deliberately NOT granted.
    "--security-opt", "no-new-privileges",
    "--cap-drop", "ALL",
    "--cap-add", "CHOWN",
    "--cap-add", "FOWNER",
    // Restricted bridge network — provides container isolation, NOT egress
    // filtering. Default mode has full internet egress; for SNI-allowlisted
    // egress run docker-compose.egress.yml and set AGENT_EGRESS_PROXY.
    "--network", network,
    DOCKER_IMAGE,
    requestJson,
  ], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  // Buffer for incomplete JSON lines
  let buffer = "";

  const lineIterator = new Promise<void>((resolvePromise, reject) => {
    container.stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      // Process complete lines
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? ""; // Keep incomplete last line in buffer
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event: AgentEvent = JSON.parse(line);
          pendingEvents.push(event);
          if (eventResolve) {
            eventResolve();
            eventResolve = null;
          }
        } catch {
          // Skip malformed lines (e.g. npm warnings)
        }
      }
    });

    container.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString().trim();
      if (text) {
        pendingEvents.push({ event: "stderr", data: { text } });
        if (eventResolve) {
          eventResolve();
          eventResolve = null;
        }
      }
    });

    container.on("close", (code) => {
      cleanup();
      done = true;
      if (code && code !== 0) {
        pendingEvents.push({
          event: "error",
          data: { message: `Container exited with code ${code}` },
        });
      }
      if (eventResolve) {
        eventResolve();
        eventResolve = null;
      }
      resolvePromise();
    });

    container.on("error", (err) => {
      cleanup();
      done = true;
      pendingEvents.push({
        event: "error",
        data: { message: err.message },
      });
      if (eventResolve) {
        eventResolve();
        eventResolve = null;
      }
      reject(err);
    });
  });

  // Event queue consumed by the async generator
  const pendingEvents: AgentEvent[] = [];
  let eventResolve: (() => void) | null = null;
  let done = false;

  function waitForEvent(): Promise<void> {
    if (pendingEvents.length > 0 || done) return Promise.resolve();
    return new Promise((r) => { eventResolve = r; });
  }

  // Yield events as they arrive
  while (true) {
    await waitForEvent();
    while (pendingEvents.length > 0) {
      yield pendingEvents.shift()!;
    }
    if (done) break;
  }

  await lineIterator;
}
