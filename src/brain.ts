/**
 * Dom's shared brain — a markdown memory bank.
 *
 * Layout (default ./.dom-brain, override with AGENT_BRAIN_DIR):
 *   .dom-brain/
 *     MEMORY.md           index of all memories (one line per entry)
 *     <slug>.md           one memory per file, with frontmatter
 *
 * Lifecycle:
 *   - At session start, agent.ts loads every <slug>.md into the system
 *     prompt as a "## Memory" section.
 *   - The main agent uses these memories to inform its behavior.
 *   - At Stop (after goal-verifier), the brain-curator subagent edits the
 *     brain: saves new memories, overwrites conflicting ones, evicts dormant.
 *
 * Each memory file has YAML-ish frontmatter:
 *   ---
 *   name: <short title>
 *   description: <one-line description>
 *   type: user | feedback | project | reference
 *   created: <ISO timestamp>
 *   last_used: <ISO timestamp>
 *   ---
 *
 *   <markdown body>
 */

import {
  readFileSync,
  writeFileSync,
  readdirSync,
  existsSync,
  mkdirSync,
  statSync,
} from "fs";
import { join, resolve, isAbsolute } from "path";
import { detectSecrets, summarizeMatches } from "./leak-detect.js";

export const DEFAULT_BRAIN_DIR = ".dom-brain";
export const INDEX_FILENAME = "MEMORY.md";
export const ENTRY_SUFFIX = ".md";

// Soft cap on what we load into the system prompt. Beyond this, oldest-by-
// last_used entries are dropped from the load (file is kept on disk so the
// curator can decide to evict). Tunable via AGENT_BRAIN_MAX_LOADED.
const DEFAULT_MAX_LOADED = 30;

// Hard cap on total entries the brain holds — when exceeded, brain.ts
// refuses to add more until the curator evicts something. Tunable via
// AGENT_BRAIN_MAX_ENTRIES.
const DEFAULT_MAX_ENTRIES = 100;

// Hard cap on the prompt-section byte size; well below the SDK's prompt
// budget but generous enough for ~30 modest entries.
const DEFAULT_MAX_PROMPT_BYTES = 60_000;

export type MemoryType = "user" | "feedback" | "project" | "reference";

export interface MemoryEntry {
  filename: string;       // basename, e.g. "user-prefers-typescript.md"
  absPath: string;
  name: string;
  description: string;
  type: MemoryType;
  created: string;        // ISO timestamp
  lastUsed: string;       // ISO timestamp
  body: string;
}

// ---------------------------------------------------------------------------
// Directory resolution
// ---------------------------------------------------------------------------

export function getBrainDir(): string {
  const raw = process.env.AGENT_BRAIN_DIR || DEFAULT_BRAIN_DIR;
  return isAbsolute(raw) ? raw : resolve(raw);
}

export function ensureBrainDir(): string {
  const dir = getBrainDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function getMaxLoaded(): number {
  const raw = process.env.AGENT_BRAIN_MAX_LOADED;
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_LOADED;
}

function getMaxEntries(): number {
  const raw = process.env.AGENT_BRAIN_MAX_ENTRIES;
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_ENTRIES;
}

// ---------------------------------------------------------------------------
// Frontmatter parsing — minimal, intentionally not a YAML library
// ---------------------------------------------------------------------------

const FRONTMATTER_DELIM = "---";

interface ParsedFile {
  frontmatter: Record<string, string>;
  body: string;
}

function parseFile(raw: string): ParsedFile {
  const lines = raw.split(/\r?\n/);
  if (lines[0]?.trim() !== FRONTMATTER_DELIM) {
    return { frontmatter: {}, body: raw };
  }
  const fm: Record<string, string> = {};
  let i = 1;
  for (; i < lines.length; i++) {
    if (lines[i].trim() === FRONTMATTER_DELIM) {
      i++;
      break;
    }
    const idx = lines[i].indexOf(":");
    if (idx === -1) continue;
    const k = lines[i].slice(0, idx).trim();
    const v = lines[i].slice(idx + 1).trim();
    fm[k] = v;
  }
  // Drop one leading blank line after the closing delimiter, if present.
  if (lines[i] !== undefined && lines[i].trim() === "") i++;
  return { frontmatter: fm, body: lines.slice(i).join("\n") };
}

function buildFile(entry: MemoryEntry): string {
  return (
    `${FRONTMATTER_DELIM}\n` +
    `name: ${entry.name}\n` +
    `description: ${entry.description}\n` +
    `type: ${entry.type}\n` +
    `created: ${entry.created}\n` +
    `last_used: ${entry.lastUsed}\n` +
    `${FRONTMATTER_DELIM}\n\n` +
    entry.body.trimEnd() +
    "\n"
  );
}

// ---------------------------------------------------------------------------
// Read all entries
// ---------------------------------------------------------------------------

function isValidType(s: string): s is MemoryType {
  return s === "user" || s === "feedback" || s === "project" || s === "reference";
}

export function listEntries(): MemoryEntry[] {
  const dir = ensureBrainDir();
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }

  const entries: MemoryEntry[] = [];
  for (const name of names) {
    if (!name.endsWith(ENTRY_SUFFIX)) continue;
    if (name === INDEX_FILENAME) continue;
    const absPath = join(dir, name);
    let st;
    try { st = statSync(absPath); } catch { continue; }
    if (!st.isFile()) continue;

    let raw: string;
    try { raw = readFileSync(absPath, "utf-8"); } catch { continue; }

    const { frontmatter, body } = parseFile(raw);
    const fmType = frontmatter.type;
    if (!fmType || !isValidType(fmType)) continue; // malformed — skip

    entries.push({
      filename: name,
      absPath,
      name: frontmatter.name || name.replace(/\.md$/, ""),
      description: frontmatter.description || "",
      type: fmType,
      created: frontmatter.created || new Date(st.birthtimeMs || st.mtimeMs).toISOString(),
      lastUsed: frontmatter.last_used || new Date(st.mtimeMs).toISOString(),
      body: body.trimEnd(),
    });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Prompt section builder — what gets injected into SYSTEM_PROMPT
// ---------------------------------------------------------------------------

/**
 * Build the markdown section that gets appended to the SYSTEM_PROMPT.
 * Returns an empty string when there are no entries.
 *
 * Selection: newest `last_used` first, capped by AGENT_BRAIN_MAX_LOADED and
 * by DEFAULT_MAX_PROMPT_BYTES. Older entries are kept on disk for the
 * curator to consider; they're just not loaded this run.
 */
export function buildPromptSection(): string {
  const entries = listEntries();
  if (entries.length === 0) return "";

  const sorted = [...entries].sort((a, b) => b.lastUsed.localeCompare(a.lastUsed));
  const cap = getMaxLoaded();

  const blocks: string[] = [];
  const skipped: Array<{ filename: string; reason: string }> = [];
  let totalBytes = 0;
  const header =
    "## Memory (loaded from brain/)\n\n" +
    "Long-lived knowledge curated from prior sessions. Treat as authoritative — these are not suggestions, they are facts the team has chosen to remember. If a memory becomes wrong, the brain-curator subagent will overwrite it after a run; do not silently ignore.\n";

  totalBytes += header.length;

  for (const e of sorted.slice(0, cap)) {
    // Defense in depth: even though the curator's Write goes through the
    // leak-detect guardrail, a hand-edited brain file could still contain a
    // secret. Refuse to load any memory whose body matches a known pattern.
    const matches = detectSecrets(e.body);
    if (matches.length > 0) {
      skipped.push({ filename: e.filename, reason: `contains secret pattern(s): ${summarizeMatches(matches).join(", ")}` });
      continue;
    }
    // Tombstones (curator-evicted entries) skip the prompt section too.
    if (e.description.startsWith("[EVICTED]")) {
      continue;
    }
    const block =
      `\n### ${e.name} _(${e.type})_\n` +
      `${e.description ? `_${e.description}_\n\n` : ""}` +
      `${e.body.trim()}\n`;
    if (totalBytes + block.length > DEFAULT_MAX_PROMPT_BYTES) break;
    blocks.push(block);
    totalBytes += block.length;
  }

  if (skipped.length > 0) {
    // Surface as a single line at the top of the section so a human notices.
    return (
      header +
      `\n> Warning: ${skipped.length} memory file(s) skipped due to suspected secrets — run the brain-curator to scrub them: ${skipped.map((s) => s.filename).join(", ")}\n` +
      blocks.join("")
    );
  }

  return header + blocks.join("");
}

// ---------------------------------------------------------------------------
// Index file — for human inspection; curator updates it on every change
// ---------------------------------------------------------------------------

export function rebuildIndex(): void {
  const dir = ensureBrainDir();
  const entries = listEntries();
  const sorted = [...entries].sort((a, b) => b.lastUsed.localeCompare(a.lastUsed));

  const header =
    "# Dom brain — index\n\n" +
    "Curated by the `brain-curator` subagent after each successful run.\n" +
    "Each entry below points to a memory file in this directory.\n\n";

  const lines = sorted.map((e) => {
    const desc = e.description ? ` — ${e.description}` : "";
    return `- [${e.name}](${e.filename}) _(${e.type})_${desc}`;
  });

  const body = sorted.length === 0
    ? "_(empty — no memories saved yet)_\n"
    : lines.join("\n") + "\n";

  writeFileSync(join(dir, INDEX_FILENAME), header + body, { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Touch — bump last_used. The curator should call this when it confirms a
// memory was actually useful in the current run. Used to keep dormant
// memories out of the eviction queue.
// ---------------------------------------------------------------------------

export function touchEntry(filename: string): void {
  const dir = getBrainDir();
  const absPath = join(dir, filename);
  if (!existsSync(absPath)) return;
  const raw = readFileSync(absPath, "utf-8");
  const { frontmatter, body } = parseFile(raw);
  const fmType = frontmatter.type;
  if (!fmType || !isValidType(fmType)) return;
  const entry: MemoryEntry = {
    filename,
    absPath,
    name: frontmatter.name || filename.replace(/\.md$/, ""),
    description: frontmatter.description || "",
    type: fmType,
    created: frontmatter.created || new Date().toISOString(),
    lastUsed: new Date().toISOString(),
    body: body.trimEnd(),
  };
  writeFileSync(absPath, buildFile(entry), { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Stats — used by the curator's dispatch prompt to decide whether to evict
// ---------------------------------------------------------------------------

export interface BrainStats {
  entryCount: number;
  maxEntries: number;
  maxLoaded: number;
  totalBytes: number;
  dir: string;
}

export function getStats(): BrainStats {
  const entries = listEntries();
  const totalBytes = entries.reduce((n, e) => n + e.body.length, 0);
  return {
    entryCount: entries.length,
    maxEntries: getMaxEntries(),
    maxLoaded: getMaxLoaded(),
    totalBytes,
    dir: getBrainDir(),
  };
}

/**
 * Returns true if the brain is at or over its hard cap. The curator should
 * evict before saving when this is true.
 */
export function isAtCapacity(): boolean {
  return listEntries().length >= getMaxEntries();
}

// Exposed for tests
export const _internal = { parseFile, buildFile };
