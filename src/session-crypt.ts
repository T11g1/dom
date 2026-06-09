/**
 * Bracket encryption for session files at rest.
 *
 * Strategy: the SDK writes plaintext session files during an active run.
 * After the run completes, we walk the session directory and encrypt each
 * file in place. Before a resume or a listing, we decrypt. The plaintext
 * window is therefore only during active execution — when the same data
 * is already in memory anyway.
 *
 * Why not transparent per-write encryption? The SDK owns its session I/O;
 * there is no public storage hook. Monkey-patching fs is fragile. Bracket
 * encryption is the honest, workable compromise.
 *
 * File format (binary):
 *   [7 bytes]  magic "DOMENC1"
 *   [16 bytes] salt (PBKDF2)
 *   [12 bytes] iv (GCM nonce)
 *   [16 bytes] auth tag (GCM)
 *   [N bytes]  ciphertext
 *
 * Key derivation: PBKDF2-SHA256(AGENT_API_TOKEN, salt, 200_000 iters, 32 bytes)
 */

import {
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  randomBytes,
} from "crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { join, resolve, dirname } from "path";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const MAGIC = Buffer.from("DOMENC1", "utf-8");
const MAGIC_LEN = MAGIC.length;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const PBKDF2_ITERS = 200_000;
const PBKDF2_DIGEST = "sha256";
const CIPHER_ALGO = "aes-256-gcm";

/**
 * The SDK looks at CLAUDE_CONFIG_DIR. We default it to a project-local
 * directory so sessions never land in the user's home (and so our
 * encryption sweep has a safe, bounded blast radius).
 */
export const DEFAULT_CLAUDE_CONFIG_DIR = resolve(".dom-claude");

export function ensureClaudeConfigDir(): string {
  if (!process.env.CLAUDE_CONFIG_DIR) {
    process.env.CLAUDE_CONFIG_DIR = DEFAULT_CLAUDE_CONFIG_DIR;
  }
  const dir = process.env.CLAUDE_CONFIG_DIR;
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  return dir;
}

export function isEncryptionEnabled(): boolean {
  return process.env.AGENT_SESSION_ENCRYPT === "true";
}

function getSessionsRoot(): string {
  const base = ensureClaudeConfigDir();
  return join(base, "projects");
}

// ---------------------------------------------------------------------------
// Core crypto primitives
// ---------------------------------------------------------------------------

function deriveKey(salt: Buffer): Buffer {
  const token = process.env.AGENT_API_TOKEN;
  if (!token) {
    throw new Error("AGENT_API_TOKEN must be set to encrypt/decrypt session files");
  }
  return pbkdf2Sync(token, salt, PBKDF2_ITERS, KEY_LEN, PBKDF2_DIGEST);
}

export function isCiphertext(buf: Buffer): boolean {
  return buf.length >= MAGIC_LEN && buf.subarray(0, MAGIC_LEN).equals(MAGIC);
}

export function encryptBuffer(plaintext: Buffer): Buffer {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(salt);
  const cipher = createCipheriv(CIPHER_ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, salt, iv, tag, ciphertext]);
}

export function decryptBuffer(blob: Buffer): Buffer {
  if (!isCiphertext(blob)) {
    throw new Error("Not an encrypted session file (missing DOMENC1 magic)");
  }
  if (blob.length < MAGIC_LEN + SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error("Encrypted session file is truncated");
  }
  let off = MAGIC_LEN;
  const salt = blob.subarray(off, off + SALT_LEN); off += SALT_LEN;
  const iv = blob.subarray(off, off + IV_LEN); off += IV_LEN;
  const tag = blob.subarray(off, off + TAG_LEN); off += TAG_LEN;
  const ciphertext = blob.subarray(off);
  const key = deriveKey(salt);
  const decipher = createDecipheriv(CIPHER_ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ---------------------------------------------------------------------------
// File-level helpers (atomic-ish in-place rewrite)
// ---------------------------------------------------------------------------

/**
 * Walk a directory recursively, yielding absolute paths to regular files.
 * Returns an array so callers can act without holding state mid-iteration.
 */
function listRegularFiles(root: string): string[] {
  const out: string[] = [];
  function walk(dir: string) {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      const path = join(dir, name);
      let st;
      try {
        st = statSync(path);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(path);
      else if (st.isFile()) out.push(path);
    }
  }
  walk(root);
  return out;
}

/**
 * Rewrite a file atomically via temp + rename. Crash-safe on POSIX.
 */
function atomicWrite(path: string, data: Buffer) {
  const tmp = path + ".domcrypt.tmp";
  writeFileSync(tmp, data, { mode: 0o600 });
  renameSync(tmp, path);
}

function encryptFile(path: string) {
  const raw = readFileSync(path);
  if (isCiphertext(raw)) return; // already encrypted
  atomicWrite(path, encryptBuffer(raw));
}

function decryptFile(path: string) {
  const raw = readFileSync(path);
  if (!isCiphertext(raw)) return; // already plaintext (or foreign file)
  const plain = decryptBuffer(raw);
  atomicWrite(path, plain);
}

// ---------------------------------------------------------------------------
// Public API — bracket encryption around the agent run
// ---------------------------------------------------------------------------

/**
 * Encrypt every file under the SDK's sessions directory in place.
 * Safe to call when encryption is disabled (no-op).
 * Safe to call on a mix of encrypted + plaintext files (skips already-encrypted).
 */
export function encryptSessionsNow(): { encrypted: number; skipped: number; errors: number } {
  if (!isEncryptionEnabled()) return { encrypted: 0, skipped: 0, errors: 0 };

  const root = getSessionsRoot();
  if (!existsSync(root)) return { encrypted: 0, skipped: 0, errors: 0 };

  let encrypted = 0, skipped = 0, errors = 0;
  for (const file of listRegularFiles(root)) {
    try {
      const raw = readFileSync(file);
      if (isCiphertext(raw)) { skipped++; continue; }
      atomicWrite(file, encryptBuffer(raw));
      encrypted++;
    } catch {
      errors++;
    }
  }
  return { encrypted, skipped, errors };
}

/**
 * Decrypt every file under the SDK's sessions directory in place.
 * Gracefully handles files that are already plaintext (e.g. sessions
 * from a prior run when encryption was disabled).
 */
export function decryptSessionsNow(): { decrypted: number; skipped: number; errors: number } {
  const root = getSessionsRoot();
  if (!existsSync(root)) return { decrypted: 0, skipped: 0, errors: 0 };

  let decrypted = 0, skipped = 0, errors = 0;
  for (const file of listRegularFiles(root)) {
    try {
      const raw = readFileSync(file);
      if (!isCiphertext(raw)) { skipped++; continue; }
      atomicWrite(file, decryptBuffer(raw));
      decrypted++;
    } catch {
      errors++;
    }
  }
  return { decrypted, skipped, errors };
}

/**
 * Read a session file, transparently decrypting if it's DOMENC1-prefixed.
 * Returns the plaintext content as a Buffer. Does NOT rewrite the file.
 */
export function readSessionFile(path: string): Buffer {
  const raw = readFileSync(path);
  return isCiphertext(raw) ? decryptBuffer(raw) : raw;
}

// Exposed for tests
export const _internal = {
  MAGIC,
  MAGIC_LEN,
  SALT_LEN,
  IV_LEN,
  TAG_LEN,
  KEY_LEN,
  getSessionsRoot,
};
