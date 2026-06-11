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
  createHmac,
  hkdfSync,
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

// V1 = legacy (PBKDF2 key used directly). V2 = current (PBKDF2 stretch then
// HKDF-Expand with a domain label, so the at-rest key is cryptographically
// separated from the raw AGENT_API_TOKEN / its other uses). Both magics are
// the same length; V1 is still readable for backward compatibility.
const MAGIC_V1 = Buffer.from("DOMENC1", "utf-8");
const MAGIC_V2 = Buffer.from("DOMENC2", "utf-8");
const MAGIC = MAGIC_V1; // retained for callers/tests referencing the original name
const MAGIC_LEN = MAGIC_V2.length;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const PBKDF2_ITERS = 200_000;
const PBKDF2_DIGEST = "sha256";
const CIPHER_ALGO = "aes-256-gcm";
// Domain-separation label for the HKDF expand step (V2 key derivation).
const HKDF_INFO_V2 = Buffer.from("dom-session-encryption-v2", "utf-8");
// Label for the directory seal marker (HMAC over the token).
const SEAL_LABEL = "dom-session-seal-v1";
const MARKER_FILENAME = ".dom-enc-marker";

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

function getToken(): string {
  const token = process.env.AGENT_API_TOKEN;
  if (!token) {
    throw new Error("AGENT_API_TOKEN must be set to encrypt/decrypt session files");
  }
  return token;
}

/** Legacy V1 key: PBKDF2 output used directly. */
function deriveKeyV1(salt: Buffer): Buffer {
  return pbkdf2Sync(getToken(), salt, PBKDF2_ITERS, KEY_LEN, PBKDF2_DIGEST);
}

/**
 * V2 key: PBKDF2 stretch (unchanged 200k cost) THEN HKDF-Expand with a fixed
 * domain label. The encryption key is therefore distinct from the raw token
 * and from any other PBKDF2 use of it — leaking the bearer token no longer
 * directly yields the at-rest key without also knowing this derivation.
 */
function deriveKeyV2(salt: Buffer): Buffer {
  const prk = pbkdf2Sync(getToken(), salt, PBKDF2_ITERS, KEY_LEN, PBKDF2_DIGEST);
  return Buffer.from(hkdfSync(PBKDF2_DIGEST, prk, salt, HKDF_INFO_V2, KEY_LEN));
}

export function isCiphertext(buf: Buffer): boolean {
  if (buf.length < MAGIC_LEN) return false;
  const head = buf.subarray(0, MAGIC_LEN);
  return head.equals(MAGIC_V2) || head.equals(MAGIC_V1);
}

function encryptWith(magic: Buffer, deriveKey: (s: Buffer) => Buffer, plaintext: Buffer): Buffer {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(salt);
  const cipher = createCipheriv(CIPHER_ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([magic, salt, iv, tag, ciphertext]);
}

export function encryptBuffer(plaintext: Buffer): Buffer {
  return encryptWith(MAGIC_V2, deriveKeyV2, plaintext);
}

export function decryptBuffer(blob: Buffer): Buffer {
  if (!isCiphertext(blob)) {
    throw new Error("Not an encrypted session file (missing DOMENC magic)");
  }
  if (blob.length < MAGIC_LEN + SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error("Encrypted session file is truncated");
  }
  const isV2 = blob.subarray(0, MAGIC_LEN).equals(MAGIC_V2);
  const deriveKey = isV2 ? deriveKeyV2 : deriveKeyV1;
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
// Seal marker + downgrade detection
// ---------------------------------------------------------------------------
//
// When encryption is enabled we drop a tamper-evident marker (HMAC of a fixed
// label under AGENT_API_TOKEN) in the config dir after a successful seal. If a
// file under the sessions root is found PLAINTEXT while a valid marker exists,
// that's a downgrade/tamper signal — an attacker swapped ciphertext for chosen
// plaintext, or a crash left the tree unsealed. We refuse to silently ingest
// it. (A full per-file signed manifest is the complete fix; this closes the
// common silent-acceptance case.)

function markerPath(): string {
  return join(ensureClaudeConfigDir(), MARKER_FILENAME);
}

function expectedMarker(): string {
  return createHmac("sha256", getToken()).update(SEAL_LABEL).digest("hex");
}

function writeSealMarker(): void {
  try {
    writeFileSync(markerPath(), expectedMarker(), { mode: 0o600 });
  } catch { /* best-effort */ }
}

function sealMarkerValid(): boolean {
  try {
    const p = markerPath();
    return existsSync(p) && readFileSync(p, "utf-8") === expectedMarker();
  } catch {
    return false;
  }
}

/**
 * One-time migration escape hatch. Enabling encryption on a directory that
 * already holds PLAINTEXT sessions is the ONLY legitimate reason to accept
 * plaintext at rest. It must be opted into explicitly; otherwise plaintext is
 * always treated as a downgrade. This makes the check independent of the
 * (attacker-deletable) seal marker — deleting the marker no longer re-opens
 * silent plaintext acceptance.
 */
function isMigrationMode(): boolean {
  return process.env.AGENT_SESSION_ENCRYPT_MIGRATE === "true";
}

function isPlaintextDowngrade(buf: Buffer): boolean {
  return isEncryptionEnabled() && !isMigrationMode() && !isCiphertext(buf);
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
    if (file === markerPath()) { skipped++; continue; }
    try {
      const raw = readFileSync(file);
      if (isCiphertext(raw)) { skipped++; continue; }
      atomicWrite(file, encryptBuffer(raw));
      encrypted++;
    } catch {
      errors++;
    }
  }
  // Drop the seal marker once everything is encrypted, so a later plaintext
  // file under a valid marker reads as tampering (see isPlaintextDowngrade).
  if (errors === 0) writeSealMarker();
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
    if (file === markerPath()) { skipped++; continue; }
    try {
      const raw = readFileSync(file);
      if (!isCiphertext(raw)) {
        // Plaintext at rest while encryption is enabled = downgrade/tamper (or
        // a crash left it unsealed). Surface loudly instead of silently passing
        // — UNLESS this is an explicit one-time migration.
        if (isMigrationMode()) {
          skipped++; // will be sealed on the next encrypt sweep
        } else {
          console.error(
            `[session-crypt] SECURITY: plaintext session file with encryption enabled: ${file}. ` +
            `Possible tampering/downgrade, or a prior run crashed before re-sealing. ` +
            `If you are intentionally migrating a plaintext directory, set AGENT_SESSION_ENCRYPT_MIGRATE=true once.`,
          );
          errors++;
        }
        continue;
      }
      atomicWrite(file, decryptBuffer(raw));
      decrypted++;
    } catch {
      errors++;
    }
  }
  return { decrypted, skipped, errors };
}

/**
 * Read a session file, transparently decrypting if it's DOMENC-prefixed.
 * Returns the plaintext content as a Buffer. Does NOT rewrite the file.
 * Throws if the file is plaintext while the directory is sealed (downgrade).
 */
export function readSessionFile(path: string): Buffer {
  const raw = readFileSync(path);
  if (isPlaintextDowngrade(raw)) {
    throw new Error(
      `Refusing to read plaintext session file '${path}' under a valid encryption seal — ` +
      `possible tampering or downgrade attack.`,
    );
  }
  return isCiphertext(raw) ? decryptBuffer(raw) : raw;
}

// ---------------------------------------------------------------------------
// Active-run reference counting — defers re-encryption until the LAST
// concurrent run/listing finishes, so one run's finally-block can't re-encrypt
// the tree while another run is still reading plaintext. (Node is single-
// threaded, so the counter mutations at these sync points don't interleave.)
// ---------------------------------------------------------------------------

let activeRuns = 0;

/** Enter the decrypted bracket: decrypt on the first concurrent entrant. */
export function beginActiveRun(): void {
  if (!isEncryptionEnabled()) return;
  if (activeRuns === 0) decryptSessionsNow();
  activeRuns++;
}

/** Leave the bracket: re-encrypt (and surface failures) when the last one exits. */
export function endActiveRun(): void {
  if (!isEncryptionEnabled()) return;
  activeRuns = Math.max(0, activeRuns - 1);
  if (activeRuns === 0) {
    const r = encryptSessionsNow();
    if (r.errors > 0) {
      console.error(
        `[session-crypt] SECURITY: re-encryption reported ${r.errors} error(s) — ` +
        `some session files may remain plaintext on disk.`,
      );
    }
  }
}

// Exposed for tests
export const _internal = {
  MAGIC,
  MAGIC_V1,
  MAGIC_V2,
  MAGIC_LEN,
  SALT_LEN,
  IV_LEN,
  TAG_LEN,
  KEY_LEN,
  getSessionsRoot,
  writeSealMarker,
  sealMarkerValid,
  isPlaintextDowngrade,
  beginActiveRun,
  endActiveRun,
  resetActiveRunsForTests: () => { activeRuns = 0; },
  /** Build a legacy V1 ciphertext (for backward-compat tests). */
  encryptLegacyV1: (plaintext: Buffer): Buffer => encryptWith(MAGIC_V1, deriveKeyV1, plaintext),
};
