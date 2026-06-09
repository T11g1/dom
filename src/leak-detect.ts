/**
 * Secret-pattern detection shared by:
 *   - audit.ts        — redact secrets in Bash commands before persisting to disk
 *   - guardrails.ts   — block Write/Edit when generated content contains secrets
 *
 * Patterns are conservative on purpose: a false positive blocks a write or
 * masks a value; a false negative leaks data. Prefer over-redaction.
 *
 * Each entry has a name (for telemetry), a regex, and a replacement strategy.
 * Replacements always preserve a short prefix when useful so a reader can
 * still recognize the kind of secret without recovering it.
 */

export interface SecretMatch {
  name: string;
  index: number;
  length: number;
}

interface Pattern {
  name: string;
  re: RegExp;
  redact: (match: string) => string;
}

const KEEP_PREFIX = (n: number) => (m: string) => (m.length > n ? m.slice(0, n) + "***" : "***");

// Order matters: more specific patterns first so generic kv= patterns
// don't catch already-redacted values.
const PATTERNS: Pattern[] = [
  // Provider API keys (vendor-prefixed, high confidence)
  { name: "anthropic_api_key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, redact: KEEP_PREFIX(6) },
  { name: "openai_api_key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, redact: KEEP_PREFIX(3) },
  { name: "github_pat", re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g, redact: KEEP_PREFIX(4) },
  { name: "gitlab_pat", re: /\bglpat-[A-Za-z0-9_-]{16,}\b/g, redact: KEEP_PREFIX(6) },
  { name: "gitlab_prat", re: /\bglptt-[A-Za-z0-9_-]{16,}\b/g, redact: KEEP_PREFIX(6) },
  { name: "slack_token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, redact: KEEP_PREFIX(4) },
  { name: "stripe_live", re: /\b(?:sk|pk|rk)_live_[A-Za-z0-9]{16,}\b/g, redact: KEEP_PREFIX(8) },
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/g, redact: () => "AKIA***" },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{30,}\b/g, redact: KEEP_PREFIX(4) },

  // Authorization headers
  {
    name: "auth_bearer",
    re: /\b[Aa]uthorization\s*:\s*Bearer\s+[A-Za-z0-9_\-.~+/]+=*/g,
    redact: () => "Authorization: Bearer ***",
  },
  {
    name: "auth_basic",
    re: /\b[Aa]uthorization\s*:\s*Basic\s+[A-Za-z0-9+/]+=*/g,
    redact: () => "Authorization: Basic ***",
  },

  // DB / message-bus connection strings with embedded credentials
  // postgres://user:pass@host  →  postgres://user:***@host
  {
    name: "db_connection_string",
    re: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp[s]?):\/\/([^:\s/]+):([^@\s]+)@/g,
    redact: (m) => m.replace(/:([^@:\s/]+)@/, ":***@"),
  },

  // PEM-encoded private keys (any kind)
  {
    name: "private_key_pem",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    redact: () => "-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----",
  },

  // Generic high-entropy kv assignments — last so they don't override specific
  // patterns. Requires a known-sensitive key name and >= 16 chars of value.
  // Captures forms: KEY=value, KEY: value, --key=value, "key": "value"
  {
    name: "generic_secret_kv",
    re: /\b(api[_-]?key|secret|secret[_-]?key|access[_-]?token|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|pwd)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=]{16,})["']?/gi,
    redact: (m) => m.replace(/([:=]\s*["']?)([A-Za-z0-9_\-+/=]{16,})/, "$1***"),
  },
];

/**
 * Return all secret matches in the text. Useful for tests and audit metadata
 * (so we can log "leaked: anthropic_api_key" without logging the value).
 */
export function detectSecrets(text: string): SecretMatch[] {
  const found: SecretMatch[] = [];
  for (const { name, re } of PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      found.push({ name, index: m.index, length: m[0].length });
      if (m.index === re.lastIndex) re.lastIndex++; // zero-width safety
    }
  }
  return found;
}

/**
 * Return text with any detected secrets replaced by a redacted placeholder.
 * Idempotent: redacting already-redacted text is a no-op.
 */
export function redactSecrets(text: string): string {
  let out = text;
  for (const { re, redact } of PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, redact);
  }
  return out;
}

/**
 * Return the distinct pattern names that matched, suitable for safe logging.
 */
export function summarizeMatches(matches: SecretMatch[]): string[] {
  return [...new Set(matches.map((m) => m.name))];
}

// Exposed for tests
export const _internal = { PATTERNS };
