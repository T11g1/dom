import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectSecrets, redactSecrets, summarizeMatches } from "../leak-detect.js";

describe("leak-detect", () => {
  it("detects an Anthropic API key", () => {
    const text = "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz123456";
    const matches = detectSecrets(text);
    assert.ok(matches.some((m) => m.name === "anthropic_api_key"), "expected anthropic_api_key match");
  });

  it("detects a GitHub PAT", () => {
    const matches = detectSecrets("token=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
    assert.ok(matches.some((m) => m.name === "github_pat"));
  });

  it("detects a GitLab project access token", () => {
    const matches = detectSecrets("export GITLAB_TOKEN=glptt-1234567890abcdef1234");
    assert.ok(matches.some((m) => m.name === "gitlab_prat"));
  });

  it("detects an AWS access key", () => {
    const matches = detectSecrets("aws_access_key=AKIA1234567890ABCDEF");
    assert.ok(matches.some((m) => m.name === "aws_access_key"));
  });

  it("detects an Authorization: Bearer header", () => {
    const matches = detectSecrets("curl -H 'Authorization: Bearer abc.def.ghi' https://api.example.com");
    assert.ok(matches.some((m) => m.name === "auth_bearer"));
  });

  it("detects a Postgres connection string with embedded credentials", () => {
    const matches = detectSecrets("DATABASE_URL=postgres://user:hunter2@db.example.com:5432/app");
    assert.ok(matches.some((m) => m.name === "db_connection_string"));
  });

  it("detects a PEM private key block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    const matches = detectSecrets(pem);
    assert.ok(matches.some((m) => m.name === "private_key_pem"));
  });

  it("detects a generic api_key=long_value assignment", () => {
    const matches = detectSecrets('api_key = "abcdefghijklmnop1234"');
    assert.ok(matches.some((m) => m.name === "generic_secret_kv"));
  });

  it("does not false-positive on short values or placeholders", () => {
    assert.equal(detectSecrets("password=YOUR_PASSWORD").length, 0, "placeholder shouldn't match");
    assert.equal(detectSecrets("token=abc").length, 0, "too-short value shouldn't match");
  });

  it("redacts secrets while preserving identifiable prefixes", () => {
    const text = "auth = sk-ant-realsecrettoken1234567890abcdef";
    const redacted = redactSecrets(text);
    assert.ok(redacted.includes("sk-ant***"), `expected prefix-preserved redaction, got: ${redacted}`);
    assert.equal(detectSecrets(redacted).length, 0, "redacted output should not re-match");
  });

  it("redacts Postgres password but keeps user + host", () => {
    const redacted = redactSecrets("postgres://app:hunter2@db.example.com:5432/x");
    assert.ok(redacted.includes("postgres://app:***@db.example.com"), `got: ${redacted}`);
  });

  it("redactSecrets is idempotent", () => {
    const text = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 and Authorization: Bearer xyz.abc";
    const once = redactSecrets(text);
    const twice = redactSecrets(once);
    assert.equal(once, twice, "second redaction should be a no-op");
  });

  it("summarizeMatches dedupes by name", () => {
    const text = "k1=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 k2=ghp_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210";
    const matches = detectSecrets(text);
    const names = summarizeMatches(matches);
    assert.deepEqual(names, ["github_pat"]);
  });
});
