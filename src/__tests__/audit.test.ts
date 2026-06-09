import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { _internal } from "../audit.js";

const { sanitizeToolInput } = _internal;

describe("audit — sanitizeToolInput", () => {
  it("redacts an Authorization: Bearer header from a Bash command", () => {
    const out = sanitizeToolInput("Bash", {
      command: "curl -H 'Authorization: Bearer realtokenvalue.xyz' https://github.com/foo",
    });
    assert.ok(typeof out.command === "string");
    assert.ok(!String(out.command).includes("realtokenvalue.xyz"), `not redacted: ${out.command}`);
    assert.ok(String(out.command).includes("Bearer ***"));
  });

  it("redacts an embedded postgres password", () => {
    const out = sanitizeToolInput("Bash", {
      command: "psql 'postgres://app:hunter2@db.internal/app' -c 'select 1'",
    });
    assert.ok(!String(out.command).includes("hunter2"), `password leaked: ${out.command}`);
  });

  it("redacts a github PAT in a gh auth command", () => {
    const out = sanitizeToolInput("Bash", {
      command: "echo ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 | gh auth login --with-token",
    });
    assert.ok(!String(out.command).includes("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ"), `PAT leaked: ${out.command}`);
  });

  it("never includes content for Write — only file_path", () => {
    const out = sanitizeToolInput("Write", { file_path: "/x", content: "secret payload" });
    assert.deepEqual(out, { file_path: "/x" });
  });

  it("logs only key names for unknown tools, never values", () => {
    const out = sanitizeToolInput("MysteryTool", { sensitive: "abc", other: 123 });
    assert.deepEqual(out, { _unknown_tool_input_keys: ["sensitive", "other"] });
  });
});
