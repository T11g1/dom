import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let tmpBrainDir: string;
let prevEnv: string | undefined;

beforeEach(() => {
  tmpBrainDir = mkdtempSync(join(tmpdir(), "dom-brain-test-"));
  prevEnv = process.env.AGENT_BRAIN_DIR;
  process.env.AGENT_BRAIN_DIR = tmpBrainDir;
});

afterEach(() => {
  rmSync(tmpBrainDir, { recursive: true, force: true });
  if (prevEnv === undefined) delete process.env.AGENT_BRAIN_DIR;
  else process.env.AGENT_BRAIN_DIR = prevEnv;
});

// Re-import per test so the module reads the fresh env var. node:test
// shares module state between tests, so we use a dynamic helper instead.
async function brain() {
  return await import(`../brain.ts?cachebust=${Math.random()}`);
}

describe("brain — directory + stats", () => {
  it("ensureBrainDir creates the dir", async () => {
    const b = await brain();
    rmSync(tmpBrainDir, { recursive: true, force: true });
    assert.equal(existsSync(tmpBrainDir), false);
    const dir = b.ensureBrainDir();
    assert.equal(existsSync(dir), true);
    assert.equal(dir, tmpBrainDir);
  });

  it("listEntries returns [] on an empty brain", async () => {
    const b = await brain();
    assert.deepEqual(b.listEntries(), []);
  });

  it("stats reflect current state", async () => {
    const b = await brain();
    const s = b.getStats();
    assert.equal(s.entryCount, 0);
    assert.equal(s.dir, tmpBrainDir);
    assert.ok(s.maxEntries > 0);
    assert.ok(s.maxLoaded > 0);
  });
});

describe("brain — file parsing", () => {
  it("listEntries reads a well-formed memory file", async () => {
    writeFileSync(
      join(tmpBrainDir, "user-prefers-vitest.md"),
      `---
name: User prefers Vitest
description: User always wants Vitest, not Jest
type: user
created: 2026-06-09T10:00:00Z
last_used: 2026-06-09T10:00:00Z
---

Vitest only. Why: explicit preference stated 2026-06-08.
`,
    );
    const b = await brain();
    const entries = b.listEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "User prefers Vitest");
    assert.equal(entries[0].type, "user");
    assert.match(entries[0].body, /Vitest only/);
  });

  it("listEntries skips files without valid frontmatter type", async () => {
    writeFileSync(
      join(tmpBrainDir, "malformed.md"),
      "no frontmatter just a body\n",
    );
    writeFileSync(
      join(tmpBrainDir, "wrong-type.md"),
      "---\nname: x\ntype: unknown\n---\nbody",
    );
    const b = await brain();
    assert.equal(b.listEntries().length, 0);
  });

  it("listEntries ignores MEMORY.md (the index)", async () => {
    writeFileSync(
      join(tmpBrainDir, "MEMORY.md"),
      "# Index\n- entry1\n",
    );
    const b = await brain();
    assert.equal(b.listEntries().length, 0);
  });
});

describe("brain — prompt section", () => {
  it("returns empty string when brain is empty", async () => {
    const b = await brain();
    assert.equal(b.buildPromptSection(), "");
  });

  it("includes entries in newest-first order", async () => {
    writeFileSync(
      join(tmpBrainDir, "old.md"),
      "---\nname: old fact\ndescription: stale\ntype: project\ncreated: 2026-01-01T00:00:00Z\nlast_used: 2026-01-01T00:00:00Z\n---\nold body",
    );
    writeFileSync(
      join(tmpBrainDir, "new.md"),
      "---\nname: new fact\ndescription: fresh\ntype: project\ncreated: 2026-06-09T00:00:00Z\nlast_used: 2026-06-09T00:00:00Z\n---\nnew body",
    );
    const b = await brain();
    const section = b.buildPromptSection();
    const oldIdx = section.indexOf("old fact");
    const newIdx = section.indexOf("new fact");
    assert.ok(newIdx >= 0 && oldIdx >= 0);
    assert.ok(newIdx < oldIdx, "newer entries should come first");
  });

  it("respects AGENT_BRAIN_MAX_LOADED cap", async () => {
    for (let i = 0; i < 5; i++) {
      writeFileSync(
        join(tmpBrainDir, `m${i}.md`),
        `---\nname: m${i}\ndescription: d${i}\ntype: project\ncreated: 2026-06-09T00:00:0${i}Z\nlast_used: 2026-06-09T00:00:0${i}Z\n---\nbody-${i}`,
      );
    }
    process.env.AGENT_BRAIN_MAX_LOADED = "2";
    try {
      const b = await brain();
      const section = b.buildPromptSection();
      // m4 is newest, m3 second. m0..m2 should be absent.
      assert.ok(section.includes("m4"));
      assert.ok(section.includes("m3"));
      assert.ok(!section.includes("body-0"));
    } finally {
      delete process.env.AGENT_BRAIN_MAX_LOADED;
    }
  });
});

describe("brain — touch updates last_used", () => {
  it("touchEntry bumps last_used to now", async () => {
    const path = join(tmpBrainDir, "user-thing.md");
    writeFileSync(
      path,
      "---\nname: thing\ndescription: d\ntype: user\ncreated: 2020-01-01T00:00:00Z\nlast_used: 2020-01-01T00:00:00Z\n---\nbody",
    );
    const b = await brain();
    const before = b.listEntries()[0].lastUsed;
    b.touchEntry("user-thing.md");
    const after = b.listEntries()[0].lastUsed;
    assert.notEqual(before, after);
    assert.ok(new Date(after) > new Date(before));
  });

  it("touchEntry is a no-op for missing files", async () => {
    const b = await brain();
    assert.doesNotThrow(() => b.touchEntry("missing.md"));
  });
});

describe("brain — leak defense at load", () => {
  it("skips a memory file containing a known secret pattern", async () => {
    writeFileSync(
      join(tmpBrainDir, "tainted.md"),
      `---\nname: tainted\ndescription: harmless looking\ntype: user\ncreated: 2026-06-09T00:00:00Z\nlast_used: 2026-06-09T00:00:00Z\n---\nour Anthropic key is sk-ant-realsecrettoken1234567890abcdef`,
    );
    writeFileSync(
      join(tmpBrainDir, "clean.md"),
      `---\nname: clean\ndescription: ok\ntype: user\ncreated: 2026-06-09T00:00:00Z\nlast_used: 2026-06-09T00:00:00Z\n---\nuser prefers Postgres`,
    );
    const b = await brain();
    const section = b.buildPromptSection();
    assert.ok(!section.includes("sk-ant-real"), "secret must not leak into prompt");
    assert.ok(section.includes("clean"), "clean memory should still load");
    assert.match(section, /Warning.*tainted\.md/, "human-visible warning should be present");
  });

  it("skips tombstoned (evicted) entries", async () => {
    writeFileSync(
      join(tmpBrainDir, "old.md"),
      `---\nname: old fact\ndescription: [EVICTED] no longer relevant\ntype: project\ncreated: 2026-01-01T00:00:00Z\nlast_used: 2026-06-09T00:00:00Z\n---\n(evicted on 2026-06-09: superseded by new policy)`,
    );
    const b = await brain();
    const section = b.buildPromptSection();
    assert.ok(!section.includes("old fact"), "evicted entry should not be loaded");
  });
});

describe("brain — index rebuild", () => {
  it("rebuildIndex writes MEMORY.md with one line per entry", async () => {
    writeFileSync(
      join(tmpBrainDir, "a.md"),
      "---\nname: A\ndescription: first\ntype: user\ncreated: 2026-06-09T00:00:00Z\nlast_used: 2026-06-09T00:00:00Z\n---\nbody",
    );
    writeFileSync(
      join(tmpBrainDir, "b.md"),
      "---\nname: B\ndescription: second\ntype: project\ncreated: 2026-06-09T00:00:01Z\nlast_used: 2026-06-09T00:00:01Z\n---\nbody",
    );
    const b = await brain();
    b.rebuildIndex();
    const idx = readFileSync(join(tmpBrainDir, "MEMORY.md"), "utf-8");
    assert.match(idx, /\[A\]\(a\.md\)/);
    assert.match(idx, /\[B\]\(b\.md\)/);
  });

  it("rebuildIndex on empty brain writes a placeholder", async () => {
    const b = await brain();
    b.rebuildIndex();
    const idx = readFileSync(join(tmpBrainDir, "MEMORY.md"), "utf-8");
    assert.match(idx, /empty/);
  });
});
