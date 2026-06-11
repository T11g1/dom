import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  encryptBuffer,
  decryptBuffer,
  isCiphertext,
  readSessionFile,
  _internal,
} from "../session-crypt.js";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// session-crypt derives its key from AGENT_API_TOKEN.
process.env.AGENT_API_TOKEN = process.env.AGENT_API_TOKEN || "test-token-1234567890abcdef";

describe("session-crypt", () => {
  it("encrypt → decrypt round-trips a buffer", () => {
    const plaintext = Buffer.from('{"prompt":"build me a thing","extra":true}\n');
    const blob = encryptBuffer(plaintext);
    assert.ok(isCiphertext(blob));
    const out = decryptBuffer(blob);
    assert.equal(out.toString(), plaintext.toString());
  });

  it("isCiphertext is false for plaintext", () => {
    assert.equal(isCiphertext(Buffer.from("hello")), false);
  });

  it("a wrong key fails the GCM auth check", () => {
    const plaintext = Buffer.from("important");
    const blob = encryptBuffer(plaintext);
    const orig = process.env.AGENT_API_TOKEN;
    process.env.AGENT_API_TOKEN = "different-token-with-enough-length";
    try {
      assert.throws(() => decryptBuffer(blob));
    } finally {
      process.env.AGENT_API_TOKEN = orig;
    }
  });

  it("two encryptions of the same plaintext produce different blobs (random salt+iv)", () => {
    const a = encryptBuffer(Buffer.from("x"));
    const b = encryptBuffer(Buffer.from("x"));
    assert.notEqual(a.toString("hex"), b.toString("hex"));
  });

  it("magic header is the documented length", () => {
    assert.equal(_internal.MAGIC_LEN, _internal.MAGIC.length);
  });
});

describe("session-crypt — HKDF domain separation (security-hardening)", () => {
  it("new ciphertext uses the DOMENC2 magic", () => {
    const blob = encryptBuffer(Buffer.from("hi"));
    assert.ok(blob.subarray(0, _internal.MAGIC_LEN).equals(_internal.MAGIC_V2));
  });

  it("the derived key is NOT the raw PBKDF2 of the token (domain separated)", () => {
    // A v2 ciphertext must not be decryptable with the legacy v1 derivation.
    const blob = encryptBuffer(Buffer.from("secret-payload"));
    // Re-tag as a v1 blob without changing salt/iv/tag/ct; v1 derivation must fail.
    const forgedV1 = Buffer.concat([_internal.MAGIC, blob.subarray(_internal.MAGIC_LEN)]);
    assert.throws(() => decryptBuffer(forgedV1), "v1 derivation must not decrypt a v2 blob");
  });

  it("still decrypts legacy DOMENC1 (v1) ciphertext for backward compatibility", () => {
    const plaintext = Buffer.from('{"legacy":true}');
    const v1 = _internal.encryptLegacyV1(plaintext);
    assert.ok(v1.subarray(0, _internal.MAGIC_LEN).equals(_internal.MAGIC));
    assert.equal(decryptBuffer(v1).toString(), plaintext.toString());
  });
});

describe("session-crypt — plaintext-downgrade fail-closed (security-hardening)", () => {
  it("rejects plaintext even when the seal marker is missing/deleted", () => {
    const prevDir = process.env.CLAUDE_CONFIG_DIR;
    const prevEnc = process.env.AGENT_SESSION_ENCRYPT;
    const prevMig = process.env.AGENT_SESSION_ENCRYPT_MIGRATE;
    const dir = mkdtempSync(join(tmpdir(), "dom-crypt-nomarker-"));
    process.env.CLAUDE_CONFIG_DIR = dir;
    process.env.AGENT_SESSION_ENCRYPT = "true";
    delete process.env.AGENT_SESSION_ENCRYPT_MIGRATE; // not migrating
    try {
      mkdirSync(join(dir, "projects"), { recursive: true });
      // Seal, then DELETE the marker — an attacker can remove it.
      _internal.writeSealMarker();
      unlinkSync(join(dir, ".dom-enc-marker"));
      assert.equal(_internal.sealMarkerValid(), false, "marker should be gone");
      const victim = join(dir, "projects", "session.json");
      writeFileSync(victim, '{"prompt":"forged"}');
      assert.throws(
        () => readSessionFile(victim),
        /downgrade|tamper|plaintext/i,
        "plaintext must be rejected regardless of the (deletable) marker",
      );
    } finally {
      if (prevDir === undefined) delete process.env.CLAUDE_CONFIG_DIR; else process.env.CLAUDE_CONFIG_DIR = prevDir;
      if (prevEnc === undefined) delete process.env.AGENT_SESSION_ENCRYPT; else process.env.AGENT_SESSION_ENCRYPT = prevEnc;
      if (prevMig === undefined) delete process.env.AGENT_SESSION_ENCRYPT_MIGRATE; else process.env.AGENT_SESSION_ENCRYPT_MIGRATE = prevMig;
    }
  });

  it("readSessionFile throws on plaintext under a valid seal marker", () => {
    const prevDir = process.env.CLAUDE_CONFIG_DIR;
    const prevEnc = process.env.AGENT_SESSION_ENCRYPT;
    const dir = mkdtempSync(join(tmpdir(), "dom-crypt-test-"));
    process.env.CLAUDE_CONFIG_DIR = dir;
    process.env.AGENT_SESSION_ENCRYPT = "true";
    try {
      mkdirSync(join(dir, "projects"), { recursive: true });
      // Seal the directory (writes the HMAC marker).
      _internal.writeSealMarker();
      assert.ok(_internal.sealMarkerValid(), "marker should validate");
      // Attacker swaps an encrypted file for chosen plaintext.
      const victim = join(dir, "projects", "session.json");
      writeFileSync(victim, '{"prompt":"forged by attacker"}');
      assert.throws(
        () => readSessionFile(victim),
        /downgrade|tamper|plaintext/i,
        "must refuse to read plaintext under a valid seal",
      );
    } finally {
      if (prevDir === undefined) delete process.env.CLAUDE_CONFIG_DIR; else process.env.CLAUDE_CONFIG_DIR = prevDir;
      if (prevEnc === undefined) delete process.env.AGENT_SESSION_ENCRYPT; else process.env.AGENT_SESSION_ENCRYPT = prevEnc;
    }
  });
});

describe("session-crypt — active-run refcount defers re-encryption (security-hardening)", () => {
  it("does not re-encrypt while a concurrent run is still active", () => {
    const prevDir = process.env.CLAUDE_CONFIG_DIR;
    const prevEnc = process.env.AGENT_SESSION_ENCRYPT;
    const prevMig = process.env.AGENT_SESSION_ENCRYPT_MIGRATE;
    const dir = mkdtempSync(join(tmpdir(), "dom-crypt-rc-"));
    process.env.CLAUDE_CONFIG_DIR = dir;
    process.env.AGENT_SESSION_ENCRYPT = "true";
    process.env.AGENT_SESSION_ENCRYPT_MIGRATE = "true"; // first-seal of a plaintext dir
    try {
      const projects = join(dir, "projects");
      mkdirSync(projects, { recursive: true });
      const f = join(projects, "s.json");
      writeFileSync(f, '{"a":1}');

      _internal.resetActiveRunsForTests();
      _internal.beginActiveRun(); // run A: decrypts (no-op, already plaintext), count=1
      _internal.beginActiveRun(); // run B: count=2
      _internal.endActiveRun();   // run A ends, B still active → must NOT encrypt
      assert.equal(isCiphertext(readFileSync(f)), false, "file must stay plaintext while B active");
      _internal.endActiveRun();   // run B ends, count=0 → encrypt now
      assert.equal(isCiphertext(readFileSync(f)), true, "file must be sealed once all runs end");
    } finally {
      _internal.resetActiveRunsForTests();
      if (prevDir === undefined) delete process.env.CLAUDE_CONFIG_DIR; else process.env.CLAUDE_CONFIG_DIR = prevDir;
      if (prevEnc === undefined) delete process.env.AGENT_SESSION_ENCRYPT; else process.env.AGENT_SESSION_ENCRYPT = prevEnc;
      if (prevMig === undefined) delete process.env.AGENT_SESSION_ENCRYPT_MIGRATE; else process.env.AGENT_SESSION_ENCRYPT_MIGRATE = prevMig;
    }
  });

  it("re-encrypts even when the run throws mid-stream (endActiveRun in finally)", async () => {
    const prevDir = process.env.CLAUDE_CONFIG_DIR;
    const prevEnc = process.env.AGENT_SESSION_ENCRYPT;
    const dir = mkdtempSync(join(tmpdir(), "dom-crypt-throw-"));
    process.env.CLAUDE_CONFIG_DIR = dir;
    process.env.AGENT_SESSION_ENCRYPT = "true";
    delete process.env.AGENT_SESSION_ENCRYPT_MIGRATE;
    try {
      const projects = join(dir, "projects");
      mkdirSync(projects, { recursive: true });
      const f = join(projects, "s.json");
      writeFileSync(f, '{"a":1}');
      // Start sealed (ciphertext at rest), like steady state.
      _internal.resetActiveRunsForTests();
      const { encryptSessionsNow } = await import("../session-crypt.js");
      encryptSessionsNow();
      assert.equal(isCiphertext(readFileSync(f)), true, "precondition: sealed");

      // Mirror agent.ts's wrapped(): beginActiveRun, then a finally that calls
      // endActiveRun even when the body throws.
      async function* run() {
        _internal.beginActiveRun(); // decrypts → plaintext
        try {
          yield 1;
          throw new Error("boom mid-run");
        } finally {
          _internal.endActiveRun(); // must re-seal despite the throw
        }
      }
      const g = run();
      await g.next();
      assert.equal(isCiphertext(readFileSync(f)), false, "decrypted while run active");
      await assert.rejects(() => g.next(), /boom mid-run/);
      assert.equal(isCiphertext(readFileSync(f)), true, "re-sealed by endActiveRun in finally after the throw");
    } finally {
      _internal.resetActiveRunsForTests();
      if (prevDir === undefined) delete process.env.CLAUDE_CONFIG_DIR; else process.env.CLAUDE_CONFIG_DIR = prevDir;
      if (prevEnc === undefined) delete process.env.AGENT_SESSION_ENCRYPT; else process.env.AGENT_SESSION_ENCRYPT = prevEnc;
    }
  });
});
