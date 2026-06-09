import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  encryptBuffer,
  decryptBuffer,
  isCiphertext,
  _internal,
} from "../session-crypt.js";

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
