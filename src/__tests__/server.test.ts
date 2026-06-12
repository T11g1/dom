import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";

// Must be set before importing server.ts so isAuthorized has an expected token.
process.env.AGENT_API_TOKEN = "test-api-token-abcdef0123456789";
process.env.AGENT_AUDIT_LOG = "false";

const {
  sanitizeAgentRequest,
  isValidSessionId,
  isAuthorized,
  clientIp,
  checkRateLimit,
  readBody,
  BodyTooLargeError,
  assertStartupConfig,
  _internal,
} = await import("../server.js");

function fakeReq(opts: { headers?: Record<string, string>; remoteAddress?: string } = {}) {
  return {
    headers: opts.headers ?? {},
    socket: { remoteAddress: opts.remoteAddress ?? "127.0.0.1" },
  } as never;
}

describe("server — input validation", () => {
  it("accepts a well-formed request", () => {
    const r = sanitizeAgentRequest({ prompt: "build a todo app", sessionId: "abc-123" });
    assert.equal(r.ok, true);
  });
  it("rejects a missing prompt", () => {
    assert.equal(sanitizeAgentRequest({}).ok, false);
  });
  it("rejects an over-long prompt", () => {
    const r = sanitizeAgentRequest({ prompt: "x".repeat(100_001) });
    assert.equal(r.ok, false);
  });
  it("rejects a bad sessionId charset", () => {
    assert.equal(sanitizeAgentRequest({ prompt: "hi", sessionId: "a/b" }).ok, false);
  });
  it("rejects outputDir traversal", () => {
    assert.equal(sanitizeAgentRequest({ prompt: "hi", outputDir: "../escape" }).ok, false);
  });
});

describe("server — session id validation (security-hardening)", () => {
  it("accepts a clean id", () => {
    assert.equal(isValidSessionId("Abc-123"), true);
  });
  for (const bad of ["../../etc/passwd", "a/b", "..%2f..", "", "a".repeat(129), "a b"]) {
    it(`rejects: ${JSON.stringify(bad)}`, () => {
      assert.equal(isValidSessionId(bad), false);
    });
  }
});

describe("server — startup config fails closed (security-hardening)", () => {
  it("refuses to start without AGENT_API_TOKEN", () => {
    assert.throws(() => assertStartupConfig({ apiToken: undefined }), /AGENT_API_TOKEN/);
  });
  it("accepts a token with no TLS (plain HTTP)", () => {
    assert.doesNotThrow(() => assertStartupConfig({ apiToken: "t" }));
  });
  it("rejects TLS cert without key", () => {
    assert.throws(() => assertStartupConfig({ apiToken: "t", tlsCert: "cert.pem" }), /TLS/);
  });
  it("rejects TLS key without cert", () => {
    assert.throws(() => assertStartupConfig({ apiToken: "t", tlsKey: "key.pem" }), /TLS/);
  });
  it("accepts both cert and key", () => {
    assert.doesNotThrow(() => assertStartupConfig({ apiToken: "t", tlsCert: "cert.pem", tlsKey: "key.pem" }));
  });
});

describe("server — bearer auth", () => {
  it("accepts the correct token", () => {
    assert.equal(isAuthorized(fakeReq({ headers: { authorization: "Bearer test-api-token-abcdef0123456789" } })), true);
  });
  it("rejects a wrong token", () => {
    assert.equal(isAuthorized(fakeReq({ headers: { authorization: "Bearer wrong-token-zzzzzzzzzzzzzzzzz" } })), false);
  });
  it("rejects a missing header", () => {
    assert.equal(isAuthorized(fakeReq()), false);
  });
  it("rejects a non-bearer scheme", () => {
    assert.equal(isAuthorized(fakeReq({ headers: { authorization: "Basic abc" } })), false);
  });
});

describe("server — request body cap (security-hardening)", () => {
  it("resolves a small body", async () => {
    const body = await readBody(Readable.from([Buffer.from("hello")]) as never, 100);
    assert.equal(body, "hello");
  });
  it("rejects a body over the cap with BodyTooLargeError", async () => {
    await assert.rejects(
      () => readBody(Readable.from([Buffer.alloc(500)]) as never, 100),
      (err: unknown) => err instanceof BodyTooLargeError,
    );
  });
});

describe("server — rate limiter (security-hardening)", () => {
  beforeEach(() => _internal.rateBuckets.clear());

  it("allows up to the limit then blocks", () => {
    const ip = "10.0.0.1";
    const limit = Number(process.env.AGENT_RATE_LIMIT) || 10;
    for (let i = 0; i < limit; i++) assert.equal(checkRateLimit(ip), null, `request ${i} should pass`);
    assert.equal(typeof checkRateLimit(ip), "number", "over-limit request should be throttled");
  });

  it("bounds the bucket map so a source-rotating flood can't grow it unbounded", () => {
    _internal.setMaxRateBucketsForTests(5);
    try {
      for (let i = 0; i < 200; i++) checkRateLimit(`flood-${i}`);
      assert.ok(_internal.rateBuckets.size <= 5, `map should stay bounded, was ${_internal.rateBuckets.size}`);
    } finally {
      _internal.setMaxRateBucketsForTests(10_000);
    }
  });

  it("touches the bucket on access so eviction is LRU, not FIFO", () => {
    _internal.rateBuckets.clear();
    checkRateLimit("a"); checkRateLimit("b"); checkRateLimit("c");
    checkRateLimit("a"); // re-access 'a' → should become most-recent
    const order = [..._internal.rateBuckets.keys()];
    assert.equal(order[order.length - 1], "a", "most-recently-accessed key must be last (LRU)");
  });

  it("does not reset an actively-limited client during a source-rotating flood", () => {
    _internal.rateBuckets.clear();
    _internal.setMaxRateBucketsForTests(8);
    try {
      const limit = Number(process.env.AGENT_RATE_LIMIT) || 10;
      for (let i = 0; i < limit; i++) checkRateLimit("victim");
      assert.equal(typeof checkRateLimit("victim"), "number", "victim should be limited");
      // Flood with many distinct IPs; victim keeps sending (stays active).
      // With FIFO eviction the victim's early bucket would be dropped and reset.
      for (let i = 0; i < 60; i++) {
        checkRateLimit(`flood-${i}`);
        assert.equal(typeof checkRateLimit("victim"), "number", "victim must stay limited (not evicted/reset)");
      }
    } finally {
      _internal.setMaxRateBucketsForTests(10_000);
      _internal.rateBuckets.clear();
    }
  });
});

describe("server — client IP source (security-hardening)", () => {
  it("uses the socket address by default (X-Forwarded-For NOT trusted)", () => {
    assert.equal(
      clientIp(fakeReq({ headers: { "x-forwarded-for": "1.1.1.1" }, remoteAddress: "9.9.9.9" })),
      "9.9.9.9",
    );
  });
  it("uses the rightmost X-Forwarded-For hop when proxy is trusted", () => {
    _internal.setTrustProxyForTests(true);
    try {
      assert.equal(
        clientIp(fakeReq({ headers: { "x-forwarded-for": "1.1.1.1, 8.8.8.8" }, remoteAddress: "9.9.9.9" })),
        "8.8.8.8",
      );
    } finally {
      _internal.setTrustProxyForTests(false);
    }
  });
});
