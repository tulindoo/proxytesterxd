import { test } from "node:test";
import assert from "node:assert/strict";
import { checkRateLimit, clientIp, resetRateLimits } from "../src/rateLimit.js";

test("clientIp prefers X-Forwarded-For", () => {
  const req = { headers: { "x-forwarded-for": "203.0.113.5, 10.0.0.1" }, socket: { remoteAddress: "10.0.0.1" } };
  assert.equal(clientIp(req), "203.0.113.5");
});

test("rate limit allows up to limit then blocks", () => {
  resetRateLimits();
  const req = { headers: {}, socket: { remoteAddress: "192.0.2.99" } };
  for (let i = 0; i < 5; i++) assert.equal(checkRateLimit(req, { limit: 5, windowMs: 60_000 }).allowed, true);
  const blocked = checkRateLimit(req, { limit: 5, windowMs: 60_000 });
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfter > 0);
});
