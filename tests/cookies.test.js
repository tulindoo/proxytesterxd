import { test } from "node:test";
import assert from "node:assert/strict";
import { validateSetCookies } from "../src/cookies.js";

test("validateSetCookies keeps valid cookies, drops __Host- without Secure", async () => {
  const valid = await validateSetCookies("https://example.com/", [
    "session=abc; Path=/; Secure; HttpOnly",
    "__Host-token=xyz; Path=/", // missing Secure -> dropped
    "__Secure-token=xyz; Secure; Path=/",
    "bad=1; Domain=com", // public suffix -> dropped by PSL
  ]);
  assert.equal(valid.length, 2);
  assert.ok(valid[0].startsWith("session="));
  assert.ok(valid[1].startsWith("__Secure-token="));
});

test("validateSetCookies drops malformed lines", async () => {
  const valid = await validateSetCookies("https://example.com/", ["", "no-equals-here", "ok=1; Path=/"]);
  assert.equal(valid.length, 1);
});
