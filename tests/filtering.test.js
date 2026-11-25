import { test } from "node:test";
import assert from "node:assert/strict";

process.env.PROXY_FILTER_LAB = "1";
process.env.PROXY_FILTER_BLOCK = "blocked.example, test.internal ";
const { filterDecision, filterStats } = await import("../src/filtering.js");

test("controlled filter lab blocks only exact configured hostnames", () => {
  assert.equal(filterDecision(new URL("https://blocked.example/a")).blocked, true);
  assert.equal(filterDecision(new URL("https://sub.blocked.example/a")).blocked, false);
  assert.equal(filterDecision(new URL("https://allowed.example/")).blocked, false);
  assert.equal(filterStats().blocks, 1);
  assert.deepEqual(filterStats().rules, ["blocked.example", "test.internal"]);
});
