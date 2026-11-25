import { test } from "node:test";
import assert from "node:assert/strict";

process.env.PROXY_SERVER_STORE = "1";
const { getCookieHeader, storeSetCookies, clearSite, clearAll, stats, isStoreEnabled } = await import("../src/sessionStore.js");

test("server cookie store is opt-in and isolates target origins", () => {
  assert.equal(isStoreEnabled(), true);
  const a = new URL("https://alpha.example/account");
  const b = new URL("https://beta.example/account");
  storeSetCookies(a, ["sid=alpha; Path=/; Secure; HttpOnly; SameSite=Lax"]);
  storeSetCookies(b, ["sid=beta; Path=/; Secure"]);
  assert.equal(getCookieHeader(a), "sid=alpha");
  assert.equal(getCookieHeader(b), "sid=beta");
  assert.equal(stats().sites, 2);
});

test("cookie matching respects path, Secure, and deletion", () => {
  clearAll();
  const target = new URL("https://example.test/private/page");
  storeSetCookies(target, [
    "root=1; Path=/; Secure",
    "scoped=2; Path=/private; Secure",
    "plain=3; Path=/private",
    "gone=4; Path=/; Max-Age=0",
    "__Host-invalid=5; Path=/private; Secure",
    "__Secure-invalid=6; Path=/;",
    "partitioned-invalid=7; Path=/; Partitioned",
  ]);
  assert.equal(getCookieHeader(target), "scoped=2; plain=3; root=1");
  const httpTarget = new URL("http://example.test/private/page");
  assert.equal(getCookieHeader(httpTarget), ""); // distinct origin jar
  storeSetCookies(httpTarget, ["http-only=8; Path=/private"]);
  assert.equal(getCookieHeader(httpTarget), "http-only=8");
});

test("clearSite only clears that site's jar", () => {
  clearAll();
  const a = new URL("https://a.example/");
  const b = new URL("https://b.example/");
  storeSetCookies(a, ["sid=a; Secure"]);
  storeSetCookies(b, ["sid=b; Secure"]);
  clearSite(a.origin);
  assert.equal(getCookieHeader(a), "");
  assert.equal(getCookieHeader(b), "sid=b");
  clearAll();
});
