import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrivate, checkTarget } from "../src/security.js";
import { ProxyError } from "../src/errors.js";

test("isPrivate blocks IPv4 private/reserved ranges", () => {
  const blocked = [
    "0.0.0.0", "0.1.2.3",
    "10.0.0.1", "10.255.255.255",
    "127.0.0.1", "127.0.0.53",
    "169.254.1.1",
    "172.16.0.1", "172.31.255.255",
    "192.168.1.1",
    "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.19.255.255",
    "198.51.100.1", "203.0.113.1",
    "100.64.0.1", "100.127.255.255",
    "224.0.0.1", "240.0.0.1", "255.255.255.255",
  ];
  for (const ip of blocked) assert.equal(isPrivate(ip), true, ip);
});

test("isPrivate allows public IPv4", () => {
  for (const ip of ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "100.128.0.1"]) {
    assert.equal(isPrivate(ip), false, ip);
  }
});

test("isPrivate blocks IPv6 private/reserved incl. fe80::/10 and mapped", () => {
  const blocked = ["::1", "::", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:0a00:0001",
    "0:0:0:0:0:ffff:7f00:1", "fc00::1", "fd00::1", "fe80::1", "fe90::1", "fea0::1", "febf::1", "fec0::1", "ff02::1", "2001:db8::1", "2001:2::1", "2001:0::1", "2002:7f00:1::1", "64:ff9b::7f00:1", "0:0:0:0:0:0:0:1"];
  for (const ip of blocked) assert.equal(isPrivate(ip), true, ip);
  for (const ip of ["2606:4700:4700::1111", "2001:4860:4860::8888"]) {
    assert.equal(isPrivate(ip), false, ip);
  }
});

test("checkTarget rejects bad protocol, private literal, self, bad port", () => {
  const req = { headers: { host: "proxy.example.com" } };
  assert.throws(() => checkTarget(new URL("ftp://example.com/"), req), (e) => e instanceof ProxyError && e.proxyCode === "bad_url");
  assert.throws(() => checkTarget(new URL("http://127.0.0.1/"), req), (e) => e.proxyCode === "blocked");
  assert.throws(() => checkTarget(new URL("http://proxy.example.com/"), req), (e) => e.proxyCode === "blocked");
  assert.throws(() => checkTarget(new URL("http://example.com:22/"), req), (e) => e.proxyCode === "blocked");
  // allowed
  checkTarget(new URL("https://example.com/"), req);
  checkTarget(new URL("http://example.com:8080/"), req);
});
