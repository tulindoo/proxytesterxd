import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

// Optional server-side cookie store (multi-device sync).
// Enabled with PROXY_SERVER_STORE=1. Encrypted at rest with AES-256-GCM;
// key derived from PROXY_PASSWORD. On Render the file is ephemeral —
// the SW IndexedDB jar remains the primary store.

const enabled = process.env.PROXY_SERVER_STORE === "1";
const storeFile = process.env.PROXY_STORE_FILE || "";

function key() {
  return createHash("sha256").update((process.env.PROXY_PASSWORD || "") + ":proxy-session-store-v1").digest();
}

// origin -> Map<id, cookie>
const mem = new Map();

function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return JSON.stringify({ iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ct: ct.toString("base64") });
}

function decrypt(payload) {
  const { iv, tag, ct } = JSON.parse(payload);
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ct, "base64")), decipher.final()]).toString("utf8");
}

function load() {
  if (!enabled || !storeFile) return;
  try {
    const raw = readFileSync(storeFile, "utf8");
    const data = JSON.parse(decrypt(raw));
    for (const [origin, cookies] of Object.entries(data)) {
      mem.set(origin, new Map(Object.entries(cookies)));
    }
  } catch { /* no file yet or corrupt: start empty */ }
}

function save() {
  if (!enabled || !storeFile) return;
  try {
    const data = {};
    for (const [origin, cookies] of mem) data[origin] = Object.fromEntries(cookies);
    writeFileSync(storeFile, encrypt(JSON.stringify(data)));
  } catch { /* ephemeral FS: ignore */ }
}

load();

function parseSetCookie(line, host) {
  const parts = line.split(";");
  const first = parts.shift();
  const eq = first.indexOf("=");
  if (eq < 1) return null;
  const cookie = {
    name: first.slice(0, eq).trim(),
    value: first.slice(eq + 1).trim(),
    domain: host,
    hostOnly: true,
    path: "/",
    secure: false,
    sameSite: "Lax",
    partitioned: false,
    expires: Date.now() + 30 * 86400000,
  };
  let maxAge = null;
  let expiresAt = null;
  for (const part of parts) {
    const i = part.indexOf("=");
    const k = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? "" : part.slice(i + 1).trim();
    if (k === "domain" && v) {
      const domain = v.replace(/^\./, "").toLowerCase();
      if (domain.includes(".") && (host === domain || host.endsWith("." + domain))) {
        cookie.domain = domain;
        cookie.hostOnly = false;
      }
    } else if (k === "path" && v.startsWith("/")) cookie.path = v;
    else if (k === "secure") cookie.secure = true;
    else if (k === "samesite") cookie.sameSite = ["lax", "strict", "none"].includes(v.toLowerCase()) ? v : "Lax";
    else if (k === "partitioned") cookie.partitioned = true;
    else if (k === "max-age") { const n = parseInt(v, 10); if (!Number.isNaN(n)) maxAge = n; }
    else if (k === "expires") { const t = Date.parse(v); if (!Number.isNaN(t)) expiresAt = t; }
  }
  if (maxAge !== null) cookie.expires = Date.now() + maxAge * 1000;
  else if (expiresAt !== null) cookie.expires = expiresAt;
  // __Host- / __Secure- enforcement (mirror of server validation).
  if (cookie.name.startsWith("__Host-") && (!cookie.secure || !cookie.hostOnly || cookie.path !== "/")) return null;
  if (cookie.name.startsWith("__Secure-") && !cookie.secure) return null;
  // Partitioned requires Secure.
  if (cookie.partitioned && !cookie.secure) return null;
  cookie.id = cookie.domain + "|" + cookie.path + "|" + cookie.name;
  return cookie;
}

function matches(cookie, url) {
  const host = url.hostname;
  const hostOk = cookie.hostOnly ? host === cookie.domain : host === cookie.domain || host.endsWith("." + cookie.domain);
  if (!hostOk || cookie.expires <= Date.now()) return false;
  if (cookie.secure && url.protocol !== "https:") return false;
  const path = url.pathname;
  return path === cookie.path || (path.startsWith(cookie.path) && (cookie.path.endsWith("/") || path[cookie.path.length] === "/"));
}

export function isStoreEnabled() { return enabled; }

export function getCookieHeader(target) {
  if (!enabled) return "";
  const cookies = mem.get(target.origin);
  if (!cookies) return "";
  const list = [...cookies.values()].filter((c) => matches(c, target));
  list.sort((a, b) => b.path.length - a.path.length);
  return list.map((c) => c.name + "=" + c.value).join("; ");
}

export function storeSetCookies(target, lines) {
  if (!enabled) return;
  let jar = mem.get(target.origin);
  if (!jar) { jar = new Map(); mem.set(target.origin, jar); }
  for (const line of lines || []) {
    const cookie = parseSetCookie(line, target.hostname);
    if (!cookie) continue;
    if (cookie.expires <= Date.now()) jar.delete(cookie.id);
    else jar.set(cookie.id, cookie);
  }
  save();
}

export function clearSite(origin) {
  if (!enabled) return;
  mem.delete(origin);
  save();
}

export function clearAll() {
  if (!enabled) return;
  mem.clear();
  save();
}

export function stats() {
  let cookies = 0;
  for (const jar of mem.values()) cookies += jar.size;
  return { cookies, sites: mem.size, enabled };
}
