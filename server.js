import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";
import { promisify } from "node:util";
import { pipeline } from "node:stream";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { ProxyError, ERRORS, classifyError } from "./src/errors.js";
import { guardedLookup, checkTarget } from "./src/security.js";
import { checkRateLimit } from "./src/rateLimit.js";
import { validateSetCookies } from "./src/cookies.js";
import { rewriteDash, rewritePlaylist, classifyMedia, applyDashMarkers } from "./src/media.js";
import { filterDecision, filterStats } from "./src/filtering.js";
import { isStoreEnabled, getCookieHeader, storeSetCookies, clearSite, clearAll, stats as storeStats } from "./src/sessionStore.js";

const PASSWORD = process.env.PROXY_PASSWORD;
if (!PASSWORD) {
  console.error("Set the PROXY_PASSWORD environment variable before starting.");
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const PREFIX = "/service/";
const MAX_REWRITE_BYTES = 20 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 30_000;
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;

const gunzip = promisify(zlib.gunzip);
const brotli = promisify(zlib.brotliDecompress);
const inflate = promisify(zlib.inflate);
const gzip = promisify(zlib.gzip);

/* ==========================================================================
   1. Shared code
   These functions run in four places: this server, the service worker, the
   script injected into proxied pages, and the home page. They are copied into
   each as source text, so they must not use anything from this file except
   PREFIX (which each copy defines for itself).
   ========================================================================== */

// A proxied address looks like /service/<base64url of origin+path>?<real query>#<real hash>.
// The query stays outside the token so location.search on a proxied page is the site's real query.
function encodeTarget(url) {
  return btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeTarget(token) {
  const url = atob(token.replace(/-/g, "+").replace(/_/g, "/"));
  if (!/^https?:\/\//i.test(url)) throw new Error("not a web address");
  return url;
}

function isProxiedPath(pathname) {
  if (!pathname.startsWith(PREFIX)) return false;
  try {
    decodeTarget(pathname.slice(PREFIX.length));
    return true;
  } catch {
    return false; // a real site path that only happens to start with /service/
  }
}

// Turns any URL found in a page into a proxied path. Returns null when the value
// should be left alone (anchors, data: URLs, already-proxied paths, ...).
function proxify(value, base, selfOrigin) {
  const raw = String(value).trim();
  if (!raw || /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(raw)) return null;
  let url;
  try {
    url = new URL(raw, base);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (selfOrigin && url.origin === selfOrigin) return null;
  if (isProxiedPath(raw.split(/[?#]/)[0])) return null;
  return PREFIX + encodeTarget(url.origin + url.pathname) + url.search + url.hash;
}

// Works out which real URL a request on this server is for. A request that is not
// a proxied path is treated as a path on the site of the page that made it.
function targetFromPath(pathname, search, contextBase) {
  if (isProxiedPath(pathname)) {
    const url = new URL(decodeTarget(pathname.slice(PREFIX.length)));
    return applyDashMarkers(url, search);
  }
  return contextBase ? new URL(pathname + search, contextBase) : null;
}

function renderErrorPage(info) {
  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const fixes = (info.fixes || []).map((f) => "<li>" + esc(f) + "</li>").join("");
  const retry = info.retry
    ? "<p id=retry>Retrying automatically.</p><script>var n=+sessionStorage.getItem('proxy-retry')||0;" +
      "if(n<8){sessionStorage.setItem('proxy-retry',n+1);setTimeout(function(){location.reload()},8000)}" +
      "else{document.getElementById('retry').textContent='Stopped retrying. Reload when you are ready.'}<\/script>"
    : "";
  return (
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>" +
    "<title>" + esc(info.title) + "</title><style>" +
    ":root{color-scheme:light dark;--bg:#fafafa;--fg:#17191c;--mut:#626a75;--card:#fff;--line:#e3e6ea;--acc:#c2410c}" +
    "@media(prefers-color-scheme:dark){:root{--bg:#0f1114;--fg:#e9ebee;--mut:#98a1ad;--card:#171a1e;--line:#262b31;--acc:#fb923c}}" +
    "body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}" +
    "main{max-width:34rem;margin:12vh auto;padding:0 1.25rem}svg{width:2rem;height:2rem;color:var(--acc)}" +
    "h1{font-size:1.4rem;margin:.5rem 0}p,li{color:var(--mut)}a{color:var(--acc)}" +
    "details{margin-top:1.5rem;background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:.7rem 1rem}" +
    "pre{white-space:pre-wrap;word-break:break-word;margin:.5rem 0 0;font-size:.85rem}</style>" +
    "<main><svg viewBox='0 0 24 24' fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round>" +
    "<path d='M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z'/><path d='M12 9v4M12 17h.01'/></svg>" +
    "<h1>" + esc(info.title) + "</h1><p>" + esc(info.what) + "</p>" +
    (fixes ? "<ul>" + fixes + "</ul>" : "") + retry +
    "<p><a href='/'>Back to the home page</a></p>" +
    "<details><summary>Technical details</summary><pre>" + esc(info.detail || "") + "</pre></details></main>"
  );
}

const sharedSource = [encodeTarget, decodeTarget, isProxiedPath, proxify, applyDashMarkers, targetFromPath]
  .map(String)
  .join("\n");
const preamble = `const PREFIX = ${JSON.stringify(PREFIX)};\n${sharedSource}\n`;

/* ==========================================================================
   2. Errors (ProxyError/ERRORS/classifyError live in src/errors.js)
   ========================================================================== */

function sendError(res, wantsPage, code, err) {
  const [status, title, what, fixes] = ERRORS[code] || ERRORS.unknown;
  const detail = `${code}: ${err.message}`;
  console.error("Proxy request failed:", detail);
  const headers = { "x-proxy-error": code, "cache-control": "no-store", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" };
  if (wantsPage) {
    res.writeHead(status, { ...headers, "content-type": "text/html; charset=utf-8" });
    res.end(renderErrorPage({ title, what, fixes, detail }));
  } else {
    res.writeHead(status, { ...headers, "content-type": "text/plain; charset=utf-8" });
    res.end(`${title}. ${what}`);
  }
}

/* ==========================================================================
   3. Network safety: refuse private addresses (src/security.js)
   ========================================================================== */

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64, lookup: guardedLookup });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64, lookup: guardedLookup });

/* ==========================================================================
   4. Login session
   ========================================================================== */

const digest = (value) => createHash("sha256").update(value).digest();
const passwordMatches = (given) => timingSafeEqual(digest(given), digest(PASSWORD));
const sign = (expires) => createHmac("sha256", PASSWORD).update("session:" + expires).digest("hex");

function readCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function isAuthed(req) {
  const token = readCookie(req, "proxy_session");
  if (!token) return false;
  const [expires, mac] = token.split(".");
  if (!expires || !mac || Number(expires) < Date.now()) return false;
  const expected = sign(expires);
  return mac.length === expected.length && timingSafeEqual(Buffer.from(mac), Buffer.from(expected));
}

function sessionCookie(req) {
  const expires = Date.now() + SESSION_MS;
  const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  return `proxy_session=${expires}.${sign(expires)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MS / 1000}${secure}`;
}

// Global, not per-IP: the forwarded-for header can be spoofed, and only one person uses this.
let failedLogins = [];
function loginLocked() {
  const cutoff = Date.now() - 10 * 60 * 1000;
  failedLogins = failedLogins.filter((time) => time > cutoff);
  return failedLogins.length >= 10;
}

const safeNext = (value) =>
  typeof value === "string" && value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\") ? value : "/";

function readSmallBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 4096) {
        req.destroy();
        reject(new Error("body too large"));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

/* ==========================================================================
   5. Rewriting HTML, CSS and HLS playlists
   ========================================================================== */

const resolveUrl = (value, base) => {
  try {
    return new URL(value.trim().replace(/&amp;/g, "&"), base);
  } catch {
    return null;
  }
};

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (match, quote, value) => {
      const out = proxify(value, base);
      return out === null ? match : `url(${quote}${out}${quote})`;
    })
    .replace(/@import\s+(["'])(.*?)\1/gi, (match, quote, value) => {
      const out = proxify(value, base);
      return out === null ? match : `@import ${quote}${out}${quote}`;
    });
}

const ATTRIBUTE = /(\s)(href|src|poster|action|formaction|data)=("[^"]*"|'[^']*')/gi;
const SRCSET = /(\s)srcset=("[^"]*"|'[^']*')/gi;
const RUNTIME_TAG = '<script src="/runtime.js"></script>';

function rewriteHtml(html, target, status) {
  const baseTag = /<base\b[^>]*?\bhref=(["'])(.*?)\1[^>]*>/i.exec(html);
  const base = ((baseTag && resolveUrl(baseTag[2], target.href)) || target).href;
  const attr = (value) => escapeHtml(value).replace(/&amp;amp;/g, "&amp;");

  let out = html
    .replace(/<base\b[^>]*>/gi, "")
    .replace(/(\s)integrity=("[^"]*"|'[^']*')/gi, "$1") // rewriting changes bytes, so the hash would never match
    .replace(ATTRIBUTE, (match, space, name, quoted) => {
      const proxied = proxify(quoted.slice(1, -1).replace(/&amp;/g, "&"), base);
      return proxied === null ? match : `${space}${name}=${quoted[0]}${attr(proxied)}${quoted[0]}`;
    })
    .replace(SRCSET, (match, space, quoted) => {
      const list = quoted
        .slice(1, -1)
        .split(/,\s+/)
        .map((part) => {
          const [url, ...descriptor] = part.trim().split(/\s+/);
          const proxied = proxify(url.replace(/&amp;/g, "&"), base);
          return [proxied === null ? url : attr(proxied), ...descriptor].join(" ");
        })
        .join(", ");
      return `${space}srcset=${quoted[0]}${list}${quoted[0]}`;
    })
    .replace(/(\sstyle=)("[^"]*"|'[^']*')/gi, (match, prefix, quoted) =>
      quoted.includes("url(") ? prefix + quoted[0] + rewriteCss(quoted.slice(1, -1), base) + quoted[0] : match)
    .replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (match, open, css, close) => open + rewriteCss(css, base) + close)
    .replace(/(<meta\b[^>]*http-equiv=["']?refresh["']?[^>]*\scontent=)(["'])(.*?)\2/gi, (match, prefix, quote, content) =>
      prefix + quote + content.replace(/(url\s*=\s*)(.+)$/i, (m, key, value) => key + (proxify(value.trim(), base) ?? value)) + quote);

  if ([403, 429, 503].includes(status)) {
    const banner =
      '<div style="position:fixed;z-index:2147483647;left:12px;right:12px;bottom:12px;padding:10px 14px;border-radius:8px;' +
      'background:#1b1e23;color:#fff;font:14px/1.4 system-ui,sans-serif;box-shadow:0 2px 12px #0006">' +
      `The site answered with HTTP ${status}. If you see a captcha or "access denied", the site is probably rejecting ` +
      "this proxy's server address, not the proxy code. " +
      '<button onclick="this.parentNode.remove()" style="margin-left:8px">Dismiss</button></div>';
    out = /<body\b[^>]*>/i.test(out) ? out.replace(/<body\b[^>]*>/i, (m) => m + banner) : banner + out;
  }

  if (/<head\b[^>]*>/i.test(out)) return out.replace(/<head\b[^>]*>/i, (m) => m + RUNTIME_TAG);
  if (/<html\b[^>]*>/i.test(out)) return out.replace(/<html\b[^>]*>/i, (m) => m + RUNTIME_TAG);
  return RUNTIME_TAG + out;
}

function classify(contentType, pathname) {
  if (/text\/html|application\/xhtml\+xml/i.test(contentType)) return "html";
  if (/text\/css/i.test(contentType)) return "css";
  const media = classifyMedia(contentType, pathname);
  if (media === "hls") return "playlist";
  if (media === "dash") return "dash";
  return null;
}

function decodeText(buffer, contentType) {
  let charset = /charset=["']?([\w-]+)/i.exec(contentType)?.[1];
  if (!charset) charset = /<meta[^>]+charset=["']?([\w-]+)/i.exec(buffer.subarray(0, 2048).toString("latin1"))?.[1];
  try {
    return new TextDecoder(charset || "utf-8").decode(buffer);
  } catch {
    return buffer.toString("utf8"); // unknown charset label
  }
}

async function readLimited(stream, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) {
      stream.destroy();
      throw new ProxyError("too_large", `response is larger than ${limit} bytes`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function decompress(buffer, encoding) {
  const options = { maxOutputLength: MAX_REWRITE_BYTES };
  if (!encoding || encoding === "identity") return buffer;
  if (encoding === "gzip" || encoding === "x-gzip") return gunzip(buffer, options);
  if (encoding === "br") return brotli(buffer, options);
  if (encoding === "deflate") return inflate(buffer, options);
  throw new ProxyError("encoding", encoding);
}

/* ==========================================================================
   6. Proxying a request
   ========================================================================== */

const entries = [];
let active = 0;
const startedAt = Date.now();

function record(entry) {
  entries.push(entry);
  if (entries.length > 150) entries.shift();
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const PASS_RESPONSE = [
  "content-type", "content-length", "content-range", "accept-ranges", "content-encoding",
  "cache-control", "etag", "last-modified", "expires", "content-disposition", "content-language",
];
const BLOCKED_REQUEST = new Set([
  "host", "connection", "content-length", "accept-encoding", "cookie", "origin", "referer", "user-agent",
  "transfer-encoding", "upgrade", "te", "keep-alive", "proxy-authorization", "proxy-connection",
]);

function mergeCookies(a, b) {
  const map = new Map();
  for (const part of (a || "").split(";")) {
    const t = part.trim();
    if (!t) continue;
    const eq = t.indexOf("=");
    if (eq > 0) map.set(t.slice(0, eq).trim(), t);
  }
  for (const part of (b || "").split(";")) {
    const t = part.trim();
    if (!t) continue;
    const eq = t.indexOf("=");
    if (eq > 0) map.set(t.slice(0, eq).trim(), t);
  }
  return [...map.values()].join("; ");
}

function buildUpstreamHeaders(req, target) {
  let fromPage = {};
  try {
    fromPage = JSON.parse(decodeURIComponent(req.headers["x-proxy-headers"] || "{}"));
  } catch {
    // malformed: continue without the page's own headers
  }
  const headers = {
    "user-agent": req.headers["user-agent"] || "Mozilla/5.0",
    "accept-language": req.headers["accept-language"] || "en-US,en;q=0.9",
    accept: "*/*",
    // Only encodings this server can decode when it has to rewrite the body.
    "accept-encoding": "gzip, br",
  };
  for (const [name, value] of Object.entries(fromPage)) {
    const key = name.toLowerCase();
    if (!BLOCKED_REQUEST.has(key) && !key.startsWith("x-proxy-") && !key.startsWith("sec-")) headers[key] = String(value);
  }
  // Cookie merge: SW jar (per-browser) + optional server store (multi-device).
  // Server store wins on name conflicts (it reflects the latest Set-Cookie).
  const swCookie = req.headers["x-proxy-cookie"] || "";
  const serverCookie = isStoreEnabled() ? getCookieHeader(target) : "";
  const merged = mergeCookies(swCookie, serverCookie);
  if (merged) headers.cookie = merged;

  const writes = req.method !== "GET" && req.method !== "HEAD";
  let referer = null;
  try {
    referer = new URL(req.headers["x-proxy-referer"]);
  } catch {
    // no referer known
  }
  if (referer) {
    headers.referer = referer.origin === target.origin ? referer.href : referer.origin + "/";
    if (writes) headers.origin = referer.origin;
  } else if (writes) {
    headers.origin = target.origin;
  }
  if (req.headers["content-length"]) headers["content-length"] = req.headers["content-length"];
  return headers;
}

function requestUpstream(req, res, target, headers) {
  return new Promise((resolve, reject) => {
    const secure = target.protocol === "https:";
    const upstreamReq = (secure ? https : http).request(
      target,
      { method: req.method, headers, agent: secure ? httpsAgent : httpAgent, timeout: UPSTREAM_TIMEOUT_MS },
      resolve,
    );
    upstreamReq.on("timeout", () => upstreamReq.destroy(new ProxyError("timeout", "no response from the site")));
    upstreamReq.on("error", reject);
    // The browser cancels requests when you seek or leave a page; stop downloading for it.
    res.on("close", () => {
      if (!res.writableFinished) upstreamReq.destroy();
    });
    if (req.method === "GET" || req.method === "HEAD") upstreamReq.end();
    else req.pipe(upstreamReq);
  });
}

async function handleService(req, res, url) {
  const started = Date.now();
  const entry = { time: new Date().toISOString(), method: req.method, target: "?", status: 0, ms: 0, note: "" };
  const maxActive = Math.max(8, Number(process.env.PROXY_MAX_ACTIVE) || 64);
  if (active >= maxActive) {
    res.writeHead(503, { "retry-after": "2", "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" });
    return res.end("Proxy is busy; retry shortly.");
  }
  active++;
  res.on("close", () => {
    active--;
    entry.ms = Date.now() - started;
    if (!entry.status) entry.status = res.statusCode;
    record(entry);
  });
  const wantsPage = req.headers["x-proxy-dest"] === "document";

  try {
    let target = null;
    try {
      target = targetFromPath(url.pathname, url.search, null);
    } catch {
      // malformed address: reported below
    }
    if (!target) throw new ProxyError("bad_url", "The path is not a valid proxied address.");
    entry.target = target.host + target.pathname; // no query string: it can hold tokens
    checkTarget(target, req);
    const filter = filterDecision(target);
    if (filter.blocked) throw new ProxyError("blocked", `Blocked by controlled filtering lab rule for ${target.hostname}`);

    const upstream = await requestUpstream(req, res, target, buildUpstreamHeaders(req, target));
    await respond(req, res, target, upstream, entry);
  } catch (err) {
    entry.note = err.message;
    if (res.headersSent) return res.destroy();
    sendError(res, wantsPage, classifyError(err), err);
  }
}

const MAX_REDIRECTS = 10;

function cspModeFor(target) {
  const mode = (process.env.PROXY_CSP_MODE || "drop").toLowerCase();
  if (mode !== "rewrite") return "drop";
  const allow = (process.env.PROXY_CSP_ALLOW || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (allow.length === 0) return "rewrite";
  return allow.some((h) => target.hostname.toLowerCase() === h || target.hostname.toLowerCase().endsWith("." + h)) ? "rewrite" : "drop";
}

async function respond(req, res, target, upstream, entry) {
  const status = upstream.statusCode;
  entry.status = status;
  const out = {};

  const setCookies = upstream.headers["set-cookie"];
  if (setCookies?.length) {
    const valid = await validateSetCookies(target.href, setCookies);
    if (valid.length) {
      out["x-proxy-set-cookie"] = encodeURIComponent(JSON.stringify(valid));
      if (isStoreEnabled()) storeSetCookies(target, valid);
    }
  }

  // Redirects become a normal reply with extra headers. The service worker turns them back
  // into real redirects after saving any cookies the redirect set.
  if (REDIRECTS.has(status) && upstream.headers.location) {
    upstream.resume();
    const count = Number(req.headers["x-proxy-redirect-count"] || 0);
    if (count >= MAX_REDIRECTS) throw new ProxyError("too_many_redirects", `redirect loop detected after ${count} hops`);
    const proxied = proxify(upstream.headers.location, target.href);
    if (proxied === null) throw new ProxyError("bad_url", "The site redirected to an address the proxy cannot follow.");
    // Loop detection: redirect back to the exact same target.
    try {
      const nextTarget = targetFromPath(new URL(proxied, "http://localhost").pathname, new URL(proxied, "http://localhost").search, null);
      if (nextTarget && nextTarget.href === target.href) throw new ProxyError("too_many_redirects", "redirect loop to same address");
    } catch (e) {
      if (e instanceof ProxyError) throw e;
    }
    out["x-proxy-redirect"] = String(status);
    out["x-proxy-location"] = proxied;
    out["x-proxy-redirect-count"] = String(count + 1);
    entry.note = `redirect ${status} (${count + 1}/${MAX_REDIRECTS})`;
    res.writeHead(200, { ...out, "cache-control": "no-store" });
    return res.end();
  }

  if ([403, 429].includes(status)) entry.note = `HTTP ${status}: the site may be blocking this server's address`;
  if (upstream.headers["cf-mitigated"]) entry.note = "Cloudflare challenge: the site wants a browser check";

  for (const name of PASS_RESPONSE) {
    if (upstream.headers[name] !== undefined) out[name] = upstream.headers[name];
  }

  // CSP: default drop (not in PASS_RESPONSE). Rewrite mode replaces with a
  // permissive policy so sites that require inline scripts can load.
  const upstreamCsp = upstream.headers["content-security-policy"] || upstream.headers["content-security-policy-report-only"];
  if (upstreamCsp && cspModeFor(target) === "rewrite") {
    out["content-security-policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src 'self' data: blob:; img-src 'self' data: blob:; media-src 'self' data: blob:; frame-src 'self' data: blob:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'";
    if (!entry.note) entry.note = "CSP rewritten (permissive)";
  }

  const contentType = upstream.headers["content-type"] || "";
  const kind = classify(contentType, target.pathname);
  const rewritable = kind && req.method !== "HEAD" && ![204, 206, 304].includes(status);

  if (!rewritable) {
    res.writeHead(status, out);
    if (req.method === "HEAD") {
      upstream.resume();
      return res.end();
    }
    return pipeline(upstream, res, (err) => {
      if (err && !entry.note) entry.note = `ended early: ${err.code || err.message}`;
    });
  }

  const raw = await readLimited(upstream, MAX_REWRITE_BYTES);
  const text = decodeText(await decompress(raw, upstream.headers["content-encoding"]), contentType);
  const rewritten =
    kind === "html" ? rewriteHtml(text, target, status)
    : kind === "css" ? rewriteCss(text, target.href)
    : kind === "playlist" ? rewritePlaylist(text, target.href, proxify)
    : rewriteDash(text, target.href, proxify);

  // The body changed, so the original encoding, length and validators no longer apply.
  for (const name of ["content-encoding", "content-length", "etag", "last-modified"]) delete out[name];
  if (kind === "html") out["content-type"] = "text/html; charset=utf-8";
  if (kind === "css") out["content-type"] = "text/css; charset=utf-8";
  if (kind === "dash") out["content-type"] = "application/dash+xml; charset=utf-8";

  let body = Buffer.from(rewritten, "utf8");
  if (/\bgzip\b/.test(req.headers["accept-encoding"] || "") && body.length > 1024) {
    body = await gzip(body, { level: 5 });
    out["content-encoding"] = "gzip";
  }
  out["content-length"] = String(body.length);
  res.writeHead(status, out);
  res.end(body);
}

/* ==========================================================================
   7. Service worker (runs in the browser, source is served at /sw.js)
   ========================================================================== */

function swMain() {
  const INTERNAL = new Set(["/", "/sw.js", "/runtime.js", "/login", "/logout", "/debug", "/debug.json", "/favicon.ico"]);
  const DAY = 86400000;
  // Redirect hop counts per target URL (cleared on non-redirect responses).
  const redirectCounts = new Map();

  // Cookie jar: lives in the browser, so logins survive server restarts and the server never stores them.
  const database = new Promise((resolve, reject) => {
    const open = indexedDB.open("proxy-jar", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("cookies", { keyPath: "id" });
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });

  async function store(mode, run) {
    const db = await database;
    return new Promise((resolve, reject) => {
      const tx = db.transaction("cookies", mode);
      const request = run(tx.objectStore("cookies"));
      tx.oncomplete = () => resolve(request ? request.result : undefined);
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  }
  const allCookies = () => store("readonly", (s) => s.getAll());
  const saveCookie = (cookie) => store("readwrite", (s) => s.put(cookie));
  const removeCookie = (id) => store("readwrite", (s) => s.delete(id));
  const clearCookies = () => store("readwrite", (s) => s.clear());

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
      expires: Date.now() + 30 * DAY, // session cookies are kept 30 days so logins survive closing the browser
    };
    let maxAge = null;
    let expiresAt = null;
    for (const part of parts) {
      const i = part.indexOf("=");
      const key = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase();
      const value = i < 0 ? "" : part.slice(i + 1).trim();
      if (key === "domain" && value) {
        const domain = value.replace(/^\./, "").toLowerCase();
        // No public-suffix list here, so a bare "com" is the only thing rejected.
        if (domain.includes(".") && (host === domain || host.endsWith("." + domain))) {
          cookie.domain = domain;
          cookie.hostOnly = false;
        }
      } else if (key === "path" && value.startsWith("/")) cookie.path = value;
      else if (key === "secure") cookie.secure = true;
      else if (key === "samesite") cookie.sameSite = ["lax", "strict", "none"].includes(value.toLowerCase()) ? value : "Lax";
      else if (key === "partitioned") cookie.partitioned = true;
      else if (key === "max-age") {
        const n = parseInt(value, 10);
        if (!Number.isNaN(n)) maxAge = n;
      } else if (key === "expires") {
        const t = Date.parse(value);
        if (!Number.isNaN(t)) expiresAt = t;
      }
    }
    if (maxAge !== null) cookie.expires = Date.now() + maxAge * 1000;
    else if (expiresAt !== null) cookie.expires = expiresAt;
    if (cookie.name.startsWith("__Host-") && (!cookie.secure || !cookie.hostOnly || cookie.path !== "/")) return null;
    if (cookie.name.startsWith("__Secure-") && !cookie.secure) return null;
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

  async function cookieHeader(url) {
    const cookies = (await allCookies()).filter((cookie) => matches(cookie, url));
    cookies.sort((a, b) => b.path.length - a.path.length);
    return cookies.map((cookie) => cookie.name + "=" + cookie.value).join("; ");
  }

  async function storeCookies(url, lines) {
    for (const line of lines) {
      const cookie = parseSetCookie(line, url.hostname);
      if (!cookie) continue;
      if (cookie.expires <= Date.now()) await removeCookie(cookie.id);
      else await saveCookie(cookie);
    }
  }

  // The real address of the page that made a request, used to resolve paths the page built itself.
  async function contextBase(event) {
    let pageUrl = null;
    if (event.clientId) {
      const client = await self.clients.get(event.clientId);
      if (client) pageUrl = client.url;
    }
    if (!pageUrl && event.request.referrer) pageUrl = event.request.referrer;
    if (!pageUrl) return null;
    try {
      const page = new URL(pageUrl);
      const target = targetFromPath(page.pathname, page.search, null);
      return target ? target.href : null;
    } catch {
      return null; // the request did not come from a proxied page
    }
  }

  function failure(isPage, status, info) {
    if (!isPage) return new Response(info.title + ". " + info.what, { status, headers: { "content-type": "text/plain" } });
    return new Response(renderErrorPage(info), { status, headers: { "content-type": "text/html; charset=utf-8" } });
  }

  const unreachable = (err) =>
    failure(true, 503, {
      title: "The proxy server did not answer",
      what: "The browser could not reach the proxy server.",
      fixes: [
        "On Render's free plan the server sleeps when idle and can take up to a minute to wake up. This page retries automatically.",
        "If it never comes back, check the service in the Render dashboard.",
      ],
      detail: String(err),
      retry: true,
    });

  async function handle(event) {
    const request = event.request;
    const isPage = request.mode === "navigate" || request.destination === "iframe" || request.destination === "frame";
    const url = new URL(request.url);
    try {
      const context = await contextBase(event);
      let target = null;
      try {
        target = targetFromPath(url.pathname, url.search, context);
      } catch {
        // malformed address: reported below
      }
      if (!target) {
        return failure(isPage, 400, {
          title: "This is not a proxied page",
          what: "The address does not point at a site, and the proxy cannot tell which site it belongs to.",
          fixes: ["Start from the home page and enter the address there."],
          detail: url.pathname,
        });
      }

      const pageHeaders = {};
      request.headers.forEach((value, name) => {
        pageHeaders[name] = value;
      });
      const headers = new Headers({
        "x-proxy-headers": encodeURIComponent(JSON.stringify(pageHeaders)),
        "x-proxy-dest": isPage ? "document" : request.destination || "empty",
      });
      const cookie = await cookieHeader(target);
      if (cookie) headers.set("x-proxy-cookie", cookie);
      if (context) headers.set("x-proxy-referer", context);
      // Redirect hop count: carried in SW memory across navigations.
      const priorCount = redirectCounts.get(target.href) || 0;
      if (priorCount > 0) headers.set("x-proxy-redirect-count", String(priorCount));

      const init = { method: request.method, headers };
      if (request.method !== "GET" && request.method !== "HEAD") init.body = await request.arrayBuffer();

      const canonical = PREFIX + encodeTarget(target.origin + target.pathname) + target.search;
      const response = await fetch(canonical, init);

      const setCookies = response.headers.get("x-proxy-set-cookie");
      if (setCookies) await storeCookies(target, JSON.parse(decodeURIComponent(setCookies)));

      const redirectStatus = response.headers.get("x-proxy-redirect");
      if (redirectStatus) {
        const location = new URL(response.headers.get("x-proxy-location"), self.location.origin).href;
        const nextCount = Number(response.headers.get("x-proxy-redirect-count") || priorCount + 1);
        redirectCounts.set(target.href, nextCount);
        // Also key the next URL so the follow-up navigation carries the count.
        try { redirectCounts.set(new URL(location).href, nextCount); } catch { /* ignore */ }
        return Response.redirect(location, Number(redirectStatus));
      }
      redirectCounts.delete(target.href);
      if (response.status === 401 && response.headers.get("x-proxy-error") === "auth" && isPage) {
        return Response.redirect(new URL("/login?next=" + encodeURIComponent(url.pathname + url.search), self.location.origin).href, 302);
      }
      return response;
    } catch (err) {
      return isPage
        ? unreachable(err)
        : new Response("The proxy server could not be reached: " + err, { status: 502, headers: { "content-type": "text/plain" } });
    }
  }

  self.addEventListener("install", () => self.skipWaiting());
  self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

  self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    if (url.origin !== self.location.origin) return;
    if (INTERNAL.has(url.pathname)) {
      // Pass through, but show a useful page if the server is asleep.
      if (event.request.mode === "navigate") event.respondWith(fetch(event.request).catch(unreachable));
      return;
    }
    event.respondWith(handle(event));
  });

  self.addEventListener("message", (event) => {
    const type = event.data && event.data.type;
    if (type !== "cookies:clear" && type !== "cookies:stats") return;
    event.waitUntil(
      (async () => {
        if (type === "cookies:clear") await clearCookies();
        const live = (await allCookies()).filter((cookie) => cookie.expires > Date.now());
        event.source.postMessage({ type: "cookies:stats", cookies: live.length, sites: new Set(live.map((c) => c.domain)).size });
      })(),
    );
  });
}

const swSource = `${preamble}${renderErrorPage}\n(${swMain})();\n`;

/* ==========================================================================
   8. Runtime injected into every proxied page
   ========================================================================== */

function runtimeMain() {
  const ORIGIN = location.origin;

  const current = () => {
    try {
      const target = targetFromPath(location.pathname, location.search, null);
      return target ? target.href : null;
    } catch {
      return null;
    }
  };

  // Rewrites a URL the page's own scripts built, so it goes through the proxy.
  const px = (value) => {
    const base = current();
    if (base === null || value === null || value === undefined) return value;
    const out = proxify(String(value), base, ORIGIN);
    return out === null ? value : out;
  };

  const nativeFetch = window.fetch;
  window.fetch = function (input, init) {
    if (input instanceof Request) {
      const rewritten = px(input.url);
      if (rewritten !== input.url) {
        try {
          input = new Request(rewritten, input);
        } catch {
          // the request body was already consumed; send the original
        }
      }
    } else {
      input = px(input);
    }
    return nativeFetch.call(this, input, init);
  };

  const nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    return nativeOpen.call(this, method, px(url), ...rest);
  };

  if (navigator.sendBeacon) {
    const nativeBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function (url, data) {
      return nativeBeacon.call(this, px(url), data);
    };
  }

  const nativeWindowOpen = window.open;
  window.open = function (url, ...rest) {
    return nativeWindowOpen.call(this, url ? px(url) : url, ...rest);
  };

  for (const method of ["pushState", "replaceState"]) {
    const native = history[method];
    history[method] = function (state, title, url) {
      return native.call(this, state, title, url === undefined || url === null ? url : px(url));
    };
  }

  // location.assign/replace bypass history hooks.
  try {
    const nativeAssign = location.assign.bind(location);
    const nativeReplace = location.replace.bind(location);
    location.assign = (url) => nativeAssign(px(url));
    location.replace = (url) => nativeReplace(px(url));
  } catch { /* location not hookable */ }

  // form.submit() bypasses action setter hooks.
  try {
    const nativeSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () {
      const action = this.getAttribute("action");
      if (action) {
        const rewritten = px(action);
        if (rewritten !== action) nativeSetAttribute.call(this, "action", rewritten);
      }
      return nativeSubmit.call(this);
    };
  } catch { /* forms not hookable */ }

  // EventSource (server-sent events) does not use fetch/XHR.
  if (window.EventSource) {
    const NativeEventSource = window.EventSource;
    window.EventSource = function (url, init) {
      return new NativeEventSource(px(url), init);
    };
    window.EventSource.prototype = NativeEventSource.prototype;
  }

  // Workers load scripts directly; rewrite their URLs through the proxy.
  if (window.Worker) {
    const NativeWorker = window.Worker;
    window.Worker = function (url, options) {
      return new NativeWorker(px(url), options);
    };
    window.Worker.prototype = NativeWorker.prototype;
  }
  if (window.SharedWorker) {
    const NativeSharedWorker = window.SharedWorker;
    window.SharedWorker = function (url, options) {
      return new NativeSharedWorker(px(url), options);
    };
    window.SharedWorker.prototype = NativeSharedWorker.prototype;
  }

  // WebSocket: rewrite ws(s):// URLs to the proxy origin so Node can upgrade.
  // Node's upgrade handler decodes /service/<token> and tunnels to the target.
  if (window.WebSocket) {
    const NativeWebSocket = window.WebSocket;
    const pxWs = (value) => {
      const base = current();
      if (base === null || value === null || value === undefined) return value;
      let url;
      try { url = new URL(String(value), base); } catch { return value; }
      if (url.protocol !== "ws:" && url.protocol !== "wss:") return value;
      const httpProto = url.protocol === "wss:" ? "https:" : "http:";
      const httpUrl = new URL(url.href);
      httpUrl.protocol = httpProto;
      const out = proxify(httpUrl.href, base, ORIGIN);
      if (out === null) return value;
      const proxyProto = location.protocol === "https:" ? "wss:" : "ws:";
      return proxyProto + "//" + location.host + out;
    };
    window.WebSocket = function (url, protocols) {
      return protocols === undefined ? new NativeWebSocket(pxWs(url)) : new NativeWebSocket(pxWs(url), protocols);
    };
    window.WebSocket.prototype = NativeWebSocket.prototype;
    window.WebSocket.CONNECTING = NativeWebSocket.CONNECTING;
    window.WebSocket.OPEN = NativeWebSocket.OPEN;
    window.WebSocket.CLOSING = NativeWebSocket.CLOSING;
    window.WebSocket.CLOSED = NativeWebSocket.CLOSED;
  }

  const nativeSetAttribute = Element.prototype.setAttribute;
  const URL_ATTRIBUTES = ["src", "href", "poster", "action", "data"];
  Element.prototype.setAttribute = function (name, value) {
    return nativeSetAttribute.call(this, name, URL_ATTRIBUTES.includes(String(name).toLowerCase()) ? px(value) : value);
  };

  const hookSetter = (proto, prop) => {
    const descriptor = Object.getOwnPropertyDescriptor(proto, prop);
    if (descriptor && descriptor.set) {
      Object.defineProperty(proto, prop, {
        ...descriptor,
        set(value) {
          descriptor.set.call(this, px(value));
        },
      });
    }
  };
  hookSetter(HTMLMediaElement.prototype, "src");
  hookSetter(HTMLSourceElement.prototype, "src");
  hookSetter(HTMLImageElement.prototype, "src");
  hookSetter(HTMLScriptElement.prototype, "src");
  hookSetter(HTMLIFrameElement.prototype, "src");
  hookSetter(HTMLLinkElement.prototype, "href");
  hookSetter(HTMLAnchorElement.prototype, "href");
  hookSetter(HTMLVideoElement.prototype, "poster");
  hookSetter(HTMLFormElement.prototype, "action");

  // Elements added with innerHTML bypass the hooks above, so fix their attributes as they appear.
  const fix = (el) => {
    for (const name of ["src", "href", "poster", "action"]) {
      const value = el.getAttribute(name);
      if (value === null || value.startsWith(PREFIX)) continue;
      const rewritten = px(value);
      if (rewritten !== value) nativeSetAttribute.call(el, name, rewritten);
    }
  };
  new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType !== 1) continue;
        fix(node);
        node.querySelectorAll("[src],[href],[poster],[action]").forEach(fix);
      }
    }
  }).observe(document, { childList: true, subtree: true });

  // The proxy owns the one service worker on this origin; a site registering its own would take over.
  if (navigator.serviceWorker) {
    navigator.serviceWorker.register = () =>
      Promise.reject(new Error("Service workers are disabled on proxied pages."));
  }

  // --- Origin-isolated storage shim -------------------------------------
  // All proxied sites share the proxy origin, so raw localStorage/IndexedDB
  // would leak across sites. Namespace every key/db by target origin.
  // Limitation: document.cookie still shares the proxy origin; the SW cookie
  // jar isolates network cookies, but page JS reading document.cookie sees
  // only the proxy's own cookies (sites get cookies via the SW header).
  const siteOrigin = () => {
    const base = current();
    try { return base ? new URL(base).origin : "unknown"; } catch { return "unknown"; }
  };
  const ns = (key) => siteOrigin() + "|" + String(key);
  const wrapStorage = (native) => {
    if (!native) return native;
    const ownKeys = () => {
      const prefix = siteOrigin() + "|";
      const out = [];
      for (let i = 0; i < native.length; i++) {
        const k = native.key(i);
        if (k && k.startsWith(prefix)) out.push(k.slice(prefix.length));
      }
      return out;
    };
    return {
      get length() { return ownKeys().length; },
      getItem: (k) => native.getItem(ns(k)),
      setItem: (k, v) => native.setItem(ns(k), String(v)),
      removeItem: (k) => native.removeItem(ns(k)),
      clear: () => { for (const k of ownKeys()) native.removeItem(siteOrigin() + "|" + k); },
      key: (i) => ownKeys()[i] ?? null,
    };
  };
  try {
    const nativeLocal = window.localStorage;
    Object.defineProperty(window, "localStorage", { value: wrapStorage(nativeLocal), configurable: true });
  } catch { /* storage blocked */ }
  try {
    const nativeSession = window.sessionStorage;
    Object.defineProperty(window, "sessionStorage", { value: wrapStorage(nativeSession), configurable: true });
  } catch { /* storage blocked */ }
  if (window.indexedDB) {
    const nativeOpen = window.indexedDB.open.bind(window.indexedDB);
    const nativeDelete = window.indexedDB.deleteDatabase.bind(window.indexedDB);
    window.indexedDB.open = (name, version) =>
      version === undefined ? nativeOpen(siteOrigin() + "|" + String(name)) : nativeOpen(siteOrigin() + "|" + String(name), version);
    window.indexedDB.deleteDatabase = (name) => nativeDelete(siteOrigin() + "|" + String(name));
  }
  if (window.caches) {
    const nativeOpenCache = window.caches.open.bind(window.caches);
    window.caches.open = (name) => nativeOpenCache(siteOrigin() + "|" + String(name));
  }
}

const runtimeSource = `${preamble}(${runtimeMain})();\n`;

/* ==========================================================================
   9. Pages: home, login, request log
   ========================================================================== */

function homeMain() {
  const $ = (id) => document.getElementById(id);
  const ENGINES = {
    ddg: "https://html.duckduckgo.com/html/?q=%s",
    bing: "https://www.bing.com/search?q=%s",
    google: "https://www.google.com/search?q=%s",
  };
  const read = (key, fallback) => {
    try {
      return JSON.parse(localStorage.getItem(key)) ?? fallback;
    } catch {
      return fallback; // storage blocked or corrupted
    }
  };
  const write = (key, value) => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // storage blocked: settings just will not persist
    }
  };

  const settings = read("settings", { engine: "ddg" });
  let recent = read("recent", []);
  let ready = false;
  let problem = "";

  const say = (text) => {
    $("msg").textContent = text;
  };
  const setStatus = (ok, text) => {
    $("sw").innerHTML = '<span class="dot ' + (ok ? "ok" : "bad") + '"></span>';
    $("sw").append(text);
  };

  function toUrl(input) {
    const value = input.trim();
    if (!value) return null;
    if (/^https?:\/\//i.test(value)) return value;
    if (/^[^\s/]+\.[^\s/]{2,}(\/\S*)?$/.test(value) || /^localhost(:\d+)?(\/|$)/.test(value)) return "https://" + value;
    return (ENGINES[settings.engine] || ENGINES.ddg).replace("%s", encodeURIComponent(value));
  }

  function go(input) {
    say("");
    const address = toUrl(input);
    if (!address) return;
    let url;
    try {
      url = new URL(address);
    } catch {
      return say("That does not look like a web address.");
    }
    if (!ready) return say("The service worker is not ready. " + (problem || "Give it a second and try again."));
    recent = [url.origin, ...recent.filter((item) => item !== url.origin)].slice(0, 8);
    write("recent", recent);
    location.href = PREFIX + encodeTarget(url.origin + url.pathname) + url.search + url.hash;
  }

  function renderRecent() {
    $("recent").replaceChildren(
      ...recent.map((origin) => {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = origin.replace(/^https?:\/\//, "");
        button.onclick = () => go(origin);
        return button;
      }),
    );
  }

  async function startWorker() {
    if (!("serviceWorker" in navigator)) {
      throw new Error("This browser does not support service workers, or they are blocked here (some private windows do this).");
    }
    await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("The service worker installed but did not take control. Reload this page once.")), 4000);
        navigator.serviceWorker.addEventListener("controllerchange", () => {
          clearTimeout(timer);
          resolve();
        }, { once: true });
      });
    }
  }

  $("go").addEventListener("submit", (event) => {
    event.preventDefault();
    go($("q").value);
  });
  $("engine").value = settings.engine in ENGINES ? settings.engine : "ddg";
  $("engine").addEventListener("change", () => {
    settings.engine = $("engine").value;
    write("settings", settings);
  });
  $("clear").addEventListener("click", async () => {
    if (navigator.serviceWorker.controller) navigator.serviceWorker.controller.postMessage({ type: "cookies:clear" });
    try { await fetch("/cookies", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "" }); } catch { /* SW-only mode or endpoint unavailable */ }
    setTimeout(() => location.reload(), 250);
  });
  fetch("/cookies").then((r) => r.json()).then((info) => {
    $("serverStore").textContent = info.enabled ? "Server sync enabled (encrypted at rest)" : "Server sync disabled (browser-only)";
  }).catch(() => { $("serverStore").textContent = "Browser-only"; });
  fetch("/debug.json").then((r) => r.json()).then((info) => {
    const lab = info.filtering;
    $("filterMode").textContent = lab.enabled ? `Enabled · ${lab.rules.length} rules · ${lab.blocks} blocks` : "Disabled";
  }).catch(() => { $("filterMode").textContent = "Disabled"; });
  renderRecent();

  startWorker().then(
    () => {
      ready = true;
      setStatus(true, "Ready");
      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data && event.data.type === "cookies:stats") {
          $("cookies").textContent = event.data.cookies + " cookies, " + event.data.sites + " sites";
        }
      });
      navigator.serviceWorker.controller.postMessage({ type: "cookies:stats" });
    },
    (err) => {
      problem = err.message;
      setStatus(false, "Not working");
      say(problem);
    },
  );

  if (navigator.storage && navigator.storage.persist) {
    navigator.storage.persist().then((granted) => {
      $("storage").textContent = granted
        ? "Protected from automatic cleanup"
        : "The browser may clear saved logins if disk space runs low";
    });
  } else {
    $("storage").textContent = "Not reported by this browser";
  }
}

const PAGE_STYLE = `
:root{color-scheme:light dark;--bg:#fafafa;--fg:#17191c;--mut:#626a75;--card:#fff;--line:#e3e6ea;--acc:#2563eb;--ok:#16a34a;--bad:#dc2626}
@media(prefers-color-scheme:dark){:root{--bg:#0f1114;--fg:#e9ebee;--mut:#98a1ad;--card:#171a1e;--line:#262b31;--acc:#6ea0ff;--ok:#4ade80;--bad:#f87171}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:36rem;margin:14vh auto 4rem;padding:0 1.25rem}
h1{font-size:1.5rem;font-weight:650;margin:0 0 1.25rem;letter-spacing:-.01em}
a{color:var(--acc)}
input,select,button{font:inherit;color:inherit}
button{cursor:pointer;border:0;border-radius:.5rem;background:var(--acc);color:#fff;padding:.55rem .9rem;display:inline-flex;align-items:center;gap:.35rem}
svg{width:1.1rem;height:1.1rem;flex:none}
`;

const homeHtml = `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Proxy</title>
<style>${PAGE_STYLE}
form{display:flex;align-items:center;gap:.5rem;background:var(--card);border:1px solid var(--line);border-radius:.75rem;padding:.35rem .35rem .35rem .85rem}
form:focus-within{border-color:var(--acc)}
form>svg{color:var(--mut)}
#q{flex:1;border:0;background:transparent;outline:0;padding:.55rem .25rem;min-width:0}
#msg{min-height:1.5rem;margin:.6rem .25rem 0;color:var(--bad);font-size:.9rem}
#recent{display:flex;flex-wrap:wrap;gap:.4rem}
#recent button{background:var(--card);color:var(--fg);border:1px solid var(--line);padding:.3rem .7rem;font-size:.9rem}
.panel{margin-top:2rem;border:1px solid var(--line);border-radius:.75rem;background:var(--card);padding:.25rem 1rem}
.row{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.7rem 0;border-bottom:1px solid var(--line);font-size:.95rem}
.row:last-child{border:0}
.row>:first-child{color:var(--mut)}
.row>:last-child{text-align:right}
select{background:var(--bg);border:1px solid var(--line);border-radius:.4rem;padding:.25rem .4rem}
.plain{background:transparent;color:var(--acc);padding:.15rem .4rem}
.dot{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;background:var(--mut);margin-right:.45rem}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}
footer{margin-top:1.5rem;font-size:.9rem;display:flex;gap:1.25rem}
</style>
<main>
<h1>Proxy</h1>
<form id="go" autocomplete="off">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>
<input id="q" placeholder="Enter a web address or search" aria-label="Address or search" autofocus>
<button>Go <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button>
</form>
<div id="msg" role="alert"></div>
<div id="recent"></div>
<section class="panel">
<div class="row"><span>Service worker</span><span id="sw"><span class="dot"></span>Starting</span></div>
<div class="row"><span>Search engine</span><select id="engine"><option value="ddg">DuckDuckGo</option><option value="bing">Bing</option><option value="google">Google</option></select></div>
<div class="row"><span>Saved logins</span><span><span id="cookies">None yet</span> <button type="button" class="plain" id="clear">Clear</button></span></div>
<div class="row"><span>Session mode</span><span id="serverStore">Checking</span></div>
<div class="row"><span>Filtering lab</span><span id="filterMode">Checking</span></div>
<div class="row"><span>Storage</span><span id="storage">Checking</span></div>
</section>
<footer><a href="/debug">Request log</a><a href="/logout">Sign out</a></footer>
</main>
<script>${preamble}(${homeMain})();</script>
</html>`;

function loginPage(next, message) {
  return `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Sign in</title>
<style>${PAGE_STYLE}
main{max-width:22rem;margin-top:22vh}
form{display:grid;gap:.75rem}
input{padding:.65rem .8rem;border:1px solid var(--line);border-radius:.6rem;background:var(--card)}
input:focus{outline:2px solid var(--acc);outline-offset:-1px}
button{justify-content:center}
.err{color:var(--bad);font-size:.9rem;min-height:1.3rem;margin:0}
</style>
<main>
<h1>Sign in</h1>
<form method="post" action="/login">
<input type="hidden" name="next" value="${escapeHtml(next)}">
<input type="password" name="password" placeholder="Password" aria-label="Password" autocomplete="current-password" autofocus required>
<p class="err" role="alert">${escapeHtml(message || "")}</p>
<button>Continue</button>
</form>
</main></html>`;
}

function debugHtml() {
  const rows = entries
    .slice()
    .reverse()
    .map((e) => {
      const tone = e.status >= 500 ? "bad" : e.status >= 400 ? "warn" : "";
      return `<tr class="${tone}"><td>${escapeHtml(e.time.slice(11, 19))}</td><td>${escapeHtml(e.method)}</td><td>${e.status}</td><td>${e.ms} ms</td><td>${escapeHtml(e.target)}</td><td>${escapeHtml(e.note)}</td></tr>`;
    })
    .join("");
  const rss = Math.round(process.memoryUsage().rss / 1048576);
  const minutes = Math.round((Date.now() - startedAt) / 60000);
  return `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Request log</title>
<style>${PAGE_STYLE}
main{max-width:70rem;margin-top:6vh}
.stats{color:var(--mut);margin:0 0 1rem;font-size:.9rem}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:.75rem;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:.85rem}
td,th{text-align:left;padding:.5rem .8rem;border-bottom:1px solid var(--line);white-space:nowrap}
td:nth-child(5),td:nth-child(6){white-space:normal;word-break:break-all}
tr.warn td:nth-child(3){color:#d97706}tr.bad td:nth-child(3){color:var(--bad)}
th{color:var(--mut);font-weight:500}
</style>
<main>
<h1>Request log</h1>
<p class="stats">Last ${entries.length} proxied requests, newest first. Query strings are not recorded. Up ${minutes} min, ${active} in flight, ${rss} MB memory, Node ${process.version}.</p>
<div class="wrap"><table><thead><tr><th>Time</th><th>Method</th><th>Status</th><th>Took</th><th>Address</th><th>Note</th></tr></thead><tbody>${rows || '<tr><td colspan="6">Nothing yet.</td></tr>'}</tbody></table></div>
<p><a href="/">Back to the home page</a></p>
</main></html>`;
}

/* ==========================================================================
   10. Routing
   ========================================================================== */

const SECURITY = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  // Home/login/debug/error pages use inline <script>/<style>, so unsafe-inline is required there.
  // Proxied pages never get this header: upstream CSP is intentionally dropped (not in PASS_RESPONSE).
  "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
};

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { ...SECURITY, "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(html);
}

function sendScript(res, source) {
  res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; script-src 'self' 'unsafe-inline'" });
  res.end(source);
}

async function handleLogin(req, res, url) {
  const next = safeNext(url.searchParams.get("next"));
  if (req.method === "POST") {
    const rl = checkRateLimit(req, { limit: 20, windowMs: 60_000 });
    if (!rl.allowed) {
      res.writeHead(429, { "retry-after": String(rl.retryAfter), "content-type": "text/plain; charset=utf-8" });
      return res.end("Too many requests. Try again later.");
    }
    if (loginLocked()) return sendHtml(res, loginPage("/", "Too many wrong passwords. Wait a few minutes and try again."), 429);
    const form = new URLSearchParams(await readSmallBody(req));
    const destination = safeNext(form.get("next"));
    if (passwordMatches(form.get("password") || "")) {
      res.writeHead(302, { location: destination, "set-cookie": sessionCookie(req), "cache-control": "no-store" });
      return res.end();
    }
    failedLogins.push(Date.now());
    return sendHtml(res, loginPage(destination, "Wrong password."), 401);
  }
  if (isAuthed(req)) {
    res.writeHead(302, { location: next });
    return res.end();
  }
  sendHtml(res, loginPage(next));
}

async function route(req, res) {
  const url = new URL(req.url, "http://localhost");
  const path = url.pathname;

  if (path === "/login") return handleLogin(req, res, url);

  if (!isAuthed(req)) {
    if (path.startsWith(PREFIX)) {
      res.writeHead(401, { "content-type": "text/plain; charset=utf-8", "x-proxy-error": "auth" });
      return res.end("Login required");
    }
    if ((req.headers.accept || "").includes("text/html")) {
      res.writeHead(302, { location: "/login?next=" + encodeURIComponent(path + url.search) });
      return res.end();
    }
    res.writeHead(401);
    return res.end();
  }

  if (path.startsWith(PREFIX)) {
    const rl = checkRateLimit(req, { limit: 300, windowMs: 60_000 });
    if (!rl.allowed) {
      res.writeHead(429, { "retry-after": String(rl.retryAfter), "content-type": "text/plain; charset=utf-8", "x-proxy-error": "rate_limited" });
      return res.end("Too many requests. Try again later.");
    }
    return handleService(req, res, url);
  }

  if (path === "/cookies") {
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return res.end(JSON.stringify(storeStats()));
    }
    if (req.method === "POST") {
      const body = await readSmallBody(req);
      const params = new URLSearchParams(body);
      const site = params.get("site");
      if (site) clearSite(site);
      else clearAll();
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ ok: true, ...storeStats() }));
    }
    res.writeHead(405);
    return res.end("Method not allowed");
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405);
    return res.end("Method not allowed");
  }
  switch (path) {
    case "/": return sendHtml(res, homeHtml);
    case "/sw.js": return sendScript(res, swSource);
    case "/runtime.js": return sendScript(res, runtimeSource);
    case "/debug": return sendHtml(res, debugHtml());
    case "/debug.json":
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return res.end(JSON.stringify({ active, uptimeMs: Date.now() - startedAt, entries, sessions: storeStats(), filtering: filterStats() }));
    case "/logout":
      res.writeHead(302, { location: "/login", "set-cookie": "proxy_session=; Path=/; HttpOnly; Max-Age=0" });
      return res.end();
    case "/favicon.ico":
      res.writeHead(204);
      return res.end();
    default:
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      return res.end("Not found");
  }
}

const server = http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error("Unhandled error:", err);
    if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end("Internal error");
  });
});

// WebSocket upgrade tunneling: ws(s)://proxy/service/<token> -> ws(s)://target.
// Same auth + SSRF guard as HTTP; raw TCP/TLS pipe after the upgrade handshake.
server.on("upgrade", (req, socket, head) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (!url.pathname.startsWith(PREFIX) || !isAuthed(req)) {
      socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      return socket.destroy();
    }
    let target = null;
    try { target = targetFromPath(url.pathname, url.search, null); } catch { /* malformed */ }
    if (!target) {
      socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return socket.destroy();
    }
    // Map ws(s) back to http(s) for SSRF checks.
    const httpTarget = new URL(target.href);
    httpTarget.protocol = target.protocol === "wss:" ? "https:" : "http:";
    checkTarget(httpTarget, req);
    if (filterDecision(httpTarget).blocked) {
      socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return socket.destroy();
    }
    const rate = checkRateLimit(req, { limit: 300, windowMs: 60_000 });
    if (!rate.allowed) {
      socket.write("HTTP/1.1 429 Too Many Requests\r\nRetry-After: " + rate.retryAfter + "\r\nConnection: close\r\n\r\n");
      return socket.destroy();
    }
    const secure = httpTarget.protocol === "https:";
    const port = httpTarget.port ? Number(httpTarget.port) : secure ? 443 : 80;
    // Socket-level lookup guard prevents DNS rebinding between validation and connect.
    const connectOpts = { host: httpTarget.hostname, port, servername: secure ? httpTarget.hostname : undefined, lookup: guardedLookup };
    const upstream = secure ? tls.connect(connectOpts) : net.connect(connectOpts);
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
    upstream.on(secure ? "secureConnect" : "connect", () => {
      // Forward only WebSocket handshake headers. Never leak proxy_session or
      // unrelated proxy-origin cookies/headers to the destination.
      const lines = [
        `GET ${httpTarget.pathname}${httpTarget.search} HTTP/1.1`,
        `Host: ${httpTarget.host}`,
        "Connection: Upgrade",
        "Upgrade: websocket",
      ];
      for (const name of ["sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions"]) {
        const value = req.headers[name];
        if (value) lines.push(`${name}: ${value}`);
      }
      lines.push(`Origin: ${httpTarget.origin}`);
      upstream.write(lines.join("\r\n") + "\r\n\r\n");
      if (head && head.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
  } catch {
    socket.destroy();
  }
});

// Render's load balancer reuses connections for longer than Node's 5 second default,
// which shows up as random 502s if left alone.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;
server.on("clientError", (err, socket) => socket.destroy());

process.on("unhandledRejection", (reason) => console.error("Unhandled rejection:", reason));
process.on("SIGTERM", () => server.close(() => process.exit(0)));

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Proxy listening on ${PORT}`);
});