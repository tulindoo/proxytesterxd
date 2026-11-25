import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";
import { timingSafeEqual } from "node:crypto";

const PASSWORD = process.env.PROXY_PASSWORD;
if (!PASSWORD) {
  console.error("Set the PROXY_PASSWORD environment variable before starting.");
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const MAX_BYTES = 20 * 1024 * 1024;

const proxied = (url) => "/go?url=" + encodeURIComponent(url);

function authorized(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Basic ")) return false;
  // Username is ignored; everything after the first colon is the password.
  const given = Buffer.from(header.slice(6), "base64").toString().split(":").slice(1).join(":");
  const a = Buffer.from(given);
  const b = Buffer.from(PASSWORD);
  return a.length === b.length && timingSafeEqual(a, b);
}

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  const v = ip.toLowerCase();
  // IPv4-mapped IPv6 can hide a private IPv4 address, so reject the whole range.
  return v === "::1" || v === "::" || v.startsWith("::ffff:") ||
    v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80");
}

async function checkTarget(url) {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http and https URLs are allowed.");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = await dns.lookup(host, { all: true });
  if (addresses.some((entry) => isPrivate(entry.address))) {
    throw new Error("That address is not allowed.");
  }
}

function resolve(value, base) {
  const trimmed = value.trim();
  if (/^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(trimmed)) return null;
  try {
    return new URL(trimmed.replace(/&amp;/g, "&"), base).href;
  } catch {
    // Unparseable value: leave the attribute untouched.
    return null;
  }
}

function decode(buffer, contentType) {
  const charset = /charset=([^;]+)/i.exec(contentType)?.[1]?.trim() || "utf-8";
  try {
    return new TextDecoder(charset).decode(buffer);
  } catch {
    // Unknown charset label.
    return buffer.toString("utf8");
  }
}

function rewriteHtml(html, base) {
  return html
    .replace(/<base\b[^>]*>/gi, "")
    .replace(/\b(href|src|poster)=(["'])(.*?)\2/gi, (match, attr, quote, value) => {
      const absolute = resolve(value, base);
      return absolute ? `${attr}=${quote}${proxied(absolute)}${quote}` : match;
    });
}

function rewriteCss(css, base) {
  return css.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (match, quote, value) => {
    const absolute = resolve(value, base);
    return absolute ? `url(${quote}${proxied(absolute)}${quote})` : match;
  });
}

const homePage = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Proxy test</title>
<style>
  body { font: 16px system-ui, sans-serif; max-width: 32rem; margin: 20vh auto; padding: 0 1rem; }
  form { display: flex; gap: .5rem; }
  input { flex: 1; padding: .6rem; font: inherit; }
  button { padding: .6rem 1rem; font: inherit; }
</style>
<form action="/go" method="get">
  <input name="url" placeholder="example.com" autofocus required>
  <button>Go</button>
</form>`;

const server = http.createServer(async (req, res) => {
  if (!authorized(req)) {
    res.writeHead(401, { "WWW-Authenticate": 'Basic realm="proxy"' });
    return res.end("Login required");
  }

  const requestUrl = new URL(req.url, "http://localhost");

  if (requestUrl.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    return res.end(homePage);
  }
  if (requestUrl.pathname !== "/go") {
    res.writeHead(404);
    return res.end("Not found");
  }
  if (req.method !== "GET") {
    res.writeHead(405);
    return res.end("Only GET is supported");
  }

  let raw = requestUrl.searchParams.get("url") || "";
  if (!/^[a-z][a-z0-9+.-]*:/i.test(raw)) raw = "https://" + raw;

  try {
    const target = new URL(raw);
    await checkTarget(target);

    const upstream = await fetch(target, {
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
      headers: {
        "user-agent": req.headers["user-agent"] || "Mozilla/5.0",
        "accept-language": req.headers["accept-language"] || "en",
      },
    });

    // Redirects go back through /go so every hop passes checkTarget.
    const location = upstream.headers.get("location");
    if (upstream.status >= 300 && upstream.status < 400 && location) {
      res.writeHead(302, { Location: proxied(new URL(location, target).href) });
      return res.end();
    }

    const body = Buffer.from(await upstream.arrayBuffer());
    if (body.length > MAX_BYTES) throw new Error("Response too large.");

    const contentType = upstream.headers.get("content-type") || "application/octet-stream";
    const headers = {
      "content-type": contentType,
      "referrer-policy": "no-referrer",
      "x-robots-tag": "noindex",
    };

    if (contentType.includes("text/html")) {
      headers["content-type"] = "text/html; charset=utf-8";
      res.writeHead(upstream.status, headers);
      return res.end(rewriteHtml(decode(body, contentType), target));
    }
    if (contentType.includes("text/css")) {
      headers["content-type"] = "text/css; charset=utf-8";
      res.writeHead(upstream.status, headers);
      return res.end(rewriteCss(decode(body, contentType), target));
    }

    res.writeHead(upstream.status, headers);
    res.end(body);
  } catch (error) {
    console.error("Proxy request failed", { url: raw, message: error.message });
    res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    res.end("Could not load that page: " + error.message);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Proxy listening on ${PORT}`);
});