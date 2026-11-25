import dns from "node:dns";
import net from "node:net";
import { ProxyError } from "./errors.js";

// Balanced port policy: common web ports by default, override via env.
const DEFAULT_PORTS = new Set([80, 443, 8080, 8443]);
function allowedPorts() {
  const raw = process.env.PROXY_ALLOWED_PORTS;
  if (!raw) return DEFAULT_PORTS;
  const set = new Set();
  for (const part of raw.split(",")) {
    const n = Number(part.trim());
    if (Number.isInteger(n) && n > 0 && n < 65536) set.add(n);
  }
  return set.size ? set : DEFAULT_PORTS;
}

export function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split(".").map(Number);
    return (
      a === 0 || // 0.0.0.0/8 "this host"
      a === 10 || // 10.0.0.0/8 private
      a === 127 || // 127.0.0.0/8 loopback
      (a === 169 && b === 254) || // 169.254.0.0/16 link-local
      (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 private
      (a === 192 && b === 168) || // 192.168.0.0/16 private
      (a === 192 && b === 0 && c === 0) || // 192.0.0.0/24 IETF protocol assignments
      (a === 192 && b === 0 && c === 2) || // 192.0.2.0/24 TEST-NET-1 (documentation)
      (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 benchmarking
      (a === 198 && b === 51 && c === 100) || // 198.51.100.0/24 TEST-NET-2
      (a === 203 && b === 0 && c === 113) || // 203.0.113.0/24 TEST-NET-3
      (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
      a >= 224 // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
    );
  }
  if (!net.isIPv6(ip)) return false;
  let v = ip.toLowerCase();
  // Canonicalize expanded literals so mapped/private prefix checks cannot be bypassed.
  try { v = new URL(`http://[${v}]/`).hostname.replace(/^\[|\]$/g, ""); } catch { /* keep parser input */ }
  // Unspecified, loopback, IPv4-compatible, and IPv4-mapped forms are never destinations.
  if (v === "::" || v === "::1" || v.startsWith("::ffff:") || (v.startsWith("::") && v !== "::")) return true;
  // fc00::/7 unique-local (fc*, fd*).
  if (v.startsWith("fc") || v.startsWith("fd")) return true;
  // fe80::/10 link-local and fec0::/10 deprecated site-local.
  if (["fe8", "fe9", "fea", "feb", "fec"].some((prefix) => v.startsWith(prefix))) return true;
  // Multicast, documentation, protocol-assignment, benchmarking, and ORCHID ranges.
  if (v.startsWith("ff") || v.startsWith("2001:db8:") || v.startsWith("2001::") || v.startsWith("2001:0:") || v.startsWith("2001:2:") || v.startsWith("2001:10:")) return true;
  // 2002::/16 embeds IPv4 (6to4); 64:ff9b::/96 is NAT64 translation.
  if (v.startsWith("2002:") || v.startsWith("64:ff9b:")) return true;
  // 100::/64 is the discard-only range.
  if (v.startsWith("100:")) return true;
  return false;
}

// Used as the socket's DNS lookup, so the address that is checked is the address that is connected to.
export function guardedLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) return callback(error);
    const allowed = addresses.filter((entry) => !isPrivate(entry.address));
    if (allowed.length === 0) {
      return callback(new ProxyError("blocked", `${hostname} resolves to a private address`));
    }
    if (options.all) return callback(null, allowed);
    callback(null, allowed[0].address, allowed[0].family);
  });
}

export function checkTarget(target, req) {
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new ProxyError("bad_url", "Only http and https addresses are supported.");
  }
  const host = target.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host) && isPrivate(host)) throw new ProxyError("blocked", `${host} is a private address`);
  if (target.host === req.headers.host) throw new ProxyError("blocked", "The proxy cannot load itself.");
  const port = target.port ? Number(target.port) : target.protocol === "https:" ? 443 : 80;
  if (!allowedPorts().has(port)) {
    throw new ProxyError("blocked", `Port ${port} is not allowed.`);
  }
}
