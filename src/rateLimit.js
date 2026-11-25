// Per-IP rate limiter (in-memory token bucket, Render-safe).
// Uses X-Forwarded-For first entry when present (Render LB), else socket IP.
// NOTE: X-Forwarded-For is spoofable by direct clients; on Render the LB appends it,
// so the first entry is the best available signal for a personal proxy. This is
// abuse mitigation, not authentication.

const buckets = new Map();

export function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

export function checkRateLimit(req, { limit = 120, windowMs = 60_000 } = {}) {
  const ip = clientIp(req);
  const now = Date.now();
  let bucket = buckets.get(ip);
  if (!bucket || now - bucket.start >= windowMs) {
    bucket = { start: now, count: 0 };
    buckets.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > limit) {
    const retryAfter = Math.ceil((windowMs - (now - bucket.start)) / 1000);
    return { allowed: false, retryAfter };
  }
  return { allowed: true, retryAfter: 0 };
}

export function resetRateLimits() {
  buckets.clear();
}
