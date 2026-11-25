// Explicit, opt-in domain filter for controlled/authorized experiments only.
// It only blocks exact hostnames listed in PROXY_FILTER_BLOCK; it never bypasses
// upstream network controls or disguises traffic.
const enabled = process.env.PROXY_FILTER_LAB === "1";
const blocked = new Set((process.env.PROXY_FILTER_BLOCK || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean));
let blocks = 0;

export function filterDecision(target) {
  if (!enabled) return { enabled: false, blocked: false, reason: "disabled" };
  const isBlocked = blocked.has(target.hostname.toLowerCase());
  if (isBlocked) blocks++;
  return { enabled, blocked: isBlocked, reason: isBlocked ? "controlled-lab rule" : "no matching rule" };
}

export function filterStats() { return { enabled, rules: [...blocked], blocks }; }
