export class ProxyError extends Error {
  constructor(code, detail) {
    super(detail || code);
    this.proxyCode = code;
  }
}

// code: [HTTP status, title, what happened, things to try]
export const ERRORS = {
  bad_url: [400, "That address is not valid", "The proxy could not understand the web address it was given.",
    ["Check the address for typos.", "Start again from the home page."]],
  blocked: [403, "That address is not allowed", "The proxy refuses to connect to private or internal addresses, or to itself.",
    ["Use the site's public address."]],
  dns: [502, "Site not found", "The site's name could not be looked up.",
    ["Check the spelling of the address.", "The site may be down, or the domain may not exist."]],
  refused: [502, "The site refused the connection", "The site's server is reachable but is not accepting connections.",
    ["Try again in a minute.", "Check that the address uses the right port."]],
  reset: [502, "The connection dropped", "The site closed the connection before finishing its reply.",
    ["Reload the page.", "If it keeps happening, the site may be rejecting this proxy."]],
  timeout: [504, "The site took too long", "The site did not answer within 30 seconds.",
    ["Reload the page.", "The site may be slow or down."]],
  tls: [502, "Security certificate problem", "The proxy could not verify the site's HTTPS certificate.",
    ["The site's certificate may be expired or misconfigured. The proxy will not load it."]],
  too_large: [502, "Page too large to process", "This response is bigger than the 20 MB the proxy will rewrite.",
    ["Open the file directly instead of through a page that needs rewriting."]],
  encoding: [502, "Unsupported compression", "The site used a compression format the proxy cannot read.", []],
  too_many_redirects: [502, "Too many redirects", "The site kept redirecting without settling on a page (more than 10 hops).",
    ["Reload the page.", "The site may be stuck in a redirect loop."]],
  unknown: [502, "Something went wrong", "The proxy hit an unexpected error while loading this page.",
    ["Reload the page.", "Open the request log on the home page and look for this request."]],
};

export function classifyError(err) {
  if (err instanceof ProxyError) return err.proxyCode;
  const code = (err && err.code) || "";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "dns";
  if (code === "ECONNREFUSED") return "refused";
  if (code === "ECONNRESET" || code === "EPIPE" || code === "ERR_STREAM_PREMATURE_CLOSE") return "reset";
  if (code === "ETIMEDOUT") return "timeout";
  if (/CERT|TLS|SSL|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code)) return "tls";
  return "unknown";
}
