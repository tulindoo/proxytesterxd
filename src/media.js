// Conservative text rewrites for streaming manifests. Preserve unknown tags/attributes.
function rewriteUrl(value, base, proxify) {
  const variables = [...value.matchAll(/\$[^$]+\$/g)].map((item) => item[0]);
  const resolved = new URL(value, base);
  const proxyUrl = proxify(resolved.href, base);
  if (proxyUrl === null) return null;
  const suffix = variables.map((variable, index) => `__pxdash_${index}=${variable}`).join("&");
  const result = suffix ? proxyUrl + (proxyUrl.includes("?") ? "&" : "?") + suffix : proxyUrl;
  return result.replace(/&/g, "&amp;");
}

export function applyDashMarkers(url, search) {
  const params = new URLSearchParams(search || "");
  const templates = [...url.href.matchAll(/\$[^$]+\$/g)];
  for (const [key, value] of [...params.entries()]) {
    const match = /^__pxdash_(\d+)$/.exec(key);
    if (!match) continue;
    const marker = templates[Number(match[1])]?.[0];
    if (marker) {
      url.pathname = url.pathname.split(marker).join(value);
      url.search = url.search.split(marker).join(value);
    }
    params.delete(key);
  }
  const extra = params.toString();
  if (extra) url.search = url.search ? url.search + "&" + extra : "?" + extra;
  return url;
}

export function rewritePlaylist(text, base, proxify) {
  return text.split(/\r?\n/).map((line) => {
    if (!line.trim()) return line;
    if (line.startsWith("#")) return line.replace(/URI="([^"]+)"/g, (match, value) => {
      const out = proxify(value, base);
      return out === null ? match : `URI="${out}"`;
    });
    return proxify(line, base) ?? line;
  }).join("\n");
}

export function rewriteDash(text, base, proxify) {
  let out = text.replace(/\b(BaseURL|Location|href|media|initialization|sourceURL|index)=(['"])(.*?)\2/gi, (match, name, quote, value) => {
    const rewritten = rewriteUrl(value, base, proxify);
    return rewritten === null ? match : `${name}=${quote}${rewritten}${quote}`;
  });
  out = out.replace(/(<BaseURL\b[^>]*>)([^<]+)(<\/BaseURL\s*>)/gi, (match, open, value, close) => {
    const rewritten = rewriteUrl(value.trim(), base, proxify);
    return rewritten === null ? match : open + rewritten + close;
  });
  return out;
}

export function classifyMedia(contentType, pathname) {
  if (/mpegurl/i.test(contentType) || /\.m3u8$/i.test(pathname)) return "hls";
  if (/dash\+xml|application\/xml|text\/xml/i.test(contentType) && /\.mpd(?:$|\?)/i.test(pathname)) return "dash";
  if (/\.mpd(?:$|\?)/i.test(pathname)) return "dash";
  return null;
}
