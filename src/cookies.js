import { Cookie, CookieJar, MemoryCookieStore } from "tough-cookie";

// Server-side Set-Cookie validation using tough-cookie (RFC 6265 + PSL).
// The SW keeps a lightweight mirror for storage; the server filters invalid
// cookies before they reach the jar so __Host-/__Secure-/domain rules hold.

const jar = new CookieJar(new MemoryCookieStore(), { rejectPublicSuffixes: true });

export async function validateSetCookies(targetUrl, setCookies) {
  const valid = [];
  for (const line of setCookies || []) {
    try {
      const cookie = Cookie.parse(line);
      if (!cookie || !cookie.key) continue;
      // __Host- requires Secure, Path=/, no Domain; __Secure- requires Secure.
      const key = cookie.key;
      if (key.startsWith("__Host-")) {
        if (!cookie.secure || cookie.domain || (cookie.path && cookie.path !== "/")) continue;
      }
      if (key.startsWith("__Secure-") && !cookie.secure) continue;
      // Reject public-suffix domains via jar (throws on PSL violation).
      await jar.setCookie(line, targetUrl, { ignoreError: false });
      valid.push(line);
    } catch {
      // Invalid cookie: drop it (do not forward to SW jar).
    }
  }
  return valid;
}

export function clearJar() {
  return jar.removeAllCookies();
}
