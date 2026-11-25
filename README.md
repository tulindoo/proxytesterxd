# ProxyTester

A password-protected, self-hosted HTTP(S) browsing proxy for compatibility testing and authorized network experiments. It rewrites HTML, CSS, HLS, and DASH manifests and uses a service worker for request routing and a browser-side cookie jar. It is not an anonymity service, not a browser security boundary between proxied origins, and does not bypass upstream access controls or DRM.

## Run

Requirements: Node.js 20 or newer.

```sh
npm install
PROXY_PASSWORD='use-a-long-unique-secret' npm start
```

Open the service URL and sign in with `PROXY_PASSWORD`. For HTTPS deployments, terminate TLS at the trusted host/proxy. Do not expose an unauthenticated instance to the public Internet. Keep the login secret private and rotate it if exposed.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Listen port |
| `PROXY_PASSWORD` | required | Login secret and HMAC session signer |
| `PROXY_ALLOWED_PORTS` | `80,443,8080,8443` | Comma-separated destination port allowlist |
| `PROXY_MAX_ACTIVE` | `64` | Maximum concurrent upstream proxy requests (minimum 8) |
| `PROXY_CSP_MODE` | `drop` | `drop` removes upstream CSP; `rewrite` replaces it with a permissive compatibility policy |
| `PROXY_CSP_ALLOW` | empty | Optional comma-separated host suffixes allowed to use CSP rewrite mode |
| `PROXY_SERVER_STORE` | `0` | Set to `1` to enable shared server-side cookie persistence |
| `PROXY_STORE_FILE` | empty | Optional path for encrypted server-store persistence; storage may be ephemeral on hosted platforms |
| `PROXY_FILTER_LAB` | `0` | Explicitly enables controlled-test hostname blocking |
| `PROXY_FILTER_BLOCK` | empty | Exact hostnames blocked when filtering lab is enabled |

The optional server cookie store uses AES-256-GCM with a key derived from `PROXY_PASSWORD`. It is a shared store, intended for a trusted single-user installation; it is not per-user account isolation. The browser-side service-worker jar remains the default. Server-side cookie persistence should only be enabled when its shared-session implications are acceptable.

The filtering lab is disabled by default and only blocks exact hostnames explicitly configured for an authorized test. It does not evade network controls or modify upstream filtering.

## Security and compatibility notes

- Destination URLs are restricted to HTTP(S), checked against private/reserved IP ranges, DNS-checked at connection time, and limited to configured ports. The same guard is used by HTTP and WebSocket connections.
- Login/session protection, rate limits, response-size bounds, redirect limits, and a concurrent-request cap are enabled. Review reverse-proxy trust and forwarded headers when deploying behind a load balancer.
- Proxied sites share the proxy browser origin. Storage namespacing and cookie routing are compatibility measures, not a hard browser-origin security boundary. Do not use this proxy for highly sensitive accounts or mutually untrusted sites.
- CSP rewrite mode is intentionally permissive and reduces defense-in-depth; leave it disabled unless required for a trusted compatibility test.
- HLS/DASH rewrites cover common manifest URL forms. DRM, protected media, unusual manifest constructs, service-worker-dependent sites, complex browser fingerprinting, and sites that reject the server's network address may not work. No universal site or video compatibility is promised.
- Destinations see the proxy server's IP and TLS/network characteristics. This does not provide network anonymity.

## Development and checks

```sh
npm test
```

The test suite uses Node's built-in test runner and focuses on security controls, cookie handling, session-store behavior, filtering rules, and media-manifest URL rewriting. Smoke checks should be run against a local test deployment before hosting changes.
