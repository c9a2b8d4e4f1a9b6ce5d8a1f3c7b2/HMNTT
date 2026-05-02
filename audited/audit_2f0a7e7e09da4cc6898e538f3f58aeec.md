### Title
Unauthenticated Bandwidth Exhaustion via Unprotected OpenAPI Spec Endpoints

### Summary
The `serveSpec()` handler in `rest/middleware/openapiHandler.js` unconditionally transmits the full YAML spec body on every GET request with no rate limiting, no response caching, and no compression (due to middleware registration order). Any unprivileged external user can flood these two endpoints in a loop to saturate outbound bandwidth and degrade API availability for legitimate users.

### Finding Description
**Code location:** `rest/middleware/openapiHandler.js`, line 126; routes registered at lines 143–144.

```js
// line 126
const serveSpec = (req, res) => res.type('text/yaml').send(getV1OpenApiFile());

// lines 143–144
app.get(`/api/v1/${config.openapi.swaggerUIPath}/${config.openapi.specFileName}.yml`,  serveSpec);
app.get(`/api/v1/${config.openapi.swaggerUIPath}/${config.openapi.specFileName}.yaml`, serveSpec);
```

**Root cause — three compounding failures:**

1. **No rate limiting.** `grep` across all `rest/**/*.js` finds zero use of `express-rate-limit` or any equivalent. The throttle/bucket4j configuration found in the codebase lives exclusively in the `web3` Java service and does not protect the Node.js REST server.

2. **Compression not applied to spec routes.** In `rest/server.js`, `serveSwaggerDocs(app)` is called at **line 62**, which registers the two spec routes. The `compression()` middleware is added at **lines 76–79** — after the routes are already registered. In Express, a route handler that calls `res.send()` terminates the middleware chain; the later-registered `compression()` middleware never wraps `res.write`/`res.end` for these routes. Every response is sent uncompressed, maximising bytes-on-wire per request.

3. **Response cache bypassed.** The `responseCacheCheckHandler` is registered at **lines 95–98**, again after the spec routes. Spec responses are never served from cache; every request triggers a full `res.send()` of the in-memory YAML string.

**Why HEAD does not help the attacker (and why it doesn't help the defender either):** Express automatically strips the body for HEAD requests on GET routes, so HEAD alone causes no body transmission. However, GET requests are entirely sufficient for the attack and require no special privilege.

### Impact Explanation
The `openapi.yml` spec for this API is a large, multi-path YAML document. An attacker issuing high-frequency GET requests to either or both endpoints receives the full uncompressed body each time. Because there is no per-IP or global request cap, a single client with sufficient upload bandwidth can keep the server's NIC saturated, causing connection timeouts and elevated latency for all other API consumers. The impact is availability degradation (griefing-class DoS) with no economic cost to the attacker.

### Likelihood Explanation
The attack requires zero authentication, zero knowledge of internal state, and only a basic HTTP client in a loop (e.g., `while true; do curl -s <url> > /dev/null; done`). Two endpoints serve identical content, doubling the surface. The attack is trivially repeatable from any IP and can be amplified with multiple source addresses or a botnet. Likelihood is high given the complete absence of mitigations on the Node.js REST server.

### Recommendation
Apply mitigations in order of effectiveness:

1. **Rate limiting:** Add `express-rate-limit` (or equivalent) specifically for the swagger/spec routes, or globally before `serveSwaggerDocs` is called.
2. **Fix compression ordering:** Move `serveSwaggerDocs(app)` to after `app.use(compression())` in `rest/server.js`, or explicitly wrap `serveSpec` with the compressor. YAML compresses extremely well (>80% reduction), drastically cutting bytes-per-request.
3. **HTTP caching headers:** Add `Cache-Control: public, max-age=3600` and `ETag` support so clients and CDN/proxies can avoid re-fetching unchanged content.
4. **Serve via CDN/static hosting:** The spec is a static file; offloading it to a CDN removes the Node.js process from the blast radius entirely.

### Proof of Concept
```bash
# Flood both endpoints concurrently from a single unprivileged client
while true; do
  curl -s "https://<mirror-node-host>/api/v1/docs/openapi.yml"  -o /dev/null &
  curl -s "https://<mirror-node-host>/api/v1/docs/openapi.yaml" -o /dev/null &
done
```
Observe: server outbound bandwidth climbs monotonically; legitimate API requests begin timing out or receiving 503s as the Node.js event loop and NIC become saturated. No credentials, tokens, or special headers are required.