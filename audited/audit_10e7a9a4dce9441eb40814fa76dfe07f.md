### Title
Unbounded URL-Encoded Body Parsing Without Rate Limiting Enables Resource Exhaustion and DB Pool Starvation

### Summary
`rest/server.js` registers `express.urlencoded({extended: false})` globally with no explicit `limit` option, relying on the undocumented 100 KB default. Combined with the complete absence of any rate-limiting middleware in the REST API, an unprivileged attacker can flood the server with concurrent POST requests carrying maximum-size URL-encoded bodies, saturating the Node.js event loop and memory before any authentication or route guard runs, indirectly starving the 10-connection DB pool and causing a network partition.

### Finding Description

**Exact code location:** `rest/server.js` lines 68–72

```js
app.use(
  express.urlencoded({
    extended: false,
  })
);
```

No `limit:` key is passed. The underlying `body-parser` library defaults to `'100kb'`. This is never overridden anywhere in `rest/server.js` or any loaded config (`rest/config.js`, `docs/configuration.md`).

**Middleware ordering (lines 68–86):** The body parser is registered *before* `httpContext`, `requestLogger`, and `authHandler`. Every inbound request — authenticated or not, GET or POST — passes through the URL-encoded body parser first.

**No rate limiting:** A search across all `rest/**/*.js` files finds zero instances of `rateLimit`, `express-rate-limit`, `helmet`, or any equivalent. The only throttling in the repository lives in `web3/` (Bucket4j) and the Rosetta Traefik ingress (`charts/hedera-mirror-rosetta/values.yaml`), neither of which protects the Node.js REST API.

**DB pool:** `rest/dbpool.js` lines 13–14 show `max: config.db.pool.maxConnections`, which defaults to **10** connections (`docs/configuration.md` line 556) with a `statementTimeout` of 20 000 ms (line 557). Each in-flight request that reaches a route handler holds a pool connection for up to 20 seconds.

**Exploit flow:**

1. Attacker sends N concurrent `POST /api/v1/accounts` (or any path) requests with `Content-Type: application/x-www-form-urlencoded` and a ~100 KB body.
2. `express.urlencoded` buffers and percent-decodes each body synchronously on the Node.js event loop before any auth check runs.
3. With N large enough, the event loop is saturated: existing requests that already hold DB connections cannot complete their callbacks, so connections are not released.
4. New legitimate requests queue for a pool slot; after `connectionTimeoutMillis` (20 s default) they fail with a connection-timeout error — the service is effectively partitioned from its database.
5. POST requests are ultimately rejected (405 or 404) after body parsing, but the damage (memory allocation, CPU decoding, event-loop delay) has already occurred.

**Why existing checks fail:**

- `authHandler` (line 86) runs *after* body parsing — the attacker's body is already decoded.
- `openApiValidator` (lines 63–65) is disabled by default (`openapi.validation.enabled: false`, `docs/configuration.md` line 577).
- `config.query.maxRepeatedQueryParameters` (line 582) limits query-string parameters, not request bodies.
- No `Content-Length` pre-check or connection-level throttle exists before `express.urlencoded` fires.

### Impact Explanation

With a 10-connection pool and 20-second statement timeouts, holding all connections for even a few seconds is sufficient to deny service to all legitimate API consumers. Because the REST API is the sole read interface to the Hedera mirror node data, pool exhaustion constitutes a full network partition for downstream clients (wallets, explorers, dApps). The attack requires no credentials and no knowledge of the API schema.

### Likelihood Explanation

Any internet-reachable instance is vulnerable. The attacker needs only `curl` or a trivial script sending concurrent HTTP POST requests with a URL-encoded body up to 100 KB. No authentication, no special headers, no prior knowledge beyond the server's IP and port (default 5551). The attack is repeatable and cheap: 100 KB × 100 concurrent connections = 10 MB of in-flight data, well within a single machine's capability. The absence of any ingress-level rate limiting for the Node.js REST service (unlike the Rosetta service which has Traefik middleware) makes sustained exploitation straightforward.

### Recommendation

1. **Set an explicit, minimal body size limit** on the parser — since all API routes are read-only GET endpoints, the body is never used; set `limit: '0'` or `'1b'` to reject any body immediately:
   ```js
   app.use(express.urlencoded({ extended: false, limit: '1kb' }));
   app.use(express.json({ limit: '1kb' }));
   ```
2. **Add rate limiting** before body parsing using `express-rate-limit` or equivalent, keyed on IP (respecting `trust proxy` already set).
3. **Reject non-GET methods early** with a middleware placed before body parsers, returning 405 for any method other than GET/HEAD/OPTIONS on API routes.
4. **Add ingress-level throttling** (e.g., Traefik `inFlightReq` + `rateLimit` middleware) mirroring what is already done for the Rosetta service.

### Proof of Concept

```bash
# Generate a 100 KB URL-encoded payload
python3 -c "print('a=' + 'B'*102400)" > body.txt

# Send 200 concurrent POST requests
seq 200 | xargs -P200 -I{} curl -s -o /dev/null \
  -X POST http://<target>:5551/api/v1/accounts \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @body.txt &

# Simultaneously probe legitimate GET endpoint — observe timeouts
for i in $(seq 1 20); do
  time curl -s http://<target>:5551/api/v1/transactions | head -c 100
done
```

Expected result: legitimate GET requests begin timing out or returning 503/connection-refused errors as the DB pool is exhausted by in-flight requests whose event-loop callbacks are delayed by concurrent body-parsing work.