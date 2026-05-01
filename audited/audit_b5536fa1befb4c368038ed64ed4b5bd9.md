### Title
Unauthenticated Pagination Loop Exhausts DB Connection Pool in `getTokenRelationships()`

### Summary
The `getTokenRelationships()` handler in `rest/controllers/tokenController.js` issues multiple database queries per request (account lookup, validity check, token fetch, and a potential second token-cache query) against a connection pool that defaults to only 10 connections. No application-level rate limiting exists on the REST API. An unauthenticated attacker who follows the `nextLink` cursor in a tight concurrent loop can saturate the pool, causing all subsequent REST API requests to queue and time out, effectively taking the mirror-node REST service offline.

### Finding Description

**Exact code path:**

`getTokenRelationships()` at `rest/controllers/tokenController.js` lines 66–92 executes, per HTTP request:
1. `EntityService.getEncodedId()` — DB query (line 67)
2. `EntityService.isValidAccount()` — DB query (line 68)
3. `TokenService.getTokenAccounts()` → `getTokenRelationshipsQuery()` + `super.getRows()` — DB query (line 74, `rest/service/tokenService.js` line 97–98)
4. `getCachedTokens()` — a second DB query for any token IDs not yet in the in-process LRU cache (lines 136–161)

That is 3–4 pool connections consumed per HTTP request, held for up to `statementTimeout` (default 20 000 ms).

**Connection pool:**

`rest/dbpool.js` lines 13–14 configure the pool with `max: config.db.pool.maxConnections`. The documented default is **10** connections (`hiero.mirror.rest.db.pool.maxConnections = 10`, `docs/configuration.md` line 556).

**Pagination link generation:**

Lines 77–84 of `tokenController.js` unconditionally emit a `nextLink` whenever `tokens.length === query.limit`. Any unauthenticated caller can follow this link indefinitely as long as data exists.

**No application-level rate limiting:**

The REST API middleware stack (`rest/middleware/index.js`, `authHandler.js`, `requestHandler.js`, etc.) contains no per-IP or global request-rate limiter. The `ThrottleManagerImpl` / `ThrottleConfiguration` rate-limiting code lives exclusively in the `web3` module and is not applied to the REST API. The Traefik `rateLimit` / `inFlightReq` middleware visible in the Helm chart values is defined only for the Rosetta service, not the REST API.

**Root cause / failed assumption:**

The design assumes that infrastructure-level controls (Traefik, PgBouncer) will always be present and correctly configured in front of the REST API. In default or bare deployments they are absent, and the application itself provides no fallback rate limit.

### Impact Explanation

With 10 pool connections and a 20-second statement timeout, only **10 concurrent requests** are needed to hold every connection for up to 20 seconds. During that window every other REST API call (across all endpoints) blocks waiting for a connection and eventually fails with a connection-timeout error (default 20 000 ms). This constitutes a complete outage of the mirror-node REST service for the duration of the attack. Because the attack is stateless and self-sustaining (each response provides the next cursor), a single attacker machine can maintain it indefinitely.

### Likelihood Explanation

- **No authentication required** — the endpoint is fully public.
- **No special knowledge** — the `nextLink` URL is returned in every paginated response.
- **Low resource cost** — 10–20 concurrent HTTP connections from one host suffice.
- **Self-sustaining** — the attacker simply follows the cursor; no brute-force or credential guessing is needed.
- **Repeatable** — the attack can be restarted immediately after any timeout clears.

### Recommendation

1. **Add application-level rate limiting** to the REST API (e.g., `express-rate-limit` or equivalent), keyed on client IP, applied globally before any route handler.
2. **Increase the default pool size** or, better, enforce a per-request concurrency cap so that a single client cannot monopolise the pool.
3. **Reduce `statementTimeout`** for the token-relationship query to a value well below 20 s (e.g., 3–5 s) to release connections faster under load.
4. **Do not rely solely on infrastructure controls** — document and enforce that Traefik (or equivalent) rate-limiting middleware is mandatory, and add a startup warning if the REST API detects it is running without a reverse proxy.

### Proof of Concept

```
# Step 1 – obtain a valid account ID with many token associations
ACCOUNT=0.0.1234

# Step 2 – fetch first page and extract nextLink
NEXT=$(curl -s "https://<mirror-node>/api/v1/accounts/$ACCOUNT/tokens?limit=100" \
       | jq -r '.links.next')

# Step 3 – flood the endpoint concurrently from a single host
# (10 workers is enough to saturate the default pool of 10 connections)
for i in $(seq 1 10); do
  while true; do
    curl -s "https://<mirror-node>$NEXT" > /dev/null
  done &
done

# Result: within seconds all other REST API calls return 503 / connection-timeout errors
# because the pg pool (max=10) is fully occupied by the attack workers.
```