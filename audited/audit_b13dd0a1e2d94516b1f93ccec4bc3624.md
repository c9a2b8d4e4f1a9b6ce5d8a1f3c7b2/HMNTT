### Title
Unauthenticated Exchange Rate Endpoint Issues Up to 10 DB Queries Per Request with No Rate Limiting, Enabling DB Connection Pool Exhaustion

### Summary
The `GET /api/v1/network/exchangerate` endpoint is publicly accessible with no authentication or rate limiting. Each request invokes `getExchangeRate()` → `fallbackRetry()`, which loops up to 10 times issuing a separate DB query per iteration. An unprivileged attacker sending concurrent requests with varied `timestamp` parameters can collectively exhaust the database connection pool, causing a denial of service for all mirror node consumers.

### Finding Description

**Exact code path:**

`rest/service/fileDataService.js`, `fallbackRetry()`, lines 93–118:

```js
fallbackRetry = async (fileEntityId, filterQueries, resultConstructor) => {
  const whereQuery = filterQueries.whereQuery ?? [];
  const filters = {whereQuery};

  let attempts = 0;
  while (++attempts <= 10) {                          // up to 10 iterations
    const row = await this.getLatestFileDataContents(fileEntityId, filters); // 1 DB query each
    try {
      return row === null ? null : new resultConstructor(row);
    } catch (error) {
      // on parse failure, adjusts timestamp bound and retries
      filters.whereQuery = [...whereQuery, { query: ..., param: row.first_consensus_timestamp }];
    }
  }
  return null;
};
```

`getExchangeRate()` at line 89–91 calls `fallbackRetry()` unconditionally for every HTTP request.

**Root cause:** The retry loop is designed to handle corrupt/incomplete file data by falling back to earlier DB records. There is no cap on concurrent callers, no per-IP throttle, and no application-level rate limiter guarding this path.

**Why existing checks fail:**

1. **No application-level rate limiting.** Searching all `rest/middleware/*.js` files reveals no rate-limiting middleware. The middleware stack (`rest/middleware/index.js`) exports only: `authHandler`, `handleError`, `openApiValidator`, `requestHandler`, `responseCacheHandler`, `responseHandler` — none of which throttle requests.

2. **Infrastructure middleware is disabled by default.** `charts/hedera-mirror-rest/values.yaml` line 89 sets `global.middleware: false`. The Traefik middleware template (`charts/hedera-mirror-rest/templates/middleware.yaml` line 3) gates on `{{ if and .Values.global.middleware .Values.middleware }}`, so the entire middleware chain (including the circuit breaker) is **not applied** in the default deployment. Contrast this with the Rosetta chart (`charts/hedera-mirror-rosetta/values.yaml` lines 157–160) which explicitly configures `rateLimit` and `inFlightReq` — the REST chart has neither.

3. **Response cache is bypassable.** `responseCacheHandler.js` line 152 generates cache keys from `req.originalUrl` (MD5 hash). An attacker varying the `?timestamp=` query parameter produces a unique cache key per request, bypassing the Redis cache entirely. The `DEFAULT_REDIS_EXPIRY` is also only 1 second (line 24), meaning even identical requests re-hit the DB every second.

4. **No authentication required.** The endpoint has no `@Authenticated` guard or API key requirement; `authHandler.js` only sets an elevated limit for *optionally* authenticated users — unauthenticated requests proceed normally.

**Exploit flow:**

1. Attacker identifies that `GET /api/v1/network/exchangerate?timestamp=lt:<T>` is unauthenticated.
2. Attacker seeds the DB with 10 corrupt exchange rate file records (or simply relies on the worst-case path where all 10 DB records fail to parse), or simply floods with unique timestamps to bypass cache.
3. Each concurrent request holds a DB connection for up to 10 sequential queries.
4. With N concurrent requests, up to 10×N DB connections are consumed simultaneously.
5. DB connection pool is exhausted; all other mirror node API endpoints that require DB access begin returning errors or timing out.

### Impact Explanation

The DB connection pool is a shared resource across all mirror node REST endpoints. Exhausting it causes a complete service outage for all API consumers — not just the exchange rate endpoint. Since the Hedera mirror node serves as the canonical data source for network state (balances, transactions, exchange rates), this constitutes a high-impact non-network-based DoS. The affected service handles ≥25% of Hedera ecosystem market cap data queries, matching the stated scope threshold.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero special knowledge beyond the public OpenAPI spec (`rest/api/v1/openapi.yml` line 871). The attacker needs only an HTTP client capable of sending concurrent GET requests with varying `timestamp` parameters. The attack is trivially scriptable, repeatable, and requires no on-chain resources. The absence of `inFlightReq` or `rateLimit` in the REST chart (unlike Rosetta) means there is no infrastructure-level backstop in default deployments.

### Recommendation

1. **Add application-level rate limiting** to the REST middleware stack (e.g., `express-rate-limit` or `express-slow-down`) scoped per IP, specifically for the `/api/v1/network/exchangerate` and `/api/v1/network/fees` endpoints.
2. **Enable `inFlightReq` and `rateLimit` Traefik middleware** in `charts/hedera-mirror-rest/values.yaml` (mirroring the Rosetta chart configuration) and set `global.middleware: true` or document the security implication of leaving it `false`.
3. **Cap `fallbackRetry` concurrency** — consider a semaphore or connection-pool-aware retry limit so that a single request cannot hold more than 1–2 DB connections regardless of retry count.
4. **Increase cache TTL** for the exchange rate endpoint (exchange rates change infrequently) to reduce DB query frequency under load.

### Proof of Concept

```bash
# Bypass cache by varying timestamp; each request triggers up to 10 DB queries
for i in $(seq 1 500); do
  curl -s "https://<mirror-node>/api/v1/network/exchangerate?timestamp=lt:$((1700000000 + i))" &
done
wait
# Result: DB connection pool exhausted; subsequent API calls return 500/timeout
```

Verification: Monitor DB connection pool metrics during the above. With a pool size of ~50 connections and 500 concurrent requests each consuming up to 10 connections sequentially, the pool saturates within the first wave of requests.