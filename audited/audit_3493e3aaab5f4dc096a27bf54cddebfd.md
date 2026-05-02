### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Concurrent Block List Requests

### Summary
The REST API `/api/v1/blocks` endpoint enforces a per-request row limit (default max 100) but has no rate limiting or concurrency control. An unprivileged attacker can flood the endpoint with concurrent `block.number=gte:0&limit=100` requests, each holding a database connection for the full `statementTimeout` duration, exhausting the finite `pg` connection pool and causing all subsequent requests to fail with connection-timeout errors.

### Finding Description

**Code path:**

`rest/controllers/blockController.js` `getBlocks()` (line 101–112) calls `extractLimitFromFilters()` (lines 57–61):

```js
extractLimitFromFilters = (filters) => {
  const limit = findLast(filters, {key: filterKeys.LIMIT});
  const maxLimit = getEffectiveMaxLimit();
  return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
};
```

`getEffectiveMaxLimit()` (`rest/utils.js:533–536`) returns `responseLimit.max` = **100** for unauthenticated users. Passing `limit=100` passes the `> maxLimit` check and is used verbatim.

`rest/service/recordFileService.js` `getBlocks()` (lines 149–162) directly interpolates this limit into SQL:

```js
const query = RecordFileService.blocksQuery + `
  ${where}
  order by ${filters.orderBy} ${filters.order}
  limit ${filters.limit}
`;
const rows = await super.getRows(query, params);
```

With `block.number=gte:0`, the `WHERE` clause becomes `index >= 0`, matching every block in the table. The query scans and returns up to 100 rows — the maximum possible per-request DB load.

**No rate limiting exists on the REST API.** A `grep` for `rateLimiter|rateLimit|throttle|express-rate-limit` across all `rest/**/*.js` returns zero matches. The `ThrottleConfiguration`/`ThrottleManagerImpl` throttling is scoped exclusively to the `web3` module (contract calls).

**DB pool** (`rest/dbpool.js:7–16`) is a finite `pg.Pool` bounded by `config.db.pool.maxConnections`. Each call to `super.getRows()` acquires a connection and holds it for the full query duration (up to `statementTimeout`, default 10 000 ms per docs). Under high concurrency, all pool slots are occupied simultaneously; new requests block for `connectionTimeout` ms then throw `DbError`, causing 500 responses.

**Root cause / failed assumption:** The design assumes that a per-request row cap (100 rows) is sufficient to prevent resource exhaustion. It fails to account for the multiplicative effect of many concurrent requests each holding a connection for up to 10 seconds against a pool of fixed size.

### Impact Explanation

When the pool is exhausted:
- All in-flight and queued requests that need a DB connection receive a `DbError` and return HTTP 500.
- The readiness probe (`rest/health.js:22–33`) also queries the pool; if it cannot acquire a connection it throws `DbError`, potentially causing the pod to be marked unready by Kubernetes and removed from load-balancer rotation.
- Legitimate users receive error responses or stale cached data for the entire duration of the attack.

Severity: **High** — complete denial of service for all REST API consumers, achievable with no credentials.

### Likelihood Explanation

- No authentication or API key required.
- The attack URL is trivially constructed: `GET /api/v1/blocks?block.number=gte:0&order=asc&limit=100`.
- A single attacker with a modest HTTP client (e.g., `ab`, `wrk`, or a simple async script) sending ~50–200 concurrent requests sustains pool exhaustion continuously.
- The attack is repeatable and stateless; no prior knowledge of the chain state is needed.
- Public mirror node deployments are directly reachable from the internet.

### Recommendation

1. **Add rate limiting middleware** to the REST API (e.g., `express-rate-limit` keyed on IP) before any DB-touching route, including `/api/v1/blocks`.
2. **Add a concurrency cap** per IP or globally using a semaphore/queue in front of `RecordFileService.getBlocks()`.
3. **Reduce `statementTimeout`** for the blocks query to limit how long each connection is held.
4. **Increase `maxConnections`** or use a connection-queue with a short wait timeout so pool exhaustion fails fast rather than blocking.
5. Consider returning HTTP 429 when the pool queue depth exceeds a threshold.

### Proof of Concept

```bash
# Flood with 200 concurrent requests, repeat continuously
while true; do
  for i in $(seq 1 200); do
    curl -s "http://<mirror-node>/api/v1/blocks?block.number=gte:0&order=asc&limit=100" \
      -o /dev/null &
  done
  wait
done
```

**Expected result:** After the first wave saturates the pool, subsequent requests return HTTP 500 (`{"_status":{"messages":[{"message":"..."}]}}`). The readiness endpoint `/actuator/health/readiness` may also begin failing, triggering pod restarts and amplifying the outage.