### Title
Cache Fragmentation via Query Parameter Order Manipulation in `cacheKeyGenerator()`

### Summary
The `cacheKeyGenerator()` function in `rest/middleware/responseCacheHandler.js` computes cache keys by MD5-hashing `req.originalUrl` verbatim, without normalizing query parameter order. An unprivileged attacker can send semantically identical requests with reordered parameters (e.g., `?limit=10&order=asc` vs `?order=asc&limit=10`) to generate distinct cache keys, fragmenting the Redis cache and forcing repeated database queries for every permutation. The developers explicitly acknowledged this gap in a code comment referencing a future fix ("Edwin's request normalizer, #9113"), confirming the defect is known and unmitigated.

### Finding Description

**Exact code location:**
`rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, line 152:

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` is the raw URL string as received from the client. Two requests that differ only in query parameter order produce different MD5 digests and therefore different Redis keys.

**Root cause:** No query-parameter normalization is applied before hashing. The code comment at line 149 reads:
> *"In the future, this will utilize Edwin's request normalizer (9113)."*

This confirms the normalization step was intentionally deferred and is currently absent.

**Is `requestNormalizer.js` applied upstream?** No. `rest/middleware/requestNormalizer.js` contains `normalizeRequestQueryParams()` which sorts parameters, but:
- It is **not exported** from `rest/middleware/index.js` (which exports only `authHandler`, `handleError`, `openApiValidator`, `requestHandler`, `responseCacheHandler`, `responseHandler`).
- It is **not registered** anywhere in `rest/server.js` before `responseCacheCheckHandler` (line 97).

**Middleware order in `rest/server.js`:**
```
authHandler          (line 86)
responseCacheCheckHandler  (line 97)  ← cache key generated here, no normalization
[route handlers]
responseHandler      (line 136)
responseCacheUpdateHandler (line 140)
```

**Exploit flow:**
1. Attacker sends `GET /api/v1/transactions?limit=10&order=asc` → cache miss → DB query → result stored under key `md5("/api/v1/transactions?limit=10&order=asc")-v1`.
2. Attacker sends `GET /api/v1/transactions?order=asc&limit=10` → different MD5 → cache miss → another DB query → stored under a second key.
3. With N query parameters, up to N! permutations each produce a distinct cache key. For the `/api/v1/transactions` endpoint, which accepts `account.id`, `limit`, `order`, `timestamp`, `transactiontype`, `result`, `type` (7 parameters), that is up to 5040 distinct keys for the same logical query.
4. Legitimate users whose clients send parameters in a consistent order never benefit from entries populated by other orderings.

**Why existing checks fail:** There are no checks. The cache key is computed from the raw URL with no sanitization, sorting, or canonicalization step anywhere in the request pipeline.

### Impact Explanation

- **Cache pollution / fragmentation:** Redis fills with duplicate entries for the same logical query, each under a different key. Cache hit rate for transaction endpoints drops toward zero under sustained attack.
- **Database amplification:** Every unique parameter permutation triggers a full DB query. With 7 parameters and automated tooling, an attacker can sustain thousands of DB queries per second that would otherwise be served from cache.
- **Denial of service on the DB layer:** The mirror node's PostgreSQL backend is exposed to query load that the cache tier was designed to absorb, potentially degrading or denying service to all users.
- **No authentication required:** The `/api/v1/transactions` endpoint is publicly accessible; no credentials or elevated privileges are needed.

**Severity: High** — unauthenticated, trivially automatable, directly degrades availability of a core API endpoint.

### Likelihood Explanation

- **Precondition:** None beyond network access to the API.
- **Skill required:** Minimal — reordering URL query parameters is trivial with any HTTP client or script.
- **Repeatability:** Fully repeatable and automatable; a simple loop over parameter permutations suffices.
- **Detection difficulty:** Requests are individually valid and indistinguishable from normal traffic at the HTTP layer; only anomalous cache-miss rates or DB load would signal an attack.

### Recommendation

Apply query-parameter normalization **before** `cacheKeyGenerator()` is called. The existing `normalizeRequestQueryParams()` in `rest/middleware/requestNormalizer.js` already sorts parameters and adds defaults — it should be:

1. Exported from `rest/middleware/index.js`.
2. Registered as Express middleware in `rest/server.js` **before** `responseCacheCheckHandler`.
3. `cacheKeyGenerator()` should then hash the normalized URL (e.g., from `res.locals` after normalization) rather than `req.originalUrl`.

Alternatively, inside `cacheKeyGenerator()` itself, parse `req.query`, sort keys alphabetically, and reconstruct a canonical query string before hashing — ensuring parameter order is irrelevant to the cache key.

### Proof of Concept

```bash
# Seed the cache with one ordering
curl "https://<mirror-node>/api/v1/transactions?limit=10&order=asc"

# Request with reordered parameters — cache MISS, triggers new DB query
curl "https://<mirror-node>/api/v1/transactions?order=asc&limit=10"

# Automate all permutations of 3 parameters (6 total)
for params in \
  "limit=10&order=asc&result=success" \
  "limit=10&result=success&order=asc" \
  "order=asc&limit=10&result=success" \
  "order=asc&result=success&limit=10" \
  "result=success&limit=10&order=asc" \
  "result=success&order=asc&limit=10"; do
  curl -s -o /dev/null "https://<mirror-node>/api/v1/transactions?$params"
done
# Each of the 6 requests is a cache miss and triggers a separate DB query.
# Extend to 7 parameters for up to 5040 unique cache-busting permutations.
```