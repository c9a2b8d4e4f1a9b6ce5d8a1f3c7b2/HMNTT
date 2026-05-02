### Title
Cache Key Bypass via Query Parameter Case Variation in `cacheKeyGenerator()`

### Summary
The `cacheKeyGenerator()` function computes an MD5 hash of `req.originalUrl` — the raw, unmodified request URL — without any case normalization. Although `requestQueryParser` normalizes query parameter keys and select values to lowercase in `req.query`, it never modifies `req.originalUrl`. An unprivileged attacker can therefore send semantically identical requests with varied casing (e.g., `?limit=10` vs `?Limit=10` vs `?LIMIT=10`) to generate distinct cache keys, causing repeated cache misses and forcing the backend to execute a full database query for every variant.

### Finding Description
**Exact code path:**

`cacheKeyGenerator` at `rest/middleware/responseCacheHandler.js` line 151–153:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
`req.originalUrl` is Express's immutable copy of the raw HTTP request URL. No middleware ever rewrites it.

**Root cause — failed assumption:**
The code assumes `req.originalUrl` is already in a canonical form. It is not. `requestQueryParser` in `rest/middleware/requestHandler.js` (lines 56–66) lowercases keys and canonicalizes `order`/`result` values, but only in the parsed `req.query` object:
```js
const lowerKey = key.toLowerCase();
// ...
caseInsensitiveQueryString[lowerKey] = canonicalValue;
```
`req.originalUrl` is never touched. The comment inside `cacheKeyGenerator` itself acknowledges this gap:
> *"In the future, this will utilize Edwin's request normalizer (9113)."*

`normalizeRequestQueryParams` in `rest/middleware/requestNormalizer.js` (lines 35–59) also operates on the parsed query object, not on `req.originalUrl`.

**Exploit flow:**
1. Attacker sends `GET /api/v1/accounts?limit=25&order=asc` → MD5 of `/api/v1/accounts?limit=25&order=asc` → cache key **A** (miss → DB query → cached under A).
2. Attacker sends `GET /api/v1/accounts?Limit=25&order=asc` → MD5 of `/api/v1/accounts?Limit=25&order=asc` → cache key **B** (miss → DB query → cached under B).
3. Attacker sends `GET /api/v1/accounts?limit=25&Order=ASC` → cache key **C** (miss → DB query).
4. Repeat with any permutation of casing across all parameter names and values.

Each variant is semantically identical (backend returns the same data because `req.query` is normalized), but each generates a unique Redis key, so every variant is a cache miss.

### Impact Explanation
Every cache miss triggers a full database query. An attacker with no credentials can enumerate case permutations of common parameters (`limit`, `order`, `account.id`, `timestamp`, etc.) to:
- Exhaust Redis memory with duplicate cached entries.
- Amplify database load proportionally to the number of case variants sent.
- Degrade API availability for legitimate users (cache-DoS / backend amplification).

Severity: **Medium–High**. The cache is the primary defense against repeated identical queries; bypassing it removes that protection entirely for the targeted endpoints.

### Likelihood Explanation
No authentication or special privileges are required. The attack is trivially scriptable: a simple loop over case permutations of a single parameter name (26 variants for a 1-character key, more for longer names) generates enough distinct cache keys to keep the backend under sustained load. It is repeatable indefinitely and requires only standard HTTP tooling.

### Recommendation
Normalize `req.originalUrl` (or derive the cache key from the already-normalized `req.query` object) before hashing. Specifically:
1. **Short-term:** Derive the cache key from the normalized query object (already computed by `requestQueryParser` and `normalizeRequestQueryParams`) rather than from `req.originalUrl`. Reconstruct a canonical URL string from `req.path` + sorted, lowercased query parameters, then hash that.
2. **Long-term:** Complete the integration of the request normalizer referenced in the comment ("Edwin's request normalizer, issue 9113") so that `req.originalUrl` itself is rewritten to a canonical form before `cacheKeyGenerator` is called.

### Proof of Concept
```bash
# All three requests return identical JSON but generate distinct Redis cache keys

curl "https://api.example.com/api/v1/accounts?limit=25&order=asc"
# Cache key: md5("/api/v1/accounts?limit=25&order=asc") → MISS → DB query

curl "https://api.example.com/api/v1/accounts?Limit=25&order=asc"
# Cache key: md5("/api/v1/accounts?Limit=25&order=asc") → MISS → DB query

curl "https://api.example.com/api/v1/accounts?limit=25&Order=ASC"
# Cache key: md5("/api/v1/accounts?limit=25&Order=ASC") → MISS → DB query

# Automate: iterate over case variants of "limit" alone
for param in limit Limit LIMIT lImIt LiMiT; do
  curl -s "https://api.example.com/api/v1/accounts?${param}=25" > /dev/null
done
# Result: 5 distinct cache keys, 5 DB queries, 5 Redis entries — all for the same data
```