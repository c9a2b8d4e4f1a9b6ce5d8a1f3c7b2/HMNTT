### Title
Cache Key Fragmentation via Case-Variant Hex Transaction Hash in URL Path

### Summary
`cacheKeyGenerator()` in `rest/middleware/responseCacheHandler.js` computes an MD5 hash of `req.originalUrl` verbatim, with no case normalization applied to the URL path. The `/api/v1/transactions/{transactionIdOrHash}` endpoint accepts 48-byte hex transaction hashes whose hex digits are case-insensitive at the database lookup layer, meaning `ae8bebf1...` and `AE8BEBF1...` resolve to the same transaction but produce distinct Redis cache keys. An unprivileged external user can exploit this to fragment the cache, force repeated database queries, and observe inconsistent `cache-control: max-age` values across semantically identical requests.

### Finding Description

**Exact code location:**
`rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, lines 151–153:

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

The comment at lines 141–149 explicitly acknowledges the absence of normalization: *"In the future, this will utilize Edwin's request normalizer (9113)."*

**Root cause:** `req.originalUrl` is used as-is. No path normalization is applied before hashing. The failed assumption is that all semantically equivalent URLs arrive in a canonical form.

**Why hex hashes are case-insensitive at the DB layer:**
In `rest/transactions.js` `extractSqlFromTransactionsByIdOrHashRequest()` (lines 763–783), when `isValidTransactionHash` is true, the hash is decoded via `Buffer.from(transactionIdOrHash, 'hex')`, which is inherently case-insensitive. The validation regex in `rest/transactionHash.js` line 42 accepts `[\dA-Fa-f]{96}` — both upper and lowercase hex digits are valid.

The spec test at `rest/__tests__/specs/transactions/{id}/no-params.json` lines 361–363 confirms that both:
- `/api/v1/transactions/ae8bebf1c9fa0f309356e48057f6047af7cde63037d0509d16ddc3b20e085158bfdf14d15345c1b18b199b72fed4ac6f`
- `/api/v1/transactions/0xae8bebf1c9fa0f309356e48057f6047af7cde63037d0509d16ddc3b20e085158bfdf14d15345c1b18b199b72fed4ac6f`

return HTTP 200 with identical response bodies.

**Why existing normalization is insufficient:**
- `rest/middleware/requestNormalizer.js` `normalizeRequestQueryParams()` (lines 35–59) normalizes only **query parameters**, not URL path segments.
- `rest/middleware/requestHandler.js` `requestQueryParser()` (lines 38–68) lowercases query parameter **keys** and a small set of values (`order`, `result`), but does not touch path parameters.
- The cache middleware is applied globally before any route handler via `app.useExt(responseCacheCheckHandler)` in `rest/server.js` line 97, so it runs before any per-route normalization could occur.

**Exploit flow:**
1. Attacker sends `GET /api/v1/transactions/ae8bebf1c9fa0f309356e48057f6047af7cde63037d0509d16ddc3b20e085158bfdf14d15345c1b18b199b72fed4ac6f` → cache miss → DB hit → response cached under key `md5("...ae8beb...") + "-v1"`.
2. Attacker sends `GET /api/v1/transactions/AE8BEBF1C9FA0F309356E48057F6047AF7CDE63037D0509D16DDC3B20E085158BFDF14D15345C1B18B199B72FED4AC6F` → different MD5 → cache miss → another DB hit → cached under a different key.
3. Repeating with mixed-case variants (e.g., alternating nibbles) multiplies cache entries and DB queries for the same transaction.

### Impact Explanation
Every distinct case-variant of a 96-hex-character hash generates a separate Redis cache entry and a separate database query. This degrades cache hit rates, increases Redis memory consumption, and amplifies database load proportionally to the number of case variants an attacker cycles through. Clients observing responses from different cache entries will see different `cache-control: max-age` values for the same transaction, producing inconsistent apparent freshness. Severity is **Medium**: no data integrity or authentication bypass is possible, but the attack is a realistic cache-layer DoS amplifier requiring zero privileges.

### Likelihood Explanation
Any unauthenticated HTTP client can trigger this. No special knowledge beyond the transaction hash format is required. The attack is trivially scriptable: generate all-uppercase, all-lowercase, and mixed-case variants of a known transaction hash and issue one request per variant. The `DEFAULT_REDIS_EXPIRY = 1` second means cache entries expire quickly, so the attacker must sustain the request stream to keep the DB under load, but this is trivially achievable. Repeatability is unlimited.

### Recommendation
Normalize the URL path to lowercase before computing the cache key. The minimal fix is:

```js
const cacheKeyGenerator = (req) => {
  const normalizedUrl = req.originalUrl.toLowerCase();
  return crypto.createHash('md5').update(normalizedUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

A more robust fix is to integrate the already-planned `requestNormalizer` (issue 9113) so that `req.originalUrl` is rewritten to a canonical form (lowercase hex path, sorted query params) before the cache key is computed. The `requestNormalizer.js` `normalizeRequestQueryParams()` should be extended to also canonicalize path parameters that are known to be case-insensitive (hex hashes, entity IDs).

### Proof of Concept

```bash
HASH="ae8bebf1c9fa0f309356e48057f6047af7cde63037d0509d16ddc3b20e085158bfdf14d15345c1b18b199b72fed4ac6f"
HASH_UPPER=$(echo $HASH | tr 'a-f' 'A-F')
BASE="http://localhost:5551/api/v1/transactions"

# Request 1: lowercase hash — cache miss, DB hit, response cached under key A
curl -v "$BASE/$HASH"

# Request 2: uppercase hash — cache miss (different key), DB hit again, cached under key B
curl -v "$BASE/$HASH_UPPER"

# Request 3: lowercase again — cache HIT (key A), max-age differs from key B's remaining TTL
curl -v "$BASE/$HASH"

# Automate fragmentation:
for i in $(seq 1 1000); do
  VARIANT=$(echo $HASH | sed 's/./\U&/g;s/[0-9]/\L&/g')  # mixed case
  curl -s "$BASE/$VARIANT" > /dev/null &
done
```

Both requests 1 and 2 return HTTP 200 with identical transaction data but are served from separate cache entries, confirming the fragmentation. Observe Redis key count growing with `redis-cli DBSIZE` during the loop.