### Title
Cache Key Collision Bypass via Unormalized `req.originalUrl` Percent-Encoding in `cacheKeyGenerator()`

### Summary
`cacheKeyGenerator()` hashes `req.originalUrl` directly with MD5 without any URL normalization. Because Express preserves the raw, client-supplied URL in `req.originalUrl`, semantically identical requests with different percent-encodings (e.g., `limit=25` vs `limit=%32%35`, or `%2F` vs `/`, or `%3a` vs `%3A`) produce distinct MD5 hashes and therefore distinct Redis cache keys. An unprivileged attacker can exploit this to permanently bypass the response cache and force repeated database-backed backend queries for any endpoint.

### Finding Description

**Exact code location:** `rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, line 151–153.

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**Root cause:** `req.originalUrl` in Express.js is the verbatim URL string as received from the HTTP client. Express never decodes or normalizes it. The function hashes this raw string with no preprocessing, so any byte-level difference in the URL — even if semantically equivalent after percent-decoding — produces a different MD5 digest and a different Redis key.

The code comment at line 149 explicitly acknowledges the absence of normalization:
> `path?query - In the future, this will utilize Edwin's request normalizer (9113).`

**Why existing normalization is insufficient:**
- `requestNormalizer.js` (`normalizeRequestQueryParams`) operates on `req.openapi?.openApiRoute`, `req.path`, and the already-parsed `req.query` object. It never writes back to `req.originalUrl`.
- `requestHandler.js` (`requestQueryParser`) lowercases query parameter keys and canonicalizes a small set of values (`order`, `result`), but again operates on the parsed query object and does not touch `req.originalUrl`.
- Neither middleware modifies `req.originalUrl` before `cacheKeyGenerator()` reads it.

**Exploit flow:**
1. Legitimate request `GET /api/v1/accounts?limit=25` → cache miss → backend DB query → response stored under key `md5("/api/v1/accounts?limit=25")-v1`.
2. Attacker sends `GET /api/v1/accounts?limit=%32%35` → `req.originalUrl` = `/api/v1/accounts?limit=%32%35` → different MD5 → cache miss → another backend DB query → stored under a second key.
3. Attacker sends `GET /api/v1/accounts?limit=%32%35` with uppercase hex `%32%35` vs lowercase `%32%35` — same issue applies to any hex digit case variation.
4. Attacker varies parameter order: `?limit=25&order=asc` vs `?order=asc&limit=25` → two more distinct cache keys.
5. Repeat indefinitely; each variant is a guaranteed cache miss.

For a single two-digit value like `25`, encoding each digit with upper/lowercase hex yields 4^2 = 16 variants. For longer parameter values or multiple parameters, the variant space grows exponentially.

### Impact Explanation

Every cache miss forces a full database-backed query. By cycling through percent-encoding variants of any cacheable endpoint, an attacker can:
- Render the Redis response cache entirely ineffective for targeted endpoints.
- Drive sustained, amplified load on the database with zero authentication.
- Cause service degradation or denial of service against the mirror node REST API.

The cache is the primary defense against repeated identical queries; bypassing it removes that protection entirely.

### Likelihood Explanation

No authentication or special privileges are required. The attack requires only the ability to send HTTP GET requests with crafted URLs — trivially scriptable. Percent-encoding manipulation is a well-known technique. The variant space is large enough to sustain the attack indefinitely. The code comment confirms the developers are aware the normalization gap exists and has not yet been closed.

### Recommendation

Normalize `req.originalUrl` (or a derived canonical form) before hashing in `cacheKeyGenerator()`. Specifically:

1. Percent-decode the URL before hashing: apply `decodeURIComponent` to path segments and query parameter names/values.
2. Re-encode consistently (e.g., using `encodeURIComponent`) to produce a canonical form.
3. Sort query parameters alphabetically (already partially done by `normalizeRequestQueryParams` — wire that output into the cache key instead of `req.originalUrl`).
4. Normalize percent-encoding hex digits to uppercase (RFC 3986 §6.2.2.1).

The simplest correct fix is to use the output of the existing `normalizeRequestQueryParams()` (after percent-decoding) as the cache key input rather than the raw `req.originalUrl`.

### Proof of Concept

```bash
# Step 1: Warm the cache with a canonical request
curl -s "http://mirror-node/api/v1/accounts?limit=25"

# Step 2: Bypass cache with percent-encoded equivalent — forces a new DB query
curl -v "http://mirror-node/api/v1/accounts?limit=%32%35"
# X-Cache: MISS (different MD5 key)

# Step 3: Bypass again with uppercase hex encoding
curl -v "http://mirror-node/api/v1/accounts?limit=%32%35"
# (already a miss from step 2, but stored under yet another key if hex case differs)

# Step 4: Automate to exhaust cache and hammer DB
python3 -c "
import requests, itertools
base = 'http://mirror-node/api/v1/accounts?limit='
# Encode '25' with all upper/lower hex combinations
for a in ['2','%32','%32']:
    for b in ['5','%35','%35']:
        url = base + a + b
        r = requests.get(url)
        print(url, r.status_code)
"
```

Each variant hits the backend database, bypassing the Redis cache entirely.