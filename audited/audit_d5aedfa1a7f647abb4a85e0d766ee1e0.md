### Title
Unauthenticated Sustained Database Load via Uncached Negative Alias Lookups in `getEncodedId()`

### Summary
Any unauthenticated external user can submit an unbounded stream of syntactically valid but non-existent account alias strings to the REST API. Each request passes `AccountAlias.isValid()`, triggers a live database query via `getAccountFromAlias()`, and returns a 404 — which is explicitly excluded from the response cache. With no rate limiting and no negative-result caching, an attacker can sustain arbitrarily high database query rates using a trivially generated stream of unique base32 strings.

### Finding Description
**Code path:**

`getEncodedId()` — `rest/service/entityService.js` lines 125–126:
```js
} else if (AccountAlias.isValid(entityIdString)) {
  return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
}
```

`AccountAlias.isValid()` — `rest/accountAlias.js` line 41–44 — accepts any string matching `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/`. This includes bare aliases (`ABCDEFG`), one-prefix aliases (`0.ABCDEFG`), and two-prefix aliases (`0.0.ABCDEFG`). The character set is 32 symbols; even 7-character strings yield ~34 billion unique valid inputs.

`AccountAlias.fromString()` — `rest/accountAlias.js` lines 51–64 — splits the string, pads with nulls, and constructs an `AccountAlias`. The `validate()` call at line 29 only throws if the provided shard/realm is non-null AND mismatches the configured value. For the common case (realm=0, shard=0), `0.ABCDEFG` passes cleanly.

`getAccountFromAlias()` — `rest/service/entityService.js` lines 42–53 — unconditionally executes:
```sql
SELECT id FROM entity WHERE coalesce(deleted, false) <> true AND alias = $1
```
for every call. There is no in-process cache, no negative-result memoization, and no deduplication.

**Why the response cache does not help:**

`responseCacheUpdateHandler` — `rest/middleware/responseCacheHandler.js` line 95:
```js
if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```
Only HTTP 2xx responses are stored in Redis. A 404 `NotFoundError` (the result of a missing alias) is never cached. Every unique alias string that does not exist in the database will always reach the database, regardless of how many times it has been queried before.

**No rate limiting:** A glob search for `rateLimit*` across the entire repository returned no results. There is no application-layer throttling on alias lookup endpoints.

### Impact Explanation
An attacker can drive an arbitrary number of `SELECT` queries against the `entity` table by cycling through unique valid base32 strings. If the `alias` column lacks a covering index, each query is a full or partial table scan. Even with an index, connection pool exhaustion and I/O saturation are achievable at modest request rates from a single client. This degrades or denies service for all legitimate users of the mirror node REST API, which serves as the primary read interface for the Hedera/Hiero network state.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and zero knowledge of the system beyond the public API schema. The input space is effectively infinite. A single attacker with a standard HTTP client and a loop can sustain the attack indefinitely. The alias format is documented in the public OpenAPI spec, making discovery trivial.

### Recommendation
1. **Cache negative results**: After a failed alias lookup, store a sentinel value in Redis (with a short TTL, e.g., 30–60 s) keyed on the normalized alias string. Check this cache before issuing a DB query.
2. **Extend the response cache to cover 404s**: Modify `responseCacheUpdateHandler` to also cache 404 responses for alias lookups with a short TTL.
3. **Add application-layer rate limiting**: Introduce per-IP (and optionally global) rate limiting middleware for alias-lookup endpoints, e.g., using `express-rate-limit`.
4. **Ensure a database index exists** on `entity.alias` to bound per-query cost.

### Proof of Concept
```bash
# Generate and send unique valid base32 alias strings in a tight loop.
# No authentication, no special headers required.

BASE32_CHARS="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
i=0
while true; do
  # Produce a unique 8-character base32 alias by encoding the counter
  ALIAS=$(printf '%08d' $i | tr '0-9' 'ABCDEFGHIJ')
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.${ALIAS}" -o /dev/null &
  i=$((i+1))
  # Throttle only to avoid local resource exhaustion; remove sleep for full attack
  [ $((i % 100)) -eq 0 ] && wait
done
```

Each request:
1. Passes `AccountAlias.isValid()` (regex matches `0.XXXXXXXX`)
2. Passes `AccountAlias.fromString()` (realm=0 matches configured realm)
3. Executes `SELECT id FROM entity WHERE ... AND alias = $1` against the live DB
4. Returns HTTP 404 — not cached
5. Next request with a different alias string repeats from step 1