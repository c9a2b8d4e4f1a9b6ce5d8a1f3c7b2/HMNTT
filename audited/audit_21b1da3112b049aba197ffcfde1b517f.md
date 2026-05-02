### Title
Cache-Miss Amplification via Non-Existent Transaction Hash Lookups (No Rate Limiting)

### Summary
The REST API accepts any syntactically valid transaction hash and immediately executes a database query against `get_transaction_info_by_hash`. Because `responseCacheUpdateHandler` only caches HTTP 2xx/304 responses, every lookup for a non-existent hash returns a 404 that is never stored in Redis. With no rate limiting present anywhere in the REST middleware stack, an unprivileged attacker can flood the endpoint with an unbounded stream of unique valid-format hashes, each forcing a fresh DB round-trip and degrading query throughput for legitimate users.

### Finding Description

**Validation accepts any well-formed hash without existence pre-check.**

In `rest/transactionHash.js`, `isValidTransactionHash` only checks format via regex:

```
/^([\dA-Za-z+\-\/_]{64}|(0x)?[\dA-Fa-f]{96})$/
``` [1](#0-0) 

Any 48-byte hash (base64url or hex) that matches this pattern is immediately forwarded to `getTransactionHash`, which calls `pool.queryQuietly` against the DB stored procedure: [2](#0-1) 

The stored procedure `get_transaction_info_by_hash` performs **two sequential queries** — first against recent rows, then (if empty) against older rows — making each miss doubly expensive: [3](#0-2) 

**404 responses are never cached.**

`responseCacheUpdateHandler` gates cache writes on `httpStatusCodes.isSuccess(res.statusCode)`: [4](#0-3) 

A non-existent hash throws `NotFoundError` (HTTP 404) at line 774 of `transactions.js`: [5](#0-4) 

That 404 is never written to Redis, so the next request for the same hash (or any new hash) bypasses the cache entirely and hits the DB again.

**No rate limiting exists in the REST middleware.**

A grep across all `rest/**/*.js` files for `rateLimit`, `throttle`, `express-rate`, `slowDown`, or `helmet` returns zero matches. There is no per-IP or global request throttle protecting this endpoint.

**The same pattern applies to the contracts endpoint** via `isValidEthHash` (32-byte / 64 hex-char hashes), which also accepts all-zero or all-one patterns and routes to `getContractTransactionDetailsByHash`: [6](#0-5) [7](#0-6) 

### Impact Explanation
Each unique valid-format hash that does not exist in the database causes two SQL queries against the `transaction_hash` table (one for recent rows, one for older rows). Because 404 responses are never cached, an attacker can sustain an arbitrarily high rate of DB queries with no diminishing returns from the cache layer. This degrades DB connection pool availability and query latency for all concurrent legitimate users. The impact is availability degradation (griefing), not data exfiltration, consistent with the medium severity classification.

### Likelihood Explanation
No special privileges, credentials, or network position are required. Any internet-accessible client can generate an unlimited supply of unique valid-format 48-byte hex hashes (e.g., sequential or random) and submit them at line rate. The attack is trivially scriptable, repeatable, and stateless. The only practical barrier is the attacker's own network bandwidth and the upstream infrastructure's connection limits (neither of which is enforced by the application itself).

### Recommendation
1. **Cache negative results**: Store 404 responses in Redis with a short TTL (e.g., 5–30 seconds). This converts repeated lookups for the same non-existent hash into cache hits.
2. **Add rate limiting**: Introduce per-IP rate limiting middleware (e.g., `express-rate-limit`) on hash-lookup endpoints, rejecting requests that exceed a threshold (e.g., 60 req/min per IP).
3. **Validate hash entropy (optional hardening)**: Reject trivially degenerate inputs (all-zero, all-one) at the validation layer before any DB interaction, as these are never valid transaction hashes.

### Proof of Concept
```bash
# Generate 10,000 unique valid-format 48-byte hex hashes and submit them
# Each will pass isValidTransactionHash, hit the DB twice, return 404 (uncached)

for i in $(seq 1 10000); do
  HASH=$(printf '%096x' $i)   # valid 96-hex-char (48-byte) hash, unique per iteration
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/transactions/0x${HASH}" &
done
wait
```

Each request:
1. Passes the regex in `isValidTransactionHash` (96 hex chars).
2. Calls `getTransactionHash` → `pool.queryQuietly` → `get_transaction_info_by_hash($1)`.
3. Executes up to 2 SQL queries against `transaction_hash`.
4. Returns HTTP 404 — **not written to Redis cache**.
5. The next unique hash repeats the full DB round-trip with no cache benefit.

### Citations

**File:** rest/transactionHash.js (L21-36)
```javascript
const getTransactionHash = async (hash, {order = orderFilterValues.ASC, timestampFilters = []} = {}) => {
  const normalized = normalizeTransactionHash(hash);
  const params = [normalized];

  const timestampConditions = [];
  for (const filter of timestampFilters) {
    timestampConditions.push(`${TransactionHash.CONSENSUS_TIMESTAMP} ${filter.operator} $${params.push(filter.value)}`);
  }

  const query = `${mainQuery}
    ${timestampConditions.length !== 0 ? `where ${timestampConditions.join(' and ')}` : ''}
    ${orderClause} ${order}
    ${limitClause}`;

  const {rows} = await pool.queryQuietly(query, params);
  return normalized !== hash ? rows.filter((row) => row.hash.equals(hash)) : rows;
```

**File:** rest/transactionHash.js (L42-44)
```javascript
const transactionHashRegex = /^([\dA-Za-z+\-\/_]{64}|(0x)?[\dA-Fa-f]{96})$/;

const isValidTransactionHash = (hash) => transactionHashRegex.test(hash);
```

**File:** importer/src/main/resources/db/migration/v2/R__transaction_hash_lookup.sql (L19-33)
```sql
return query
select t.consensus_timestamp, (t.hash || coalesce(t.hash_suffix, ''::bytea)) as hash, t.payer_account_id
from transaction_hash t
where t.consensus_timestamp >= cutoffTsNs
  and t.hash = shortHash;

get diagnostics recent_rows = row_count;

if recent_rows = 0 then
    return query
    select t.consensus_timestamp, (t.hash || coalesce(t.hash_suffix, ''::bytea)) as hash, t.payer_account_id
    from transaction_hash t
    where t.consensus_timestamp < cutoffTsNs
      and t.hash = shortHash;
end if;
```

**File:** rest/middleware/responseCacheHandler.js (L95-95)
```javascript
  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```

**File:** rest/transactions.js (L773-775)
```javascript
    if (rows.length === 0) {
      throw new NotFoundError();
    }
```

**File:** rest/utils.js (L186-193)
```javascript
const ethHashPattern = /^(0x)?([0-9A-Fa-f]{64})$/;
const isValidEthHash = (hash) => {
  if (hash === undefined) {
    return false;
  }

  return ethHashPattern.test(hash);
};
```

**File:** rest/controllers/contractController.js (L1133-1136)
```javascript
    if (utils.isValidEthHash(transactionIdOrHash)) {
      const detailsByHash = await ContractService.getContractTransactionDetailsByHash(
        utils.parseHexStr(transactionIdOrHash)
      );
```
