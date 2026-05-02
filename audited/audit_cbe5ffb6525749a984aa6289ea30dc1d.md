### Title
Cache Stampede in `doGetTransactions` Allows Unprivileged DB Connection Exhaustion (Mirror Node DoS)

### Summary
`getTransactionTimestamps()` issues a direct `pool.queryQuietly()` on every request with no caching, and `cache.get()` in `cache.js` contains no in-flight deduplication or locking. Concurrent requests sharing the same timestamp range all pass the cache-miss check simultaneously and each independently invoke `getTransactionsDetails()` → `pool.queryQuietly()`, multiplying DB load linearly with concurrency. This can exhaust the DB connection pool and render the mirror node API unavailable. Note: the mirror node is a read-only service and does not participate in Hedera consensus; the impact is mirror node API DoS, not literal network-wide transaction confirmation failure.

### Finding Description

**Path 1 — `getTransactionTimestamps()` is never cached:** [1](#0-0) 

Every call to `doGetTransactions` unconditionally executes `pool.queryQuietly(query, params)` at line 483. There is no cache lookup before this call. N concurrent requests with the same timestamp range produce N independent DB queries here.

**Path 2 — `cache.get()` has no stampede protection:** [2](#0-1) 

The `get` method:
1. Calls `mgetBuffer` to check Redis for all keys (line 104–106).
2. Collects `missingKeys` (line 110).
3. If any are missing, immediately calls `loader(missingKeys)` (line 113).

There is no mutex, no promise deduplication, no Redis `SETNX`/`SET NX` locking, and no "in-flight" tracking. All N concurrent requests that arrive before the first `mset` completes (line 130) will independently observe a full cache miss and each call `loader` → `getTransactionsDetails` → `pool.queryQuietly`.

**Root cause:** The two-phase design (timestamp query → detail query) means every request pays one uncached DB round-trip unconditionally, and the second query is only protected by a cache with no concurrent-miss guard.

### Impact Explanation
An attacker sending a burst of concurrent requests to `/api/v1/transactions?timestamp=gte:X&timestamp=lte:Y` with a fixed timestamp range causes:
- N uncached `getTransactionTimestamps` queries (always, regardless of cache state).
- Up to N additional `getTransactionsDetails` queries (on cold cache or cache miss window).

With a sufficiently large burst, the DB connection pool is saturated. Subsequent legitimate requests queue or fail, making the mirror node API unavailable. This is a Denial-of-Service against the mirror node REST API. It does **not** affect Hedera consensus nodes or transaction confirmation at the network layer.

### Likelihood Explanation
- No authentication is required; the `/transactions` endpoint is public.
- The attack is trivially repeatable with standard HTTP load tools (`ab`, `wrk`, `hey`).
- The cold-cache window is always present on service restart or after Redis eviction (`maxmemory-policy` is configurable and can evict keys).
- The `mset` at line 130 sets keys with **no TTL**, so once populated keys persist until eviction — but the stampede window exists on every cold start and every eviction cycle.

### Recommendation
1. **Deduplicate in-flight loader calls** in `cache.get()`: use a `Map<key, Promise>` to track in-progress loads and return the existing promise to subsequent callers for the same key instead of issuing a new `loader` call.
2. **Cache the timestamp-query result** in `getTransactionTimestamps` (or at the `doGetTransactions` level) using a short TTL keyed on the normalized query parameters, so the first DB round-trip is also deduplicated.
3. **Set a TTL on `mset`** (replace with `msetex` or pipeline `setex` calls) to prevent unbounded Redis memory growth and ensure stale data is evicted predictably.
4. Apply rate limiting per IP on the `/transactions` endpoint to bound burst concurrency.

### Proof of Concept
```bash
# Send 200 concurrent requests with the same timestamp range before cache is warm
hey -n 200 -c 200 \
  "https://<mirror-node>/api/v1/transactions?timestamp=gte:1700000000.000000000&timestamp=lte:1700000060.000000000"
```
Expected result: DB connection pool saturates; subsequent requests receive 500 errors or time out. DB monitoring will show a spike of identical concurrent queries from `getTransactionTimestamps` and `getTransactionsDetails`.

### Citations

**File:** rest/transactions.js (L451-486)
```javascript
const getTransactionTimestamps = async (filters, timestampRange) => {
  if (timestampRange.eqValues.length > 1 || timestampRange.range?.isEmpty()) {
    return {rows: []};
  }

  const result = extractSqlFromTransactionsRequest(filters);
  if (result === null) {
    return {rows: []};
  }
  const {accountQuery, creditDebitQuery, limit, limitQuery, order, resultTypeQuery, transactionTypeQuery, params} =
    result;

  let nextTimestamp;
  if (timestampRange.eqValues.length === 0) {
    const {range, next} = await bindTimestampRange(timestampRange.range, order);
    timestampRange.range = range;
    nextTimestamp = next;
  }

  let [timestampQuery, timestampParams] = utils.buildTimestampQuery('t.consensus_timestamp', timestampRange);
  timestampQuery = utils.convertMySqlStyleQueryToPostgres(timestampQuery, params.length + 1);
  params.push(...timestampParams);

  const query = getTransactionTimestampsQuery(
    accountQuery,
    timestampQuery,
    resultTypeQuery,
    limitQuery,
    creditDebitQuery,
    transactionTypeQuery,
    order
  );
  const {rows} = await pool.queryQuietly(query, params);

  return {limit, order, nextTimestamp, rows};
};
```

**File:** rest/cache.js (L95-132)
```javascript
  async get(keys, loader, keyMapper = (k) => (k ? k.toString() : k)) {
    if (isEmpty(keys)) {
      return [];
    }
    if (!this.ready) {
      return loader(keys);
    }

    const buffers =
      (await this.redis
        .mgetBuffer(map(keys, keyMapper))
        .catch((err) => logger.warn(`Redis error during mget: ${err.message}`))) || new Array(keys.length);
    const values = buffers.map((t) => JSONParse(t));

    let i = 0;
    const missingKeys = keys.filter(() => isNil(values[i++]));

    if (missingKeys.length > 0) {
      const missing = await loader(missingKeys);
      const newValues = [];
      let j = 0;

      missing.forEach((value) => {
        // Update missing values in Redis array
        for (; j < values.length; j++) {
          if (isNil(values[j])) {
            values[j] = value;
            newValues.push(keyMapper(keys[j]));
            newValues.push(JSONStringify(value));
            break;
          }
        }
      });

      if (newValues.length > 0) {
        this.redis.mset(newValues).catch((err) => logger.warn(`Redis error during mset: ${err.message}`));
      }
    }
```
