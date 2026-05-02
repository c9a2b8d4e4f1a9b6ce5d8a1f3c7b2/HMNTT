### Title
Double Sequential DB Query Per Request via Cold Token Cache in `getTokenAccounts()`

### Summary
`getTokenAccounts()` in `rest/service/tokenService.js` unconditionally issues a first DB query (`tokenRelationshipsQuery`) and then, when the in-process LRU token cache is cold, issues a second sequential DB query (`tokenCacheQuery`) against the `token` table. An unauthenticated attacker can keep the cache cold by cycling through accounts associated with tokens not yet cached, forcing every request to consume two sequential connection acquisitions from the 10-connection pool and halving effective throughput under moderate concurrency.

### Finding Description

**Exact code path:**

`rest/service/tokenService.js`, `getTokenAccounts()`, lines 96–115: [1](#0-0) 

Line 98 always executes the first query: [2](#0-1) 

Line 104 calls `getCachedTokens()`, which at lines 148–152 issues a second DB query whenever any returned token ID is absent from the in-process LRU cache: [3](#0-2) 

`BaseService.getRows()` (line 55–57) calls `this.pool().queryQuietly()` for each invocation — each call independently acquires a connection from the pool, executes, and releases it: [4](#0-3) 

**Root cause / failed assumption:** The design assumes the in-process `quickLru` cache (default `maxSize: 100,000`) will be warm for most tokens in steady state. This assumption fails when an attacker deliberately cycles through accounts whose associated tokens are not cached, keeping the cache perpetually cold. [5](#0-4) 

**Why the cache check is insufficient:** The LRU cache is process-local and has no TTL — it only evicts on size overflow. An attacker with knowledge of token IDs (all public on-chain) can rotate through accounts associated with distinct tokens, ensuring each request hits uncached token IDs. On Hedera mainnet, the number of tokens far exceeds the 100,000-entry cache, making sustained cache-cold attacks straightforward.

### Impact Explanation

The REST API DB pool is capped at **10 connections** by default: [6](#0-5) 

Under cache-cold conditions, each request to `/api/v1/accounts/{id}/tokens` consumes two sequential connection acquisitions. With 10 connections and requests requiring 2 sequential round-trips each, the maximum concurrent in-flight requests that can make progress is halved. Excess requests queue waiting for a free connection. Under moderate concurrency (e.g., 10–20 concurrent attackers), legitimate requests experience severe latency degradation or connection-timeout errors (`connectionTimeout` default: 20,000 ms), constituting a non-network-based DoS against the REST API's token relationship endpoint. [7](#0-6) 

### Likelihood Explanation

- The endpoint is fully public with no authentication or rate limiting enforced at the service layer.
- Token IDs are enumerable from the public ledger.
- An attacker needs only a list of token IDs exceeding the 100,000-entry cache and a set of accounts with associations to those tokens — both trivially obtainable from the mirror node's own `/api/v1/tokens` endpoint.
- The attack is repeatable and requires no special privileges, network position, or cryptographic material.
- A single attacker with ~10–20 concurrent HTTP connections is sufficient to saturate the pool.

### Recommendation

1. **Merge the two queries into one JOIN**: Rewrite `getTokenAccounts()` to JOIN `token_account` with `token` in a single SQL query, eliminating the second round-trip entirely. The cache becomes unnecessary for this path.
2. **If the cache is retained**: Add a per-request deduplication guard or use a shared/distributed cache (Redis is already available in the stack) so the cache is not per-process and cold-start attacks are harder to sustain.
3. **Add rate limiting** on the `/accounts/{id}/tokens` endpoint at the API gateway or middleware layer.
4. **Increase pool size** or add a connection-wait timeout that returns HTTP 503 early rather than queuing indefinitely.

### Proof of Concept

**Preconditions:**
- Mirror node REST API running with default config (10 DB connections, 100,000-entry token cache).
- Attacker has enumerated >100,000 distinct token IDs from `/api/v1/tokens`.
- Attacker has identified accounts associated with those tokens.

**Steps:**
```bash
# 1. Enumerate token IDs (public endpoint, no auth)
curl "https://<mirror-node>/api/v1/tokens?limit=100&order=asc" | jq '.tokens[].token_id'

# 2. Find accounts associated with each token
curl "https://<mirror-node>/api/v1/tokens/<token_id>/balances?limit=1" | jq '.balances[].account'

# 3. Flood with concurrent requests cycling through accounts with uncached token associations
# Using GNU parallel or a simple loop:
for i in $(seq 1 500); do
  curl -s "https://<mirror-node>/api/v1/accounts/<account_$i>/tokens" &
done
wait
```

**Result:** Each request triggers 2 sequential DB queries. With 10 concurrent requests cycling through cold-cache token IDs, the 10-connection pool is saturated. Legitimate requests begin timing out or receiving 503/504 errors. The attack sustains itself as long as the attacker cycles through token IDs faster than the LRU cache can warm up. [1](#0-0)

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L96-115)
```javascript
  async getTokenAccounts(query) {
    const {sqlQuery, params} = this.getTokenRelationshipsQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    if (rows.length === 0) {
      return [];
    }

    const tokenIds = rows.reduce((result, row) => result.add(row.token_id), new Set());
    const cachedTokens = await this.getCachedTokens(tokenIds);
    return rows.map((row) => {
      const cachedToken = cachedTokens.get(row.token_id);
      if (cachedToken) {
        row.decimals = cachedToken.decimals;
        row.freeze_status = row.freeze_status ?? cachedToken.freezeStatus;
        row.kyc_status = row.kyc_status ?? cachedToken.kycStatus;
      }

      return new TokenAccount(row);
    });
  }
```

**File:** rest/service/tokenService.js (L148-152)
```javascript
    if (uncachedTokenIds.length === 0) {
      return cachedTokens;
    }

    const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
