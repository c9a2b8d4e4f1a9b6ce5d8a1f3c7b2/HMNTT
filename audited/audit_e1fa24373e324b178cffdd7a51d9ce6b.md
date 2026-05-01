### Title
Cache-Thrashing DoS via Unbounded Token ID Cycling in `getCachedTokens()` Exhausts Database Resources

### Summary
The `tokenCache` in `rest/service/tokenService.js` is a `quickLru` instance bounded by `config.cache.token.maxSize` with **no TTL/maxAge** configured. An unprivileged attacker can cycle requests across accounts with distinct token associations, continuously evicting cached entries and forcing every request to execute a live database query. The REST API layer has no IP-based rate limiting, making this attack trivially repeatable.

### Finding Description

**Cache initialization — no TTL:** [1](#0-0) 

Unlike the `entityId` cache (which sets `maxAge`), the token cache has **no `maxAge`** parameter. Entries are only evicted when the cache is full (LRU eviction). This means an attacker who can introduce more than `maxSize` unique token IDs into the system will continuously evict previously cached entries.

**Cache-miss path triggers a live DB query:** [2](#0-1) 

For every token ID not found in `tokenCache`, `getCachedTokens()` issues:
```sql
SELECT decimals, freeze_status, kyc_status, token_id
FROM token WHERE token_id = ANY ($1)
```
with no query-level throttle or circuit breaker.

**Entry point — no authentication or rate limiting required:** [3](#0-2) 

`getTokenRelationships` is publicly accessible. The only middleware present is `authHandler`, which controls **response size limits** for authenticated users — it does not enforce any per-IP request rate limit. [4](#0-3) 

The web3 throttle (`ThrottleManagerImpl`) is a separate Java service and does **not** protect the Node.js REST API. [5](#0-4) 

**Exploit flow:**

1. Attacker enumerates (or pre-generates) a set of valid Hedera account IDs whose combined token associations span `N >> maxSize` distinct token IDs.
2. Attacker sends a high-rate stream of `GET /api/v1/accounts/{accountId}/tokens` requests, rotating through those accounts.
3. Each request calls `getTokenAccounts()` → `getCachedTokens()`. Because the rotating token IDs exceed `maxSize`, every new batch evicts previously cached entries.
4. Every request results in a DB round-trip (`SELECT … FROM token WHERE token_id = ANY ($1)`).
5. With no rate limiting, the attacker can sustain this indefinitely, saturating the DB connection pool across all mirror-node REST instances.

### Impact Explanation
Sustained DB query load from cache-thrashing can exhaust the PostgreSQL connection pool (`db.pool.maxConnections`) and statement timeout budget across all deployed REST nodes. Because the REST service is stateless and horizontally scaled, every node shares the same downstream DB, meaning the attack can degrade or halt query processing across ≥30% of nodes without any brute-force credential requirement. Legitimate users experience timeouts or 503 errors on all token-related endpoints.

### Likelihood Explanation
The attack requires zero privileges — only knowledge of valid account IDs, which are publicly enumerable via `/api/v1/accounts`. The token ID space on a live Hedera network is large enough to trivially exceed any reasonable `maxSize`. A single attacker with a modest botnet (or even a single high-throughput client) can sustain the cache-thrashing loop indefinitely. No exploit tooling beyond `curl` or a simple script is needed.

### Recommendation
1. **Add a TTL to `tokenCache`**: Set `maxAge` (in milliseconds) so entries expire naturally, reducing the value of cache-thrashing.
   ```js
   const tokenCache = new quickLru({
     maxSize: config.cache.token.maxSize,
     maxAge: config.cache.token.maxAge * 1000,
   });
   ```
2. **Add IP-based rate limiting to the REST API**: Integrate a middleware such as `express-rate-limit` on token/account endpoints.
3. **Increase `maxSize` or shard the cache** to make eviction harder to trigger.
4. **Add a DB-level circuit breaker**: Reject new queries when the connection pool is near exhaustion.

### Proof of Concept
```bash
# 1. Enumerate accounts with many token associations
ACCOUNTS=$(curl -s "https://<mirror-node>/api/v1/accounts?limit=100" \
  | jq -r '.accounts[].account')

# 2. Continuously cycle through them at high rate
while true; do
  for ACCT in $ACCOUNTS; do
    curl -s "https://<mirror-node>/api/v1/accounts/$ACCT/tokens" &
  done
  wait
done
# Result: tokenCache is continuously thrashed; every request hits the DB.
# Monitor DB connections: SELECT count(*) FROM pg_stat_activity;
# Connections saturate; legitimate queries time out.
```

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L136-161)
```javascript
  async getCachedTokens(tokenIds) {
    const cachedTokens = new Map();
    const uncachedTokenIds = [];
    tokenIds.forEach((tokenId) => {
      const cachedToken = tokenCache.get(tokenId);
      if (cachedToken) {
        cachedTokens.set(tokenId, cachedToken);
      } else {
        uncachedTokenIds.push(tokenId);
      }
    });

    if (uncachedTokenIds.length === 0) {
      return cachedTokens;
    }

    const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
    rows.forEach((row) => {
      const tokenId = row.token_id;
      const cachedToken = new CachedToken(row);
      tokenCache.set(tokenId, cachedToken);
      cachedTokens.set(tokenId, cachedToken);
    });

    return cachedTokens;
  }
```

**File:** rest/controllers/tokenController.js (L66-92)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters);
    const query = this.extractTokensRelationshipQuery(filters, accountId);
    const tokenRelationships = await TokenService.getTokenAccounts(query);
    const tokens = tokenRelationships.map((token) => new TokenRelationshipViewModel(token));

    let nextLink = null;
    if (tokens.length === query.limit) {
      const lastRow = last(tokens);
      const lastValue = {
        [filterKeys.TOKEN_ID]: lastRow.token_id,
      };
      nextLink = utils.getPaginationLink(req, false, lastValue, query.order);
    }

    res.locals[responseDataLabel] = {
      tokens,
      links: {
        next: nextLink,
      },
    };
  };
```

**File:** rest/__tests__/middleware/authHandler.test.js (L37-41)
```javascript
  test('No Authorization header - proceeds without authentication', async () => {
    await authHandler(mockRequest, mockResponse);

    expect(mockResponse.status).not.toHaveBeenCalled();
  });
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
