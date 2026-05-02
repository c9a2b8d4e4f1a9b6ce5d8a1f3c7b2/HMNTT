### Title
Unauthenticated Pagination Abuse via `limit=1` in `getTokenRelationships()` Enables DB Query Amplification DoS

### Summary
The `getTokenRelationships()` handler in `rest/controllers/tokenController.js` accepts `limit=1` from any unauthenticated caller and issues one database query to `token_account` per HTTP request. Because the REST server has no rate-limiting middleware, an attacker can follow pagination links in a tight loop, forcing up to 100× more database queries than a single request with the maximum limit of 100 would require, with no mechanism to stop or slow the flood.

### Finding Description
**Code path:**

`getTokenRelationships()` (tokenController.js:66–92) calls `TokenService.getTokenAccounts(query)` (tokenService.js:96–115), which unconditionally executes one SQL query against `token_account` and, for uncached tokens, a second query against the `token` table.

**Root cause – no lower-bound enforcement on `limit`:**

`filterValidityChecks` for `filterKeys.LIMIT` delegates to `isPositiveLong(val)` (utils.js:330–331), which accepts any integer ≥ 1. The OpenAPI spec declares `minimum: 1` (openapi.yml:4975). There is no floor that prevents `limit=1`.

**Root cause – no rate limiting on the REST server:**

`server.js` registers only: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, and `responseCacheCheckHandler`. There is no per-IP or global request-rate-limiting middleware. The throttle infrastructure found in the codebase (`web3/ThrottleManagerImpl`, `ThrottleConfiguration`) is exclusively wired to the `web3` module (contract calls) and is entirely absent from the REST server.

**Exploit flow:**

1. Attacker issues `GET /api/v1/accounts/{victimAccountId}/tokens?limit=1`.
2. Each response contains `links.next` pointing to the next token (tokenController.js:77–83).
3. Attacker immediately follows the link, repeating for every token association on the account.
4. Each iteration triggers `getTokenAccounts()` → one `SELECT … FROM token_account … LIMIT 1` query (tokenService.js:97–98).
5. With N token associations, the attacker forces N sequential (or concurrent, from multiple threads) DB queries instead of the ⌈N/100⌉ queries a `limit=100` caller would require — up to 100× amplification.
6. The `quickLru` token cache (tokenService.js:12–14) only mitigates the secondary `token` table query after first access; the primary `token_account` query is issued fresh on every request.

**Why existing checks fail:**

- `isPositiveLong` explicitly accepts 1 (utils.js:93–101, confirmed by test at utils.test.js:494–498).
- `buildAndValidateFilters` passes the validated `limit=1` straight through to the query builder (tokenController.js:72–73).
- The response cache (`responseCacheCheckHandler`) does not help because each paginated URL carries a different `token.id` cursor, producing a distinct cache key per page.
- No authentication is required; the endpoint is fully public.

### Impact Explanation
Each `limit=1` request consumes a DB connection from the pool and executes an indexed but non-trivial query (account_id + associated = true + ORDER BY token_id + LIMIT). A single attacker with a script can sustain hundreds of requests per second. With accounts holding thousands of token associations (common on mainnet), the attacker can saturate the PostgreSQL connection pool (`db.pool.maxConnections`), causing query queuing, timeout errors, and cascading failures across all REST endpoints served by the same pool. Because the REST mirror node is a shared read service, degrading its database degrades all consumers, consistent with ≥30% processing-node impact in a multi-instance deployment.

### Likelihood Explanation
The attack requires zero privileges, zero tokens, and zero on-chain activity. Any public Hedera account with many token associations (or the attacker can use a known whale account) serves as the target. The pagination link structure is self-describing, making automation trivial. The attack is repeatable indefinitely and can be parallelised across multiple source IPs to bypass any upstream network-layer rate limiting.

### Recommendation
1. **Enforce a minimum effective limit**: Change the `LIMIT` validation in `filterValidityChecks` (utils.js:330–331) to reject values below a configurable floor (e.g., 10 or 25) for this endpoint, or add a per-endpoint minimum in `extractTokensRelationshipQuery`.
2. **Add rate limiting to the REST server**: Introduce a per-IP token-bucket middleware (e.g., `express-rate-limit`) in `server.js` before the route handlers, mirroring the pattern already used in the `web3` module.
3. **Cap concurrent DB connections per endpoint**: Use a semaphore or query-queue in `BaseService.getRows` to bound the number of simultaneous `token_account` queries.
4. **Increase the default limit floor**: The OpenAPI spec should raise `minimum` from 1 to a value that makes pagination abuse economically unattractive.

### Proof of Concept
```bash
# Step 1: identify an account with many token associations (e.g., 0.0.12345)
ACCOUNT="0.0.12345"
BASE="https://<mirror-node>/api/v1"
NEXT="${BASE}/accounts/${ACCOUNT}/tokens?limit=1"

# Step 2: follow pagination in a tight loop — each iteration = 1 DB query
while [ -n "$NEXT" ]; do
  RESP=$(curl -s "$NEXT")
  NEXT=$(echo "$RESP" | jq -r '.links.next // empty')
  [ -n "$NEXT" ] && NEXT="${BASE}${NEXT}"
done
# With N token associations this loop issues N queries instead of ceil(N/100).
# Run 10–50 parallel instances to exhaust the DB connection pool.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** rest/utils.js (L93-101)
```javascript
const isPositiveLong = (num, allowZero = false) => {
  if (!positiveLongRegex.test(num)) {
    return false;
  }

  const bigInt = BigInt(num);
  const min = allowZero ? 0 : 1;
  return bigInt >= min && bigInt <= maxLong;
};
```

**File:** rest/utils.js (L330-331)
```javascript
    case constants.filterKeys.LIMIT:
      ret = isPositiveLong(val);
```

**File:** rest/server.js (L67-98)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```
