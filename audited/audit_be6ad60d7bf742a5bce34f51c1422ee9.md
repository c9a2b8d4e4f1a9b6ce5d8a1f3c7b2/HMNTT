### Title
Unauthenticated Request Flooding of NFT Endpoint Exhausts DB Connection Pool and I/O, Degrading Gossip Ingestion

### Summary
The `GET /api/v1/accounts/{id}/nfts` endpoint accepts `limit=100` (the configured maximum) from any unauthenticated caller with no per-IP rate limiting in the REST API layer. Each request causes `NftService.getNfts()` to execute up to three UNIONed SQL sub-queries against the `nft` table, each bounded only by the shared DB connection pool and a per-statement timeout. An attacker flooding this endpoint with concurrent max-limit requests can saturate the DB connection pool and disk I/O, indirectly starving the importer's gossip-write path on the shared PostgreSQL instance.

### Finding Description

**Route registration** — `rest/routes/accountRoute.js:15`:
```js
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```
No authentication or rate-limiting middleware is applied.

**Handler** — `rest/controllers/accountController.js:90-103`:
```js
getNftsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(...);
  const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
  const query = this.extractNftMultiUnionQuery(filters, accountId);
  const nonFungibleTokens = await NftService.getNfts(query);
  ...
};
```

**Limit extraction** — `rest/controllers/accountController.js:52-53`:
```js
case filterKeys.LIMIT:
  limit = filter.value;   // already capped at responseLimit.max (default 100)
```
`formatComparator` in `utils.js` caps the value at `responseLimit.max` (default **100**) for unauthenticated users (`utils.js:544-553`). This is the only guard.

**Query generation** — `rest/service/nftService.js:84-126`: `getQuery()` builds up to **three UNIONed sub-queries** (lower/inner/upper bounds), each carrying `LIMIT $2` where `$2 = 100`. The outer wrapper also carries `LIMIT $2`, so the DB executes up to 3 × 100-row scans plus a merge sort per request.

**No REST-layer rate limiting**: searching `rest/*.js` for `rateLimit`, `express-rate`, `throttle`, `helmet` yields only `dbpool.js` (connection pool config) and `config.js`. The throttling found in `web3/src/main/java/.../ThrottleConfiguration.java` and `ThrottleManagerImpl.java` applies exclusively to the web3/EVM module, not the REST API. The Traefik middleware with `rateLimit` in `charts/hedera-mirror-rosetta/values.yaml` applies only to the Rosetta service.

**DB pool** — `rest/config.js:137-147`: `maxConnections` and `statementTimeout` are the only DB-level guards. A `statementTimeout` limits individual query duration but does not prevent many concurrent queries from filling the pool.

### Impact Explanation
The REST API and the Hedera importer (gossip processor) share the same PostgreSQL instance. Saturating the DB connection pool with concurrent max-limit NFT queries blocks new connections from the importer, and saturating disk I/O (sequential scans on the `nft` table) degrades write throughput for gossip-derived records. This can delay or stall consensus-timestamp ingestion, breaking the mirror node's core function of reflecting the ledger state.

### Likelihood Explanation
No authentication, no API key, no CAPTCHA, and no per-IP rate limit are required. Any internet-accessible mirror node deployment is reachable. The attack is trivially scriptable: a single machine with moderate bandwidth can sustain thousands of concurrent HTTP/1.1 keep-alive requests. The default `maxConnections` for the REST DB pool is small enough that even a modest flood fills it quickly.

### Recommendation
1. **Add per-IP rate limiting** to the Express REST API (e.g., `express-rate-limit` or an ingress-level policy) targeting the `/api/v1/accounts/*/nfts` path specifically, since its multi-union query is more expensive than single-table endpoints.
2. **Separate DB connection pools** for the REST API and the importer at the PostgreSQL level (e.g., via PgBouncer with per-role pool limits) so REST pool exhaustion cannot block importer writes.
3. **Add a DB-level statement timeout** specifically for the REST role that is tighter than the importer role's timeout, preventing long-running NFT scans from holding connections.
4. **Consider query cost limits** (PostgreSQL `statement_timeout` per role, or `pg_query_settings`) to auto-cancel expensive union scans before they accumulate.

### Proof of Concept
```bash
# Flood the NFT endpoint with max-limit requests from a single unauthenticated client
# No credentials required
TARGET="https://<mirror-node-host>/api/v1/accounts/0.0.1/nfts?limit=100"

# Send 500 concurrent requests in a loop
for i in $(seq 1 500); do
  curl -s "$TARGET" -o /dev/null &
done
wait

# Observable effect: REST API begins returning 500/503 (pool exhausted),
# and importer lag (consensus_timestamp behind chain tip) increases.
```

**Verification**: Monitor `pg_stat_activity` on the PostgreSQL instance during the flood; all connections will show `SELECT … FROM nft … UNION ALL … LIMIT 100` queries. Simultaneously monitor importer metrics for increasing `record_file_parse_duration` or stalled `consensus_timestamp`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rest/routes/accountRoute.js (L15-15)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**File:** rest/controllers/accountController.js (L52-53)
```javascript
        case filterKeys.LIMIT:
          limit = filter.value;
```

**File:** rest/controllers/accountController.js (L90-103)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
    const query = this.extractNftMultiUnionQuery(filters, accountId);
    const nonFungibleTokens = await NftService.getNfts(query);
    const nfts = nonFungibleTokens.map((nft) => new NftViewModel(nft));

    res.locals[responseDataLabel] = {
      nfts,
      links: {
        next: this.getPaginationLink(req, nfts, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/utils.js (L533-553)
```javascript
const getEffectiveMaxLimit = () => {
  const userLimit = httpContext.get(userLimitLabel);
  return userLimit !== undefined ? userLimit : responseLimit.max;
};

/**
 * Gets the limit param value, if not exists, return the default; otherwise cap it at max.
 * Note if values is an array, the last one is honored.
 * @param {string[]|string} values Values of the limit param
 * @return {number}
 */
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```

**File:** rest/service/nftService.js (L84-126)
```javascript
  getQuery(query) {
    const {lower, inner, upper, order, ownerAccountId, limit, spenderIdInFilters, spenderIdFilters} = query;
    const params = [ownerAccountId, limit];
    const accountIdCondition = `${Nft.ACCOUNT_ID} = $1`;
    const limitClause = super.getLimitQuery(2);
    const orderClause = super.getOrderByQuery(
      ...NftService.orderByColumns.map((column) => OrderSpec.from(column, order))
    );

    const subQueries = [lower, inner, upper]
      .filter((filters) => filters.length !== 0)
      .map((filters) =>
        this.getSubQuery(
          filters,
          params,
          accountIdCondition,
          limitClause,
          orderClause,
          spenderIdInFilters,
          spenderIdFilters
        )
      );

    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = this.getSubQuery(
        [],
        params,
        accountIdCondition,
        limitClause,
        orderClause,
        spenderIdInFilters,
        spenderIdFilters
      );
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
    }

    return {sqlQuery, params};
  }
```

**File:** rest/service/nftService.js (L134-138)
```javascript
  async getNfts(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new Nft(ta));
  }
```

**File:** rest/config.js (L137-147)
```javascript
function parseDbPoolConfig() {
  const {pool} = getConfig().db;
  const configKeys = ['connectionTimeout', 'maxConnections', 'statementTimeout'];
  configKeys.forEach((configKey) => {
    const value = pool[configKey];
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed) || parsed <= 0) {
      throw new InvalidConfigError(`invalid value set for db.pool.${configKey}: ${value}`);
    }
    pool[configKey] = parsed;
  });
```
