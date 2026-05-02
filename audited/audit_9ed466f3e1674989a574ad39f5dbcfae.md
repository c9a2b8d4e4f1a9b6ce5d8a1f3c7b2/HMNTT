### Title
Unauthenticated DB Connection Pool Exhaustion via Concurrent Non-Existent NFT Lookups

### Summary
The `getNftTokenInfoRequest()` handler in `rest/tokens.js` executes a full database query with a LEFT JOIN for every request, including those for non-existent NFTs, before throwing `NotFoundError`. No application-level rate limiting or per-IP throttling exists on this endpoint. With a default pool of only 10 DB connections, an unprivileged attacker can saturate the pool with concurrent requests, causing all other REST API endpoints to queue or time out.

### Finding Description
**Code path:**

`rest/tokens.js`, `getNftTokenInfoRequest()` (lines 866–880):
```
const getNftTokenInfoRequest = async (req, res) => {
  utils.validateReq(req);
  const tokenId = getAndValidateTokenIdRequestPathParam(req);
  const serialNumber = getAndValidateSerialNumberRequestPathParam(req);

  const {query, params} = extractSqlFromNftTokenInfoRequest(tokenId, serialNumber, nftSelectQuery);
  const {rows} = await pool.queryQuietly(query, params);   // <-- DB query always executes
  if (rows.length !== 1) {
    throw new NotFoundError();                              // <-- thrown AFTER query completes
  }
  ...
};
```

`extractSqlFromNftTokenInfoRequest()` (lines 795–804) builds:
```sql
select nft.account_id, ... from nft
left join entity e on e.id = nft.token_id   -- entityNftsJoinQuery
where nft.token_id = $1 and nft.serial_number = $2
```

**Root cause:** Input validation (`validateSerialNumberParam`, line 809–812; `getAndValidateTokenIdRequestPathParam`, line 424–431) only checks that the path parameters are valid positive long integers — it does not check existence before issuing the query. The full query with LEFT JOIN runs unconditionally. There is no short-circuit, no negative-result cache, and no rate limiting.

**Why checks fail:**
- `authHandler.js` only enforces custom response limits for authenticated users; unauthenticated requests pass through with no throttle.
- `grep_search` across all `rest/**/*.js` confirms zero rate-limiting middleware on this route.
- `rest/server.js` (lines 119–124) registers the route with no middleware guard.
- The Redis response cache (`responseCacheCheckHandler`) is disabled by default (`hiero.mirror.rest.cache.response.enabled: false`) and would not cache 404 responses anyway.
- The DB pool (`rest/dbpool.js`, line 14) defaults to `maxConnections: 10` and `connectionTimeoutMillis: 20000` — all 10 slots can be held by attacker requests for up to 20 seconds each.

### Impact Explanation
All REST API endpoints share the single global `pool`. Saturating its 10 connections blocks every other endpoint (accounts, transactions, topics, etc.) from acquiring a connection. Legitimate requests queue for up to 20 seconds (`connectionTimeoutMillis`) before failing. This is a complete REST API denial-of-service achievable by a single unauthenticated client. The mirror node's read API becomes unavailable to all consumers.

### Likelihood Explanation
No credentials, tokens, or special network access are required. Any internet-accessible deployment is vulnerable. The attack is trivially scriptable (e.g., `ab -n 10000 -c 500 https://host/api/v1/tokens/0.0.1/nfts/999999999`). The attacker can rotate token IDs and serial numbers to avoid any future negative-result caching. The attack is repeatable and sustainable indefinitely.

### Recommendation
1. **Add per-IP rate limiting** middleware (e.g., `express-rate-limit`) on all token/NFT endpoints before the DB query is reached.
2. **Add an existence pre-check** or use the `NftService.getNft()` path (which uses the simpler `nftByIdQuery` without the JOIN) and cache negative results in Redis with a short TTL.
3. **Increase pool size** and/or add a concurrency limiter (e.g., `p-limit`) so a single endpoint cannot monopolize all connections.
4. **Apply Traefik `inFlightReq` and `rateLimit` middleware** (already used for the Rosetta API in `charts/hedera-mirror-rosetta/values.yaml`, lines 152–160) to the REST API ingress as well.

### Proof of Concept
```bash
# Saturate the 10-connection pool with concurrent requests for a non-existent NFT
# No authentication required
for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/tokens/0.0.999999999/nfts/$i" &
done
wait

# Simultaneously, observe that legitimate requests time out:
time curl "https://<mirror-node-host>/api/v1/transactions"
# Expected: hangs for ~20 seconds then returns 503 or connection timeout
```

**Preconditions:** Public network access to the REST API. No credentials needed.
**Trigger:** Concurrent GET requests to `/api/v1/tokens/:tokenId/nfts/:serialNumber` with valid-format but non-existent IDs.
**Result:** DB connection pool exhausted; all REST API endpoints become unresponsive for the duration of the attack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/tokens.js (L117-118)
```javascript
const nftSelectQuery = ['select', nftSelectFields.join(',\n'), 'from nft'].join('\n');
const entityNftsJoinQuery = 'left join entity e on e.id = nft.token_id';
```

**File:** rest/tokens.js (L795-804)
```javascript
const extractSqlFromNftTokenInfoRequest = (tokenId, serialNumber, query) => {
  // filter for token and serialNumber
  const conditions = [`${nftQueryColumns.TOKEN_ID} = $1`, `${nftQueryColumns.SERIAL_NUMBER} = $2`];
  const params = [tokenId, serialNumber];

  const whereQuery = `where ${conditions.join('\nand ')}`;
  query = [query, entityNftsJoinQuery, whereQuery].filter((q) => q !== '').join('\n');

  return utils.buildPgSqlObject(query, params, '', '');
};
```

**File:** rest/tokens.js (L866-880)
```javascript
const getNftTokenInfoRequest = async (req, res) => {
  utils.validateReq(req);
  const tokenId = getAndValidateTokenIdRequestPathParam(req);
  const serialNumber = getAndValidateSerialNumberRequestPathParam(req);

  const {query, params} = extractSqlFromNftTokenInfoRequest(tokenId, serialNumber, nftSelectQuery);
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length !== 1) {
    throw new NotFoundError();
  }

  logger.debug(`getNftToken info returning single entry`);
  const nftModel = new Nft(rows[0]);
  res.locals[responseDataLabel] = new NftViewModel(nftModel);
};
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** rest/server.js (L119-124)
```javascript
app.getExt(`${apiPrefix}/tokens`, tokens.getTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId`, tokens.getTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/balances`, tokens.getTokenBalances);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts`, tokens.getNftTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber`, tokens.getNftTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber/transactions`, tokens.getNftTransferHistoryRequest);
```

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```
