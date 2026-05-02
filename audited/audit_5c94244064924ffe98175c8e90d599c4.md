### Title
Unauthenticated DB Query Exhaustion via Unbounded Alias Flooding in `getNftsByAccountId`

### Summary
Any unauthenticated external user can supply an arbitrary valid base32 string as the `idOrAliasOrEvmAddress` path parameter to `GET /api/v1/accounts/{id}/nfts`. Each such request unconditionally executes a live database query against the `entity` table with no rate limiting, no negative-result caching, and no alias length cap. An attacker flooding the endpoint with unique non-existent aliases can exhaust the PostgreSQL connection pool, degrading or denying service to legitimate users.

### Finding Description

**Exact code path:**

1. `rest/controllers/accountController.js` line 91 — `getNftsByAccountId` passes the raw path parameter directly to `EntityService.getEncodedId`: [1](#0-0) 

2. `rest/service/entityService.js` lines 125–126 — `getEncodedId` checks `AccountAlias.isValid()` and, if true, immediately calls `getAccountIdFromAlias` with no further guard: [2](#0-1) 

3. `rest/service/entityService.js` lines 42–53 — `getAccountFromAlias` executes a full table query on every call, with no caching layer: [3](#0-2) 

4. `rest/accountAlias.js` lines 10–11 — The validation regex `accountAliasRegex` imposes **no length limit** on the alias portion; any string of uppercase `[A-Z2-7]` characters passes: [4](#0-3) 

**Root cause:** The alias branch of `getEncodedId` has no negative-result cache, no per-IP or global rate limit, and no alias length cap. Every syntactically valid base32 string — regardless of whether it maps to a real account — triggers a live `SELECT` against the `entity` table.

**Why existing checks fail:**

- **Response cache** (`rest/middleware/responseCacheHandler.js` line 95) only stores successful (2xx) responses; 404 `NotFoundError` results are never cached, so repeated misses always hit the DB: [5](#0-4) 

- **Rate limiting** (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`) exists only in the `web3` module for contract calls; the REST API server (`rest/server.js`) registers no rate-limiting middleware at all: [6](#0-5) 

- **Authentication** (`authHandler`) does not block unauthenticated callers from this public endpoint: [7](#0-6) 

### Impact Explanation
An attacker can saturate the PostgreSQL connection pool by sending concurrent requests with unique valid base32 aliases (e.g., `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB`, …). Once the pool is exhausted, all REST API endpoints that require DB access — not just the NFT endpoint — begin queuing or rejecting requests, causing broad service degradation for all legitimate users. No account, funds, or on-chain state is modified; the impact is availability loss (griefing).

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and zero on-chain resources. The attacker needs only an HTTP client and the ability to generate unique base32 strings, which is trivial. The endpoint is publicly documented in the OpenAPI spec. The attack is fully repeatable and can be sustained indefinitely from a single machine or amplified with multiple source IPs to bypass any upstream network-level throttle.

### Recommendation
1. **Add a rate limiter** (e.g., `express-rate-limit`) in `rest/server.js` applied globally or specifically to the `/:idOrAliasOrEvmAddress/*` route family.
2. **Cache negative alias lookups** in `getAccountFromAlias` / `getAccountIdFromAlias` with a short TTL (e.g., 5–30 s) so repeated misses for the same alias do not hit the DB.
3. **Enforce a maximum alias length** in `AccountAlias.isValid()` — the base32 encoding of a 32-byte Ed25519 public key is 52 characters; reject anything longer.
4. **Cap DB query concurrency** at the pool level with a queue timeout so a flood cannot hold connections indefinitely.

### Proof of Concept

```bash
# Generate and fire 500 concurrent requests with unique non-existent base32 aliases
for i in $(seq 1 500); do
  ALIAS=$(python3 -c "import random,string; print(''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=52)))")
  curl -s "http://<mirror-node-host>/api/v1/accounts/${ALIAS}/nfts" &
done
wait
```

**Expected result:** Each request reaches `getAccountFromAlias`, executes `SELECT id FROM entity WHERE alias = $1` against the DB, finds no row, and returns HTTP 404. With sufficient concurrency the PostgreSQL connection pool (`initializePool()` in `rest/server.js` line 49) is saturated, and subsequent legitimate requests receive connection-pool timeout errors or HTTP 503 responses. [8](#0-7)

### Citations

**File:** rest/controllers/accountController.js (L90-92)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
```

**File:** rest/service/entityService.js (L42-53)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }
```

**File:** rest/service/entityService.js (L125-126)
```javascript
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
```

**File:** rest/accountAlias.js (L10-11)
```javascript
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
const noShardRealmAccountAliasRegex = /^[A-Z2-7]+$/;
```

**File:** rest/middleware/responseCacheHandler.js (L95-95)
```javascript
  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```

**File:** rest/server.js (L49-49)
```javascript
initializePool();
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
