### Title
Unauthenticated EVM Address Lookup DoS via Unbounded DB Queries on `/accounts/{idOrAliasOrEvmAddress}/nfts`

### Summary
Any unauthenticated caller can supply a syntactically valid but non-existent EVM address as the `:idOrAliasOrEvmAddress` path parameter to `GET /api/v1/accounts/{addr}/nfts`. Each such request unconditionally executes a database query against the `entity` table by `evm_address` column with no result caching and no rate limiting in the REST layer. An attacker flooding the endpoint with thousands of unique non-existent EVM addresses will exhaust the PostgreSQL connection pool, starving all other API consumers including those retrieving mirrored transaction data.

### Finding Description

**Route registration** — `rest/routes/accountRoute.js` line 15:
```js
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**Controller** — `rest/controllers/accountController.js` line 91:
```js
const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**`getEncodedId` dispatch** — `rest/service/entityService.js` lines 118–124:
```js
if (EntityId.isValidEntityId(entityIdString)) {
  const entityId = EntityId.parseString(entityIdString, {paramName});
  return entityId.evmAddress === null
    ? entityId.getEncodedId()
    : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```
`EntityId.isValidEntityId` returns `true` for any 40-hex-char string (`rest/entityId.js` lines 133–140). `parseFromString` sets `evmAddress` to the raw hex for any "opaque" address (first 12 bytes not all-zero), so the DB branch is always taken for real EVM addresses.

**DB query** — `rest/service/entityService.js` lines 22–25:
```js
static entityFromEvmAddressQuery = `select ${Entity.ID}
    from ${Entity.tableName}
    where ${Entity.DELETED} <> true
      and ${Entity.EVM_ADDRESS} = $1`;
```
`getEntityIdFromEvmAddress` (lines 90–104) executes this query for every request. When no row is found it throws `NotFoundError` (→ HTTP 404). There is **no caching of the query result**; `parseCached` in `entityId.js` (lines 314–333) only caches the string-to-`EntityId` object conversion, not the database round-trip.

**No rate limiting** — `rest/server.js` (lines 67–98) registers `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, and optional metrics/response-cache middleware. There is no per-IP or global request-rate-limiting middleware anywhere in the REST stack. The `ThrottleManagerImpl` found in `web3/` applies only to EVM contract-call endpoints, not to the REST API.

**Additional correctness defect** (amplifies attack surface): the alias query uses `coalesce(deleted, false) <> true` while the EVM address query uses `deleted <> true`. Because `NULL <> true` evaluates to `NULL` (falsy) in SQL, entities whose `deleted` column is `NULL` (the normal state for live accounts) are silently excluded, so even real EVM addresses of active accounts return 404 — making the attack indistinguishable from legitimate misses and widening the set of addresses an attacker can use.

### Impact Explanation
Each unique non-existent EVM address consumes one PostgreSQL connection for the duration of the query. With no rate limiting, an attacker can trivially saturate the connection pool (typically 10–100 connections in default Node.js `pg` pool configurations), causing all subsequent requests — including those serving mirrored transaction and account data — to queue indefinitely or fail with connection-pool-exhaustion errors. This constitutes a full denial-of-service against the mirror node REST API with no authentication or special privilege required.

### Likelihood Explanation
The attack requires only an HTTP client and knowledge of the public API schema (documented in `rest/api/v1/openapi.yml`). Generating 40-hex-char strings is trivial. The attacker does not need to know any real account addresses; random addresses will almost never exist in the entity table, guaranteeing a DB hit on every request. The attack is repeatable, stateless, and can be parallelised across many source IPs to defeat any upstream IP-based firewall rules.

### Recommendation
1. **Add rate limiting middleware** to the REST Express application (e.g., `express-rate-limit` or Traefik `rateLimit` middleware already used for Rosetta) scoped to the `/accounts/:id/nfts` and related sub-resource routes, keyed by source IP.
2. **Cache negative (miss) results** for EVM address lookups with a short TTL (e.g., 5–30 s) using the existing Redis infrastructure (`config.redis.enabled`) so repeated misses for the same address do not hit the database.
3. **Fix the `entityFromEvmAddressQuery` NULL bug**: change `where ${Entity.DELETED} <> true` to `where coalesce(${Entity.DELETED}, false) <> true`, consistent with `entityFromAliasQuery`, to avoid false 404s for live accounts.
4. Consider enforcing a maximum in-flight request count at the connection-pool level (`pg` pool `max` + queue timeout) so pool exhaustion fails fast rather than queuing indefinitely.

### Proof of Concept
```bash
# Generate and fire 5000 requests with unique random EVM addresses (no auth required)
for i in $(seq 1 5000); do
  ADDR=$(openssl rand -hex 20)
  curl -s -o /dev/null "https://<mirror-node>/api/v1/accounts/${ADDR}/nfts" &
done
wait
# After saturation: legitimate requests begin returning 503 / connection errors
curl -v "https://<mirror-node>/api/v1/transactions"
```
Each background request hits `EntityService.getEntityIdFromEvmAddress` → `entityFromEvmAddressQuery` → DB. With the default pool size exhausted, the final `transactions` request fails, demonstrating service-wide denial of service with zero privileges. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** rest/routes/accountRoute.js (L15-15)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
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

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-104)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
  }
```

**File:** rest/service/entityService.js (L118-127)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
```

**File:** rest/entityId.js (L133-140)
```javascript
const isValidEntityId = (entityId, allowEvmAddress = true, evmAddressType = constants.EvmAddressType.ANY) => {
  if ((typeof entityId === 'string' && entityIdRegex.test(entityId)) || encodedEntityIdRegex.test(entityId)) {
    // Accepted forms: shard.realm.num, realm.num, or encodedId
    return true;
  }

  return allowEvmAddress && isValidEvmAddress(entityId, evmAddressType);
};
```

**File:** rest/entityId.js (L314-333)
```javascript
const parseCached = (id, allowEvmAddress, evmAddressType, error) => {
  const key = `${id}_${allowEvmAddress}_${evmAddressType}`;
  const value = cache.get(key);
  if (value) {
    return value;
  }

  if (!isValidEntityId(id, allowEvmAddress, evmAddressType)) {
    throw error();
  }
  const [shard, realm, num, evmAddress] =
    id.includes('.') || isValidEvmAddressLength(id.length) ? parseFromString(id, error) : parseFromEncodedId(id, error);
  if (evmAddress === null && (num > maxNum || realm > maxRealm || shard > maxShard)) {
    throw error();
  }

  const entityId = of(shard, realm, num, evmAddress);
  cache.set(key, entityId);
  return entityId;
};
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
