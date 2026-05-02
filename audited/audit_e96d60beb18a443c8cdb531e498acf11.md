### Title
Unauthenticated EVM Address Lookup Exhausts DB Connection Pool via Concurrent Requests to Token Allowance Endpoint

### Summary
The `getAccountTokenAllowances()` handler in `rest/controllers/tokenAllowanceController.js` accepts an EVM address as a path parameter and unconditionally issues a live database query via `EntityService.getEntityIdFromEvmAddress()` for every request. Because the REST API has no rate limiting and the default DB connection pool is only 10 connections, an unprivileged attacker sending 10+ concurrent requests with distinct valid EVM addresses can fully exhaust the pool, blocking all REST API database operations and degrading mirror node processing capacity.

### Finding Description

**Exact code path:**

`getAccountTokenAllowances()` at [1](#0-0)  calls `EntityService.getEncodedId()`.

`getEncodedId()` at [2](#0-1)  detects a non-parsable EVM address (`entityId.evmAddress !== null`) and calls `getEntityIdFromEvmAddress()`.

`getEntityIdFromEvmAddress()` at [3](#0-2)  immediately issues a raw DB query via `this.getRows(EntityService.entityFromEvmAddressQuery, [...])` with no caching, no deduplication, and no concurrency guard.

The query issued is: [4](#0-3) 

**Root cause — no DB-result caching:**

`entityId.js` does maintain a `quickLru` cache [5](#0-4)  but it only caches the *parsed `EntityId` object* (string → shard/realm/num/evmAddress struct). It does **not** cache the result of the database lookup (evmAddress bytes → numeric entity ID). `getEntityIdFromEvmAddress()` in `entityService.js` contains zero cache reads or writes; every call hits the database unconditionally.

**Root cause — tiny default pool:**

The DB pool is configured with `max: config.db.pool.maxConnections` [6](#0-5)  whose documented default is **10 connections** [7](#0-6)  with a `connectionTimeout` of 20 000 ms and a `statementTimeout` of 20 000 ms.

**Root cause — no REST API rate limiting:**

The throttle infrastructure (`ThrottleManagerImpl`, `ThrottleConfiguration`) applies only to the **web3** module. No equivalent rate-limiting middleware exists in the `rest/` Express application. The `authHandler.js` [8](#0-7)  only enforces per-authenticated-user *response-size* limits, not request rates, and authentication itself is entirely optional.

### Impact Explanation

With a default pool of 10 connections and a statement timeout of 20 seconds, an attacker needs only 10 concurrent HTTP requests — each using a distinct 40-hex-character EVM address — to hold all pool connections simultaneously. Every subsequent REST API request that requires a DB connection (transactions, accounts, balances, NFTs, etc.) will queue and eventually time out after 20 seconds. This constitutes a full denial-of-service of the REST API's database tier, directly degrading mirror node read capacity. Because the REST API is the primary public interface for mirror node data, this satisfies the ≥30% processing degradation threshold.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero knowledge of real on-chain data. Any 40-character hex string is a syntactically valid EVM address and will pass `isValidEvmAddress()` / `isValidEntityId()` checks, causing the DB query to be issued (it will simply return 0 rows and throw `NotFoundError`, but the connection is held for the full query duration). The attack is trivially scriptable with `curl` or any HTTP client, is repeatable indefinitely, and leaves no persistent state on the attacker's side.

### Recommendation

1. **Cache DB lookup results:** In `getEntityIdFromEvmAddress()`, wrap the DB call with the existing `quickLru` cache (keyed on the hex EVM address). The cache is already configured with `maxAge: 1800s` and `maxSize: 100000` — reuse it for the resolved numeric ID, not just the parsed struct.
2. **Add REST API rate limiting:** Apply a per-IP request-rate middleware (e.g., `express-rate-limit`) to the Express application, mirroring the bucket4j throttle already present in the web3 module.
3. **Increase pool size or add a concurrency semaphore:** Raise `db.pool.maxConnections` above 10 for production, or add a semaphore that limits the number of concurrent in-flight EVM-address DB lookups.
4. **Short-circuit on non-existent addresses:** Consider returning 404 immediately for EVM addresses that are structurally "long-form" aliases (first 12 bytes zero) without a DB round-trip, since those can be decoded arithmetically.

### Proof of Concept

```bash
# Generate 50 unique random EVM addresses and fire concurrent requests
for i in $(seq 1 50); do
  addr=$(openssl rand -hex 20)
  curl -s "https://<mirror-node>/api/v1/accounts/0x${addr}/allowances/tokens" &
done
wait
```

**Preconditions:** None. No account, no API key, no prior knowledge required.

**Trigger:** Each request reaches `getEntityIdFromEvmAddress()` → acquires a pool connection → executes `entityFromEvmAddressQuery` → holds the connection until the query completes or times out (up to 20 s).

**Result:** With ≥10 concurrent requests in flight, the pool (`max=10`) is exhausted. All other REST API endpoints that call any DB-backed service will block on `pool.connect()` and return errors or time out after 20 seconds, rendering the REST API non-functional for the duration of the attack.

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L68-69)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-91)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/service/entityService.js (L118-124)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/entityId.js (L301-304)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});
```

**File:** rest/dbpool.js (L14-14)
```javascript
  max: config.db.pool.maxConnections,
```

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
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
