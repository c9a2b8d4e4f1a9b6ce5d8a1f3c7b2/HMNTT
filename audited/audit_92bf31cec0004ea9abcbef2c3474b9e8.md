### Title
Unauthenticated EVM Address Lookup Causes Unbounded DB Connection Pool Exhaustion in `getAccountCryptoAllowances()`

### Summary
`getAccountCryptoAllowances()` resolves the path parameter through `EntityService.getEncodedId()` → `getEntityIdFromEvmAddress()`, which unconditionally issues a database query for every opaque EVM address. There is no caching of the DB lookup result, no rate limiting on the REST API, and the default connection pool is only 10 connections. An unprivileged attacker can flood the endpoint with valid but non-existent EVM addresses, exhausting the pool and causing all concurrent REST API queries to queue or time out.

### Finding Description

**Exact code path:**

`rest/controllers/cryptoAllowanceController.js` line 77 calls `EntityService.getEncodedId()` with the raw path parameter: [1](#0-0) 

`getEncodedId()` in `rest/service/entityService.js` lines 120–124 parses the string and, when `entityId.evmAddress !== null` (i.e., the address is an opaque 40-hex-char EVM address that is not a long-zero alias), unconditionally calls `getEntityIdFromEvmAddress()`: [2](#0-1) 

`getEntityIdFromEvmAddress()` at line 91 always issues a live DB query — there is no caching of the result: [3](#0-2) 

**Root cause — failed assumption:** The `entityId` LRU cache in `rest/entityId.js` (lines 301–333) only caches the *parsed `EntityId` object* (which carries the `evmAddress` string). It does **not** cache the result of the DB lookup. So even if the same EVM address is sent repeatedly, `getEntityIdFromEvmAddress()` fires a fresh DB query every time: [4](#0-3) 

**Connection pool:** `rest/dbpool.js` configures the pool with `max: config.db.pool.maxConnections`, whose default is **10** connections, and `connectionTimeoutMillis` of 20 000 ms and `statement_timeout` of 20 000 ms: [5](#0-4) [6](#0-5) 

**No rate limiting:** A search of `rest/**/*.js` finds no rate-limiting or throttling middleware applied to the REST API (unlike the web3 API, which has `ThrottleManagerImpl`). Any unauthenticated client can issue unlimited concurrent requests.

**Exploit flow:**
1. Attacker generates N distinct 40-hex-char EVM addresses that do not exist in the DB (trivially: random addresses).
2. Attacker sends N concurrent `GET /api/v1/accounts/<evmAddress>/allowances/crypto` requests.
3. Each request passes `EntityId.parseString()` (valid format), sets `evmAddress` to the hex string, and enters `getEntityIdFromEvmAddress()`.
4. Each call acquires a connection from the pool and executes `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1`.
5. With N > 10, all 10 pool slots are occupied. New requests queue and wait up to 20 s for a connection.
6. Legitimate queries (from other endpoints or internal services sharing the pool) cannot acquire connections and time out.

### Impact Explanation
The REST API's shared `pg` connection pool (default 10 connections) is exhausted. All concurrent REST API queries — including those from other endpoints — are blocked for up to 20 seconds per wave of attack requests. This constitutes a denial-of-service against the mirror node REST API. Note: the mirror node REST API is a read-only service and does not participate in Hedera network consensus or transaction confirmation; the impact is REST API unavailability, not network-level transaction failure.

### Likelihood Explanation
No authentication, no rate limiting, and no per-IP throttling are required. Any internet-accessible deployment is reachable. The attack requires only an HTTP client capable of sending concurrent requests with syntactically valid 40-hex-char EVM addresses. It is trivially repeatable and automatable with tools like `curl`, `ab`, or `wrk`. The small default pool size (10) makes the threshold for impact very low.

### Recommendation
1. **Cache negative DB results**: In `getEntityIdFromEvmAddress()`, cache `null` results (address not found) in the existing `entityId` LRU cache (keyed on the hex address string) for a short TTL (e.g., 30–60 s). This prevents repeated DB hits for the same non-existent address.
2. **Add rate limiting to the REST API**: Apply a per-IP or global request-rate limiter (e.g., `express-rate-limit`) to all endpoints, especially those that trigger DB lookups from path parameters.
3. **Increase pool size or add a query queue limit**: Raise `maxConnections` and set a maximum queue depth so that excess requests are rejected with HTTP 429 rather than blocking indefinitely.
4. **Short-circuit on long-zero addresses**: The `getEntityIdFromEvmAddress()` path is only reached for opaque EVM addresses. Consider validating that the address format is plausible before issuing a DB query.

### Proof of Concept
```bash
# Generate 50 random non-existent EVM addresses and flood the endpoint concurrently
for i in $(seq 1 50); do
  addr=$(openssl rand -hex 20)
  curl -s "http://<mirror-node-host>:5551/api/v1/accounts/0x${addr}/allowances/crypto" &
done
wait
# Observe: legitimate requests to other endpoints begin timing out or returning 503
# DB pool exhaustion visible in mirror node logs: "Error: timeout exceeded when trying to connect"
```

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-78)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
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

**File:** rest/entityId.js (L301-333)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});

/**
 * Parses entity ID string, can be shard.realm.num, realm.num, the encoded entity ID or an evm address.
 * @param {string} id
 * @param {boolean} allowEvmAddress
 * @param {number} evmAddressType
 * @param {Function} error
 * @return {EntityId}
 */
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
