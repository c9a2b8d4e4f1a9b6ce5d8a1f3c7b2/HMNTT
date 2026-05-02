### Title
Unbounded pg Pool Queue in `getNfts()` Enables OOM Crash During Network Partition

### Summary
The Node.js REST service initializes its `pg` Pool in `rest/dbpool.js` without a maximum queue depth (`maxQueue`) parameter. During a network partition, all pool connections stall waiting for the unreachable database, and every incoming `getNfts()` request is appended to the pool's internal unbounded JavaScript queue. An unprivileged attacker who floods the endpoint during a partition can grow this queue without limit, exhausting Node.js heap memory and crashing the process — extending the service outage beyond the partition itself.

### Finding Description

**Pool initialization — no queue cap:**

`rest/dbpool.js` lines 7–16 construct the pool with only `connectionTimeoutMillis`, `max`, and `statement_timeout`:

```js
const poolConfig = {
  user: ..., host: ..., database: ..., password: ..., port: ...,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
  // ← no maxQueue / no queue depth limit
};
``` [1](#0-0) 

The `node-postgres` (`pg`) Pool accepts a `maxQueue` option that caps the number of pending `pool.query()` calls waiting for a free connection. Without it, the internal queue is unbounded.

**Call chain from `getNfts()` to the pool:**

`NftService.getNfts()` (line 136) calls `super.getRows()`: [2](#0-1) 

`BaseService.getRows()` (line 56) calls `this.pool().queryQuietly(query, params)`: [3](#0-2) 

`queryQuietly` (line 1520) calls `this.query(query, params)` — the standard `pg` Pool method that enqueues the request when all `max` connections are busy: [4](#0-3) 

**Config validation — no `maxQueue` key:**

`parseDbPoolConfig()` only validates `connectionTimeout`, `maxConnections`, and `statementTimeout`. There is no `maxQueue` key defined, validated, or passed to the pool: [5](#0-4) 

**No HTTP-level rate limiting in the REST service:**

All throttle/rate-limit code found (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives in the `web3` Java service. No equivalent middleware was found protecting the Node.js REST endpoints, meaning an attacker can issue unlimited concurrent HTTP requests.

### Impact Explanation

During a network partition every `pool.query()` call blocks waiting for a connection. New HTTP requests continue to arrive, each creating a new Promise + closure + query object appended to the pool's internal array. Node.js heap grows proportionally to the number of queued requests. At sufficient request rates (easily achievable with `ab`, `wrk`, or `curl` in parallel), the process hits the V8 heap limit and is killed by OOM. The crash means the service remains unavailable even after the partition heals, because the process must restart and re-initialize — extending the outage window.

### Likelihood Explanation

The endpoint `/api/v1/accounts/{id}/nfts` (backed by `getNfts()`) requires no authentication. Any external user can issue thousands of concurrent requests. Network partitions between the REST pod and the database are a realistic operational event (rolling DB restarts, network policy changes, cloud AZ issues). The attacker does not need to know a partition is occurring — sustained high-rate polling of the endpoint is sufficient to trigger the condition whenever a partition happens. The attack is repeatable and requires no special privileges.

### Recommendation

1. **Set `maxQueue` on the pool** in `rest/dbpool.js`:
   ```js
   const poolConfig = {
     ...
     connectionTimeoutMillis: config.db.pool.connectionTimeout,
     max: config.db.pool.maxConnections,
     maxQueue: config.db.pool.maxQueue, // e.g. default 200–500
     statement_timeout: config.db.pool.statementTimeout,
   };
   ```
   Add `maxQueue` to `parseDbPoolConfig()` validation in `rest/config.js`. When the queue is full, `pg` will immediately reject new queries with an error, which the REST layer should surface as HTTP 503.

2. **Add HTTP-level concurrency / rate limiting middleware** to the Node.js REST service (e.g., `express-rate-limit` or a reverse-proxy rule) so that the queue never fills in the first place.

3. **Keep `connectionTimeoutMillis` small** (it is already configurable) so queued items drain quickly during a partition rather than accumulating for the full timeout window.

### Proof of Concept

```bash
# 1. Simulate a network partition: block egress from the REST pod to the DB port
#    (or simply stop the DB).

# 2. Flood the unauthenticated NFT endpoint from any external host:
wrk -t 20 -c 2000 -d 120s \
  "https://<mirror-node-host>/api/v1/accounts/0.0.1234/nfts"

# 3. Observe Node.js heap growth via process metrics or k8s OOMKilled event.
#    With no maxQueue, each of the 2000 concurrent connections enqueues a
#    pool.query() call; wrk keeps issuing new requests as old ones time out,
#    maintaining a large queue depth throughout the partition window.

# 4. Restore network connectivity — the REST pod is already dead (OOMKilled)
#    and must be restarted, extending the outage.
```

### Citations

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

**File:** rest/service/nftService.js (L134-138)
```javascript
  async getNfts(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new Nft(ta));
  }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/utils.js (L1518-1521)
```javascript
    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
      } else {
```

**File:** rest/config.js (L137-148)
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
}
```
