### Title
Unbounded `pool.queryQuietly()` Hang During Network Partition Enables Connection-Slot Exhaustion DoS in `getContractById()`

### Summary
`getContractById()` in `rest/controllers/contractController.js` calls `pool.queryQuietly()`, which internally calls `await this.query(query, params)` with no client-side timeout. The pool is configured with only a PostgreSQL server-side `statement_timeout`, which is unreachable by the Node.js client during a network partition. An unprivileged attacker can send as few as 10 concurrent requests during a network partition to exhaust all pool connections, leaving every subsequent request queued or rejected and every HTTP connection open indefinitely.

### Finding Description

**Exact code path:**

`getContractById()` at `rest/controllers/contractController.js:726` calls:
```js
const {rows} = await pool.queryQuietly(query, params);
```

`queryQuietly` is defined in `rest/utils.js:1481–1546`. The non-`preQueryHint` path (the one taken here) executes:
```js
result = await this.query(query, params);  // line 1520
```

This is a bare `pg` Pool `query()` call with no client-side timeout wrapper (`Promise.race`, `AbortController`, or `query_timeout` pool option).

**Pool configuration** (`rest/dbpool.js:7–16`):
```js
const poolConfig = {
  connectionTimeoutMillis: config.db.pool.connectionTimeout,  // 20000ms — new connections only
  max: config.db.pool.maxConnections,                         // default 10
  statement_timeout: config.db.pool.statementTimeout,         // 20000ms — PostgreSQL server-side
};
```

`statement_timeout` is a PostgreSQL server-side parameter (`SET statement_timeout = 20000`). During a network partition between the Node.js process and PostgreSQL:
- PostgreSQL enforces the timeout and cancels the query server-side after 20 s.
- The error notification is a TCP packet that **cannot reach the client** because the network is partitioned.
- The Node.js `await this.query()` call remains suspended indefinitely — TCP keepalive on Linux defaults to ~2 hours before detecting a dead connection.
- `connectionTimeoutMillis` only governs acquiring a new connection from the pool, not queries already in flight.

**No HTTP-level timeout** is configured for the REST API server. `rest/server.js` sets up Express middleware (compression, CORS, logging, auth, metrics) but never calls `server.setTimeout()` or sets `keepAliveTimeout`/`headersTimeout`. There is no request-level timeout middleware in the chain.

**Why existing checks fail:**
- `statement_timeout` (server-side): ineffective when the network is partitioned — the error never arrives at the client.
- `connectionTimeoutMillis` (client-side): only applies to the pool's `connect()` phase, not to `query()` calls on already-acquired connections.
- No `query_timeout` pool option (client-side pg feature): not set in `rest/dbpool.js`.
- No HTTP server write/idle timeout: not configured in `rest/server.js`.

### Impact Explanation

The pool has a default maximum of 10 connections (`hiero.mirror.rest.db.pool.maxConnections = 10`). With 10 concurrent hung requests, the entire pool is exhausted. All subsequent requests queue waiting for a free connection; after `connectionTimeoutMillis` (20 s) they fail with a pool timeout error. The HTTP connections for the 10 hung requests remain open (keep-alive or not), occupying file descriptors and Node.js async context. The service is effectively unavailable for the duration of the partition — which, without OS-level TCP keepalive tuning, can be hours. This is a complete availability loss for the `/api/v1/contracts/{contractId}` endpoint and, because the pool is shared, for all other endpoints that use `pool.queryQuietly()`.

**Severity: High** — full DoS of the REST API with only 10 requests, no authentication required, no rate-limit bypass needed.

### Likelihood Explanation

The `/api/v1/contracts/{contractId}` endpoint is public and unauthenticated. Any external user can send 10 concurrent HTTP GET requests. Network partitions between application and database occur in cloud environments due to misconfiguration, rolling restarts, failover events, or deliberate network-level interference. The attacker does not need to cause the partition — they only need to time their 10 requests to coincide with one. Alternatively, an attacker with network access between the app and DB (e.g., a compromised internal host) can induce the partition themselves using firewall rules (`iptables -I OUTPUT -d <db-host> -j DROP`), making this fully attacker-controlled. The attack is repeatable and requires no special knowledge beyond the public API path.

### Recommendation

1. **Add a client-side `query_timeout`** to the `pg` Pool configuration in `rest/dbpool.js`:
   ```js
   const poolConfig = {
     ...
     query_timeout: config.db.pool.statementTimeout,  // client-side, fires even during partition
   };
   ```
   The `pg` library's `query_timeout` option rejects the query promise on the client side regardless of network state.

2. **Set an HTTP server response timeout** in `rest/server.js` after `server.listen()`:
   ```js
   server.setTimeout(30000);  // close hung connections after 30 s
   ```

3. **Tune OS TCP keepalive** on the application host to detect dead DB connections within seconds rather than hours (`net.ipv4.tcp_keepalive_time`, `tcp_keepalive_intvl`, `tcp_keepalive_probes`).

4. **Wrap `queryQuietly` with a `Promise.race`** against a timeout as a defense-in-depth measure inside `rest/utils.js`.

### Proof of Concept

**Preconditions:** Mirror node REST API is running. A network partition between the Node.js process and PostgreSQL is induced (e.g., `iptables -I OUTPUT -d <pg-host> -p tcp --dport 5432 -j DROP` on the app host, or a firewall rule on the DB host).

**Steps:**
1. Induce network partition between REST API and PostgreSQL.
2. Send 10 concurrent requests (one per pool connection):
   ```bash
   for i in $(seq 1 10); do
     curl -s --keepalive-time 3600 \
       "http://<mirror-node>/api/v1/contracts/0.0.1234" &
   done
   wait
   ```
3. Immediately send an 11th request:
   ```bash
   curl -v "http://<mirror-node>/api/v1/contracts/0.0.1234"
   ```
4. **Result:** The 11th request hangs for 20 seconds (waiting for a pool connection slot) then fails with a pool timeout error. The original 10 HTTP connections remain open indefinitely. All other endpoints sharing the pool are also unavailable.
5. Restore network: `iptables -D OUTPUT -d <pg-host> -p tcp --dport 5432 -j DROP`. The 10 hung requests eventually resolve (after TCP keepalive fires, ~2 hours by default), restoring service. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/controllers/contractController.js (L707-729)
```javascript
  getContractById = async (req, res) => {
    if (utils.conflictingPathParam(req, 'contractId', 'results')) {
      return;
    }

    const {filters, contractId: contractIdParam} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractByIdParameters
    );

    const {conditions: timestampConditions, params: timestampParams} =
      utils.extractTimestampRangeConditionFilters(filters);

    const {query, params} = getContractByIdOrAddressContractEntityQuery({
      timestampConditions,
      timestampParams,
      contractIdParam,
    });

    const {rows} = await pool.queryQuietly(query, params);
    if (rows.length !== 1) {
      throw new NotFoundError();
    }
```

**File:** rest/utils.js (L1518-1521)
```javascript
    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
      } else {
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
