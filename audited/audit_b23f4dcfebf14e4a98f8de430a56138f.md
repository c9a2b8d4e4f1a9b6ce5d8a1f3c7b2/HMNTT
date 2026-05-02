### Title
Connection Pool Exhaustion via Unbounded In-Flight Queries During Network Partition (No Client-Side Query Timeout)

### Summary
`TokenAllowanceService.getAccountTokenAllowances()` calls `BaseService.getRows()`, which delegates to `queryQuietly()`. The pool is configured with a server-side `statement_timeout` only — no client-side `query_timeout` and no socket-level timeout exist. During a network partition, the PostgreSQL server's timeout fires but its error response never reaches the Node.js client, leaving each in-flight `await this.query()` promise permanently suspended while holding a pool connection. With the default pool cap of 10 connections, 10 concurrent unauthenticated requests are sufficient to exhaust the pool and deny service to all subsequent callers.

### Finding Description

**Exact code path:**

`rest/service/tokenAllowanceService.js`, line 88:
```js
const rows = await super.getRows(sqlQuery, params);
``` [1](#0-0) 

`rest/service/baseService.js`, lines 55–57 — `getRows()` calls `queryQuietly()` with no timeout argument:
```js
async getRows(query, params) {
  return (await this.pool().queryQuietly(query, params)).rows;
}
``` [2](#0-1) 

`rest/utils.js`, lines 1518–1520 — `queryQuietly()` issues the query with no client-side deadline:
```js
result = await this.query(query, params);
``` [3](#0-2) 

`rest/dbpool.js`, lines 7–16 — pool configuration has `statement_timeout` (server-side PostgreSQL GUC) but no `query_timeout` (node-postgres client-side option) and no socket timeout:
```js
const poolConfig = {
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,   // server-side only
  // query_timeout: <missing>                           // client-side — absent
};
``` [4](#0-3) 

**Root cause and failed assumption:**

The design assumes `statement_timeout` (default 20 000 ms) will bound query duration. This assumption holds only when the network between the app and PostgreSQL is healthy. During a partition:

1. PostgreSQL fires `statement_timeout` after 20 s and sends a cancellation error over the TCP socket.
2. The TCP socket is alive at the OS level (no RST has been received), so the write appears to succeed on the server side.
3. The error packet is dropped by the partition; the Node.js client never receives it.
4. `await this.query(query, params)` (line 1520) never settles — neither resolves nor rejects.
5. The connection is not returned to the pool.

No `query_timeout` (node-postgres client-side timer that races against the socket) is set anywhere in the REST JS codebase — confirmed by grep returning zero matches for `query_timeout`, `queryTimeout`, `idleTimeoutMillis`, and socket timeout patterns across all `rest/**/*.js` files. [5](#0-4) 

### Impact Explanation

The pool's hard cap is `maxConnections` (default **10**). [6](#0-5) 

Once all 10 connections are held by suspended promises, every subsequent request that reaches `queryQuietly()` blocks inside `pool.query()` waiting for a free slot. After `connectionTimeoutMillis` (default **20 s**) the caller receives a pool-timeout error, but the 10 original connections remain leaked for the duration of the partition. The REST API is completely unavailable to all users — a full denial of service — for as long as the partition persists. Because the pool is global and shared across all endpoints, a single targeted endpoint (e.g., `/api/v1/accounts/{id}/allowances/tokens`) can take down every other endpoint simultaneously.

### Likelihood Explanation

**Preconditions:** None. The endpoint is public and unauthenticated. No API key, session, or special privilege is required.

**Feasibility:** A network partition between the mirror-node REST process and its PostgreSQL backend can be induced by an attacker who controls network infrastructure between the two (e.g., a cloud-internal adversary, a misconfigured firewall rule, or a BGP-level attack). It can also occur naturally (hardware failure, cloud AZ outage). The attacker does not need to cause the partition themselves — they only need to detect it (e.g., by observing elevated latency) and then send 10 concurrent requests before the partition heals.

**Repeatability:** The attack is fully repeatable. Each new partition window is a new opportunity. Even a brief partition (seconds) is sufficient to lock all connections for its duration.

### Recommendation

1. **Add a client-side `query_timeout`** to the pool configuration in `rest/dbpool.js`. node-postgres supports this natively:
   ```js
   const poolConfig = {
     connectionTimeoutMillis: config.db.pool.connectionTimeout,
     max: config.db.pool.maxConnections,
     statement_timeout: config.db.pool.statementTimeout,
     query_timeout: config.db.pool.statementTimeout,  // client-side enforcement
   };
   ```
   `query_timeout` races a local timer against the socket; it rejects the promise and releases the connection even if the server's error response is never received.

2. **Set a TCP socket keepalive / socket timeout** on the underlying `net.Socket` so that OS-level dead-connection detection fires within seconds rather than the default hours.

3. **Expose `query_timeout` as a configurable property** (e.g., `hiero.mirror.rest.db.pool.queryTimeout`) alongside the existing `statementTimeout`.

### Proof of Concept

**Environment:** Mirror-node REST API running normally; attacker can inject a `DROP` firewall rule between the REST process and PostgreSQL (simulating a network partition).

```
# Step 1 – Simulate partition (on the host running the REST API or a network device)
iptables -I OUTPUT -p tcp --dport 5432 -j DROP

# Step 2 – Send 10 concurrent requests (pool size = 10) to the token allowances endpoint
for i in $(seq 1 10); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1234/allowances/tokens" &
done
wait

# Step 3 – All 10 pool connections are now suspended in `await this.query()`.
# Send one more request — it will block for connectionTimeoutMillis (20 s) then fail.
curl -v "http://<mirror-node>/api/v1/accounts/0.0.1/allowances/tokens"
# Expected: hangs ~20 s, then returns pool connection timeout error.

# Step 4 – Verify all other endpoints are also unavailable (shared pool).
curl -v "http://<mirror-node>/api/v1/transactions"
# Expected: same 20 s hang + error.

# Step 5 – Restore network; connections eventually recover (OS TCP timeout, hours later).
iptables -D OUTPUT -p tcp --dport 5432 -j DROP
```

The attack requires no authentication, no special payload, and only 10 HTTP requests.

### Citations

**File:** rest/service/tokenAllowanceService.js (L86-89)
```javascript
  async getAccountTokenAllowances(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new TokenAllowance(ta));
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/utils.js (L1481-1546)
```javascript
  Pool.prototype.queryQuietly = async function (query, params = [], preQueryHint = undefined) {
    let client;
    let result;
    let startTime;

    params = Array.isArray(params) ? params : [params];
    const clientErrorCallback = (error) => {
      logger.error(`error event emitted on pg pool. ${error.stack}`);
    };

    const traceEnabled = logger.isTraceEnabled();
    if (traceEnabled || isTestEnv()) {
      const callerInfo = new Error().stack
        .split('\n')
        .splice(1)
        .filter((s) => !(s.includes('utils.js') || s.includes('baseService.js')))
        .map((entry) => {
          const result = entry.match(/^\s*at\s+(\S+)[^(]+\((.*\/(.*\.js)):(\d+):.*\)$/);
          return result?.length === 5 && {function: result[1], file: result[3], line: result[4], path: result[2]};
        })[0];

      if (isTestEnv()) {
        await recordQuery(callerInfo, query);
      }

      if (traceEnabled) {
        startTime = Date.now();
        const {format} = await import('sql-formatter');
        const prettyQuery = format(query, {language: 'postgresql'});
        logger.trace(
          `${callerInfo.function} (${callerInfo.file}:${
            callerInfo.line
          })\nquery: ${prettyQuery}\nparams: ${JSONStringify(params)}`
        );
      }
    }

    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
      } else {
        client = await this.connect();
        client.on('error', clientErrorCallback);
        await client.query(`begin; ${preQueryHint}`);
        result = await client.query(query, params);
        await client.query('commit');
      }

      if (traceEnabled) {
        const elapsed = Date.now() - startTime;
        logger.trace(`Query took ${elapsed} ms and returned ${result.rows.length} entries`);
      }

      return result;
    } catch (err) {
      if (client !== undefined) {
        await client.query('rollback');
      }
      throw new DbError(err.message);
    } finally {
      if (client !== undefined) {
        client.off('error', clientErrorCallback);
        client.release();
      }
    }
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
