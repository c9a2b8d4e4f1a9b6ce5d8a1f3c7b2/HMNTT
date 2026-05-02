### Title
Unbounded DB-Partition Hang in `getAccountTokenAllowances()` Exhausts Server File Descriptors

### Summary
`getAccountTokenAllowances()` issues a database query with no client-side query timeout and no HTTP-level response timeout. During a network partition between the Node.js process and PostgreSQL, the `pg` driver blocks indefinitely on the socket, the HTTP response is never sent, and every concurrent request holds an open TCP connection and a file descriptor until the OS limit is reached.

### Finding Description

**Exact code path:**

`rest/controllers/tokenAllowanceController.js` lines 68–81 — `getAccountTokenAllowances` is an `async` handler that `await`s `TokenAllowanceService.getAccountTokenAllowances(query)` with no timeout wrapper. [1](#0-0) 

`TokenAllowanceService.getAccountTokenAllowances()` calls `super.getRows()`: [2](#0-1) 

`BaseService.getRows()` calls `pool.queryQuietly()` with no timeout argument: [3](#0-2) 

**Pool configuration — no client-side `query_timeout`:**

`rest/dbpool.js` configures only `statement_timeout` (a PostgreSQL server-side GUC) and `connectionTimeoutMillis` (applies only to acquiring a new connection from the pool). There is no `query_timeout` option, which is the `pg` library's client-side socket-level timeout: [4](#0-3) 

**No HTTP server timeout:**

`rest/server.js` creates the HTTP server with `app.listen()` but never calls `server.setTimeout()` and registers no request-deadline middleware: [5](#0-4) 

**Root cause — why `statement_timeout` is insufficient during a partition:**

`statement_timeout` is enforced by the PostgreSQL backend process. During a network partition, the TCP segment carrying the query never reaches the server (or ACKs are dropped). The PostgreSQL process never starts executing the statement, so it never fires the timeout. The `pg` driver is blocked in a `socket.read()` waiting for a response that will never arrive. Default Linux TCP keepalive probes begin after ~7200 s, so the socket hangs for hours without OS intervention.

`connectionTimeoutMillis` (default 20 000 ms) only guards the moment a new connection is checked out of the pool; it does not apply to a query already in flight on an established connection. [6](#0-5) 

### Impact Explanation

Each hung request holds:
- One open HTTP/TCP socket (one file descriptor on the server)
- One checked-out `pg` pool connection (pool max defaults to 10)

An attacker who sends concurrent requests faster than the OS reclaims descriptors will exhaust the server's file-descriptor limit (`ulimit -n`, typically 1024–65535). Once exhausted, the Node.js process cannot accept new TCP connections, open files, or create pipes — effectively a complete denial of service. Because the pool is also exhausted (max 10 connections), legitimate requests queue and then fail even before the FD limit is hit.

### Likelihood Explanation

**Preconditions:** None beyond network access to the public REST API. No authentication is required for `/api/v1/accounts/:id/allowances/tokens`.

**Trigger:** A DB partition (firewall rule change, cloud network event, DB failover) combined with concurrent requests from any unprivileged client.

**Repeatability:** Any client can send a burst of GET requests to the endpoint. During a partition lasting minutes, tens or hundreds of connections accumulate. The attacker does not need to cause the partition — they only need to exploit the window while it exists (or repeatedly probe during rolling DB maintenance).

### Recommendation

1. **Add a client-side `query_timeout`** to the pool config in `rest/dbpool.js`. The `pg` library supports `query_timeout` (milliseconds), which aborts the query on the client side regardless of server reachability:
   ```js
   query_timeout: config.db.pool.statementTimeout, // reuse existing value
   ```

2. **Set an HTTP server response timeout** in `rest/server.js` after `app.listen()`:
   ```js
   server.setTimeout(30_000); // 30 s hard deadline per request
   ```

3. **Add a request-level deadline middleware** that calls `res.setTimeout()` or uses `AbortController` to cancel the DB query if the HTTP response has not been sent within a configurable window, consistent with how the web3 module implements `requestTimeout` via `HibernateConfiguration`. [7](#0-6) 

### Proof of Concept

```bash
# 1. Simulate a DB partition (e.g., drop packets to PostgreSQL port)
sudo iptables -I OUTPUT -p tcp --dport 5432 -j DROP

# 2. Send concurrent requests to the token allowance endpoint
#    (no authentication required)
for i in $(seq 1 200); do
  curl -s "http://<mirror-node>:5551/api/v1/accounts/0.0.1234/allowances/tokens" &
done
wait

# 3. Observe on the server:
#    - All 200 connections remain in ESTABLISHED state (ss -tnp | grep node)
#    - File descriptors consumed: ls /proc/$(pgrep node)/fd | wc -l
#    - Pool exhausted: subsequent requests receive connection-pool errors
#    - After FD limit: new connections refused with EMFILE

# 4. Restore network — existing hung requests do NOT resolve because
#    the pg driver has no client-side timeout to abort them.
sudo iptables -D OUTPUT -p tcp --dport 5432 -j DROP
```

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L68-81)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
    const allowances = tokenAllowances.map((model) => new TokenAllowanceViewModel(model));

    res.locals[responseDataLabel] = {
      allowances,
      links: {
        next: this.getPaginationLink(req, allowances, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/service/tokenAllowanceService.js (L86-90)
```javascript
  async getAccountTokenAllowances(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new TokenAllowance(ta));
  }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
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

**File:** rest/server.js (L149-156)
```javascript
if (!isTestEnv()) {
  const server = app.listen(port, '0.0.0.0', (err) => {
    if (err) {
      throw err;
    }

    logger.info(`Server running on port: ${port}`);
  });
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-46)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
```
