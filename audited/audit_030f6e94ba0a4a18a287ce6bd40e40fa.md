### Title
Connection Pool Starvation via Unbounded Query Hang in `getSchedules()` During Network Partition

### Summary
`getSchedules()` in `rest/schedules.js` calls `pool.queryQuietly()` with no client-side query execution timeout. The pool's `statement_timeout` is a PostgreSQL server-side setting that cannot fire during a network partition, leaving TCP sockets in a hung state. With the default pool size of 10 connections, an unprivileged attacker sending 10 or more concurrent requests to `/api/v1/schedules` during any network disruption between the REST API and the database exhausts the entire connection pool, causing all subsequent requests across all endpoints to fail.

### Finding Description

**Exact code path:**

`rest/schedules.js`, `getSchedules()`, lines 241 and 261–264: [1](#0-0) [2](#0-1) 

Each call resolves through `queryQuietly` in `rest/utils.js`, line 1520, which — when `preQueryHint` is absent (always the case here) — calls `this.query(query, params)` directly on the pool: [3](#0-2) 

In `node-postgres`, `pool.query()` internally acquires a dedicated client from the pool, issues the query, and holds that client until the server responds. There is no client-side query execution timeout wrapping this call.

**Pool configuration (`rest/dbpool.js`):** [4](#0-3) 

Three settings are present:
- `connectionTimeoutMillis` (default 20 000 ms): controls how long a caller waits to *acquire* a free client from the pool — not how long a query may run.
- `max` (default 10): the total number of clients in the pool.
- `statement_timeout` (default 20 000 ms): a **PostgreSQL server-side** `SET statement_timeout` sent at connection establishment time.

**Root cause — failed assumption:**

The design assumes `statement_timeout` will terminate long-running queries. This assumption fails during a network partition: the PostgreSQL server cannot send the timeout signal back over a broken TCP connection. The client-side socket enters a hung state and is held by the OS until TCP keepalive fires (Linux default: ~2 hours). There is no `query_timeout` option (node-postgres client-side timeout) anywhere in the pool configuration, so the application has no mechanism to reclaim the connection.

**Why existing checks are insufficient:**

| Check | Scope | Effective during partition? |
|---|---|---|
| `statement_timeout` 20 s | PostgreSQL server-side | No — server cannot respond |
| `connectionTimeoutMillis` 20 s | Pool queue wait only | Partially — new requests fail after 20 s, but in-flight connections are not released |
| `query_timeout` | Client-side (node-postgres) | Not configured — absent |

### Impact Explanation

With `max: 10` (default), an attacker needs exactly 10 concurrent requests to exhaust the pool. Once exhausted:
- All subsequent requests to **any** REST endpoint (not just `/schedules`) fail after `connectionTimeoutMillis` (20 s) with a pool timeout error.
- The 10 hung connections remain held for the duration of the partition (potentially hours under default OS TCP keepalive settings).
- The service is completely unavailable to all users for the entire partition window.

Severity: **High** (full service DoS, no authentication required, trivially triggered with 10 HTTP requests).

### Likelihood Explanation

- No authentication or rate limiting is required to call `/api/v1/schedules`.
- Network instability between a REST API pod and its database is a routine occurrence in cloud/Kubernetes environments (node restarts, rolling upgrades, DNS flaps, PgBouncer restarts).
- The attacker does not need to cause the partition — they only need to detect degraded response times (e.g., by measuring latency) and immediately flood the endpoint with 10 concurrent requests.
- The attack is repeatable: every time the network degrades, the attacker can re-trigger pool exhaustion.
- 10 concurrent HTTP requests is trivially achievable with any HTTP client (`curl --parallel`, `ab`, `wrk`, etc.).

### Recommendation

1. **Add a client-side `query_timeout`** to the pool configuration in `rest/dbpool.js`. In node-postgres, this is the `query_timeout` Pool option (milliseconds), which aborts the query on the client side regardless of server reachability:

```js
const poolConfig = {
  ...
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
  query_timeout: config.db.pool.statementTimeout, // client-side enforcement
};
```

2. **Configure TCP keepalive** on pool connections (`keepAlive: true`, `keepAliveInitialDelayMillis`) so the OS detects dead connections in seconds rather than hours.

3. **Add per-endpoint concurrency limiting** (e.g., via a semaphore or middleware) so a single endpoint cannot consume all pool connections.

### Proof of Concept

**Preconditions:**
- Mirror node REST API is running with default configuration (`maxConnections: 10`, no `query_timeout`).
- Network between the REST API and PostgreSQL is partitioned or severely degraded (e.g., `iptables -A OUTPUT -p tcp --dport 5432 -j DROP` on the API host, or a simulated partition via `tc netem`).

**Steps:**

```bash
# 1. Simulate network partition (on the REST API host):
sudo iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# 2. Immediately send 10 concurrent requests to exhaust the pool:
for i in $(seq 1 10); do
  curl -s "http://<mirror-node-host>:5551/api/v1/schedules" &
done
wait

# 3. Observe: the 10 requests hang indefinitely (no response).

# 4. Send an 11th request to any endpoint:
curl -v "http://<mirror-node-host>:5551/api/v1/accounts"

# Expected result: fails after ~20 seconds with a 503/500 error
# ("timeout exceeded when trying to connect" from the pool).

# 5. Restore network:
sudo iptables -D OUTPUT -p tcp --dport 5432 -j DROP
# The 10 hung requests will NOT immediately recover — they remain
# held until OS TCP keepalive fires (~2 hours by default).
```

**Result:** The service is unavailable to all users for the duration of the partition, triggered by 10 unauthenticated HTTP requests.

### Citations

**File:** rest/schedules.js (L241-241)
```javascript
  const {rows: schedules} = await pool.queryQuietly(schedulesQuery, params);
```

**File:** rest/schedules.js (L261-264)
```javascript
  const [{rows: entities}, {rows: signatures}] = await Promise.all([
    pool.queryQuietly(entityQuery, entityIds),
    pool.queryQuietly(signatureQuery, entityIds),
  ]);
```

**File:** rest/utils.js (L1518-1520)
```javascript
    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
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
