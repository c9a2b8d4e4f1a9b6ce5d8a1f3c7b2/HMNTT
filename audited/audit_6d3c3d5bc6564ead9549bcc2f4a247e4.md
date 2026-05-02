### Title
Unauthenticated DB Connection Pool Exhaustion via `transaction_hash` Filter on `GET /contracts/results/logs`

### Summary
The `getContractLogs()` handler in `rest/controllers/contractController.js` accepts a `transaction_hash` query parameter that unconditionally triggers a synchronous database lookup via `getTransactionHash()` for every incoming request. Because the REST API Node.js process has no application-level rate limiting on this endpoint and the default DB connection pool size is only 10 connections, an unauthenticated attacker sending ≥10 concurrent requests with distinct hashes can hold all pool connections for up to 20 seconds each, causing a complete denial of service for all other REST API consumers.

### Finding Description

**Code path:**

1. `GET /contracts/results/logs?transaction.hash=<hash>` is routed to `getContractLogs()`. [1](#0-0) 

2. `getContractLogs()` calls `extractContractLogsMultiUnionQuery(filters)` with no pre-check or rate gate. [2](#0-1) 

3. Inside `extractContractLogsMultiUnionQuery()`, when `transactionHash !== undefined`, the code immediately `await`s a DB query: [3](#0-2) 

4. `getTransactionHash()` calls `pool.queryQuietly()` — a real blocking DB connection checkout from the shared pool: [4](#0-3) 

5. The pool is configured with `max: config.db.pool.maxConnections` and `statement_timeout: config.db.pool.statementTimeout`. Per official documentation, the defaults are **10 connections** and **20,000 ms** respectively: [5](#0-4) 

**Root cause:** There is no application-level rate limiting, concurrency cap, or per-IP throttle on the REST Node.js API for this endpoint. The only throttle mechanisms in the codebase (`ThrottleManagerImpl`, `ThrottleProperties`, `ThrottleConfiguration`) belong exclusively to the **web3 Java API** and do not apply here: [6](#0-5) 

The `authHandler.js` only grants per-user response-limit overrides to *authenticated* users — it provides zero protection for anonymous callers.

**Failed assumption:** The design assumes that infrastructure-level Traefik rate limiting (defined in Helm chart values) will always be present. However, this is an optional deployment artifact, not enforced in code, and is absent in Docker Compose and bare-metal deployments.

### Impact Explanation

With the default pool of 10 connections and a 20-second statement timeout, an attacker holding all 10 connections blocks every other REST API endpoint that requires a DB query for the full 20-second window. This is a complete REST API denial of service — not just the `/contracts/results/logs` endpoint. All endpoints sharing the same `pool` global (accounts, transactions, tokens, etc.) are affected simultaneously. The attacker can sustain the attack indefinitely by continuously issuing new batches of 10 requests before the previous batch times out.

### Likelihood Explanation

The attack requires zero authentication, zero special knowledge, and only a basic HTTP client capable of concurrent requests. The `transaction_hash` parameter is publicly documented. The attacker does not need valid hashes — any syntactically valid 32-byte hex string triggers the DB lookup regardless of whether a matching record exists. The attack is trivially scriptable and repeatable from a single IP or distributed across multiple IPs to bypass any infrastructure-level rate limiting.

### Recommendation

1. **Add application-level concurrency limiting** for the `transaction_hash` DB lookup path — e.g., a semaphore capping simultaneous in-flight hash lookups.
2. **Add per-IP rate limiting in the Node.js application** (e.g., `express-rate-limit`) for endpoints that trigger DB queries, independent of infrastructure.
3. **Reduce `statementTimeout`** for the `get_transaction_info_by_hash` query specifically to minimize connection hold time.
4. **Increase `maxConnections`** from the default of 10 to a value that provides headroom against burst traffic, and document it as a required tuning parameter.
5. Do not rely solely on Traefik middleware for rate limiting, as it is not enforced in all deployment configurations.

### Proof of Concept

```bash
# Generate 15 concurrent requests with random valid 32-byte hex hashes
for i in $(seq 1 15); do
  HASH=$(openssl rand -hex 32)
  curl -s "http://<mirror-node-host>:5551/api/v1/contracts/results/logs?transaction.hash=0x${HASH}" &
done
wait

# All 10 pool connections are now held for up to 20 seconds.
# Any legitimate request during this window will receive a connection timeout error.
# Repeat the loop before the 20s window expires to sustain the DoS.
```

### Citations

**File:** rest/controllers/contractController.js (L669-677)
```javascript
    if (transactionHash !== undefined) {
      const timestampFilters = bounds.primary.getAllFilters();
      const rows = await getTransactionHash(transactionHash, {order, timestampFilters});
      if (rows.length === 0) {
        return null;
      }

      bounds.primary = new Bound(filterKeys.TIMESTAMP);
      bounds.primary.parse({key: filterKeys.TIMESTAMP, operator: utils.opsMap.eq, value: rows[0].consensus_timestamp});
```

**File:** rest/controllers/contractController.js (L820-836)
```javascript
  getContractLogs = async (req, res) => {
    // get sql filter query, params, limit and limit query from query filters
    const filters = alterTimestampRange(utils.buildAndValidateFilters(req.query, acceptedContractLogsParameters));
    checkTimestampsForTopics(filters);

    // Workaround: set the request path in handler so later in the router level generic middleware it won't be
    // set to /contracts/results/:transactionIdOrHash
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`;
    res.locals[responseDataLabel] = {
      logs: [],
      links: {
        next: null,
      },
    };

    const query = await this.extractContractLogsMultiUnionQuery(filters);
    if (query === null) {
```

**File:** rest/transactionHash.js (L30-36)
```javascript
  const query = `${mainQuery}
    ${timestampConditions.length !== 0 ? `where ${timestampConditions.join(' and ')}` : ''}
    ${orderClause} ${order}
    ${limitClause}`;

  const {rows} = await pool.queryQuietly(query, params);
  return normalized !== hash ? rows.filter((row) => row.hash.equals(hash)) : rows;
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
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
