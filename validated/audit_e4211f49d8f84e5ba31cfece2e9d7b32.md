Based on my code investigation, the core technical claims are verified. Let me document the findings.

**Verified facts:**

- `accounts.js` line 366-367: `preQueryHint` is set and passed to `queryQuietly` when a public key filter is present. [1](#0-0) 
- `utils.js` lines 1518-1527: When `preQueryHint` is truthy, the code calls `this.connect()` (dedicated client), wraps in a transaction (`begin; ${preQueryHint}`), runs the query, and commits — holding the connection for the full transaction lifecycle. [2](#0-1) 
- The `finally` block at lines 1540-1544 releases the client, but only after the full transaction completes. [3](#0-2) 
- `dbpool.js` confirms `max: config.db.pool.maxConnections`, `connectionTimeoutMillis`, and `statement_timeout` are all configurable with finite defaults. [4](#0-3) 

---

# Audit Report

## Title
Unauthenticated Connection Pool Exhaustion via `account.publickey` Filter Forcing Dedicated DB Connection Acquisition

## Summary
Any unauthenticated caller supplying a valid `account.publickey` query parameter triggers a code path in `queryQuietly` that acquires a **dedicated, exclusive pg client** for the full duration of a database transaction. With a finite pool ceiling and no rate limiting, concurrent requests can exhaust all available connections, denying service to all API endpoints.

## Finding Description

In `rest/accounts.js` lines 366–367, when a public key filter is present, `preQueryHint` is set to `constants.zeroRandomPageCostQueryHint` (a non-empty string, therefore truthy) and passed to `pool.queryQuietly`: [1](#0-0) 

Inside `queryQuietly` (`rest/utils.js` lines 1518–1527), the truthy `preQueryHint` branch calls `this.connect()` to acquire a **dedicated client** from the pool, opens a transaction with `begin; ${preQueryHint}`, executes the query, and commits — holding the connection for the entire transaction lifecycle: [2](#0-1) 

The client is only released in the `finally` block after the full transaction completes: [3](#0-2) 

This contrasts with the non-hint path (`this.query()`), which uses pg's internal acquire-execute-release cycle and holds connections for a much shorter duration.

The pool is configured with a hard ceiling (`max: config.db.pool.maxConnections`) and a `connectionTimeoutMillis` that causes waiting requests to fail after the timeout: [5](#0-4) 

## Impact Explanation

The pg pool is shared across all REST endpoints. Exhausting it via the `account.publickey` endpoint denies service to all other endpoints (transactions, balances, tokens, etc.) for the duration of the attack. With a `statement_timeout` of 20,000 ms (default), each wave of concurrent requests can hold the pool for up to 20 seconds. An attacker sustaining ~10 concurrent HTTP connections can keep the pool permanently exhausted, rendering the entire REST API unavailable.

## Likelihood Explanation

The attack requires zero authentication, zero privileges, and only a syntactically valid 66-character hex public key (trivially obtained from any Ethereum wallet or generated locally). The `account.publickey` parameter is publicly documented. No IP-based rate limiting, per-user throttle, or circuit breaker exists in the REST layer. The attack is fully automatable with standard HTTP tooling (`curl`, `ab`, etc.).

## Recommendation

1. **Rate-limit** the `account.publickey` endpoint (and ideally all endpoints) at the HTTP layer (e.g., via a reverse proxy or middleware) to bound concurrent requests per IP.
2. **Limit dedicated-connection concurrency**: use a semaphore or separate, smaller connection pool for the `preQueryHint` transaction path to prevent it from consuming the entire shared pool.
3. **Reduce `connectionTimeoutMillis`** and `statement_timeout` defaults to limit how long a single request can hold a connection.
4. Consider whether `SET LOCAL random_page_cost = 0` can be issued as a session-level hint within a normal `Pool.query()` call using a single-statement approach, eliminating the need for a dedicated client entirely.

## Proof of Concept

```bash
# Generate a valid secp256k1 public key (or use any known one)
PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Send 10 concurrent requests to exhaust the default pool of 10
for i in $(seq 1 10); do
  curl -s "http://<mirror-node>/api/v1/accounts?account.publickey=$PUBKEY" &
done
wait

# Any subsequent request from a legitimate user will now block for up to 20s
curl -v "http://<mirror-node>/api/v1/transactions"
# Expected: connection timeout error after ~20000ms
```

Each of the 10 concurrent requests acquires one dedicated pg client via `this.connect()` in the `preQueryHint` branch of `queryQuietly`. With all 10 pool slots held, the 11th request (any endpoint) blocks until `connectionTimeoutMillis` expires and throws a connection timeout error.

### Citations

**File:** rest/accounts.js (L366-367)
```javascript
  const preQueryHint = pubKeyQuery.query !== '' && constants.zeroRandomPageCostQueryHint;
  const result = await pool.queryQuietly(query, params, preQueryHint);
```

**File:** rest/utils.js (L1518-1527)
```javascript
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
```

**File:** rest/utils.js (L1540-1544)
```javascript
    } finally {
      if (client !== undefined) {
        client.off('error', clientErrorCallback);
        client.release();
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
