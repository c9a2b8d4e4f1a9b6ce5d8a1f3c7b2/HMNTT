### Title
Orphaned DB Connection Pool Exhaustion via Client Disconnect in `getTokenRelationships()`

### Summary
`getTokenRelationships()` in `rest/controllers/tokenController.js` issues multiple sequential database queries with no mechanism to detect or react to client disconnection. When a client drops its TCP connection after the DB call is issued, the Node.js handler continues executing and holds a `pg` pool connection for the full `statement_timeout` duration (default 20 seconds). Because the pool is capped at 10 connections by default, an unprivileged attacker sending as few as 10 concurrent requests and immediately disconnecting can fully exhaust the DB connection pool, causing all subsequent legitimate requests to queue or fail.

### Finding Description

**Exact code path:**

`getTokenRelationships()` (lines 66–92, `rest/controllers/tokenController.js`) makes three sequential awaited calls after the HTTP layer has accepted the request:

```js
const accountId = await EntityService.getEncodedId(...);   // DB call 1
const isValidAccount = await EntityService.isValidAccount(accountId); // DB call 2
const tokenRelationships = await TokenService.getTokenAccounts(query); // DB call 3
```

`TokenService.getTokenAccounts()` (`rest/service/tokenService.js`, lines 96–115) calls `super.getRows(sqlQuery, params)` and potentially a second query via `getCachedTokens()`. `BaseService.getRows()` (`rest/service/baseService.js`, line 55–57) resolves to:

```js
return (await this.pool().queryQuietly(query, params)).rows;
```

No `AbortSignal`, no `req.on('close', ...)` listener, and no cancellation token is ever passed into the `pg` pool query path.

**Root cause:**

The handler is a plain `async` function. Express does not cancel in-flight async operations on client disconnect. The `pg` library's `pool.query()` does not accept an `AbortSignal`. Once the DB query is dispatched, the only thing that will release the connection is query completion or `statement_timeout` expiry.

**Why existing checks fail:**

- `statement_timeout: 20000` (`rest/dbpool.js`, line 15; `docs/configuration.md` line 557): This is the *only* backstop. It limits how long each orphaned query runs, but does not prevent pool exhaustion — it defines the *window* during which each connection is held hostage.
- `maxConnections: 10` (`rest/dbpool.js`, line 14; `docs/configuration.md` line 556): This is the attack surface, not a mitigation. With only 10 slots, an attacker needs only 10 concurrent orphaned requests to saturate the pool.
- PgBouncer `max_user_connections: 250` (`charts/hedera-mirror/values.yaml`, line 372–373): This is a PgBouncer-level cap on client-side connections, not on the Node.js application pool. The Node.js pool itself is bounded at 10.

### Impact Explanation

A fully exhausted `pg` pool means every new incoming request that requires a DB query will block waiting for a connection up to `connectionTimeoutMillis` (default 20 seconds, `docs/configuration.md` line 555), then fail with a connection timeout error. This is a complete denial-of-service of the REST API's database-backed endpoints for the duration of the attack. The attack is self-sustaining: the attacker only needs to maintain 10 concurrent "connect-and-drop" cycles, each lasting less than 20 seconds, to keep the pool permanently exhausted. No data is read or written by the attacker; the impact is pure availability loss.

### Likelihood Explanation

The endpoint `/api/v1/accounts/:id/tokens` is a public, unauthenticated read endpoint. No credentials, tokens, or special network position are required. The attack requires only the ability to open and immediately close TCP connections to the REST API port (5551 by default). This is trivially scriptable with `curl`, `ab`, or any HTTP client that supports connection abort. The pool size of 10 is small enough that a single attacker machine can sustain the attack indefinitely. The attack is repeatable, low-cost, and leaves no persistent side effects.

### Recommendation

1. **Add a client-disconnect guard in the handler.** Listen for `req.on('close', ...)` and set a flag; check it between each `await` to short-circuit execution before issuing the next DB call.
2. **Propagate an `AbortSignal` to DB queries.** Use `pg`'s support for query cancellation (via `pg-query-stream` or a wrapper that issues `pg_cancel_backend`) tied to the request lifecycle.
3. **Increase the pool size** or use a connection pooler (PgBouncer in session mode is already partially configured) to reduce the blast radius of pool exhaustion.
4. **Add rate limiting** at the HTTP layer (e.g., per-IP request rate) to limit how many concurrent in-flight requests a single client can hold open.

### Proof of Concept

```bash
# Exhaust the 10-connection pool by sending 10 concurrent requests
# and immediately aborting each TCP connection after the server
# has accepted and begun processing (i.e., after the DB call is issued).

for i in $(seq 1 10); do
  # --max-time 0.1 causes curl to abort after 100ms,
  # well before the DB query completes (up to 20s).
  curl -s --max-time 0.1 \
    "http://<mirror-node-rest>:5551/api/v1/accounts/0.0.1234/tokens" \
    &
done
wait

# Now issue a legitimate request — it will block for up to 20s
# (connectionTimeoutMillis) and then fail:
time curl -s "http://<mirror-node-rest>:5551/api/v1/accounts/0.0.1234/tokens"
# Expected: hangs ~20s then returns connection timeout error
```

Repeat the first loop every 15 seconds to maintain continuous pool exhaustion.