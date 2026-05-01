### Title
Unauthenticated Double DB Query via `scheduled=true` Parameter in `getTransactionsByIdOrHash()`

### Summary
Any unauthenticated user can force two sequential database queries per request by supplying `?scheduled=true` against a transaction ID that has no corresponding scheduled transaction. The branch at line 991 of `rest/transactions.js` unconditionally returns `true` when `scheduled === true && transactions.length === 0`, triggering a second `pool.queryQuietly()` with an expanded timestamp range. Because no authentication or rate-limiting guards this path, an attacker can sustain a 2× DB amplification factor at will.

### Finding Description

**Exact code path:**

In `getTransactionsByIdOrHash()` ( [1](#0-0) ), the first DB query is issued and its result is immediately passed to `mayMissLongTermScheduledTransaction()`:

```js
const {rows} = await pool.queryQuietly(query, params).then((result) => {
  if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
    return result;
  }
  params[params.upperConsensusTimestampIndex] =
    params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
  return pool.queryQuietly(query, params);   // ← second query
});
```

Inside `mayMissLongTermScheduledTransaction()` ( [2](#0-1) ):

```js
} else if (scheduled && transactions.length === 0) {
  return true;   // line 991 – unconditionally triggers second query
}
```

**Root cause:** The function assumes that zero results with `scheduled=true` means the scheduled transaction might exist but fall outside the narrow timestamp window, so it widens the window and retries. There is no check that the underlying transaction ID itself is real, recent, or has ever had a scheduled counterpart. The `scheduled=true` filter is added to the SQL WHERE clause at line 820–823 ( [3](#0-2) ), so any transaction ID — real or fabricated — combined with `scheduled=true` will produce zero rows from the first query, satisfying the trigger condition.

**Exploit flow:**
1. Attacker sends `GET /api/v1/transactions/0.0.1234-1234567890-000000000?scheduled=true` (transaction ID need not exist).
2. First `pool.queryQuietly()` runs with `WHERE … AND scheduled = true` → returns 0 rows.
3. `mayMissLongTermScheduledTransaction(false, true, [])` evaluates `scheduled && transactions.length === 0` → `true`.
4. Second `pool.queryQuietly()` runs with an expanded upper timestamp bound.
5. Both queries return 0 rows; `NotFoundError` is thrown — but two DB round-trips have already been consumed.
6. Attacker repeats at high concurrency.

**Why existing checks are insufficient:**
- The `isTransactionHash` guard at line 976 only short-circuits hash-based lookups, not ID-based ones. [4](#0-3) 
- The `scheduled === false` guard at line 976 only prevents the second query when the caller explicitly passes `scheduled=false`; passing `scheduled=true` bypasses it entirely.
- No authentication, API-key, or rate-limit check is present in this handler.

### Impact Explanation
Every request with `?scheduled=true` and a non-existent (or non-scheduled) transaction ID costs exactly two DB queries instead of one. Because the mirror-node REST tier is stateless and horizontally scaled but shares a single PostgreSQL backend, sustained amplified load on the DB degrades query latency for all REST nodes simultaneously. At sufficient request rates this can push DB CPU/connection-pool utilization past the threshold that causes 30%+ of processing nodes to become unresponsive or time out.

### Likelihood Explanation
The endpoint is public and unauthenticated. The parameter `scheduled` is a documented, accepted query parameter (`acceptedSingleTransactionParameters` at line 1014). [5](#0-4)  No special knowledge of the system internals is required — the attacker only needs to know the API path and that `scheduled=true` is a valid parameter. The attack is trivially scriptable, repeatable, and requires no privileged access.

### Recommendation
Add an existence pre-check before the second query: only widen the timestamp range if the base transaction ID (ignoring the `scheduled` filter) is known to exist. Concretely, change the condition at line 991 to also verify that a non-scheduled version of the transaction was found in a prior lookup, or restructure the logic so that `scheduled=true` with zero results from the first query does **not** automatically trigger a retry unless there is positive evidence (e.g., a matching `SCHEDULECREATE` row) that a scheduled counterpart could exist. Additionally, apply per-IP rate limiting on the `/transactions/:id` endpoint.

### Proof of Concept
```bash
# Single amplified request (2 DB queries, 1 HTTP request)
curl "https://<mirror-node>/api/v1/transactions/0.0.9999-9999999999-000000000?scheduled=true"
# → 404 Not Found, but 2 DB queries were executed

# Sustained amplification (replace N with desired concurrency)
seq 1 10000 | xargs -P 200 -I{} \
  curl -s -o /dev/null \
  "https://<mirror-node>/api/v1/transactions/0.0.{}-9999999999-000000000?scheduled=true"
```
Each request in the loop triggers two DB queries. At 200 concurrent connections, the DB sees 400 queries/batch instead of 200, with no authentication barrier.

### Citations

**File:** rest/transactions.js (L820-823)
```javascript
  if (scheduled !== undefined) {
    params.push(scheduled);
    conditions.push(`${Transaction.SCHEDULED} = $${params.length}`);
  }
```

**File:** rest/transactions.js (L923-938)
```javascript
const getTransactionsByIdOrHash = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedSingleTransactionParameters);
  const {query, params, scheduled, isTransactionHash} = await extractSqlFromTransactionsByIdOrHashRequest(
    req.params.transactionIdOrHash,
    filters
  );

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

**File:** rest/transactions.js (L1014-1014)
```javascript
const acceptedSingleTransactionParameters = new Set([constants.filterKeys.NONCE, constants.filterKeys.SCHEDULED]);
```
