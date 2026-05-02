### Title
Unauthenticated 2x DB Query Amplification via Omitted `scheduled` Parameter in `mayMissLongTermScheduledTransaction()`

### Summary
When the `scheduled` query parameter is omitted from a request to `/api/v1/transactions/:transactionIdOrHash`, `mayMissLongTermScheduledTransaction()` returns `true` for any transaction ID backed by a successful `SCHEDULECREATE` without a yet-executed scheduled child, unconditionally triggering a second database query. Because successful `SCHEDULECREATE` transaction IDs are public blockchain data, any unauthenticated attacker can reliably double the database load per request with no additional effort, and no application-level rate limiting exists in the REST API layer to prevent this.

### Finding Description

**Exact code location:** `rest/transactions.js`, `mayMissLongTermScheduledTransaction()`, lines 974–996; called at line 931.

```
// rest/transactions.js:974-996
const mayMissLongTermScheduledTransaction = (isTransactionHash, scheduled, transactions) => {
  if (isTransactionHash || scheduled === false) {   // ← only blocks hash lookups or explicit false
    return false;
  }

  if (scheduled === undefined) {                    // ← triggered when param is omitted
    let scheduleExists = false;
    for (const transaction of transactions) {
      if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
        scheduleExists = true;                      // ← set true on any successful SCHEDULECREATE
      } else if (transaction.scheduled) {
        return false;
      }
    }
    return scheduleExists;                          // ← returns true → second query fires
  }
  ...
};
```

**Caller (lines 930–938):**
```
const {rows} = await pool.queryQuietly(query, params).then((result) => {
  if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
    return result;
  }
  params[params.upperConsensusTimestampIndex] =
    params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
  return pool.queryQuietly(query, params);   // ← second DB query, wider timestamp range
});
```

**Root cause:** The function distinguishes `scheduled === undefined` (parameter absent) from `scheduled === false` (explicit opt-out). When absent, the function performs a content-based heuristic: if the first query returns a successful `SCHEDULECREATE` row with no corresponding scheduled child, it returns `true` and a second query with an extended timestamp window is issued. The failed assumption is that this path is safe from abuse because it is "normal" API usage — but it is equally reachable by an attacker who simply omits the parameter.

**Why existing checks are insufficient:**
- `isTransactionHash` guard only applies to hash-based lookups, not transaction-ID lookups.
- `scheduled === false` guard only applies when the caller explicitly passes `scheduled=false`.
- No application-level rate limiting exists in the REST API server (`rest/server.js` lines 132–133 register the route with no throttle middleware; the rate-limiting found in the codebase belongs to the `web3` module only).
- The second query fires on *every* request for a qualifying transaction ID, not just the first.

### Impact Explanation

Every request to `/api/v1/transactions/{id}` for a transaction ID that has a successful `SCHEDULECREATE` without an executed child causes exactly **two** database queries instead of one. An attacker sending N requests causes 2N database queries. This is a consistent, bounded (2×) amplification of database load achievable with zero authentication and zero special knowledge beyond a valid `SCHEDULECREATE` transaction ID. Under sustained high-rate attack, this doubles effective DB pressure on the mirror node's PostgreSQL backend, potentially degrading availability for all users of the REST API.

### Likelihood Explanation

- **No authentication required.** The endpoint is fully public.
- **Trigger condition is trivially discoverable.** All `SCHEDULECREATE` transactions are recorded on the public ledger; an attacker can enumerate them via the same mirror node API (`/api/v1/transactions?type=SCHEDULECREATE`).
- **Trigger condition is stable.** Long-term scheduled transactions (those with `wait_for_expiry=true`) may not execute for up to 62 days, meaning the same transaction ID remains a valid amplification target for the entire window.
- **Repeatable with no state.** Each request is stateless; the attacker needs only a single valid transaction ID and can loop indefinitely.

### Recommendation

1. **Short-term:** Add a guard that also returns `false` when `scheduled === undefined` and the first query already returned results that include a `SCHEDULECREATE` but no scheduled child — i.e., treat the "no scheduled param + SCHEDULECREATE found" path as a cache-miss hint only, not a trigger for an unconditional second query. Alternatively, require the caller to explicitly pass `scheduled=true` to opt into the wider-range query.
2. **Medium-term:** Add application-level rate limiting to the REST API transaction-by-ID endpoint (analogous to the `web3` throttle middleware already present), keyed per source IP.
3. **Long-term:** Consider caching the result of the second query (keyed on transaction ID) with a short TTL so repeated requests for the same ID do not each incur two DB round-trips.

### Proof of Concept

**Precondition:** Identify a successful `SCHEDULECREATE` transaction whose scheduled child has not yet executed (long-term schedule, `wait_for_expiry=true`). This can be found via:
```
GET /api/v1/transactions?type=SCHEDULECREATE&result=success
```
Pick any `transaction_id` from the response, e.g. `0.0.100-1234567890-000000001`.

**Trigger:** Send repeated requests omitting the `scheduled` parameter:
```bash
while true; do
  curl -s "https://<mirror-node>/api/v1/transactions/0.0.100-1234567890-000000001" > /dev/null
done
```

**Result:** Each iteration causes two `pool.queryQuietly()` calls against the database instead of one. At N requests/second, the database receives 2N queries/second for this endpoint alone. The second query uses an extended upper timestamp bound (`lowerConsensusTimestampIndex + maxScheduledTransactionConsensusTimestampRangeNs`), potentially scanning a larger index range than the first.

**Contrast with mitigated path:** Adding `?scheduled=false` to the same URL causes `mayMissLongTermScheduledTransaction` to return `false` immediately (line 976), resulting in only one DB query per request — confirming the parameter distinction is the sole gate. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rest/server.js (L132-133)
```javascript
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);
```
