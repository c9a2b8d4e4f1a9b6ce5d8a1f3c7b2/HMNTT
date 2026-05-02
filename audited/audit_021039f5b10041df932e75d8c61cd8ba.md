### Title
DoS via Unconditional Second DB Query Triggered by Omitting `scheduled` Parameter on SCHEDULECREATE Transactions

### Summary
When the `scheduled` query parameter is omitted from a `/api/v1/transactions/{id}` request, `mayMissLongTermScheduledTransaction()` returns `true` for any transaction ID that resolves to a successful `SCHEDULECREATE` without a corresponding scheduled execution in the initial result set. This unconditionally triggers a second, wider-range database query. An unprivileged attacker who knows any such transaction ID can repeatedly exploit this to double the DB load per request with no authentication required.

### Finding Description

**Code location:** `rest/transactions.js`, `mayMissLongTermScheduledTransaction()`, lines 974–996, called from `getTransactionsByIdOrHash()` at lines 930–938.

**Root cause:** The function distinguishes three states of the `scheduled` parameter:
- `scheduled === false` → early return `false` (no second query)
- `scheduled === undefined` (parameter omitted) → enters the branch at line 980 that scans transactions and returns `true` if a successful SCHEDULECREATE exists without a scheduled execution
- `scheduled === true` → second query only if `transactions.length === 0` [1](#0-0) 

When `scheduled` is omitted, the branch at line 980 iterates the first query's rows. If it finds `transaction.type === scheduleCreateProtoId` (42) with a success result code, it sets `scheduleExists = true`. It only returns `false` early if it also finds a row with `transaction.scheduled === true`. If no such row exists (i.e., the scheduled execution hasn't been recorded yet), it returns `true`. [2](#0-1) 

Returning `true` causes the caller to mutate `params[params.upperConsensusTimestampIndex]` to `lowerConsensusTimestampIndex + maxScheduledTransactionConsensusTimestampRangeNs` and fire a second `pool.queryQuietly()` call — a wider-range DB query. [3](#0-2) 

The test suite explicitly confirms this behavior: the test case `'by transaction id, no scheduled, successful schedulecreate'` with `scheduled: undefined` and a single successful SCHEDULECREATE row expects `true`. [4](#0-3) 

**Failed assumption:** The design assumes that the `scheduled === undefined` path is only reached in legitimate browsing scenarios. There is no guard preventing an attacker from deliberately and repeatedly hitting this path.

### Impact Explanation

Every request against a qualifying SCHEDULECREATE transaction ID (one that succeeded but whose scheduled execution is not yet in the initial timestamp window) issues two database queries instead of one. The second query scans a wider timestamp range bounded by `maxScheduledTransactionConsensusTimestampRangeNs`. For long-term scheduled transactions — which by design may not execute for an extended period — this condition is persistent and stable. An attacker can sustain a 2× (or greater, given the wider scan range) DB amplification indefinitely against any such transaction ID, degrading database performance for all users of the mirror node.

### Likelihood Explanation

- **No privileges required.** The `/api/v1/transactions/{id}` endpoint is public.
- **Transaction IDs are public.** SCHEDULECREATE transactions are visible on-chain and through the mirror node's own list endpoints. An attacker can enumerate them trivially.
- **Persistent trigger condition.** A long-term scheduled transaction that hasn't executed yet remains a valid trigger for an extended period.
- **No rate limiting found in application code.** A search of `rest/*.js` found no application-level rate limiting on this endpoint. [5](#0-4) 

### Recommendation

1. **Treat omitted `scheduled` the same as `scheduled=false` for the second-query guard**, unless there is a specific user-facing reason to distinguish them. If the intent is to help users who don't know about the `scheduled` parameter, add a cap on how many times the second query can be triggered per IP/time window.
2. **Add application-level rate limiting** on the `/api/v1/transactions/{id}` endpoint (e.g., via an express rate-limit middleware), independent of any upstream proxy.
3. **Short-circuit the second query** if the first query already returned results that definitively account for the SCHEDULECREATE (e.g., the schedule entity shows it was deleted or expired).

### Proof of Concept

**Precondition:** Identify a transaction ID of a successful `SCHEDULECREATE` whose scheduled execution has not yet been recorded (e.g., a long-term schedule). This is obtainable from the public `/api/v1/transactions?type=SCHEDULECREATE` endpoint.

**Steps:**
```
# Step 1: Find a qualifying SCHEDULECREATE transaction ID
GET /api/v1/transactions?type=SCHEDULECREATE&result=success&limit=25

# Step 2: Pick a transaction ID where no scheduled=true sibling exists yet
# e.g., 0.0.12345-1700000000-000000000

# Step 3: Repeatedly call without the scheduled parameter (omit it entirely)
while true; do
  curl -s "https://<mirror-node>/api/v1/transactions/0.0.12345-1700000000-000000000"
done
```

Each iteration causes `mayMissLongTermScheduledTransaction()` to return `true` (confirmed by the test at line 1391–1403), triggering two DB queries per HTTP request — the second scanning a wider timestamp range — with no authentication or special access required. [4](#0-3)

### Citations

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

**File:** rest/__tests__/transactions.test.js (L1391-1403)
```javascript
      name: 'by transaction id, no scheduled, successful schedulecreate',
      input: {
        isTransactionHash: false,
        scheduled: undefined,
        transactions: [
          {
            scheduled: false,
            result: 22,
            type: 42,
          },
        ],
      },
      expected: true,
```
