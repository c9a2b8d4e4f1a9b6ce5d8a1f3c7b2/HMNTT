### Title
Unprivileged Double DB Query Amplification via SCHEDULECREATE Transaction ID Lookup

### Summary
Any unauthenticated external user can deterministically force two `pool.queryQuietly()` database calls per HTTP request by supplying a transaction ID belonging to a known successful SCHEDULECREATE transaction. The `mayMissLongTermScheduledTransaction()` guard has no rate limiting, no authentication requirement, and its trigger condition is fully controllable by the caller using publicly observable on-chain data. Under concurrent load this doubles effective DB query volume, amplifying a partial database partition into a full one.

### Finding Description

**Exact code path:**

`getTransactionsByIdOrHash()` at [1](#0-0)  issues the first query, then immediately chains `.then()` to call `mayMissLongTermScheduledTransaction()`. If that function returns `true`, a second `pool.queryQuietly()` is issued with an expanded upper timestamp bound:

```js
// rest/transactions.js lines 930-938
const {rows} = await pool.queryQuietly(query, params).then((result) => {
  if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
    return result;
  }
  params[params.upperConsensusTimestampIndex] =
    params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
  return pool.queryQuietly(query, params);   // ← second DB query
});
```

**Root cause — `mayMissLongTermScheduledTransaction()` logic:** [2](#0-1) 

The function returns `true` (triggering the second query) when **all** of the following hold:
1. `isTransactionHash === false` — the caller used a transaction ID (not a hash).
2. `scheduled === undefined` — no `?scheduled=` query parameter was supplied.
3. The first query returned ≥1 row with `type === 42` (`scheduleCreateProtoId`) [3](#0-2)  and `result` in `SUCCESS_PROTO_IDS` [4](#0-3) , and no row has `scheduled === true`.

**All three conditions are fully attacker-controlled:**
- Condition 1: the attacker simply uses the `/transactions/{transactionId}` path (not a hash).
- Condition 2: the attacker omits the `?scheduled=` parameter (the default).
- Condition 3: successful SCHEDULECREATE transactions are publicly visible on the Hedera network ledger; the attacker picks any known one.

**`extractSqlFromTransactionsByIdOrHashRequest()` confirms** that when a transaction ID is supplied, `isTransactionHash` is set to `false` and `scheduled` defaults to `undefined` unless the caller explicitly passes `?scheduled=`: [5](#0-4) 

**No rate limiting exists** in the REST layer — a search across all `rest/**/*.js` files finds zero matches for `rateLimit`, `throttle`, or `express-rate`. 

**Existing guards are insufficient:**
- The `isTransactionHash` check only blocks hash-based lookups, not ID-based ones.
- The `scheduled === false` check only blocks requests that explicitly pass `?scheduled=false`.
- Neither check prevents an attacker from omitting `?scheduled=` entirely while using a transaction ID.

### Impact Explanation
Every request matching the trigger condition costs **two full DB queries** instead of one. The second query uses an expanded timestamp range (`maxScheduledTransactionConsensusTimestampRangeNs`) [6](#0-5) , making it potentially more expensive than the first. Under concurrent attacker-controlled load (e.g., 100 parallel requests/second), this doubles the DB query rate and connection pool pressure. If the database is already under a partial network partition (elevated latency, reduced throughput), the doubled query volume can exhaust the connection pool and push the system into a full outage. The `getTransactionQuery` itself is a multi-join query with correlated subqueries against `crypto_transfer`, `token_transfer`, and `assessed_custom_fee` tables, making each call non-trivial. [7](#0-6) 

### Likelihood Explanation
- **No authentication required.** Any internet-accessible client can call `/api/v1/transactions/{id}`.
- **Trigger data is public.** Successful SCHEDULECREATE transaction IDs are visible on public Hedera explorers (HashScan, etc.) and via the mirror node's own `/api/v1/transactions?type=SCHEDULECREATE&result=success` endpoint.
- **Deterministic and repeatable.** The same transaction ID always triggers the double query; the attacker can reuse a single known ID indefinitely.
- **No jitter or backoff.** The second query fires synchronously in the same request handler with no delay.
- **Trivially scriptable.** A single `curl` loop or any HTTP load tool suffices.

### Recommendation
1. **Add a per-IP or global rate limit** on the `/api/v1/transactions/:transactionIdOrHash` endpoint using middleware (e.g., `express-rate-limit`) before this amplification can be exploited at scale.
2. **Cache the result of the first query** for a short TTL (e.g., 1–2 seconds) keyed on the transaction ID, so repeated requests for the same SCHEDULECREATE ID do not each issue two DB queries.
3. **Bound the retry** — if the first query already returned a SCHEDULECREATE row, the scheduled child transaction (if it exists) will have a consensus timestamp within a known window. Consider issuing a targeted query for the child rather than re-running the full query with an expanded range.
4. **Consider requiring `?scheduled=true` explicitly** to opt into the wider-range retry, removing the implicit trigger on any successful SCHEDULECREATE result.

### Proof of Concept

**Preconditions:**
- Mirror node REST API is publicly accessible.
- At least one successful SCHEDULECREATE transaction exists on the network (trivially true on mainnet/testnet).

**Steps:**

```bash
# Step 1: Find a successful SCHEDULECREATE transaction ID
TXID=$(curl -s "https://<mirror-node>/api/v1/transactions?transactiontype=SCHEDULECREATE&result=success&limit=1" \
  | jq -r '.transactions[0].transaction_id')

# Step 2: Confirm it triggers the double query (single request)
curl -v "https://<mirror-node>/api/v1/transactions/${TXID}"
# Observe: two pool.queryQuietly calls in server trace logs

# Step 3: Amplify under load (no auth required)
seq 1 500 | xargs -P 100 -I{} \
  curl -s "https://<mirror-node>/api/v1/transactions/${TXID}" -o /dev/null
# Result: 1000 DB queries issued for 500 HTTP requests
# Under partial partition: connection pool exhaustion → full outage
```

**Expected result:** DB query rate doubles relative to HTTP request rate. Under concurrent load with a degraded DB connection, the pool is exhausted and subsequent requests fail with `DbError`, producing a service-wide outage.

### Citations

**File:** rest/transactions.js (L31-31)
```javascript
const SUCCESS_PROTO_IDS = TransactionResult.getSuccessProtoIds();
```

**File:** rest/transactions.js (L35-36)
```javascript
    maxScheduledTransactionConsensusTimestampRangeNs,
    maxTransactionConsensusTimestampRangeNs,
```

**File:** rest/transactions.js (L46-46)
```javascript
const scheduleCreateProtoId = 42;
```

**File:** rest/transactions.js (L733-754)
```javascript
const getTransactionQuery = (mainCondition, subQueryCondition) => {
  return `
      select ${transactionFullFields},
             (select ${cryptoTransferJsonAgg}
              from ${CryptoTransfer.tableName}
              where ${CryptoTransfer.CONSENSUS_TIMESTAMP} = t.consensus_timestamp
                and ${CryptoTransfer.PAYER_ACCOUNT_ID} = t.payer_account_id
                and ${subQueryCondition}) as crypto_transfer_list,
             (select ${tokenTransferJsonAgg}
              from ${TokenTransfer.tableName}
              where ${TokenTransfer.CONSENSUS_TIMESTAMP} = t.consensus_timestamp
                and ${TokenTransfer.PAYER_ACCOUNT_ID} = t.payer_account_id
                and ${subQueryCondition}) as token_transfer_list,
             (select ${assessedCustomFeeJsonAgg}
              from ${AssessedCustomFee.tableName}
              where ${AssessedCustomFee.CONSENSUS_TIMESTAMP} = t.consensus_timestamp
                and ${AssessedCustomFee.PAYER_ACCOUNT_ID} = t.payer_account_id
                and ${subQueryCondition}) as assessed_custom_fees
      from ${Transaction.tableName} ${Transaction.tableAlias}
      where ${mainCondition}
      order by ${Transaction.CONSENSUS_TIMESTAMP}`;
};
```

**File:** rest/transactions.js (L763-794)
```javascript
const extractSqlFromTransactionsByIdOrHashRequest = async (transactionIdOrHash, filters) => {
  const isTransactionHash = isValidTransactionHash(transactionIdOrHash);

  if (isTransactionHash) {
    const encoding = transactionIdOrHash.length === Transaction.BASE64_HASH_SIZE ? 'base64url' : 'hex';
    if (transactionIdOrHash.length === Transaction.HEX_HASH_WITH_PREFIX_SIZE) {
      transactionIdOrHash = transactionIdOrHash.substring(2);
    }

    const rows = await getTransactionHash(Buffer.from(transactionIdOrHash, encoding));
    if (rows.length === 0) {
      throw new NotFoundError();
    }

    const payerAccountId = rows[0].payer_account_id;
    const lookupKeys = rows.map((row) => [payerAccountId, row.consensus_timestamp]).flat();

    return {
      ...getTransactionsByTransactionIdsSql(lookupKeys, filters, Transaction.CONSENSUS_TIMESTAMP),
      isTransactionHash,
    };
  } else {
    // try to parse it as a transaction id
    const transactionId = TransactionId.fromString(transactionIdOrHash);
    const payerAccountId = BigInt(transactionId.getEntityId().getEncodedId());
    const validStartTimestamp = BigInt(transactionId.getValidStartNs());

    return {
      ...getTransactionsByTransactionIdsSql([payerAccountId, validStartTimestamp], filters, Transaction.VALID_START_NS),
      isTransactionHash,
    };
  }
```

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
