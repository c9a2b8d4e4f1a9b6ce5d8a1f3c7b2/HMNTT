### Title
Unauthenticated Repeated Pagination Triggers Expensive Three-Way FULL OUTER JOIN, Enabling DB Resource Exhaustion

### Summary
Any unauthenticated user can supply an `account.id` filter to `GET /api/v1/transactions` and repeatedly paginate through results using the maximum `limit` value. Each page request independently re-executes the three-way FULL OUTER JOIN in `getTransactionTimestampsQuery()`, scanning three large tables (`transaction`, `crypto_transfer`, `token_transfer`) per request with no per-user rate limiting or caching of the timestamp-resolution phase.

### Finding Description
**Code path:** `rest/transactions.js`, `getTransactionTimestampsQuery()`, lines 555–604; called from `getTransactionTimestamps()` (line 474), called from `doGetTransactions()` (line 701), called from `getTransactions()` (line 676).

**Root cause:** When `accountQuery` is truthy — which happens whenever the user supplies any `account.id` query parameter — the function unconditionally builds and executes a three-way FULL OUTER JOIN:

```js
// rest/transactions.js lines 595-604
return `
    select coalesce(t.consensus_timestamp, ctl.consensus_timestamp, ttl.consensus_timestamp) ...
    from (${transactionOnlyQuery}) as t
             full outer join (${cryptoTransferQuery}) as ctl
                             on t.consensus_timestamp = ctl.consensus_timestamp
             full outer join (${tokenTransferQuery}) as ttl
                             on coalesce(t.consensus_timestamp, ctl.consensus_timestamp) = ttl.consensus_timestamp
    order by consensus_timestamp ${order}
        ${limitQuery}`;
```

Each of the three subqueries (`transactionOnlyQuery`, `cryptoTransferQuery`, `tokenTransferQuery`) independently scans its respective table with its own `LIMIT` clause, then the outer FULL OUTER JOIN merges them. This means every paginated request performs **three independent bounded table scans plus a FULL OUTER JOIN** — roughly 3× the work of a simple query.

**Why existing checks fail:**
- The `Cache` in `doGetTransactions` (line 705) only caches the results of `getTransactionsDetails()` (the second-phase detail query), **not** the `getTransactionTimestamps()` call that contains the FULL OUTER JOIN. Every page request re-executes the expensive join unconditionally.
- The `limit` parameter is bounded by a configured maximum (typically 100), but this only caps the result set size per page — it does not prevent repeated requests.
- The `bindTimestampRange` call (line 465) bounds the timestamp window, but pagination advances the timestamp cursor, so an attacker can walk through the entire dataset page by page, each time triggering a fresh FULL OUTER JOIN.
- No authentication or per-user rate limiting is visible in the request handler (`getTransactions`, line 671–677). [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
Each attacker request with `account.id` causes the database to execute three parallel bounded table scans plus a FULL OUTER JOIN. At maximum `limit` (e.g., 100), a single attacker sending requests in a tight loop can sustain a continuous stream of these expensive queries. Because the timestamp cursor advances with each page, the attacker can iterate through the entire transaction history indefinitely. This can saturate DB CPU and I/O, degrading or denying service to legitimate users. The impact is amplified on high-volume nodes where `crypto_transfer` and `token_transfer` tables are very large.

### Likelihood Explanation
The exploit requires zero privileges — only knowledge of any valid account ID (e.g., the well-known treasury account `0.0.2` or fee collector `0.0.98`). The pagination `next` link is returned in every response, making automated iteration trivial. A single attacker with a script can sustain the attack indefinitely. No special tooling is needed beyond `curl` or any HTTP client.

### Recommendation
1. **Cache the timestamp-resolution phase**: Apply the existing `Cache` mechanism (or a short-lived TTL cache) to the output of `getTransactionTimestamps()`, keyed on the full filter set including the timestamp cursor. This prevents re-executing the FULL OUTER JOIN for identical or near-identical paginated requests.
2. **Rate-limit by IP/account at the API gateway or middleware layer** for the `account.id` filter path, independent of the general rate limit.
3. **Add a query cost guard**: If `accountQuery` is present and no tight timestamp range is supplied, enforce a mandatory narrow timestamp window (e.g., max 1 hour) to bound the scan range of each subquery.
4. **Consider materializing the three-way join** as a DB view or using a single CTE-based query instead of three independent subqueries feeding a FULL OUTER JOIN, to reduce per-request DB work.

### Proof of Concept
```bash
# Step 1: Send first request with account.id filter at max limit
curl "https://<mirror-node>/api/v1/transactions?account.id=0.0.98&limit=100&order=desc"
# Response includes: "links": {"next": "/api/v1/transactions?account.id=0.0.98&limit=100&order=desc&timestamp=lt:X.Y"}

# Step 2: Follow the next link — triggers a fresh FULL OUTER JOIN
curl "https://<mirror-node>/api/v1/transactions?account.id=0.0.98&limit=100&order=desc&timestamp=lt:X.Y"

# Step 3: Automate in a loop
while true; do
  NEXT=$(curl -s "https://<mirror-node>/api/v1/transactions?account.id=0.0.98&limit=100" \
    | jq -r '.links.next')
  [ -z "$NEXT" ] && break
  curl -s "https://<mirror-node>$NEXT" > /dev/null
done
# Each iteration executes a three-way FULL OUTER JOIN on the DB with no caching.
```

### Citations

**File:** rest/transactions.js (L555-604)
```javascript
  if (creditDebitQuery || accountQuery) {
    const cryptoTransferQuery = getTransferDistinctTimestampsQuery(
      CryptoTransfer.tableName,
      'ctl',
      timestampQuery,
      resultTypeQuery,
      transactionTypeQuery,
      accountQuery,
      creditDebitQuery,
      order,
      limitQuery
    );

    const tokenTransferQuery = getTransferDistinctTimestampsQuery(
      TokenTransfer.tableName,
      'ttl',
      timestampQuery,
      resultTypeQuery,
      transactionTypeQuery,
      accountQuery.replace(/ctl\.entity_id/g, 'ttl.account_id'),
      creditDebitQuery.replace(/ctl\.amount/g, 'ttl.amount'),
      order,
      limitQuery
    );

    if (creditDebitQuery) {
      // credit/debit filter applies to crypto_transfer.amount and token_transfer.amount, a full outer join is needed to get
      // transactions that only have a crypto_transfer or a token_transfer
      return `
          select coalesce(ctl.consensus_timestamp, ttl.consensus_timestamp) as consensus_timestamp,
                 coalesce(ctl.payer_account_id, ttl.payer_account_id)       as payer_account_id
          from (${cryptoTransferQuery}) as ctl
                   full outer join (${tokenTransferQuery}) as ttl
                                   on ctl.consensus_timestamp = ttl.consensus_timestamp
          order by consensus_timestamp ${order}
              ${limitQuery}`;
    }

    // account filter applies to transaction.payer_account_id, crypto_transfer.entity_id,
    // and token_transfer.account_id, a full outer join between the four tables is needed to get rows that may only exist in one.
    return `
        select coalesce(t.consensus_timestamp, ctl.consensus_timestamp, ttl.consensus_timestamp) as consensus_timestamp,
               coalesce(t.payer_account_id, ctl.payer_account_id, ttl.payer_account_id)          as payer_account_id
        from (${transactionOnlyQuery}) as t
                 full outer join (${cryptoTransferQuery}) as ctl
                                 on t.consensus_timestamp = ctl.consensus_timestamp
                 full outer join (${tokenTransferQuery}) as ttl
                                 on coalesce(t.consensus_timestamp, ctl.consensus_timestamp) = ttl.consensus_timestamp
        order by consensus_timestamp ${order}
            ${limitQuery}`;
```

**File:** rest/transactions.js (L671-677)
```javascript
const getTransactions = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedTransactionParameters);
  const timestampFilters = filters.filter((filter) => filter.key === constants.filterKeys.TIMESTAMP);
  const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);

  res.locals[constants.responseDataLabel] = await doGetTransactions(filters, req, timestampRange);
};
```

**File:** rest/transactions.js (L695-723)
```javascript
const doGetTransactions = async (filters, req, timestampRange) => {
  const {
    limit,
    order,
    nextTimestamp,
    rows: payerAndTimestamps,
  } = await getTransactionTimestamps(filters, timestampRange);

  const loader = (keys) => getTransactionsDetails(keys, order).then((result) => formatTransactionRows(result.rows));

  const transactions = await cache.get(payerAndTimestamps, loader, keyMapper);

  const isEnd = transactions.length !== limit;
  const next = utils.getPaginationLink(
    req,
    isEnd && !nextTimestamp,
    {
      [constants.filterKeys.TIMESTAMP]: !isEnd
        ? transactions[transactions.length - 1]?.consensus_timestamp
        : nextTimestamp,
    },
    order
  );

  return {
    transactions,
    links: {next},
  };
};
```
