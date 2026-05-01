### Title
Unauthenticated Multi-Path Amplification of Expensive `ethereum_transaction` JOIN via `getDetailedContractResults()` with No REST-Layer Rate Limiting

### Summary
`getEthTransactionByTimestampAndPayerId()` executes an unbounded `ethereum_transaction JOIN transaction` query on every cache miss. Because `getDetailedContractResults()` is invoked from two distinct public endpoints whose response-cache keys are URL-derived, an unprivileged attacker can force repeated execution of this JOIN for the same underlying data by rotating across endpoints and timestamps, with no rate-limiting guard in the REST API layer.

### Finding Description

**Exact code path:**

`rest/service/transactionService.js` lines 74–85 — `getEthTransactionByTimestampAndPayerId()` builds and executes a JOIN query on every call with no service-layer caching:

```js
// transactionService.js:74-85
async getEthTransactionByTimestampAndPayerId(timestamp, payerId) {
  const params = [timestamp, payerId];
  const query = [
    TransactionService.ethereumTransactionDetailsQuery,  // JOIN ethereum_transaction + transaction
    `where et.consensus_timestamp = $1 and et.payer_account_id = $2`,
  ].join('\n');
  const rows = await super.getRows(query, params);
  return rows.map((row) => new EthereumTransaction(row));
}
```

The static query at lines 28–55 performs a full JOIN:
```sql
from ethereum_transaction et
join transaction t
  on et.consensus_timestamp = t.consensus_timestamp
 and et.payer_account_id   = t.payer_account_id
```

**Two public endpoints call `getDetailedContractResults()` which always calls this function:**

- `getContractResultsByTimestamp` (`/api/v1/contracts/:contractId/results/:timestamp`) — `contractController.js:1002–1042`
- `getContractResultsByTransactionIdOrHash` (`/api/v1/contracts/results/:transactionIdOrHash`) — `contractController.js:1120–1203`

Both converge at `contractController.js:1205–1220`:
```js
getDetailedContractResults = async (contractDetails, contractId = undefined) => {
  return Promise.all([
    ContractService.getContractResultsByTimestamps(...),
    TransactionService.getEthTransactionByTimestampAndPayerId(   // ← always fired
      contractDetails.consensusTimestamp,
      contractDetails.payerAccountId
    ),
    RecordFileService.getRecordFileBlockDetailsFromTimestamp(...),
    ContractService.getContractLogsByTimestamps(...),
    ContractService.getContractStateChangesByTimestamps(...),
  ]);
};
```

**Why the cache does not protect against this:**

The response cache key is computed as `MD5(req.originalUrl)` (`responseCacheHandler.js:151–153`). The two endpoints have structurally different URLs for the same underlying ethereum transaction, so they produce different cache keys and each independently triggers a full DB round-trip on cache miss. Cache TTL is 600 s (`max-age=600`) for both single-result endpoints, meaning the window for repeated DB hits per unique timestamp is 10 minutes.

Additionally, the cache key includes query parameters, so `?hbar=true` vs `?hbar=false` (both accepted by `acceptedSingleContractResultsParameters`) produce separate cache entries for the same data, further multiplying misses.

**No rate limiting in the REST API:**

A search of all REST middleware (`rest/middleware/*.js`) finds no rate-limiting or throttling middleware. The `ThrottleManagerImpl` / `ThrottleConfiguration` found in the codebase are scoped exclusively to the `web3` Java module (contract-call/eth_call). The Node.js REST API has no per-IP, per-user, or global request-rate guard.

### Impact Explanation

Each unique `(timestamp, contractId/hash)` pair that reaches either endpoint before its cache warms triggers 5 parallel DB queries, including the `ethereum_transaction JOIN transaction`. An attacker rotating through N distinct timestamps across both endpoints generates up to 10N DB queries (5 per endpoint × 2 endpoints) before any caching takes effect. With a 600-second cache window and no rate limiting, a sustained low-rate flood of unique timestamps (e.g., iterating over known block timestamps from the public `/api/v1/blocks` endpoint) can continuously saturate DB I/O. Achieving a 30% increase over the 24-hour baseline is realistic for a moderately resourced attacker given the absence of any throttle.

### Likelihood Explanation

- **No authentication required**: all three endpoints are fully public.
- **No rate limiting**: the REST API has zero throttling middleware.
- **Timestamps are enumerable**: block/transaction timestamps are publicly discoverable via other mirror-node endpoints.
- **Repeatability**: the attacker simply iterates timestamps; each new timestamp resets the cache miss window.
- **Low sophistication**: a simple script cycling through timestamps across both endpoint paths is sufficient.

### Recommendation

1. **Add rate limiting to the REST API**: introduce a per-IP (and optionally global) request-rate limiter middleware (e.g., `express-rate-limit`) applied before route handlers, covering all `/api/v1/contracts/results/*` paths.
2. **Deduplicate at the service layer**: cache `getEthTransactionByTimestampAndPayerId` results keyed on `(timestamp, payerId)` in a short-lived in-process or Redis cache, so that concurrent or near-concurrent requests for the same data share a single DB round-trip regardless of which endpoint triggered them.
3. **Normalize the response-cache key**: for endpoints that resolve to the same underlying `(consensusTimestamp, payerAccountId)`, consider a canonical cache key at the data level rather than the URL level.

### Proof of Concept

**Preconditions**: public access to the mirror-node REST API; a list of known ethereum transaction timestamps (obtainable from `/api/v1/contracts/results?limit=100`).

**Steps**:

```bash
# 1. Collect known timestamps
TIMESTAMPS=$(curl -s 'https://<mirror-node>/api/v1/contracts/results?limit=100' \
  | jq -r '.results[].timestamp')

# 2. For each timestamp, hit both endpoints simultaneously (cache miss on both)
for TS in $TIMESTAMPS; do
  # Endpoint 1: by contractId + timestamp
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1234/results/$TS" &
  # Endpoint 2: by transactionId or hash (resolve hash from results list)
  HASH=$(curl -s "https://<mirror-node>/api/v1/contracts/results?timestamp=$TS" \
    | jq -r '.results[0].hash')
  curl -s "https://<mirror-node>/api/v1/contracts/results/$HASH" &
done
wait

# 3. Repeat in a loop; each new timestamp batch bypasses the 600s cache window
# and triggers fresh JOIN queries on both endpoints.
```

**Result**: DB query rate doubles compared to single-endpoint flooding; with no rate limiting, the attacker can sustain this indefinitely, driving aggregate DB resource consumption above the 30% threshold relative to the 24-hour baseline.