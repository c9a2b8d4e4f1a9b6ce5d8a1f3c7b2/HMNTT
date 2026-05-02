### Title
Unauthenticated DB Connection Pool Exhaustion via `getDetailedContractResults()` on `/contracts/:contractId/results/:consensusTimestamp`

### Summary
The public endpoint `/contracts/:contractId/results/:consensusTimestamp` invokes `getDetailedContractResults()`, which unconditionally fires 5 concurrent database queries via `Promise.all()` per request. With the default pool ceiling of 10 connections and a 20-second statement timeout, just 2 simultaneous unauthenticated requests saturate the entire pool, blocking every other REST API endpoint that shares it. No rate limiting, authentication, or concurrency guard exists on this path.

### Finding Description

**Exact code path:**

`rest/routes/contractRoute.js` line 18 registers the route with no middleware:
```
router.getExt('/:contractId/results/:consensusTimestamp', ContractController.getContractResultsByTimestamp);
```

`getContractResultsByTimestamp` (lines 1002–1042) calls `getDetailedContractResults()` after a single sequential lookup:

```javascript
// rest/controllers/contractController.js lines 1205-1220
getDetailedContractResults = async (contractDetails, contractId = undefined) => {
    return Promise.all([
      ContractService.getContractResultsByTimestamps(...),          // query 1
      TransactionService.getEthTransactionByTimestampAndPayerId(...), // query 2
      RecordFileService.getRecordFileBlockDetailsFromTimestamp(...),  // query 3
      ContractService.getContractLogsByTimestamps(...),              // query 4
      ContractService.getContractStateChangesByTimestamps(...),      // query 5
    ]);
};
```

All 5 queries are dispatched simultaneously and each holds a pool connection until it completes or times out.

**Pool configuration** (`rest/dbpool.js` lines 13–15, `docs/configuration.md` line 556):
- `max` (maxConnections): **10** (default)
- `statement_timeout`: **20 000 ms** (20 s)
- `connectionTimeoutMillis`: **20 000 ms** (20 s)

**Root cause:** 5 connections are acquired atomically per request with no upper bound on concurrent callers. At 2 simultaneous requests, all 10 pool slots are occupied for up to 20 seconds. Every subsequent request — on any endpoint — queues for a connection and times out after 20 seconds.

**Why existing checks fail:**
- Input validation (`validateContractIdAndConsensusTimestampParam`, lines 351–363) only rejects malformed IDs/timestamps; any syntactically valid pair passes through and triggers all 5 queries.
- A grep across `rest/**/*.js` for `rateLimit`, `throttle`, `slowDown`, and `express-rate` returns **zero matches** — no rate-limiting middleware is applied to the REST API.
- No authentication is required; the route is fully public.

### Impact Explanation

The REST API's single `pg` pool is shared across all endpoints. Exhausting it with requests to this one endpoint makes the entire REST API unresponsive: `/api/v1/transactions`, `/api/v1/accounts`, and every other path all queue for connections and return errors after 20 seconds. REST API nodes are effectively taken offline for the duration of the attack. Because the attack is stateless and requires no credentials, an attacker can sustain it indefinitely with a small number of concurrent HTTP clients, keeping the pool permanently saturated.

### Likelihood Explanation

The attack requires only:
1. Knowledge of any valid `contractId` and `consensusTimestamp` pair (both are public data, visible in block explorers or via other mirror node endpoints).
2. The ability to send 2+ concurrent HTTP GET requests — achievable with `curl --parallel`, `ab`, `wrk`, or any scripting language.

No authentication, no special network position, and no prior account is needed. The endpoint is reachable from the public internet. The attack is repeatable and fully automated.

### Recommendation

1. **Add a per-IP (or global) rate limiter** on the REST API using `express-rate-limit` or an equivalent, targeting at minimum the `/contracts/*/results/*` family of routes.
2. **Increase the default pool size** or, preferably, **cap per-endpoint concurrency** (e.g., with a semaphore) so that no single endpoint can monopolize the pool.
3. **Reduce `statement_timeout`** for read-only contract-result queries to limit how long each connection is held under load.
4. **Consider serializing the 5 queries** (sequential `await` instead of `Promise.all`) for this endpoint, accepting slightly higher per-request latency in exchange for consuming only 1 connection at a time.
5. **Deploy an API gateway or reverse proxy** (e.g., Traefik with `inFlightReq` and `rateLimit` middleware, already used for the Rosetta API) in front of the REST API nodes.

### Proof of Concept

```bash
# Step 1: Obtain any valid contractId and consensusTimestamp
# (e.g., from /api/v1/contracts/{id}/results)
CONTRACT_ID="0.0.1234"
TIMESTAMP="1234567890.000000001"
BASE_URL="https://<mirror-node-host>/api/v1"

# Step 2: Saturate the pool with 10 concurrent requests (2× the 5-query fan-out)
for i in $(seq 1 10); do
  curl -s "$BASE_URL/contracts/$CONTRACT_ID/results/$TIMESTAMP" &
done
wait

# Step 3: Immediately probe a different endpoint — it will time out or error
curl -v "$BASE_URL/transactions"
# Expected: connection timeout (~20 s) or 500/503 error
# while the pool remains saturated, all REST API endpoints are blocked
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/contractController.js (L1002-1017)
```javascript
  getContractResultsByTimestamp = async (req, res) => {
    if (requestPathLabel in res.locals) {
      return;
    }

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    const {contractId, timestamp} = await getAndValidateContractIdAndConsensusTimestampPathParams(req);
    const contractDetails = await ContractService.getInvolvedContractsByTimestampAndContractId(timestamp, contractId);
    if (!contractDetails) {
      throw new NotFoundError();
    }

    const [contractResults, ethTransactions, recordFile, contractLogs, contractStateChanges] =
      await this.getDetailedContractResults(contractDetails, contractId);
```

**File:** rest/controllers/contractController.js (L1205-1220)
```javascript
  getDetailedContractResults = async (contractDetails, contractId = undefined) => {
    return Promise.all([
      ContractService.getContractResultsByTimestamps(contractDetails.consensusTimestamp, contractDetails.contractIds),
      TransactionService.getEthTransactionByTimestampAndPayerId(
        contractDetails.consensusTimestamp,
        contractDetails.payerAccountId
      ),
      RecordFileService.getRecordFileBlockDetailsFromTimestamp(contractDetails.consensusTimestamp),
      ContractService.getContractLogsByTimestamps(contractDetails.consensusTimestamp, contractDetails.contractIds),
      ContractService.getContractStateChangesByTimestamps(
        contractDetails.consensusTimestamp,
        contractId,
        contractDetails.contractIds
      ),
    ]);
  };
```

**File:** rest/routes/contractRoute.js (L18-18)
```javascript
router.getExt('/:contractId/results/:consensusTimestamp', ContractController.getContractResultsByTimestamp);
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
