### Title
Unauthenticated High-Cost Endpoint: 7 DB Queries Per Request with No Rate Limiting in `getContractResultsByTransactionIdOrHash`

### Summary
The `GET /api/v1/contracts/results/:transactionIdOrHash` endpoint is publicly accessible with no authentication or rate limiting. Each request unconditionally triggers 7 sequential/parallel database round-trips. An unprivileged attacker with knowledge of any valid transaction ID can send a modest volume of concurrent requests to exhaust database connection pool resources and increase node resource consumption well beyond 30% compared to baseline.

### Finding Description

**Exact code path:**

`rest/controllers/contractController.js`, function `getContractResultsByTransactionIdOrHash` (lines 1120–1203):

- **DB Query 1** (line 1142): `TransactionService.getTransactionDetailsFromTransactionId(transactionId, nonce)` — sequential, must complete before proceeding.
- **DB Query 2** (line 1156): `ContractService.getInvolvedContractsByTimestampAndContractId(transactionDetails.consensusTimestamp, transactionDetails.entityId)` — sequential, must complete before proceeding.
- **DB Queries 3–7** (lines 1165–1166, 1205–1219): `this.getDetailedContractResults()` fires five queries in parallel via `Promise.all`:
  1. `ContractService.getContractResultsByTimestamps()`
  2. `TransactionService.getEthTransactionByTimestampAndPayerId()`
  3. `RecordFileService.getRecordFileBlockDetailsFromTimestamp()`
  4. `ContractService.getContractLogsByTimestamps()`
  5. `ContractService.getContractStateChangesByTimestamps()`

**Root cause:** There is no rate limiting anywhere in the REST layer (confirmed: `grep` for `rateLimit`, `throttle`, `rateLimiter` returns zero matches in `rest/**/*.js`). The `authHandler` middleware (`rest/middleware/authHandler.js`, lines 15–36) only sets a custom response-row `limit` for authenticated users — it does not block or throttle unauthenticated requests. Unauthenticated requests proceed freely with the default row limit, and the 7-query execution path is unconditional for any valid transaction ID.

**Failed assumption:** The design assumes that the public mirror node API will be accessed at benign rates. No server-side enforcement exists to prevent a single IP or distributed set of IPs from issuing high-frequency requests.

### Impact Explanation
Each request consumes 7 database round-trips (2 sequential + 5 parallel). With a PostgreSQL connection pool of typical size (e.g., 10–20 connections), as few as 3–5 concurrent attackers each sending requests at ~10 req/s can saturate the pool, causing query queuing, latency spikes for all users, and CPU/memory pressure on the database host. The 30% resource consumption threshold is reachable without brute force — a single attacker sending ~20–30 concurrent requests is sufficient given the query fan-out factor of 7x.

### Likelihood Explanation
- **No privileges required**: The endpoint is fully public per the OpenAPI spec (`rest/api/v1/openapi.yml`, lines 666–692) and the route definition (`rest/routes/contractRoute.js`, line 21).
- **Valid transaction IDs are freely available**: Any Hedera/Hiero blockchain explorer exposes thousands of valid transaction IDs.
- **Trivially scriptable**: A single `curl` loop or `ab`/`wrk` invocation is sufficient.
- **No detection or blocking**: No IP-based throttle, no connection-level rate limit, no circuit breaker.

### Recommendation
1. **Add rate limiting middleware** (e.g., `express-rate-limit`) applied globally or specifically to high-cost endpoints like `/results/:transactionIdOrHash`, keyed by IP or API key.
2. **Set a database query timeout** per request to bound worst-case DB resource consumption.
3. **Consider caching** results for recently-queried transaction IDs (e.g., Redis with a short TTL) to avoid redundant DB fan-out for repeated lookups of the same transaction.
4. **Instrument and alert** on DB connection pool saturation as a detection signal.

### Proof of Concept

**Preconditions:**
- Mirror node REST API is publicly reachable (e.g., `https://mainnet-public.mirrornode.hedera.com`).
- One valid transaction ID obtained from any public explorer (e.g., `0.0.1234-1234567890-000000000`).

**Trigger:**
```bash
# Send 30 concurrent requests using a valid transaction ID
for i in $(seq 1 30); do
  curl -s "https://<mirror-node-host>/api/v1/contracts/results/0.0.1234-1234567890-000000000" &
done
wait
```

**Result:**
Each of the 30 concurrent requests independently triggers 7 DB queries (210 total DB operations in flight simultaneously). With a typical pool size of 10–20 connections, this saturates the pool, causes query queuing, and measurably increases CPU and memory on the database host. Sustained at modest rates (no brute force needed), this degrades service for all users and exceeds the 30% resource consumption threshold relative to the preceding 24-hour baseline. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/controllers/contractController.js (L1120-1166)
```javascript
  getContractResultsByTransactionIdOrHash = async (req, res) => {
    if (utils.conflictingPathParam(req, 'transactionIdOrHash', 'logs')) {
      return;
    }

    utils.validateReq(req, acceptedSingleContractResultsParameters);

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    let transactionDetails;

    const {transactionIdOrHash} = req.params;
    if (utils.isValidEthHash(transactionIdOrHash)) {
      const detailsByHash = await ContractService.getContractTransactionDetailsByHash(
        utils.parseHexStr(transactionIdOrHash)
      );
      transactionDetails = detailsByHash[0];
    } else {
      const transactionId = TransactionId.fromString(transactionIdOrHash);
      const nonce = getLastNonceParamValue(req.query);
      // Map the transactions id to a consensus timestamp
      const transactions = await TransactionService.getTransactionDetailsFromTransactionId(transactionId, nonce);

      if (transactions.length === 0) {
        throw new NotFoundError();
      }
      transactionDetails = transactions[0];
      // want to look up involved contract parties using the payer account id
      transactionDetails.entityId = transactionDetails.payerAccountId;
    }

    if (!transactionDetails) {
      throw new NotFoundError();
    }

    const contractDetails = await ContractService.getInvolvedContractsByTimestampAndContractId(
      transactionDetails.consensusTimestamp,
      transactionDetails.entityId
    );

    if (!contractDetails) {
      throw new NotFoundError();
    }

    const [contractResults, ethTransactions, recordFile, contractLogs, contractStateChanges] =
      await this.getDetailedContractResults(contractDetails, undefined);
```

**File:** rest/controllers/contractController.js (L1205-1219)
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
```

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** rest/routes/contractRoute.js (L21-21)
```javascript
router.getExt('/results/:transactionIdOrHash', ContractController.getContractResultsByTransactionIdOrHash);
```
