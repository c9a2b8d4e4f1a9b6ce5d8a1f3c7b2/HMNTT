### Title
Connection Pool Exhaustion via Unbounded Concurrent Hanging Queries in `getContractActions`

### Summary
The `getContractActions` handler in `rest/controllers/contractController.js` performs two sequential database queries per request with no per-request concurrency guard or rate limiting. During a network partition where the first query (`getContractTransactionDetailsByHash`) succeeds but the second (`getContractActionsByConsensusTimestamp`) hangs, an unprivileged attacker can exhaust the default 10-connection pool by sending as few as 10 concurrent requests with valid, publicly-available transaction hashes, blocking all other DB-dependent endpoints for up to the full `statement_timeout` window (default 20 seconds) per burst.

### Finding Description

**Exact code path:**

`getContractActions` (lines 1222–1291, `rest/controllers/contractController.js`) executes two sequential awaited DB calls:

```
// Step 1 — succeeds during partition
tx = await ContractService.getContractTransactionDetailsByHash(...)   // line 1249
// Step 2 — hangs during partition
const rows = await ContractService.getContractActionsByConsensusTimestamp(...)  // line 1263
``` [1](#0-0) 

`getContractTransactionDetailsByHash` queries the `contract_transaction_hash` table: [2](#0-1) 

`getContractActionsByConsensusTimestamp` queries the `contract_action` table: [3](#0-2) 

Both ultimately call `super.getRows()` which calls `pool.queryQuietly()` — a blocking pool checkout + query execution with no per-handler concurrency limit: [4](#0-3) 

**Connection pool configuration:**

The pool is initialized with a default of **10 connections** and a `statement_timeout` of **20,000 ms**: [5](#0-4) [6](#0-5) 

**Root cause and failed assumption:**

The design assumes that either (a) both queries complete quickly, or (b) the `statement_timeout` prevents indefinite hangs. The failed assumption is that `statement_timeout` is sufficient to prevent pool exhaustion. With only 10 connections and a 20-second timeout window, 10 concurrent requests each holding a connection in the hanging second query fully saturate the pool. Any subsequent request requiring a DB connection will block for up to `connectionTimeoutMillis` (default 20,000 ms) before failing.

**No rate limiting exists on this endpoint in the REST API:** [7](#0-6) 

The throttling found in the codebase applies only to the separate `web3` Java service, not the Node.js REST API.

### Impact Explanation

All REST API endpoints that require a database connection become unavailable for up to 20 seconds per burst. This includes `/api/v1/transactions`, `/api/v1/accounts`, and all other contract endpoints. The attack is repeatable: a new burst can be sent immediately after the previous `statement_timeout` expires, creating a near-continuous denial of service. The default pool size of 10 means the threshold for full exhaustion is extremely low.

### Likelihood Explanation

The attack requires no authentication or privileges. Valid Ethereum transaction hashes are publicly observable on the Hedera network. The attacker needs only 10 concurrent HTTP requests — trivially achievable with any HTTP client. The network partition precondition is the only external dependency; however, the attacker does not need to cause the partition — they only need to exploit it opportunistically when it occurs (e.g., during a Citus shard failure, a DB replica failover, or a cloud availability zone event). The attack is fully repeatable and requires no special knowledge beyond public transaction hashes.

### Recommendation

1. **Add a per-endpoint concurrency limit** for `getContractActions` (e.g., using a semaphore or an in-flight request counter) to cap simultaneous DB-holding requests.
2. **Reduce `statement_timeout`** for this specific query path, or apply a shorter per-query timeout using `SET LOCAL statement_timeout` within the query.
3. **Increase `maxConnections`** or deploy a connection pooler (PgBouncer is already referenced in the Helm chart) with per-user connection limits enforced closer to the application.
4. **Add IP-based rate limiting middleware** to the Node.js REST API for the `/contracts/results/:transactionIdOrHash/actions` route.

### Proof of Concept

**Preconditions:**
- A network partition is active where the `contract_action` table queries hang (e.g., a Citus worker shard is unreachable).
- Collect 10 valid Ethereum transaction hashes from the public Hedera network.

**Steps:**
```bash
# Send 10 concurrent requests simultaneously
for hash in <hash1> <hash2> ... <hash10>; do
  curl -s "https://<mirror-node>/api/v1/contracts/results/${hash}/actions" &
done
wait

# Immediately probe another endpoint — it will time out or return a DB error
curl -v "https://<mirror-node>/api/v1/transactions?limit=1"
```

**Expected result:** The 10 concurrent `getContractActions` requests each hold a pool connection for up to 20 seconds (until `statement_timeout` fires). During this window, the final `transactions` request fails to acquire a pool connection and returns a 500 error or connection timeout. The burst can be repeated continuously to maintain the denial of service.

### Citations

**File:** rest/controllers/contractController.js (L1248-1269)
```javascript
    if (utils.isValidEthHash(transactionIdOrHash)) {
      tx = await ContractService.getContractTransactionDetailsByHash(utils.parseHexStr(transactionIdOrHash));
    } else {
      transactionId = TransactionId.fromString(transactionIdOrHash);
      tx = await TransactionService.getTransactionDetailsFromTransactionId(transactionId);
    }

    let payerAccountId;
    if (tx.length) {
      consensusTimestamp = tx[0].consensusTimestamp;
      payerAccountId = transactionId ? transactionId.getEntityId().getEncodedId() : tx[0].payerAccountId;
    } else {
      throw new NotFoundError();
    }

    const rows = await ContractService.getContractActionsByConsensusTimestamp(
      consensusTimestamp,
      payerAccountId,
      filters,
      order,
      limit
    );
```

**File:** rest/service/contractService.js (L305-308)
```javascript
  async getContractTransactionDetailsByHash(hash) {
    const rows = await super.getRows(ContractService.ethereumTransactionsByHashQuery, [hash]);
    return rows.map((row) => new ContractTransactionHash(row));
  }
```

**File:** rest/service/contractService.js (L478-487)
```javascript
  async getContractActionsByConsensusTimestamp(consensusTimestamp, payerAccountId, filters, order, limit) {
    const params = [consensusTimestamp, payerAccountId];
    return this.getContractActions(
      ContractService.contractActionsByConsensusTimestampQuery,
      params,
      filters,
      order,
      limit
    );
  }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
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

**File:** rest/middleware/requestHandler.js (L1-30)
```javascript
// SPDX-License-Identifier: Apache-2.0

import httpContext from 'express-http-context';
import qs from 'qs';

import config from '../config';
import {httpStatusCodes, requestIdLabel, requestStartTime} from '../constants';
import {lowerCaseQueryValue, randomString} from '../utils';

const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};

const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};

const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};

```
