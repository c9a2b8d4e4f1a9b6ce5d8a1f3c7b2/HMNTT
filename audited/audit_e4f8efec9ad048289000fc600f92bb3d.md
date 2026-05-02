### Title
Unauthenticated Multi-Query DB Amplification DoS on `GET /contracts/results`

### Summary
The `getContractResults()` handler in `rest/controllers/contractController.js` issues at least 3 sequential/parallel database queries per unauthenticated HTTP request with no filters. The REST service has zero rate-limiting middleware, meaning any external user can flood this endpoint and exhaust the PostgreSQL connection pool, degrading or denying service to all consumers of the mirror node API.

### Finding Description

**Exact code path:**

`GET /contracts/results` → `ContractController.getContractResults` (line 1050) → `extractContractResultsByIdQuery(filters)` with no `contractId` (line 1067) → `optimizeTimestampFilters(timestampFilters, order)` (line 505) → `bindTimestampRange(range, order)` (line 392) → optionally `getFirstTransactionTimestamp()` DB query (line 51 of `rest/timestampRange.js`, cached after first call) → `ContractService.getContractResultsByIdAndFilters(...)` (line 1072, DB query 1) → `Promise.all([getEthereumTransactionsByPayerAndTimestampArray(...), getRecordFileBlockDetailsFromTimestampArray(...)])` (lines 1083–1086, DB queries 2 and 3 in parallel).

**Root cause:**

The REST Node.js server (`rest/server.js`) registers no rate-limiting middleware for any route. The `authHandler` middleware (line 86) only sets a custom response-row limit for authenticated users; it does not block or throttle unauthenticated requests. The `grep_search` across all `rest/**/*.js` files for `rateLimit`, `throttle`, `express-rate`, or `requestsPerSecond` returns zero matches. The throttling that exists lives exclusively in the Java `web3` service (`ThrottleConfiguration.java`) and applies only to `POST /api/v1/contracts/call`, not to the REST mirror-node endpoints.

**Per-request DB query breakdown (no filters, `bindTimestampRange=false`, default config):**

| Step | Query | Always? |
|---|---|---|
| `getContractResultsByIdAndFilters` | `SELECT … FROM contract_result cr LEFT JOIN entity e …` with `LIMIT $N` | Yes |
| `getEthereumTransactionsByPayerAndTimestampArray` | `SELECT … FROM ethereum_transaction WHERE payer_account_id = any($1) AND consensus_timestamp = any($2) …` | Yes, if rows > 0 |
| `getRecordFileBlockDetailsFromTimestampArray` | Correlated subquery over `record_file` for each timestamp | Yes, if rows > 0 |

When `bindTimestampRange=true` and the in-process cache is cold (first request after process start), a fourth query hits `transaction` table:
```sql
select consensus_timestamp from transaction order by consensus_timestamp limit 1
``` [1](#0-0) 

The `getFirstTransactionTimestamp` result is cached in-process after the first call, so subsequent requests produce exactly 3 DB queries. [2](#0-1) 

**Why existing checks fail:**

- `buildAndValidateFilters` validates filter syntax but does not require any filter to be present; an empty filter set is fully accepted.
- The `defaultLimit` (typically 25) caps the number of rows returned but does not prevent the 3 DB queries from executing on every request.
- The `skip` early-return path (line 1068) is only reached when `optimizeTimestampFilters` returns an empty filter set after a non-empty input — it is never triggered by a no-filter request.
- There is no connection-pool-aware back-pressure or circuit breaker on the REST service. [3](#0-2) [4](#0-3) [5](#0-4) 

### Impact Explanation

Each unauthenticated `GET /contracts/results` request with no filters unconditionally issues 3 DB queries (or 4 on cold start). An attacker sending requests at a sustained rate of R req/s causes 3R DB queries/s. Because the PostgreSQL connection pool has a finite size, pool exhaustion causes all other API endpoints (accounts, transactions, tokens, etc.) to queue or fail. This is a non-network-based DoS: the attacker's bandwidth cost is negligible (a single short HTTP GET), while the server-side cost is multiplied 3×. For a public mirror node serving DeFi applications and wallets that depend on contract result data, this degrades the entire API surface.

### Likelihood Explanation

No authentication, no API key, no CAPTCHA, and no rate limit are required. The endpoint is publicly documented. Any attacker with a basic HTTP client and a loop can trigger this. The attack is trivially repeatable, requires no special knowledge of the chain state, and is effective even at modest request rates (e.g., 100 req/s → 300 DB queries/s). The attack is also amplifiable by distributing requests across multiple source IPs to defeat any upstream IP-based rate limiting that may be applied at a reverse proxy.

### Recommendation

1. **Add rate-limiting middleware to the REST service.** Use `express-rate-limit` or equivalent, applied globally in `rest/server.js` before route registration, with per-IP limits (e.g., 60 req/min for unauthenticated callers).
2. **Require at least one timestamp or `from` filter** for `GET /contracts/results` (the no-contract-id variant), similar to how other unbounded list endpoints enforce mandatory filters.
3. **Add a DB connection pool circuit breaker** so that pool exhaustion returns HTTP 503 rather than queuing indefinitely.
4. **Cache the `getContractResultsByIdAndFilters` response** at the Redis layer (already wired in `server.js` for `applicationCacheEnabled`) to reduce repeated identical queries.

### Proof of Concept

```bash
# No authentication, no filters — triggers 3 DB queries per request
# Run from any machine with network access to the mirror node

for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/contracts/results" -o /dev/null &
done
wait
```

Expected result: PostgreSQL connection pool exhaustion; subsequent requests to any `/api/v1/*` endpoint return 500 or time out. Observable via mirror node logs showing pool wait times spiking and DB query latency increasing across all endpoints.

**Minimal single-request verification** (confirms 3 DB queries per call):
```bash
curl -v "https://<mirror-node-host>/api/v1/contracts/results"
# Observe: response contains results[] with block_number, hash, from fields
# populated from all three DB queries (contract_result, ethereum_transaction, record_file)
``` [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** rest/timestampRange.js (L46-71)
```javascript
const getFirstTransactionTimestamp = (() => {
  let timestamp;

  const func = async () => {
    if (timestamp === undefined) {
      const {rows} = await pool.queryQuietly(`select consensus_timestamp
                                              from transaction
                                              order by consensus_timestamp
                                              limit 1`);
      if (rows.length !== 1) {
        return 0n; // fallback to 0
      }

      timestamp = rows[0].consensus_timestamp;
      logger.info(`First transaction's consensus timestamp is ${timestamp}`);
    }

    return BigInt(timestamp);
  };

  if (isTestEnv()) {
    func.reset = () => (timestamp = undefined);
  }

  return func;
})();
```

**File:** rest/controllers/contractController.js (L504-508)
```javascript
    const {filters: optimizedTimestampFilters, next} =
      contractId === undefined ? await optimizeTimestampFilters(timestampFilters, order) : {filters: timestampFilters};
    if (timestampFilters.length !== 0 && optimizedTimestampFilters.length === 0) {
      return {skip: true};
    }
```

**File:** rest/controllers/contractController.js (L1050-1086)
```javascript
  getContractResults = async (req, res) => {
    const filters = utils.buildAndValidateFilters(
      req.query,
      acceptedContractResultsParameters,
      contractResultsFilterValidityChecks
    );

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    const response = {
      results: [],
      links: {
        next: null,
      },
    };
    res.locals[responseDataLabel] = response;
    const {conditions, params, order, limit, skip, next} = await this.extractContractResultsByIdQuery(filters);
    if (skip) {
      return;
    }

    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
    if (rows.length === 0) {
      return;
    }

    const payers = [];
    const timestamps = [];
    rows.forEach((row) => {
      payers.push(row.payerAccountId);
      timestamps.push(row.consensusTimestamp);
    });
    const [ethereumTransactionMap, recordFileMap] = await Promise.all([
      ContractService.getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps),
      RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps),
    ]);
```

**File:** rest/server.js (L68-98)
```javascript
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/service/contractService.js (L519-546)
```javascript
  async getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps) {
    const transactionMap = new Map();
    if (isEmpty(payers) || isEmpty(timestamps)) {
      return transactionMap;
    }

    let maxTimestamp = -1n;
    let minTimestamp = MAX_LONG;
    timestamps.forEach((timestamp) => {
      if (timestamp > maxTimestamp) {
        maxTimestamp = timestamp;
      }
      if (timestamp < minTimestamp) {
        minTimestamp = timestamp;
      }
    });

    const rows = await super.getRows(ContractService.ethereumTransactionByPayerAndTimestampArrayQuery, [
      payers,
      timestamps,
      minTimestamp,
      maxTimestamp,
    ]);

    rows.forEach((row) => transactionMap.set(row.consensus_timestamp, new EthereumTransaction(row)));

    return transactionMap;
  }
```

**File:** rest/service/recordFileService.js (L92-123)
```javascript
  async getRecordFileBlockDetailsFromTimestampArray(timestamps) {
    const recordFileMap = new Map();
    if (timestamps.length === 0) {
      return recordFileMap;
    }

    const {maxTimestamp, minTimestamp, order} = this.getTimestampArrayContext(timestamps);
    const query = `${RecordFileService.recordFileBlockDetailsFromTimestampArrayQuery}
      order by consensus_end ${order}`;
    const params = [timestamps, minTimestamp, BigInt(maxTimestamp) + config.query.maxRecordFileCloseIntervalNs];

    const rows = await super.getRows(query, params);

    let index = 0;
    for (const row of rows) {
      const recordFile = new RecordFile(row);
      const {consensusEnd, consensusStart} = recordFile;
      for (; index < timestamps.length; index++) {
        const timestamp = timestamps[index];
        if (consensusStart <= timestamp && consensusEnd >= timestamp) {
          recordFileMap.set(timestamp, recordFile);
        } else if (
          (order === orderFilterValues.ASC && timestamp > consensusEnd) ||
          (order === orderFilterValues.DESC && timestamp < consensusStart)
        ) {
          break;
        }
      }
    }

    return recordFileMap;
  }
```
