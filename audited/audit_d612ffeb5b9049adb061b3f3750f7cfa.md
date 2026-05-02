### Title
Unauthenticated Block-Number-Keyed Cache-Bypass DoS via Concurrent GET /contracts/:contractId/results Requests

### Summary
Any unauthenticated user can send `GET /api/v1/contracts/:contractId/results?block.number=<N>` requests. Each request triggers an extra DB lookup via `RecordFileService.getRecordFileBlockDetailsFromIndex()` followed by a `contract_result` table query. Because the response cache key is derived from the full URL, cycling through distinct block numbers produces a continuous stream of cache misses, forcing two DB queries per request with no rate limiting in place.

### Finding Description

**Route registration** — `rest/routes/contractRoute.js` line 14 registers the endpoint with no authentication or rate-limiting middleware: [1](#0-0) 

**Handler** — `getContractResultsById` (lines 856–892) calls `extractContractResultsByIdQuery` unconditionally: [2](#0-1) 

**Extra DB lookup** — Inside `extractContractResultsByIdQuery`, when `blockFilter.key === filterKeys.BLOCK_NUMBER`, the code immediately awaits `RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value)` with no caching or deduplication: [3](#0-2) 

**DB query executed** — `getRecordFileBlockDetailsFromIndex` issues a synchronous DB round-trip: [4](#0-3) 

using the query: [5](#0-4) 

If the block exists, a second, potentially expensive query against `contract_result` is then issued: [6](#0-5) 

**Cache bypass** — The response cache key is the MD5 of `req.originalUrl`: [7](#0-6) 

Every distinct `block.number` value produces a unique URL → unique cache key → guaranteed cache miss → two DB queries per request.

**No HTTP-level rate limiting** — The only "limit" mechanism in the middleware stack is `authHandler.js`, which only adjusts the response page-size limit for authenticated users; it does not throttle request rates: [8](#0-7) 

**DB pool** — The pool is bounded by `maxConnections` and `statementTimeout`: [9](#0-8) 

When the pool is saturated, new requests queue inside `pg`, holding Node.js event-loop handles and memory, compounding the degradation.

### Impact Explanation

An attacker flooding the endpoint with N concurrent requests, each using a different `block.number`, forces 2N DB queries with zero cache benefit. The `record_file` index lookup is fast, but the subsequent `contract_result` range scan (filtered by `consensus_start`/`consensus_end` of the block) can be expensive for high-traffic blocks. Pool exhaustion causes legitimate queries across all endpoints to queue or time out, degrading the mirror node's ability to serve the network. Because mirror nodes are the primary read path for dApps and wallets, sustained overload on a significant fraction of deployed mirror nodes impairs network observability and EVM-compatible tooling.

### Likelihood Explanation

The attack requires zero credentials, zero on-chain activity, and only knowledge of the public REST API (documented in the OpenAPI spec). Block numbers are sequential integers starting from 0, trivially enumerable. A single attacker with a modest HTTP client (e.g., `wrk`, `hey`, or a simple async script) can sustain thousands of requests per second. The attack is repeatable indefinitely and is not self-limiting.

### Recommendation

1. **Add HTTP-level rate limiting** (e.g., `express-rate-limit`) per IP on all `/contracts` routes, especially those accepting block-scoped filters.
2. **Cache the `getRecordFileBlockDetailsFromIndex` result** in-process (LRU) or in Redis, keyed by block index. Block data is immutable once finalized, making it safe to cache indefinitely.
3. **Deduplicate in-flight requests** for the same block index (promise coalescing / request collapsing) so N concurrent requests for block 12345 issue only one DB query.
4. **Apply a `statement_timeout`** aggressive enough to shed load quickly under attack (the current default is operator-configurable but not enforced at a low value by default).

### Proof of Concept

```bash
# Flood with 500 concurrent requests, each using a unique block number
seq 1 500 | xargs -P 50 -I{} \
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1001/results?block.number={}" \
  -o /dev/null

# Observe DB connection pool saturation in mirror node logs:
# "error event emitted on pool" or connection timeout errors
# Legitimate requests to /api/v1/transactions, /api/v1/blocks, etc. begin timing out
```

Each iteration of `{}` is a distinct URL → distinct cache key → two DB queries. Scaling to thousands of parallel clients produces sustained DB overload.

### Citations

**File:** rest/routes/contractRoute.js (L14-14)
```javascript
router.getExt('/:contractId/results', ContractController.getContractResultsById);
```

**File:** rest/controllers/contractController.js (L486-502)
```javascript
    if (blockFilter) {
      let blockData;
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }

      if (blockData) {
        timestampFilters.push(
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.gte, value: blockData.consensusStart},
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.lte, value: blockData.consensusEnd}
        );
      } else {
        return {skip: true};
      }
    }
```

**File:** rest/controllers/contractController.js (L856-876)
```javascript
  getContractResultsById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractResultsParameters
    );

    const contractId = await ContractService.computeContractIdFromString(contractIdParam);

    const response = {
      results: [],
      links: {
        next: null,
      },
    };
    res.locals[responseDataLabel] = response;
    const {conditions, params, order, limit, skip} = await this.extractContractResultsByIdQuery(filters, contractId);
    if (skip) {
      return;
    }

    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
```

**File:** rest/service/recordFileService.js (L52-56)
```javascript
  static recordFileBlockDetailsFromIndexQuery = `select
    ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
    from ${RecordFile.tableName}
    where  ${RecordFile.INDEX} = $1
    limit 1`;
```

**File:** rest/service/recordFileService.js (L131-135)
```javascript
  async getRecordFileBlockDetailsFromIndex(index) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromIndexQuery, [index]);

    return row === null ? null : new RecordFile(row);
  }
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
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
