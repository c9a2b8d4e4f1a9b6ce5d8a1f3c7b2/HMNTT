### Title
Unauthenticated Sequential Double-DB-Query DoS via `block_hash` Parameter in `GET /contracts/:contractId/results`

### Summary
An unauthenticated external user can supply a valid `block_hash` query parameter to `GET /contracts/:contractId/results`, causing the handler to execute two sequential database queries per request: first a `LIKE`-based hash lookup against `record_file`, then a full contract-results range query. With no per-IP rate limiting on the REST API and a default connection pool of only 10 connections, a modest number of concurrent requests exhausts the pool and denies service to all other API consumers.

### Finding Description

**Exact code path:**

Route registration in `rest/routes/contractRoute.js:14`:
```
router.getExt('/:contractId/results', ContractController.getContractResultsById);
```

Handler `getContractResultsById` at `rest/controllers/contractController.js:856-892` calls `extractContractResultsByIdQuery` (line 871), which at lines 486–502 branches on `blockFilter.key === filterKeys.BLOCK_HASH` and issues **DB query 1**:

```js
blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
```

`getRecordFileBlockDetailsFromHash` at `rest/service/recordFileService.js:143-147` executes:
```sql
SELECT consensus_start, consensus_end, hash, index
FROM record_file
WHERE hash LIKE $1   -- $1 = '<supplied_hash>%'
LIMIT 1
```

If the hash resolves to a block, `consensusStart`/`consensusEnd` are pushed as timestamp range filters and control returns to the handler, which at line 876 issues **DB query 2**:
```js
const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
```

These two queries are `await`-chained (sequential), meaning each in-flight request holds a pool connection for the full duration of query 1, releases it, then immediately acquires another for query 2.

**Root cause — failed assumptions:**

1. The REST server (`rest/server.js`) applies no per-IP rate-limiting or in-flight-request cap middleware. The `authHandler` (`rest/middleware/authHandler.js:15-36`) only sets a custom response-size limit for authenticated users; unauthenticated requests pass through unconditionally.

2. The Traefik ingress middleware for the REST service (`charts/hedera-mirror-rest/values.yaml:134-139`) configures only `circuitBreaker` and `retry` — no `rateLimit` or `inFlightReq` (contrast with the Rosetta service at `charts/hedera-mirror-rosetta/values.yaml:157-163` which has both).

3. The default DB connection pool is **10 connections** (`hiero.mirror.rest.db.pool.maxConnections = 10`, `docs/configuration.md:556`) with a `connectionTimeout` of 20 s and a `statementTimeout` of 20 s (`docs/configuration.md:555-557`), configured in `rest/dbpool.js:14`.

### Impact Explanation
With 10 concurrent attacker requests each holding a pool connection for up to 20 s (per query), the entire pool is saturated. All legitimate API requests — across every endpoint — queue for a connection and time out after 20 s, returning 500 errors. The `circuitBreaker` at `NetworkErrorRatio() > 0.25` may then trip, amplifying the outage. Because the REST API serves the Hedera mirror node's public data surface, this constitutes a non-network-based DoS against a high-value public infrastructure component.

### Likelihood Explanation
No authentication, no API key, no CAPTCHA, and no IP-level rate limit is required. Any HTTP client capable of issuing concurrent GET requests can trigger this. A valid block hash is publicly observable from any block explorer or prior API call. The attack is trivially repeatable and scriptable with tools like `curl`, `ab`, or `wrk`. The attacker needs only a single valid block hash and the ability to open ~10 TCP connections.

### Recommendation
1. **Add per-IP in-flight request limiting** to the Traefik middleware for the REST service (mirror the `inFlightReq` + `rateLimit` already present in the Rosetta chart).
2. **Add application-level concurrency control** (e.g., a semaphore or `express-rate-limit`) in `rest/server.js` before route handlers.
3. **Increase the connection pool** (`maxConnections`) or introduce a query queue with a hard cap on waiting requests.
4. **Short-circuit on cache**: enable the Redis response cache (`hiero.mirror.rest.cache.response.enabled`) for this endpoint so repeated identical `block_hash` queries are served without hitting the DB.
5. Consider parallelising the two queries where possible (they are currently sequential `await` calls) to reduce per-request connection hold time.

### Proof of Concept
```bash
# 1. Obtain a valid block hash (publicly available)
HASH=$(curl -s https://<mirror-node>/api/v1/blocks?limit=1 | jq -r '.blocks[0].hash')

# 2. Fire 15 concurrent requests (exceeds default pool of 10)
for i in $(seq 1 15); do
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1234/results?block.hash=${HASH}" &
done
wait

# 3. Simultaneously issue a legitimate request and observe timeout / 500
curl -v "https://<mirror-node>/api/v1/contracts/0.0.1234/results"
# Expected: connection pool exhausted → 500 or connection timeout after 20 s
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** rest/service/recordFileService.js (L58-62)
```javascript
  static recordFileBlockDetailsFromHashQuery = `select
    ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
    from ${RecordFile.tableName}
    where  ${RecordFile.HASH} like $1
    limit 1`;
```

**File:** rest/service/recordFileService.js (L143-147)
```javascript
  async getRecordFileBlockDetailsFromHash(hash) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromHashQuery, [`${hash}%`]);

    return row === null ? null : new RecordFile(row);
  }
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

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
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
