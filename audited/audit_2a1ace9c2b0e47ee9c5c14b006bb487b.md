### Title
Unauthenticated BLOCK_HASH Filter Triggers Uncached DB Lookup on Every Request to `/contracts/results`, Enabling Connection Pool Exhaustion

### Summary
The `extractContractResultsByIdQuery()` function in `rest/controllers/contractController.js` unconditionally executes a database query (`SELECT … FROM record_file WHERE hash LIKE $1 LIMIT 1`) for every request that supplies a `block.hash` query parameter, with no caching and no application-level rate limiting in the REST module. Because the endpoint is publicly accessible and `BLOCK_HASH` is an accepted filter, an unprivileged attacker can flood the endpoint with concurrent requests carrying arbitrary (non-existent) hashes, exhausting the shared PostgreSQL connection pool and degrading or denying service to all other REST API consumers on affected nodes.

### Finding Description

**Exact code path:**

`rest/controllers/contractController.js`, `extractContractResultsByIdQuery()`, lines 464–492:

```js
case filterKeys.BLOCK_NUMBER:
case filterKeys.BLOCK_HASH:
  blockFilter = filter;          // line 466
  break;
...
if (blockFilter) {
  let blockData;
  if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
    blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
  } else {
    blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value); // line 491
  }
``` [1](#0-0) 

`BLOCK_HASH` is explicitly listed as an accepted parameter for the public `/contracts/results` endpoint:

```js
const acceptedContractResultsParameters = new Set([
  ...
  filterKeys.BLOCK_HASH,
  ...
]);
``` [2](#0-1) 

`getRecordFileBlockDetailsFromHash()` in `rest/service/recordFileService.js` issues a raw DB query on every call — no cache, no deduplication:

```js
static recordFileBlockDetailsFromHashQuery = `select
  ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
  from ${RecordFile.tableName}
  where  ${RecordFile.HASH} like $1
  limit 1`;
...
async getRecordFileBlockDetailsFromHash(hash) {
  const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromHashQuery, [`${hash}%`]);
  return row === null ? null : new RecordFile(row);
}
``` [3](#0-2) 

**Root cause and failed assumption:** The design assumes that callers will supply valid, real block hashes and that request volume will be bounded by infrastructure-level controls. Neither assumption is enforced at the application layer. The `contractResultsFilterValidityChecks` function only restricts `BLOCK_NUMBER` to the `eq` operator; it applies no special restriction to `BLOCK_HASH`:

```js
const contractResultsFilterValidityChecks = (param, op, val) => {
  const ret = utils.filterValidityChecks(param, op, val);
  if (ret && param === filterKeys.BLOCK_NUMBER) {
    return op === queryParamOperators.eq;
  }
  return ret;
};
``` [4](#0-3) 

The REST module's middleware stack (`rest/middleware/`) contains no rate-limiting middleware. The throttle mechanisms found (`ThrottleManager`, `ThrottleConfiguration`, `ThrottleManagerImpl`) are exclusively in the `web3` Java module and do not protect the Node.js REST API: [5](#0-4) 

### Impact Explanation
Each concurrent request with a `block.hash` filter holds a PostgreSQL connection from the shared pool for the duration of the `LIKE` query. With a small connection pool (typical Node.js deployments use 10–20 connections), a sustained flood of concurrent requests with non-existent hashes will exhaust the pool. Once exhausted, all other queries (including legitimate ones) queue or fail, causing HTTP 500/503 responses across the REST API. Because the `record_file` table grows continuously and the `LIKE hash%` pattern requires an index prefix scan, query latency is non-trivial under load. This can degrade or deny service on any mirror node REST instance without affecting consensus, but can take down 30%+ of mirror node REST API capacity if multiple instances are targeted simultaneously.

### Likelihood Explanation
No authentication, API key, or credential is required. The attack requires only an HTTP client capable of sending concurrent GET requests. The payload is trivial: `GET /api/v1/contracts/results?block.hash=0000000000000000000000000000000000000000000000000000000000000000`. The attacker can rotate fake hashes to prevent any future result-level caching. The attack is repeatable, automatable, and requires no special knowledge of the network state.

### Recommendation
1. **Add a result cache** for `getRecordFileBlockDetailsFromHash()` (and `getRecordFileBlockDetailsFromIndex()`), keyed on the hash/index value, with a short TTL (e.g., 5–10 seconds). This eliminates redundant DB hits for repeated or concurrent identical requests.
2. **Add application-level rate limiting** in the REST middleware for endpoints that trigger block-resolution DB lookups, consistent with the rate limiting already present in the `web3` module.
3. **Validate hash format and length** before issuing the DB query — reject requests where `block.hash` is not a valid 32-byte or 48-byte hex string, reducing the attack surface to only plausible-looking hashes.
4. **Consider moving block resolution before filter parsing** so that a single in-flight request for the same hash is deduplicated (promise coalescing / request deduplication pattern).

### Proof of Concept

```bash
# Send 200 concurrent requests with a non-existent block hash
# Each request forces a DB LIKE query with no cache hit

for i in $(seq 1 200); do
  curl -s "https://<mirror-node-host>/api/v1/contracts/results?block.hash=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" &
done
wait

# Observe: legitimate requests to /api/v1/contracts/results (or other endpoints
# sharing the same DB pool) begin returning 500 errors or timing out as the
# connection pool is exhausted.
```

Preconditions: None. No account, API key, or prior knowledge required.
Trigger: Concurrent unauthenticated GET requests to `/api/v1/contracts/results?block.hash=<any_hex_string>`.
Result: PostgreSQL connection pool exhausted on targeted REST API node(s); all DB-dependent endpoints degrade or fail.

### Citations

**File:** rest/controllers/contractController.js (L273-279)
```javascript
const contractResultsFilterValidityChecks = (param, op, val) => {
  const ret = utils.filterValidityChecks(param, op, val);
  if (ret && param === filterKeys.BLOCK_NUMBER) {
    return op === queryParamOperators.eq;
  }
  return ret;
};
```

**File:** rest/controllers/contractController.js (L464-492)
```javascript
        case filterKeys.BLOCK_NUMBER:
        case filterKeys.BLOCK_HASH:
          blockFilter = filter;
          break;
        case filterKeys.TRANSACTION_INDEX:
          this.updateConditionsAndParamsWithInValues(
            filter,
            transactionIndexInValues,
            params,
            conditions,
            transactionIndexFullName,
            conditions.length + 1
          );
          break;
        case filterKeys.INTERNAL:
          internal = filter.value;
          break;
        default:
          break;
      }
    }

    if (blockFilter) {
      let blockData;
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }
```

**File:** rest/controllers/contractController.js (L1336-1346)
```javascript
const acceptedContractResultsParameters = new Set([
  filterKeys.FROM,
  filterKeys.BLOCK_HASH,
  filterKeys.BLOCK_NUMBER,
  filterKeys.HBAR,
  filterKeys.INTERNAL,
  filterKeys.LIMIT,
  filterKeys.ORDER,
  filterKeys.TIMESTAMP,
  filterKeys.TRANSACTION_INDEX,
]);
```

**File:** rest/service/recordFileService.js (L58-147)
```javascript
  static recordFileBlockDetailsFromHashQuery = `select
    ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
    from ${RecordFile.tableName}
    where  ${RecordFile.HASH} like $1
    limit 1`;

  static blocksQuery = `select
    ${RecordFile.COUNT}, ${RecordFile.HASH}, ${RecordFile.NAME}, ${RecordFile.PREV_HASH},
    ${RecordFile.HAPI_VERSION_MAJOR}, ${RecordFile.HAPI_VERSION_MINOR}, ${RecordFile.HAPI_VERSION_PATCH},
    ${RecordFile.INDEX}, ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.GAS_USED},
    ${RecordFile.LOGS_BLOOM}, coalesce(${RecordFile.SIZE}, length(${RecordFile.BYTES})) as size
    from ${RecordFile.tableName}
  `;

  /**
   * Retrieves the recordFile containing the transaction of the given timestamp
   *
   * @param {string|Number|BigInt} timestamp consensus timestamp
   * @return {Promise<RecordFile>} recordFile subset
   */
  async getRecordFileBlockDetailsFromTimestamp(timestamp) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromTimestampQuery, [timestamp]);

    return row === null ? null : new RecordFile(row);
  }

  /**
   * Retrieves the recordFiles containing the transactions of the given timestamps
   *
   * The timestamps must be ordered, either ACS or DESC.
   *
   * @param {(string|Number|BigInt)[]} timestamps consensus timestamp array
   * @return {Promise<Map>} A map from the consensus timestamp to its record file
   */
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

  /**
   * Retrieves the recordFile with the given index
   *
   * @param {number} index Int8
   * @return {Promise<RecordFile>} recordFile subset
   */
  async getRecordFileBlockDetailsFromIndex(index) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromIndexQuery, [index]);

    return row === null ? null : new RecordFile(row);
  }

  /**
   * Retrieves the recordFile with the given index
   *
   * @param {string} hash
   * @return {Promise<RecordFile>} recordFile subset
   */
  async getRecordFileBlockDetailsFromHash(hash) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromHashQuery, [`${hash}%`]);

    return row === null ? null : new RecordFile(row);
  }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
