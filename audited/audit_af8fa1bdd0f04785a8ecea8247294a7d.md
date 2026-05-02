### Title
Unauthenticated Block-Number Filter Causes Unbounded Secondary DB Query Load via `extractContractResultsByIdQuery()`

### Summary
Any unauthenticated user can send `GET /contracts/results?block_number=<N>` with a valid block index, causing `extractContractResultsByIdQuery()` to unconditionally issue a `RecordFileService.getRecordFileBlockDetailsFromIndex()` database query on every cache-missing request. Because the response cache key is URL-based with a 1-second default TTL, an attacker cycling through distinct valid block numbers bypasses the cache entirely, generating sustained secondary DB query load that degrades service for all users.

### Finding Description

**Exact code path:**

In `rest/controllers/contractController.js`, `getContractResults` (line 1067) calls `extractContractResultsByIdQuery(filters)` with no authentication gate:

```js
// rest/controllers/contractController.js line 1050-1067
getContractResults = async (req, res) => {
  const filters = utils.buildAndValidateFilters(
    req.query,
    acceptedContractResultsParameters,
    contractResultsFilterValidityChecks
  );
  ...
  const {conditions, params, order, limit, skip, next} = await this.extractContractResultsByIdQuery(filters);
```

Inside `extractContractResultsByIdQuery`, when a `BLOCK_NUMBER` filter is present, the code unconditionally issues a live DB query:

```js
// rest/controllers/contractController.js lines 486-492
if (blockFilter) {
  let blockData;
  if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
    blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
  } else {
    blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
  }
```

`getRecordFileBlockDetailsFromIndex` executes:

```sql
-- rest/service/recordFileService.js lines 52-56
select consensus_start, consensus_end, hash, index
from record_file
where index = $1
limit 1
```

This is a direct, synchronous DB query with no in-process caching, no memoization, and no deduplication.

**Root cause:** The block-details lookup is performed eagerly on every request that includes `block_number=`, with no per-block result cache and no rate limiting. The only protection is the response-level Redis cache, which uses a URL-based MD5 key with a **1-second default TTL** (`DEFAULT_REDIS_EXPIRY = 1` in `rest/middleware/responseCacheHandler.js` line 24).

**Why existing checks fail:**

The response cache (`responseCacheHandler.js`) caches the full HTTP response keyed by `req.originalUrl`:

```js
// rest/middleware/responseCacheHandler.js lines 151-153
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

An attacker cycling through distinct block numbers (`block_number=1`, `block_number=2`, …, `block_number=N`) produces a distinct cache key for each, so every request is a cache miss. The 1-second TTL means even repeated identical URLs re-hit the DB every second. There is no per-IP rate limiting, no request throttling, and no authentication requirement anywhere in this path.

The `block_number` filter is restricted to the `eq` operator only (`contractResultsFilterValidityChecks`, lines 273-279), but this does not limit the number of distinct valid block values an attacker can enumerate.

### Impact Explanation

Each attacker request with a unique block number causes at minimum two DB queries: the `record_file` index lookup and the subsequent `contract_result` query. At high request rates with rotating block numbers, this creates sustained, unbounded secondary DB load on the `record_file` table. Because the mirror node's REST API and DB are shared infrastructure, this degrades response latency and throughput for all legitimate users. No economic damage occurs to any on-chain user, making this a griefing/availability attack.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero on-chain resources. The attacker needs only an HTTP client and knowledge of valid block indices (publicly available from `GET /api/v1/blocks`). The attack is trivially scriptable, repeatable indefinitely, and requires no special tooling. The large range of valid block numbers (potentially millions) makes cache-bypass trivial.

### Recommendation

1. **Cache the block-details lookup result** independently of the full response, keyed by block index/hash, with a TTL appropriate to block finality (e.g., 5–60 seconds).
2. **Add per-IP or global rate limiting** on the `/contracts/results` endpoint, particularly for requests containing `block_number` or `block_hash` filters.
3. **Increase the default response cache TTL** beyond 1 second for endpoints whose data changes infrequently (finalized blocks do not change).
4. Consider **pre-validating** that the supplied block number falls within a known range before issuing the DB query.

### Proof of Concept

```bash
# Rotate through distinct valid block numbers to bypass the URL-based cache
# and force a fresh DB query on every request.
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/contracts/results?block_number=${i}&limit=1" &
done
wait
```

Each iteration uses a unique `block_number`, producing a unique cache key, causing `getRecordFileBlockDetailsFromIndex(i)` to execute a live `SELECT … FROM record_file WHERE index = $1` query for every request. At sufficient concurrency this saturates the DB connection pool and degrades service for all users.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** rest/controllers/contractController.js (L1050-1067)
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

**File:** rest/middleware/responseCacheHandler.js (L24-24)
```javascript
const DEFAULT_REDIS_EXPIRY = 1;
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
