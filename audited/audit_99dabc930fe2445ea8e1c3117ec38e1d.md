### Title
Unauthenticated DoS via Unbounded `block.number` Filter Causing Repeated Unnecessary DB Index Scans

### Summary
An unauthenticated external user can submit `GET /api/v1/blocks?block.number=gte:9223372036854775807` (the maximum signed 64-bit integer) repeatedly. The value passes input validation because `isPositiveLong` explicitly allows values up to `maxLong`, and no semantic upper-bound check against the actual highest block index exists before the query is dispatched to the database. With no application-level rate limiting on the blocks endpoint, an attacker can sustain a high request rate, causing the database to execute repeated index scans on `record_file(index)` that always return zero rows.

### Finding Description

**Validation layer** — `rest/utils.js` lines 93–101 and 301–302:
```js
const maxLong = 9223372036854775807n;
const isPositiveLong = (num, allowZero = false) => {
  if (!positiveLongRegex.test(num)) return false;
  const bigInt = BigInt(num);
  return bigInt >= min && bigInt <= maxLong;   // 9223372036854775807 passes
};
// ...
case constants.filterKeys.BLOCK_NUMBER:
  ret = (isPositiveLong(val, true) || isHexPositiveInt(val, true)) && includes(basicOperators, op);
```
The value `9223372036854775807` satisfies `bigInt <= maxLong` exactly, so it is accepted as valid.

**Controller** — `rest/controllers/blockController.js` lines 101–112: `getBlocks` calls `buildAndValidateFilters`, then `extractSqlFromBlockFilters`, then immediately dispatches to `RecordFileService.getBlocks`. There is no check comparing the supplied value against the current maximum block index.

**Service / SQL** — `rest/service/recordFileService.js` lines 149–162:
```js
async getBlocks(filters) {
  const {where, params} = buildWhereSqlStatement(filters.whereQuery);
  const query = RecordFileService.blocksQuery + `${where} order by ${filters.orderBy} ${filters.order} limit ${filters.limit}`;
  const rows = await super.getRows(query, params);
  ...
}
```
The generated SQL is:
```sql
SELECT ... FROM record_file WHERE index >= 9223372036854775807 ORDER BY index DESC LIMIT 25
```
PostgreSQL uses the `record_file__index` B-tree index (created in `V1.35.3__record_file_block_index.sql` and maintained in `V2.0.3__index_init.sql`), traverses to the far end of the tree, finds no matching rows, and returns empty. Each execution is cheap individually but consumes connection pool slots, CPU, and I/O on the DB server.

**No rate limiting** — `rest/server.js` lines 67–112 show the middleware stack: `urlencoded`, `json`, `cors`, optional compression, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`. No rate-limiting middleware is applied to the blocks route. The throttling found (`ThrottleManagerImpl`, `ThrottleConfiguration`) is scoped exclusively to the web3 `/contracts/call` endpoint.

### Impact Explanation
An attacker can sustain thousands of requests per second against `GET /api/v1/blocks?block.number=gte:9223372036854775807`. Each request consumes a DB connection, executes an index scan, and returns an empty result. At sufficient volume this exhausts the connection pool, increases query latency for legitimate users, and can degrade overall mirror-node availability. No data is exposed, but service availability is at risk.

### Likelihood Explanation
The endpoint requires no authentication, no API key, and no session. The request is a single HTTP GET with a trivially crafted query string. Any script or tool (curl, ab, wrk) can reproduce it. The absence of application-level rate limiting means the only protection is infrastructure-level (e.g., a load balancer or WAF), which is not guaranteed in all deployment configurations.

### Recommendation
1. **Add application-level rate limiting** to the REST API blocks endpoint (and other public endpoints), analogous to the `ThrottleManagerImpl` already used for the web3 service.
2. **Add a semantic upper-bound guard** in `getBlocks` or `extractSqlFromBlockFilters`: if the supplied `block.number` value exceeds the current maximum known block index (queryable cheaply via a cached `SELECT MAX(index) FROM record_file`), return an empty response immediately without hitting the database.
3. Alternatively, reject `block.number` values that exceed a configurable reasonable ceiling (e.g., current max + some buffer) with a `400 Bad Request`.

### Proof of Concept
```bash
# Single request — returns HTTP 200 with empty blocks array
curl "https://<mirror-node>/api/v1/blocks?block.number=gte:9223372036854775807"

# Flood — no authentication required
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/blocks?block.number=gte:9223372036854775807" &
done
```
Each request passes `isPositiveLong` validation, reaches `RecordFileService.getBlocks`, and executes `SELECT ... FROM record_file WHERE index >= 9223372036854775807 ORDER BY index DESC LIMIT 25` against the database, returning zero rows.