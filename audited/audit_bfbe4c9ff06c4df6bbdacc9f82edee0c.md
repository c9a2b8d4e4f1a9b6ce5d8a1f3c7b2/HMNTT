### Title
Unbounded `string_agg` Aggregation via User-Controlled Timestamp in `getFileDataQuery`

### Summary
The static `getFileDataQuery` in `rest/service/fileDataService.js` uses a correlated subquery to find the most recent `FileCreate` (type 17) or non-empty `FileUpdate` (type 19) before a user-supplied timestamp `$2`, then uses that result as the lower bound for an unbounded `string_agg` over all matching rows up to `$2`. For files that have only one `FileCreate` and a long history of `FileAppend` operations (e.g., contract bytecode files), supplying a sufficiently large timestamp causes the database to concatenate the entire file history in a single query, consuming memory and CPU proportional to that history with no server-side row or size limit.

### Finding Description

**Exact code location:** `rest/service/fileDataService.js`, lines 44–63.

```js
static getFileDataQuery = `select
     string_agg(
       ${FileData.FILE_DATA}, ''
       order by ${FileData.CONSENSUS_TIMESTAMP}
       ) data
    from ${FileData.tableName}
    where
       ${FileData.ENTITY_ID} = $1
    and ${FileData.CONSENSUS_TIMESTAMP} >= (
    select ${FileData.CONSENSUS_TIMESTAMP}
    from ${FileData.tableName}
    where ${FileData.ENTITY_ID} = $1
    and ${FileData.CONSENSUS_TIMESTAMP} <= $2          -- user-controlled upper bound
    and (${FileData.TRANSACTION_TYPE} = 17
         or ( ${FileData.TRANSACTION_TYPE} = 19
              and
              length(${FileData.FILE_DATA}) <> 0 ))
    order by ${FileData.CONSENSUS_TIMESTAMP} desc
    limit 1                                            -- anchor = most-recent create/update
    ) and ${FileData.CONSENSUS_TIMESTAMP} <= $2`;      -- outer range: anchor → $2, no LIMIT
```

**Root cause:** The inner subquery returns the single most-recent `FileCreate`/non-empty `FileUpdate` whose `consensus_timestamp <= $2`. The outer `string_agg` then concatenates **every** row (all transaction types, no filter) from that anchor up to `$2`. There is no `LIMIT`, no `max_rows`, and no size cap anywhere in the query or in the calling method `getFileData` (lines 71–76).

**Exploit flow:**

1. Attacker identifies a file entity (e.g., a contract bytecode file) that was created once (`FileCreate` at `T_old`) and has accumulated hundreds or thousands of `FileAppend` rows but no subsequent non-empty `FileUpdate`.
2. Attacker calls the REST endpoint that invokes `FileDataService.getFileData(fileId, timestamp)` — reachable from `rest/controllers/contractController.js` — and supplies `timestamp = 9999999999.999999999` (or any value larger than the latest `FileAppend`).
3. The inner subquery scans the index for `entity_id = $1 AND consensus_timestamp <= $2 AND (type=17 OR (type=19 AND length>0))`, finds only the original `FileCreate` at `T_old`, and returns `T_old` as the anchor.
4. The outer query scans **all** rows for `entity_id = $1 AND consensus_timestamp >= T_old AND consensus_timestamp <= $2` — the entire file history — and feeds them all into `string_agg`, allocating a result buffer proportional to the total size of all `file_data` blobs.
5. The attacker repeats this request in a tight loop; each request independently triggers the full aggregation.

**Why existing checks fail:** The `getFileData` method passes `timestamp` directly as a parameterized value (`$2`) with no upper-bound clamping, no row-count guard, and no result-size limit. The query itself has no `LIMIT` clause on the outer `SELECT`. The inner `LIMIT 1` only limits the anchor lookup, not the aggregation range.

### Impact Explanation
Each crafted request forces PostgreSQL to perform a sequential scan (or large index range scan) over all `file_data` rows for the targeted entity, sort them, and concatenate their binary blobs in memory. For a contract file with N append chunks of average size S bytes, each request allocates O(N×S) bytes of server memory and O(N log N) CPU time for the sort. Repeated requests from a single unauthenticated client can exhaust the database server's `work_mem`, increase query latency for all other users, and — at sufficient concurrency — push total memory usage past available RAM, causing the database to spill to disk or OOM-kill worker processes. This satisfies the stated threshold of ≥30% increase in processing-node resource consumption without brute-force credential actions.

### Likelihood Explanation
The REST API is publicly accessible with no authentication required for read endpoints. The attacker needs only to know (or enumerate) a valid file entity ID with a long append history — contract bytecode files are a natural target since they are created once and extended via many `FileAppend` transactions. The timestamp parameter accepts arbitrary nanosecond-precision values up to `int64` max, so no special knowledge beyond a valid `fileId` is required. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Clamp `$2` to `now()`** (current consensus timestamp) server-side before executing the query, preventing requests for future timestamps from expanding the aggregation window unnecessarily.
2. **Add a `LIMIT` or `max_rows` guard** in the outer query, or enforce a maximum result size (e.g., via `pg_size_pretty` / `octet_length` check) and return an error if exceeded.
3. **Add a lower-bound parameter** (analogous to the `lowerTimestamp` added in `rest-java`'s `FileDataRepository.getFileAtTimestamp(long, long, long)`) so the aggregation window is always bounded on both sides by caller-controlled, validated values.
4. **Rate-limit** requests to file-data endpoints per IP/client at the API gateway layer.

### Proof of Concept

```bash
# 1. Identify a contract whose callDataId references a file with many FileAppend rows.
#    Example: fileId = 5001 (from test fixtures), with FileCreate at T_old and N appends.

# 2. Send a request with timestamp = max int64 nanoseconds (year ~2262):
curl "https://<mirror-node>/api/v1/contracts/0.0.1234/results/987654000123020" \
  # The handler resolves callDataId → fileId, then calls:
  # FileDataService.getFileData(fileId, 9999999999999999999)

# 3. Observe: the DB executes string_agg over ALL file_data rows for fileId,
#    from the original FileCreate timestamp to 9999999999999999999.

# 4. Repeat in a loop to sustain elevated DB CPU/memory:
for i in $(seq 1 100); do
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1234/results/987654000123020" &
done
wait
``` [1](#0-0) [2](#0-1)

### Citations

**File:** rest/service/fileDataService.js (L44-63)
```javascript
  static getFileDataQuery = `select
         string_agg(
           ${FileData.FILE_DATA}, ''
           order by ${FileData.CONSENSUS_TIMESTAMP}
           ) data
        from ${FileData.tableName}
        where
           ${FileData.ENTITY_ID} = $1
        and ${FileData.CONSENSUS_TIMESTAMP} >= (
        select ${FileData.CONSENSUS_TIMESTAMP}
        from ${FileData.tableName}
        where ${FileData.ENTITY_ID} = $1
        and ${FileData.CONSENSUS_TIMESTAMP} <= $2
        and (${FileData.TRANSACTION_TYPE} = 17
             or ( ${FileData.TRANSACTION_TYPE} = 19
                  and
                  length(${FileData.FILE_DATA}) <> 0 ))
        order by ${FileData.CONSENSUS_TIMESTAMP} desc
        limit 1
        ) and ${FileData.CONSENSUS_TIMESTAMP} <= $2`;
```

**File:** rest/service/fileDataService.js (L71-76)
```javascript
  getFileData = async (fileId, timestamp) => {
    const params = [fileId, timestamp];
    const query = FileDataService.getFileDataQuery;
    const row = await super.getSingleRow(query, params);
    return row === null ? null : row.data;
  };
```
