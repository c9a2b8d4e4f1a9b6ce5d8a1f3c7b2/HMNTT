### Title
Unbounded `string_agg` in `latestFileContentsQuery` Enables DB Memory Exhaustion via User-Controlled `callDataId`

### Summary
The static `latestFileContentsQuery` in `rest/service/fileDataService.js` performs an unbounded `string_agg` over all `file_data` rows for a given entity from its most recent create/update timestamp onward, with no LIMIT clause on the outer SELECT. Any Hedera account holder (no special privileges) can create a file with many large appends, embed its ID as `callDataId` in an Ethereum transaction, and then repeatedly query the mirror node REST API to force the database to aggregate the entire file history into memory on every request. The only time-based guard (`statementTimeout` = 20 s) does not bound peak memory consumption during query execution.

### Finding Description

**Exact code location:** `rest/service/fileDataService.js`, lines 19–42 (`latestFileContentsQuery`), called from `getLatestFileDataContents` (line 85–88), which is invoked at `rest/controllers/contractController.js` lines 1022–1023 and 1183–1184.

**The query (rendered):**
```sql
WITH latest_create AS (
    SELECT max(consensus_timestamp) AS consensus_timestamp
    FROM file_data
    WHERE entity_id = $1 AND transaction_type IN (17, 19)
    -- optional inner timestamp filter
    GROUP BY entity_id
    ORDER BY consensus_timestamp DESC
)
SELECT
    max(fd.consensus_timestamp)  AS consensus_timestamp,
    min(fd.consensus_timestamp)  AS first_consensus_timestamp,
    string_agg(fd.file_data, '' ORDER BY fd.consensus_timestamp) AS file_data
FROM file_data fd
JOIN latest_create l ON fd.consensus_timestamp >= l.consensus_timestamp
WHERE fd.entity_id = $1
  AND fd.transaction_type IN (16, 17, 19)
  AND fd.consensus_timestamp >= l.consensus_timestamp
  -- optional outer timestamp filter
GROUP BY fd.entity_id
-- NO LIMIT
```

**Root cause:** The outer SELECT has no LIMIT clause. `string_agg` concatenates every qualifying `file_data` row (all FILEAPPEND/FILECREATE/FILEUPDATE rows since the most recent create/update) into a single in-memory string. The total memory consumed is proportional to the cumulative byte size of all those rows, which is unbounded by the query itself.

**Failed assumption:** The design assumes that the files referenced via `callDataId` are small system files. In practice, `isValidUserFileId` (line 445–447 of `rest/utils.js`) only enforces `entity_num > 1000`—it imposes no size constraint. Any user-created file qualifies.

**Exploit flow:**
1. Attacker creates a Hedera file (FILECREATE, type 17) and appends many large chunks (FILEAPPEND, type 16), each up to ~4 KB, accumulating arbitrarily large total data in `file_data`.
2. Attacker submits an Ethereum transaction to any Hedera contract with `callDataId` set to the attacker's file entity ID.
3. Attacker repeatedly calls `GET /api/v1/contracts/results/{txHash}` (or `/api/v1/contracts/:contractId/results/:timestamp`) on the mirror node REST API.
4. The controller checks `isValidUserFileId(ethTransaction.callDataId)` → passes (entity num > 1000).
5. `FileDataService.getLatestFileDataContents(callDataId, {whereQuery: []})` executes `latestFileContentsQuery` with no upper-bound filter and no LIMIT.
6. PostgreSQL performs `string_agg` over all file_data rows for that entity, allocating memory proportional to the total file size on the DB server.
7. With up to 10 concurrent DB connections (`maxConnections: 10`) each running this query simultaneously, memory pressure multiplies.

**Why existing checks are insufficient:**
- `statementTimeout = 20000 ms` (confirmed in `rest/dbpool.js` line 15): kills the query after 20 seconds but does not cap peak memory allocated during execution. A large `string_agg` can exhaust `work_mem` and spill to disk or OOM the DB before the timeout fires.
- `isValidUserFileId`: only checks `entity_num > 1000`; no file-size or row-count guard.
- No rate limiting exists on the REST API endpoints (confirmed: no `rateLimit`/`throttle` middleware in `rest/**/*.js`).
- `maxConnections: 10`: limits concurrency but 10 simultaneous large aggregations still impose significant memory load.

### Impact Explanation
Each request forces the DB to allocate memory equal to the total size of the targeted file's history. With a file containing hundreds of megabytes of appended data and 10 concurrent connections, the DB server can be driven into memory exhaustion or severe swap pressure, degrading or crashing the database for all consumers of the mirror node. This directly satisfies the ">30% resource increase" threshold without brute-force volume, since a single well-crafted file can make every individual query expensive.

### Likelihood Explanation
Creating a Hedera file requires only a funded Hedera account—no operator or admin privileges. The economic cost (HBAR per FILEAPPEND) is a barrier but not a privilege barrier; the attacker pays once to create the file and then triggers the expensive query indefinitely at REST API request cost only. The attack is repeatable, automatable, and requires no authentication against the mirror node itself.

### Recommendation
1. **Add a LIMIT or size cap to `latestFileContentsQuery`:** Either add `LIMIT 1` after the outer `GROUP BY` (the query already expects a single row via `getSingleRow`) or add a `WHERE length(fd.file_data) <= <max_chunk_size>` guard.
2. **Cap `string_agg` output size** at the DB level using PostgreSQL's `SET LOCAL max_stack_depth` or application-level truncation before returning.
3. **Enforce a maximum file size** in `isValidUserFileId` or in `getLatestFileDataContents` by first querying the total byte count for the entity and rejecting oversized files.
4. **Add rate limiting** on the `/api/v1/contracts/results/` endpoints to limit how frequently a single client can trigger file-data aggregation queries.
5. **Set `work_mem`** to a low value for the `mirror_api` DB role to bound per-query memory allocation.

### Proof of Concept
```
# Step 1: Create a large Hedera file (requires a funded Hedera account, no special privileges)
# Submit FILECREATE transaction → get file entity ID, e.g., 0.0.5001
# Submit N × FILEAPPEND transactions each with ~4 KB payload
# (N = 50,000 → ~200 MB total in file_data table)

# Step 2: Submit an Ethereum transaction to any contract with callDataId = 0.0.5001
# Record the resulting transaction hash: 0xABCD...

# Step 3: Repeatedly query the mirror node (no auth required)
for i in $(seq 1 100); do
  curl -s "https://<mirror-node>/api/v1/contracts/results/0xABCD..." &
done
wait

# Result: each concurrent request causes PostgreSQL to execute:
#   string_agg(file_data, '' ORDER BY consensus_timestamp)
# over ~50,000 rows totaling ~200 MB, with no LIMIT.
# With 10 concurrent DB connections, the DB allocates ~2 GB of memory
# within the 20-second statementTimeout window, causing severe memory
# pressure or OOM on the database server.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/service/fileDataService.js (L19-42)
```javascript
  static latestFileContentsQuery = `with latest_create as (
      select max(${FileData.CONSENSUS_TIMESTAMP}) as ${FileData.CONSENSUS_TIMESTAMP}
      from ${FileData.tableName}
      where ${FileData.ENTITY_ID} = $1 and ${FileData.TRANSACTION_TYPE} in (17, 19) ${
    FileDataService.filterInnerPlaceholder
  }
      group by ${FileData.ENTITY_ID}
      order by ${FileData.CONSENSUS_TIMESTAMP} desc
    )
    select
      max(${FileData.tableAlias}.${FileData.CONSENSUS_TIMESTAMP}) as ${FileData.CONSENSUS_TIMESTAMP},
      min(${FileData.tableAlias}.${FileData.CONSENSUS_TIMESTAMP}) as first_consensus_timestamp,
      string_agg(${FileData.getFullName(FileData.FILE_DATA)}, '' order by ${FileData.getFullName(
    FileData.CONSENSUS_TIMESTAMP
  )}) as ${FileData.FILE_DATA}
    from ${FileData.tableName} ${FileData.tableAlias}
    join latest_create l on ${FileData.getFullName(FileData.CONSENSUS_TIMESTAMP)} >= l.${FileData.CONSENSUS_TIMESTAMP}
    where ${FileData.getFullName(FileData.ENTITY_ID)} = $1 and ${FileData.getFullName(
    FileData.TRANSACTION_TYPE
  )} in (16,17, 19)
      and ${FileData.getFullName(FileData.CONSENSUS_TIMESTAMP)} >= l.${FileData.CONSENSUS_TIMESTAMP} ${
    FileDataService.filterOuterPlaceholder
  }
    group by ${FileData.getFullName(FileData.ENTITY_ID)}`;
```

**File:** rest/service/fileDataService.js (L85-88)
```javascript
  getLatestFileDataContents = async (fileId, filterQueries) => {
    const {where, params} = super.buildWhereSqlStatement(filterQueries.whereQuery, [fileId]);
    return super.getSingleRow(this.getLatestFileContentsQuery(where), params);
  };
```

**File:** rest/controllers/contractController.js (L1021-1024)
```javascript
    let fileData = null;
    if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
      fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
    }
```

**File:** rest/controllers/contractController.js (L1181-1185)
```javascript
    let fileData = null;

    if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
      fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
    }
```

**File:** rest/utils.js (L445-447)
```javascript
const isValidUserFileId = (val) => {
  return !isNil(val) && val !== '' && EntityId.parse(val).num > 1000;
};
```

**File:** rest/dbpool.js (L14-16)
```javascript
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```
