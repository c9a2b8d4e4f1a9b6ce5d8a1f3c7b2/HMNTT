### Title
Unbounded `string_agg` + `GROUP BY` Aggregation in `latestFileContentsQuery` Enables DB Memory Exhaustion via Repeated Contract-Result Queries

### Summary
The static `latestFileContentsQuery` in `rest/service/fileDataService.js` performs an unbounded `string_agg(file_data, '' order by consensus_timestamp)` aggregated with `GROUP BY entity_id` over every `file_data` row for a given entity since its last FILECREATE/FILEUPDATE. There is no row-count cap, no `work_mem` guard, and no rate limit on the REST endpoints that invoke it. Any unprivileged caller who can reference an Ethereum transaction whose `callDataId` points to a file with many FILEAPPEND rows can repeatedly force the database to materialise the entire file history in a hash-aggregate node, consuming memory proportional to the cumulative blob size on every request.

### Finding Description

**Exact code path**

`rest/service/fileDataService.js` lines 19–42 — `latestFileContentsQuery`:

```sql
with latest_create as (
    select max(consensus_timestamp) as consensus_timestamp
    from file_data
    where entity_id = $1 and transaction_type in (17, 19)   -- FILECREATE / FILEUPDATE
    group by entity_id
    order by consensus_timestamp desc
)
select
    max(f.consensus_timestamp)   as consensus_timestamp,
    min(f.consensus_timestamp)   as first_consensus_timestamp,
    string_agg(f.file_data, '' order by f.consensus_timestamp) as file_data
from file_data f
join latest_create l on f.consensus_timestamp >= l.consensus_timestamp
where f.entity_id = $1
  and f.transaction_type in (16, 17, 19)          -- FILEAPPEND included
  and f.consensus_timestamp >= l.consensus_timestamp
group by f.entity_id                               -- ← hash-aggregate, no LIMIT
```

The CTE resolves to the timestamp of the oldest FILECREATE/FILEUPDATE for the entity. The outer query then pulls **every** `file_data` row from that timestamp to the present and concatenates them. PostgreSQL must buffer all matching blobs in a hash-aggregate node before emitting the single output row.

**Trigger surface**

`rest/controllers/contractController.js` lines 1022–1023 and 1183–1184 call:

```js
if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
  fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
}
```

`isValidUserFileId` (`rest/utils.js` lines 445–447) accepts any entity whose `num > 1000`:

```js
const isValidUserFileId = (val) => {
  return !isNil(val) && val !== '' && EntityId.parse(val).num > 1000;
};
```

No check on file size, row count, or blob volume is performed.

**Root cause / failed assumption**

The design assumes that a user-referenced file will be small (a single Ethereum call-data payload). It does not account for a file that has accumulated hundreds or thousands of FILEAPPEND rows, each carrying the maximum per-transaction blob size. The `GROUP BY entity_id` with `string_agg` forces a full materialisation of all rows regardless of their aggregate size.

### Impact Explanation

Each HTTP request to `GET /api/v1/contracts/:contractId/results/:timestamp` or `GET /api/v1/contracts/results/:txHashOrId` that resolves to an Ethereum transaction with a large `callDataId` causes the database to allocate memory equal to the sum of all `file_data` blobs for that entity. With concurrent requests (easily achieved with `curl`/`ab`/`wrk`), the aggregate memory pressure multiplies linearly. Because the mirror-node REST layer has no visible rate-limiting or per-query `work_mem` cap, a sustained flood of such requests can push PostgreSQL's shared-buffer and sort-memory usage well above the 30 % threshold cited in the threat model, degrading or denying service to all other API consumers.

### Likelihood Explanation

**Precondition**: An Ethereum transaction must exist in the mirror-node database whose `call_data_id` points to a file (entity_id > 1000) with many FILEAPPEND rows. This can be arranged by any Hedera account holder (no special privilege, only HBAR for fees): submit FILECREATE + N × FILEAPPEND to build a large file, then submit an `EthereumTransaction` with `callData` referencing that file ID. Alternatively, if any such transaction already exists on mainnet/testnet, no setup cost is required at all.

**Trigger**: Once the on-chain state exists, the attack is purely HTTP-level — no authentication, no special headers. The attacker issues repeated GET requests to the two contract-result endpoints. The mirror-node REST server is publicly accessible.

**Repeatability**: Unlimited. Each request independently re-executes the full aggregation. There is no caching of the assembled blob visible in the REST service layer.

### Recommendation

1. **Add a `LIMIT 1` to the CTE** and rewrite the outer query to use a correlated subquery or window function that fetches only the rows belonging to the single most-recent create/update epoch, rather than aggregating from the global max timestamp.
2. **Cap aggregate size at the DB level**: set `work_mem` per session or use a `statement_timeout` / `lock_timeout` for mirror-node read connections.
3. **Enforce a maximum `file_data` row count or blob size** before invoking `getLatestFileDataContents`, rejecting or truncating requests that exceed a configurable threshold.
4. **Apply rate-limiting** (e.g., per-IP or per-endpoint) on the contract-results endpoints in the REST layer or an upstream proxy.

### Proof of Concept

```
# Step 1 – on-chain setup (one-time, any Hedera account)
# Create a file and append ~500 chunks of 4 KB each (~2 MB total)
hedera file:create --contents chunk0.bin          # entity_id = 0.0.X (X > 1000)
for i in $(seq 1 500); do
  hedera file:append --file-id 0.0.X --contents chunk${i}.bin
done

# Submit an EthereumTransaction with callData referencing file 0.0.X
hedera contract:call --call-data-file-id 0.0.X ...
# Note the resulting consensus_timestamp T and contract_id C

# Step 2 – exploit (any unauthenticated HTTP client, no Hedera account needed)
# Flood the endpoint; each request forces a full string_agg over ~500 rows
wrk -t8 -c64 -d60s \
  "https://<mirror-node>/api/v1/contracts/0.0.C/results/T"

# Observe: PostgreSQL process memory climbs proportionally to blob volume × concurrency;
# other API endpoints experience elevated latency / timeouts.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/utils.js (L445-447)
```javascript
const isValidUserFileId = (val) => {
  return !isNil(val) && val !== '' && EntityId.parse(val).num > 1000;
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
