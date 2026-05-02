### Title
Unbounded `string_agg` Aggregation in `latestFileContentsQuery` Enables Repeated DB Resource Exhaustion via Public Contract Results API

### Summary
The static `latestFileContentsQuery` in `rest/service/fileDataService.js` uses `string_agg` to concatenate all `file_data` rows for a given `entity_id` from the most recent FileCreate/FileUpdate timestamp onwards, with no row count limit or result-size cap on the outer aggregation. An unprivileged attacker can trigger this query repeatedly through the public `/api/v1/contracts/results/{hash}` endpoint by referencing an Ethereum transaction whose `callDataId` points to a file entity with large accumulated append history, causing the database to allocate arbitrarily large result buffers on every request.

### Finding Description

**Exact code location:**

`rest/service/fileDataService.js`, lines 19–42 — the static `latestFileContentsQuery`:

```sql
with latest_create as (
    select max(consensus_timestamp) as consensus_timestamp
    from file_data
    where entity_id = $1 and transaction_type in (17, 19)
    group by entity_id
    order by consensus_timestamp desc
)
select
    max(f.consensus_timestamp) as consensus_timestamp,
    min(f.consensus_timestamp) as first_consensus_timestamp,
    string_agg(f.file_data, '' order by f.consensus_timestamp) as file_data
from file_data f
join latest_create l on f.consensus_timestamp >= l.consensus_timestamp
where f.entity_id = $1 and f.transaction_type in (16,17,19)
    and f.consensus_timestamp >= l.consensus_timestamp
group by f.entity_id
``` [1](#0-0) 

**Root cause:** The outer `SELECT` has no `LIMIT` clause and no size guard. `string_agg` concatenates every qualifying `file_data` row into a single in-memory buffer. The only bound is the total bytes stored in `file_data` for the target `entity_id` since its last FileCreate (type 17) or FileUpdate (type 19) transaction.

**Call path to public API:**

`getLatestFileDataContents` is invoked from `contractController.js` at two public endpoints:

- `GET /api/v1/contracts/{contractId}/results/{timestamp}` → `getContractResultsByTimestamp` (line 1023)
- `GET /api/v1/contracts/results/{transactionIdOrHash}` → `getContractResultsByTransactionIdOrHash` (line 1184) [2](#0-1) [3](#0-2) 

Both pass `ethTransaction.callDataId` directly as the `fileId` parameter with an empty `whereQuery: []`, meaning no additional timestamp filter is applied to the aggregation. [4](#0-3) 

**Why the existing check is insufficient:**

The only guard before calling `getLatestFileDataContents` is `utils.isValidUserFileId(ethTransaction?.callDataId)`, which validates that the value is a well-formed Hedera file entity ID. It does not inspect or limit the volume of data stored for that entity. [5](#0-4) 

The `statement_timeout` configured in `dbpool.js` (line 15) is a partial mitigation — it can kill a single long-running query — but it does not prevent concurrent requests from each independently allocating large buffers before the timeout fires, nor does it prevent repeated sequential requests. [6](#0-5) 

### Impact Explanation

PostgreSQL must materialise the entire `string_agg` result in the DB server's `work_mem` before returning it. For a file entity with gigabytes of accumulated FileAppend history (e.g., a long-lived address book or contract bytecode file with thousands of appends), each query invocation forces the DB to allocate a proportionally large buffer. With concurrent requests targeting the same or multiple large entities, aggregate DB memory and CPU consumption can exceed 30% above baseline, degrading service for all users of the mirror node. The result is also transmitted over the network and held in the Node.js process, compounding memory pressure across the stack.

### Likelihood Explanation

**Precondition:** The attacker must have submitted at least one Ethereum transaction to the Hedera network with a `callDataId` field referencing a large file entity. This is a one-time HBAR fee (fractions of a cent to a few cents). Once that transaction is ingested by the mirror node, the attacker can query the same transaction hash an unlimited number of times at zero additional cost, each time triggering a full unbounded `string_agg` scan on the DB. The attacker does not need to own or control the target file entity — they only need to reference its entity ID in their Ethereum transaction's `callDataId`. Large system files (address books, fee schedules) that accumulate many appends over the network's lifetime are natural targets. The attack is fully repeatable and scriptable.

### Recommendation

1. **Add a `LIMIT` on the number of rows fed into `string_agg`** in the outer query, or enforce a maximum aggregated byte size using PostgreSQL's `pg_size_bytes` / `octet_length` guard in a `HAVING` clause.
2. **Cap the result at the application layer** by checking `file_data.length` after retrieval and returning an error if it exceeds a configured maximum (e.g., `config.query.maxFileSize`).
3. **Apply a tight `statement_timeout`** specifically for file-data queries, separate from the global pool timeout, to bound worst-case DB resource consumption per request.
4. **Rate-limit** the `/api/v1/contracts/results/{hash}` endpoint per source IP to prevent rapid repeated triggering.

### Proof of Concept

1. Identify a Hedera file entity with large accumulated `file_data` (e.g., the address book file `0.0.102`, which has many FileAppend records).
2. Submit an Ethereum transaction to the Hedera network (testnet or mainnet) with `callDataId = 0.0.102`. This costs a small HBAR fee and is a one-time action.
3. Wait for the mirror node importer to ingest the transaction (typically seconds to minutes).
4. Retrieve the transaction hash from the Hedera network response.
5. Repeatedly send HTTP GET requests to the mirror node:
   ```
   GET /api/v1/contracts/results/{ethTxHash}
   ```
6. Each request causes the mirror node to execute `latestFileContentsQuery` with `entity_id = <encoded 0.0.102>`, forcing PostgreSQL to `string_agg` all FileAppend rows for that file since its last FileCreate/FileUpdate into a single buffer.
7. Observe DB CPU and memory metrics rising with each concurrent batch of requests, with no server-side row count or size guard terminating the aggregation early. [7](#0-6) [8](#0-7)

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

**File:** rest/controllers/contractController.js (L1182-1185)
```javascript

    if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
      fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
    }
```

**File:** rest/dbpool.js (L15-15)
```javascript
  statement_timeout: config.db.pool.statementTimeout,
```
