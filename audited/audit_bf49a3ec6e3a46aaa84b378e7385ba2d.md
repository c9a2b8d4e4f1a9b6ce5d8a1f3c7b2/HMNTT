### Title
Unbounded `string_agg` Aggregation in `getFileData()` Enables DoS via Large FileAppend Chain

### Summary
The `getFileData()` function in `rest/service/fileDataService.js` executes a SQL query that uses `string_agg` to concatenate all `file_data` rows for a given `fileId` with no row-count limit or byte-size cap. Any unprivileged user can create a Hedera contract whose bytecode file contains thousands of `FILEAPPEND` (type 16) rows, then trigger the unbounded aggregation by calling the public `GET /api/v1/contracts/:contractId` endpoint, causing PostgreSQL to allocate arbitrarily large memory for a single query and degrading or crashing the DB backend process.

### Finding Description

**Exact code path:**

`rest/service/fileDataService.js` lines 43–62 define `getFileDataQuery`:

```sql
select
  string_agg(file_data, '' order by consensus_timestamp) data
from file_data
where
  entity_id = $1
and consensus_timestamp >= (
  select consensus_timestamp
  from file_data
  where entity_id = $1
  and consensus_timestamp <= $2
  and (transaction_type = 17 or (transaction_type = 19 and length(file_data) <> 0))
  order by consensus_timestamp desc
  limit 1
) and consensus_timestamp <= $2
``` [1](#0-0) 

The outer `string_agg` has **no `LIMIT`, no `WHERE` clause restricting row count, and no maximum-size guard**. It aggregates every row (types 16, 17, 19) from the most recent create/update timestamp up to `$2`.

`getFileData()` (lines 70–75) passes caller-supplied `fileId` and `timestamp` directly as `$1`/`$2`: [2](#0-1) 

This function is invoked from the public `GET /api/v1/contracts/:contractId` handler in `contractController.js` line 732:

```javascript
if (utils.isValidUserFileId(contract.file_id)) {
  contract.bytecode = await FileDataService.getFileData(contract.file_id, contract.created_timestamp);
}
``` [3](#0-2) 

**Root cause:** The code assumes file data is always small (a single contract bytecode). It fails to account for an attacker-controlled file that has accumulated thousands of `FILEAPPEND` rows. The `isValidUserFileId` guard only checks that the file is a user-created file — it does not bound the number of rows or total byte size.

### Impact Explanation

PostgreSQL's `string_agg` builds the concatenated result entirely in memory within the backend process. With thousands of `FILEAPPEND` rows each carrying up to ~4 KB of data, the aggregate can reach hundreds of megabytes or more in a single query. This causes:

- **Memory exhaustion** on the PostgreSQL backend process, potentially triggering an OOM kill of that backend (dropping the connection).
- **Sustained high memory pressure** if multiple concurrent requests target the same or different large files, degrading the entire DB server.
- **Denial of service** for all mirror-node API consumers sharing the same PostgreSQL instance.

The `latestFileContentsQuery` (lines 18–41) used by `getLatestFileDataContents` has the identical unbounded `string_agg` pattern and is equally affected. [4](#0-3) 

### Likelihood Explanation

Any Hedera account holder (no special privilege required) can:
1. Submit a `FileCreate` transaction followed by N `FileAppend` transactions to build a large file on-chain.
2. Submit a `ContractCreate` referencing that file as the initcode file.
3. Repeatedly call `GET /api/v1/contracts/<contractId>` against the mirror node.

The cost is real HBAR per transaction, but on testnet this is free, and on mainnet the cost is low enough to be feasible for a motivated attacker. The attack is repeatable and requires no authentication.

### Recommendation

1. **Add a row-count or byte-size limit in the SQL query** — e.g., add a subquery that counts rows or sums `length(file_data)` and returns NULL/empty if it exceeds a configured threshold.
2. **Set a PostgreSQL `statement_timeout`** on the connection pool used by the REST API to bound query execution time.
3. **Set `work_mem` limits** at the session level for REST API connections.
4. **Cap the returned bytecode size** at the application layer before executing the query — check the total file size via a `SELECT sum(length(file_data))` guard query first.
5. **Add a `LIMIT` on the number of rows** fed into `string_agg` (e.g., via a CTE with `FETCH FIRST N ROWS ONLY`).

### Proof of Concept

```
# Precondition: attacker has a Hedera account on testnet (free)

# Step 1: Create a file with 10,000 FileAppend rows (~4 KB each = ~40 MB total)
for i in $(seq 1 10000); do
  hedera file-append --file-id 0.0.XXXXX --contents $(python3 -c "print('A'*4096)")
done

# Step 2: Create a contract referencing that file
hedera contract-create --file-id 0.0.XXXXX
# → returns contractId 0.0.YYYYY

# Step 3: Trigger the unbounded aggregation
curl https://<mirror-node>/api/v1/contracts/0.0.YYYYY

# Result: PostgreSQL backend allocates ~40 MB+ for string_agg in a single query.
# Repeated concurrent requests exhaust DB memory and degrade/crash DB connections.
```

### Citations

**File:** rest/service/fileDataService.js (L18-41)
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

**File:** rest/service/fileDataService.js (L43-62)
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

**File:** rest/service/fileDataService.js (L70-75)
```javascript
  getFileData = async (fileId, timestamp) => {
    const params = [fileId, timestamp];
    const query = FileDataService.getFileDataQuery;
    const row = await super.getSingleRow(query, params);
    return row === null ? null : row.data;
  };
```

**File:** rest/controllers/contractController.js (L731-734)
```javascript
    if (utils.isValidUserFileId(contract.file_id)) {
      contract.bytecode = await FileDataService.getFileData(contract.file_id, contract.created_timestamp);
    } else {
      contract.bytecode = contract.initcode?.toString('hex');
```
