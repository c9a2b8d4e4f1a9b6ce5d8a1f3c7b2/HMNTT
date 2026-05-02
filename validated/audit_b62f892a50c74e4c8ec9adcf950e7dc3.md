All code references check out. Let me verify the test file reference as well.

All critical code references are verified against the actual repository. The vulnerability is confirmed.

---

Audit Report

## Title
Stale File Data Returned for `function_parameters` When Querying Contract Results by Transaction Hash or Timestamp

## Summary
`getContractResultsByTransactionIdOrHash()` and `getContractResultsByTimestamp()` both call `FileDataService.getLatestFileDataContents()` with an empty `whereQuery: []`, imposing no timestamp upper-bound on the file data lookup. When the referenced Hedera file (`callDataId`) has been updated after the transaction executed, the API returns the current file contents rather than the contents at execution time, producing historically incorrect `function_parameters`.

## Finding Description
**Affected locations:**

- `rest/controllers/contractController.js` lines 1183–1185 (`getContractResultsByTransactionIdOrHash`): [1](#0-0) 

- `rest/controllers/contractController.js` lines 1022–1024 (`getContractResultsByTimestamp`): [2](#0-1) 

Both call `FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []})`.

**Root cause** — `getLatestFileDataContents` in `rest/service/fileDataService.js` passes the `whereQuery` array directly into `buildWhereSqlStatement`: [3](#0-2) 

With an empty array, no timestamp filter is injected into the `latest_create` CTE, which unconditionally selects `max(consensus_timestamp)` across all file create/update records: [4](#0-3) 

**Failed assumption** — The code assumes the file at `callDataId` is immutable after the transaction executes. Hedera files are mutable; any holder of the file's admin key can issue `FILEUPDATE` or `FILEAPPEND` at any time.

**Correct pattern** — `getContractById()` at line 732 correctly pins the file lookup to the contract's creation timestamp using `getFileData(contract.file_id, contract.created_timestamp)`, which applies a `consensus_timestamp <= $2` bound: [5](#0-4) [6](#0-5) 

## Impact Explanation
The mirror node's primary purpose is to serve as an accurate, immutable historical record of network activity. Returning post-execution file data as `function_parameters` corrupts the historical record of what call data was actually submitted to the EVM. Downstream systems — block explorers, compliance tools, forensic auditors, and indexers — that rely on `function_parameters` to reconstruct transaction inputs will receive incorrect data. This undermines the integrity guarantee that is the mirror node's core value proposition.

## Likelihood Explanation
The precondition is a normal, expected operation: a file update occurring after a transaction that referenced it. Files used as call data containers are explicitly designed to be updated (e.g., for large contract deployments). No special privilege is required to trigger the incorrect response — any user who knows a transaction hash can issue the query. The defect is deterministic and repeatable for any transaction whose `callDataId` file has been subsequently modified.

## Recommendation
Pass the transaction's consensus timestamp as an upper-bound filter when calling `getLatestFileDataContents`. Specifically, construct the `whereQuery` with a `consensus_timestamp <=` constraint matching the transaction's execution timestamp, mirroring the pattern already used in `getFileData`. For example:

```js
if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
  fileData = await FileDataService.getLatestFileDataContents(
    ethTransaction.callDataId,
    {
      whereQuery: [{
        query: `${FileData.CONSENSUS_TIMESTAMP}${utils.opsMap.lte}`,
        param: ethTransaction.consensusTimestamp,
      }]
    }
  );
}
```

Apply the same fix at both call sites (lines 1022–1024 and 1183–1185).

## Proof of Concept
1. Submit an Ethereum transaction `T` at consensus timestamp `t1` with `callDataId` pointing to file `F` containing call data `D1`.
2. Update file `F` to contain `D2` at timestamp `t2 > t1`.
3. Query `GET /api/v1/contracts/results/{txHash}` for transaction `T`.
4. The mirror node executes `getLatestFileDataContents(F, {whereQuery: []})`, which resolves `max(consensus_timestamp)` to `t2` and returns `D2`.
5. The response's `function_parameters` field contains `D2` instead of the historically correct `D1`.

The same result is reproducible via `GET /api/v1/contracts/results/{contractId}/{timestamp}` through the `getContractResultsByTimestamp` code path at lines 1022–1024. [7](#0-6)

### Citations

**File:** rest/controllers/contractController.js (L731-732)
```javascript
    if (utils.isValidUserFileId(contract.file_id)) {
      contract.bytecode = await FileDataService.getFileData(contract.file_id, contract.created_timestamp);
```

**File:** rest/controllers/contractController.js (L1021-1024)
```javascript
    let fileData = null;
    if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
      fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
    }
```

**File:** rest/controllers/contractController.js (L1183-1185)
```javascript
    if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
      fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
    }
```

**File:** rest/service/fileDataService.js (L19-27)
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
```

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

**File:** rest/service/fileDataService.js (L85-88)
```javascript
  getLatestFileDataContents = async (fileId, filterQueries) => {
    const {where, params} = super.buildWhereSqlStatement(filterQueries.whereQuery, [fileId]);
    return super.getSingleRow(this.getLatestFileContentsQuery(where), params);
  };
```
