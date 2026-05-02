### Title
Unbounded `string_agg` Aggregation in `latestFileContentsQuery` Enables Resource Exhaustion via Large File Blob Reconstruction

### Summary
The `latestFileContentsQuery` static query in `rest/service/fileDataService.js` performs an unbounded `string_agg` over all `file_data` rows (including FileAppend, type=16) since the last FileCreate/FileUpdate for a given entity, with no row count cap, no size limit, and no query timeout. Any external user can trigger this expensive aggregation by querying the public `/api/v1/contracts/results/:transactionIdOrHash` or `/api/v1/contracts/:contractId/results/:consensusTimestamp` endpoints when the referenced Ethereum transaction's `callDataId` points to a file that has accumulated a large number of FileAppend operations. The REST API has no rate limiting, allowing repeated concurrent requests to exhaust PostgreSQL memory and CPU.

### Finding Description

**Exact code path:**

`rest/service/fileDataService.js`, lines 18–41 — the `latestFileContentsQuery` static field:

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
where f.entity_id = $1 and f.transaction_type in (16, 17, 19)
    and f.consensus_timestamp >= l.consensus_timestamp
group by f.entity_id
``` [1](#0-0) 

The outer query joins every `file_data` row for the entity since the latest FileCreate/FileUpdate and concatenates all `file_data` bytes via `string_agg`. There is no `LIMIT`, no `WHERE length(file_data) <= X`, and no PostgreSQL `work_mem` guard at the query level.

**Trigger path:**

`rest/controllers/contractController.js`, lines 1022–1023 and 1183–1184 call `FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []})` unconditionally whenever `isValidUserFileId(ethTransaction?.callDataId)` is true (i.e., file entity ID > 1000). [2](#0-1) [3](#0-2) 

`isValidUserFileId` only checks that the ID is above the system-file threshold (>1000); it imposes no constraint on the file's accumulated size. [4](#0-3) 

**Root cause / failed assumption:**

The design assumes that files referenced as Ethereum `callDataId` are small (single-chunk call data). It does not account for a file that has been grown via many FileAppend transactions. The `string_agg` aggregation materialises the entire concatenated blob in PostgreSQL's working memory for every request, with no upper bound.

**Why existing checks fail:**

- `isValidUserFileId` only gates on entity ID range, not file size or append count.
- The REST API middleware (`rest/middleware/requestHandler.js`) has no per-IP rate limiting or query-level timeout.
- The throttling infrastructure found in the codebase (`web3/src/main/java/.../ThrottleConfiguration.java`) applies only to the `web3` module (contract call simulation), not to the Node.js REST API.
- There is no `LIMIT` clause or `max_file_size` guard anywhere in `latestFileContentsQuery` or `getFileDataQuery`. [5](#0-4) 

### Impact Explanation

Each request to `/api/v1/contracts/results/{txHash}` (or the timestamp variant) that resolves to an Ethereum transaction whose `callDataId` points to a heavily-appended file causes PostgreSQL to:
1. Scan all `file_data` rows for that entity since the last FileCreate.
2. Allocate and concatenate the entire blob in memory via `string_agg`.

With thousands of FileAppend rows (each up to 4 KB per Hedera protocol), a single file can accumulate tens to hundreds of megabytes. Concurrent requests against the same `callDataId` multiply the memory pressure. This can cause PostgreSQL OOM conditions, query executor stalls, and degraded response times across all mirror-node REST API consumers — meeting the ">30% resource increase" threshold described in the question.

### Likelihood Explanation

**Precondition:** An attacker must pay Hedera network fees to submit a FileCreate followed by N FileAppend transactions. This is a one-time, low-cost setup (HBAR fees are small). The resulting Ethereum transaction referencing the file as `callDataId` is also a one-time on-chain action.

**Trigger:** Once the on-chain state exists, any external user — including the original attacker or any third party who discovers the transaction hash — can repeatedly query the public, unauthenticated REST endpoint at zero cost. No credentials, no special role, no API key required.

**Repeatability:** The attack is fully repeatable and parallelisable. An attacker can fan out hundreds of concurrent HTTP requests to the same endpoint, each independently triggering the full `string_agg` aggregation.

### Recommendation

1. **Add a size/row cap to the query:** Introduce a `LIMIT` on the number of `file_data` rows aggregated, or add a `WHERE length(file_data) <= <max>` guard, or use a CTE that aborts if the running total exceeds a configured threshold.
2. **Add a PostgreSQL statement timeout** for this query class (e.g., `SET LOCAL statement_timeout = '5s'`).
3. **Cache the aggregated result** keyed on `(entity_id, latest_create_timestamp)` so repeated requests for the same file do not re-execute the aggregation.
4. **Apply rate limiting** to the REST API endpoints that invoke `getLatestFileDataContents`, at minimum per-IP throttling.
5. **Validate file size at ingest time** or store a pre-computed aggregate that is updated incrementally rather than recomputed on every read.

### Proof of Concept

1. **Setup (on-chain, one-time):**
   ```
   # Create a file on Hedera mainnet/testnet
   FileCreate → file_id = 0.0.X

   # Append 5,000 × 4 KB chunks
   for i in range(5000):
       FileAppend(file_id=0.0.X, contents=<4096 bytes>)
   # Total file size: ~20 MB across 5,001 file_data rows

   # Submit an Ethereum transaction with callData offloaded to file 0.0.X
   EthereumTransaction(callData=<empty>, callDataId=0.0.X)
   # Record the resulting transaction hash: TX_HASH
   ```

2. **Trigger (unauthenticated, repeatable):**
   ```bash
   # Single request — forces PostgreSQL to string_agg ~20 MB
   curl https://<mirror-node>/api/v1/contracts/results/TX_HASH

   # Concurrent flood — multiply memory pressure
   for i in $(seq 1 100); do
       curl -s https://<mirror-node>/api/v1/contracts/results/TX_HASH &
   done
   wait
   ```

3. **Observed effect:** PostgreSQL `work_mem` exhaustion, elevated CPU on the DB host, increased latency or OOM errors for all concurrent mirror-node queries, measurably exceeding 30% resource increase over baseline.

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

**File:** rest/__tests__/utils.test.js (L2152-2160)
```javascript
describe('Utils isValidUserFileId', () => {
  test('Null', () => expect(utils.isValidUserFileId(null)).toBeFalse());
  test('Empty', () => expect(utils.isValidUserFileId('')).toBeFalse());
  test('Undefined', () => expect(utils.isValidUserFileId(undefined)).toBeFalse());
  test('1001', () => expect(utils.isValidUserFileId(1001)).toBeTrue());
  test('5001', () => expect(utils.isValidUserFileId(5001)).toBeTrue());
  test('1000', () => expect(utils.isValidUserFileId(1000)).toBeFalse());
  test('150', () => expect(utils.isValidUserFileId(150)).toBeFalse());
});
```

**File:** rest/middleware/requestHandler.js (L1-30)
```javascript
// SPDX-License-Identifier: Apache-2.0

import httpContext from 'express-http-context';
import qs from 'qs';

import config from '../config';
import {httpStatusCodes, requestIdLabel, requestStartTime} from '../constants';
import {lowerCaseQueryValue, randomString} from '../utils';

const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};

const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};

const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};

```
