### Title
Unbounded File Data Fetch via `callDataId` in `getContractResultsByTransactionIdOrHash` Enables Unauthenticated Memory-Exhaustion DoS

### Summary
The `getContractResultsByTransactionIdOrHash()` handler unconditionally fetches the full contents of a Hedera file referenced by `ethTransaction.callDataId` using `FileDataService.getLatestFileDataContents()`, which executes an unbounded `string_agg` SQL aggregation with no size cap. An attacker who submits a single Ethereum transaction to Hedera with large call data (up to ~1 MB, stored as a file) can then repeatedly query `GET /api/v1/contracts/results/:txHash` — with no authentication and no rate limiting — causing the mirror node to load and serialize megabytes of data per request, creating sustained memory pressure and CPU overhead.

### Finding Description
**Code path:**

- `rest/controllers/contractController.js`, `getContractResultsByTransactionIdOrHash()`, lines 1183–1184:
  ```js
  if (utils.isValidUserFileId(ethTransaction?.callDataId)) {
    fileData = await FileDataService.getLatestFileDataContents(ethTransaction.callDataId, {whereQuery: []});
  }
  ```
- `rest/service/fileDataService.js`, `getLatestFileDataContents()`, lines 85–88:
  ```js
  getLatestFileDataContents = async (fileId, filterQueries) => {
    const {where, params} = super.buildWhereSqlStatement(filterQueries.whereQuery, [fileId]);
    return super.getSingleRow(this.getLatestFileContentsQuery(where), params);
  };
  ```
- The underlying SQL (`latestFileContentsQuery`, lines 19–42) uses `string_agg(file_data, '' order by consensus_timestamp)` with **no LIMIT, no size guard, and no truncation**.

**Root cause:** The code assumes `callDataId`-referenced files are small. Hedera supports files up to ~1 MB composed of many append chunks. The `string_agg` aggregation concatenates every chunk into a single in-memory string returned to Node.js. The guard `isValidUserFileId()` only validates the entity-ID format — it imposes no size constraint. No rate limiting exists on this endpoint.

**Exploit flow:**
1. Attacker submits an Ethereum transaction to Hedera with ~1 MB of call data. The importer stores this as a file and records its entity ID as `callDataId` in `ethereum_transaction`.
2. Attacker (or a botnet of unauthenticated clients) repeatedly issues `GET /api/v1/contracts/results/<txHash>`.
3. Each request triggers the full `string_agg` aggregation, loading ~1 MB into the DB, transferring it to Node.js, and serializing it into the HTTP response.
4. Concurrent requests multiply memory and CPU usage linearly.

**Why existing checks fail:**
- `isValidUserFileId` validates format only, not file size.
- `{whereQuery: []}` passes an empty filter, so no timestamp or size constraint is applied.
- No HTTP-layer rate limiting was found in the REST codebase.

### Impact Explanation
Each request causes the PostgreSQL server to perform an unbounded `string_agg` over all file-data rows for the given entity, then transfers the result (~1 MB) to the Node.js process, which holds it in heap memory while serializing the JSON response. Under concurrent load, this can exhaust Node.js heap memory and degrade or crash the mirror-node REST service, affecting all users. This qualifies as a non-network-based DoS against a high-market-cap project.

### Likelihood Explanation
The initial cost is one Hedera transaction with large call data (a few USD in HBAR fees). After that, the attack is free and unauthenticated — any HTTP client can replay the query. The transaction hash is public and permanent, so the amplification window is indefinite. A single attacker with modest resources can sustain the attack.

### Recommendation
1. **Cap fetched file size:** Add a `LIMIT` or `LEFT(string_agg(...), MAX_BYTES)` guard in `latestFileContentsQuery`, or check `octet_length` before returning.
2. **Truncate in the service layer:** In `getLatestFileDataContents`, reject or truncate results exceeding a configurable threshold (e.g., 128 KB).
3. **Add rate limiting:** Apply per-IP or global rate limiting to `/api/v1/contracts/results/:transactionIdOrHash`.
4. **Stream large responses** rather than buffering the full file data in heap memory.

### Proof of Concept
1. Submit an Ethereum transaction to Hedera testnet with ~900 KB of call data (stored as a file via `FileCreate`/`FileAppend`). Note the resulting transaction hash `0xABC...`.
2. Confirm the mirror node importer has indexed it: `GET /api/v1/contracts/results/0xABC...` returns HTTP 200 with `call_data` populated.
3. Run concurrent load:
   ```bash
   for i in $(seq 1 200); do
     curl -s "https://<mirror-node>/api/v1/contracts/results/0xABC..." &
   done
   wait
   ```
4. Observe Node.js heap growth and response latency degradation on the mirror node. With 200 concurrent requests each pulling ~1 MB, ~200 MB of heap is consumed simultaneously, causing GC pressure and potential OOM.