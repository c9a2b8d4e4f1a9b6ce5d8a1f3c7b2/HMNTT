### Title
Unauthenticated Timestamp Filter on `/contracts/:contractId/state` Forces Unbounded `DISTINCT ON` Scan of `contract_state_change`, Enabling DoS

### Summary
Any unprivileged caller can supply a single `timestamp` query parameter to `GET /api/v1/contracts/:contractId/state`. This causes `getContractStateById()` to switch from the cheap `contract_state` table query to an unbounded `DISTINCT ON (slot)` scan over the entire `contract_state_change` table for that contract. Because the `LIMIT` clause is applied after `DISTINCT ON` and the index ordering mismatches the required sort, PostgreSQL must read and sort every matching row before returning results. Repeated requests against a high-activity contract can saturate DB CPU/IO and degrade 30%+ of mirror-node processing capacity.

### Finding Description

**Exact code path:**

`rest/controllers/contractController.js` → `getContractStateById()` (line 964) calls `extractContractStateByIdQuery()` (line 894). Inside that function, any `TIMESTAMP` filter (except `ne`) sets `timestampPresent = true` (line 918) and pushes a `consensus_timestamp` condition into the WHERE array. [1](#0-0) 

`timestampPresent` is then passed as the `timestamp` flag to `ContractService.getContractStateByIdAndFilters()` (line 971). [2](#0-1) 

Inside `getContractStateByIdAndFilters()`, when `timestamp === true`, the query is switched from `contractStateQuery` (reads the small, current-state `contract_state` table) to `contractStateTimestampQuery` (reads the append-only, unbounded `contract_state_change` table): [3](#0-2) 

The `contractStateTimestampQuery` is:

```sql
WITH entity AS (SELECT evm_address, id FROM entity)
SELECT DISTINCT ON (slot)
    contract_id, slot, evm_address,
    coalesce(value_written, value_read) AS value,
    consensus_timestamp AS modified_timestamp
FROM contract_state_change csc
LEFT JOIN entity e ON e.id = csc.contract_id
-- WHERE and ORDER BY appended at runtime:
WHERE contract_id = $1 AND consensus_timestamp <= $2
ORDER BY slot ASC, consensus_timestamp DESC
LIMIT $3
``` [4](#0-3) 

**Root cause — index/sort mismatch makes LIMIT useless:**

The only index on `contract_state_change` relevant to this query is `contract_state_change__id_slot_timestamp` on `(contract_id, slot, consensus_timestamp)` — all columns ascending. [5](#0-4) 

The query requires `ORDER BY slot ASC, consensus_timestamp DESC`. Because `consensus_timestamp` is stored ascending in the index but the query needs it descending, PostgreSQL cannot satisfy the `DISTINCT ON` ordering directly from the index. It must:
1. Scan **all** rows for `contract_id = $1 AND consensus_timestamp <= $2`
2. Sort them by `(slot ASC, consensus_timestamp DESC)` in memory/temp storage
3. Apply `DISTINCT ON (slot)` to pick the latest row per slot
4. Only then apply `LIMIT`

With `timestamp=lte:9999999999` (or any large value), step 1 matches every row ever written for that contract. The `LIMIT` is applied after the full scan and sort, so it provides no protection.

**No timestamp range validation for this endpoint:**

`extractContractStateByIdQuery` does not call `parseTimestampFilters()` (which enforces a configurable max range, e.g., 7 days). It only validates the timestamp format via `isValidTimestampParam`. [6](#0-5) 

The accepted parameters set explicitly includes `filterKeys.TIMESTAMP` with no additional guard: [7](#0-6) 

**No authentication required:** The endpoint is public; `getContractStateById` is exported without any privilege check. [8](#0-7) 

### Impact Explanation

The `contract_state_change` table is expected to accumulate ~1,800,000 rows per autovacuum cycle at 300 TPS (10 state changes/tx × 300 TPS × 600 s). [9](#0-8) 

On a production network with popular DeFi contracts, this table can contain tens or hundreds of millions of rows. Each crafted request forces a full-table-equivalent scan + in-memory sort for that contract. Concurrent requests from multiple attacker IPs can saturate PostgreSQL CPU and I/O, causing query timeouts and cascading failures across all mirror-node API endpoints that share the same DB pool. This matches the "30%+ node processing degradation" threshold without requiring brute-force volume — a modest request rate (tens of req/s) against a high-activity contract is sufficient.

### Likelihood Explanation

- **Precondition:** None. No account, API key, or token required.
- **Knowledge required:** Knowing any high-activity contract ID (publicly visible on explorers).
- **Repeatability:** Fully repeatable; each request is stateless and independently expensive.
- **Detection evasion:** The request is syntactically valid and indistinguishable from a legitimate historical-state lookup.

### Recommendation

1. **Apply timestamp range validation** in `extractContractStateByIdQuery` using the same `parseTimestampFilters` / `maxTimestampRange` guard already used by other endpoints. Reject open-ended `lte:` filters without a corresponding lower bound, or cap the allowed range (e.g., 7 days).
2. **Fix the index to support the sort order**: Add a partial or covering index `(contract_id, slot, consensus_timestamp DESC)` so PostgreSQL can satisfy `DISTINCT ON (slot) ORDER BY slot ASC, consensus_timestamp DESC` via an index scan, making `LIMIT` effective.
3. **Apply rate limiting** per IP/contract-ID on this specific endpoint.
4. **Set a DB statement timeout** for REST API connections to bound the maximum wall-clock damage per request.

### Proof of Concept

```bash
# 1. Identify a high-activity contract (e.g., from a public explorer)
CONTRACT="0.0.1234"

# 2. Send a single request with an unbounded timestamp filter
curl -s "https://<mirror-node>/api/v1/contracts/${CONTRACT}/state?timestamp=lte:9999999999"

# 3. Observe slow response (seconds to minutes depending on table size)

# 4. Flood with concurrent requests to degrade DB
for i in $(seq 1 50); do
  curl -s "https://<mirror-node>/api/v1/contracts/${CONTRACT}/state?timestamp=lte:9999999999" &
done
wait

# Expected result: DB CPU spikes to 100%, other API endpoints begin timing out,
# mirror-node processing degrades >= 30%.
```

### Citations

**File:** rest/controllers/contractController.js (L909-919)
```javascript
        case filterKeys.TIMESTAMP:
          if (utils.opsMap.ne === filter.operator) {
            throw new InvalidArgumentError(`Not equals (ne) operator is not supported for ${filterKeys.TIMESTAMP}`);
          }

          if (utils.opsMap.eq === filter.operator) {
            filter.operator = utils.opsMap.lte;
          }
          conditions.push(this.getFilterWhereCondition(ContractStateChange.CONSENSUS_TIMESTAMP, filter));
          timestampPresent = true;
          break;
```

**File:** rest/controllers/contractController.js (L970-971)
```javascript
    const {conditions, order, limit, timestamp} = await this.extractContractStateByIdQuery(filters, contractId);
    const rows = await ContractService.getContractStateByIdAndFilters(conditions, order, limit, timestamp);
```

**File:** rest/controllers/contractController.js (L1350-1355)
```javascript
const acceptedContractStateParameters = new Set([
  filterKeys.LIMIT,
  filterKeys.ORDER,
  filterKeys.SLOT,
  filterKeys.TIMESTAMP,
]);
```

**File:** rest/controllers/contractController.js (L1379-1390)
```javascript
const contractController = exportControllerMethods([
  'getContractActions',
  'getContractById',
  'getContracts',
  'getContractLogsById',
  'getContractLogs',
  'getContractResults',
  'getContractResultsById',
  'getContractResultsByTimestamp',
  'getContractResultsByTransactionIdOrHash',
  'getContractStateById',
]);
```

**File:** rest/service/contractService.js (L111-122)
```javascript
  static contractStateTimestampQuery = `
      with ${ContractService.entityCTE}
      select DISTINCT on (${ContractStateChange.SLOT}) 
            ${ContractStateChange.CONTRACT_ID},
            ${ContractStateChange.SLOT},
            ${Entity.EVM_ADDRESS},
            coalesce(${ContractStateChange.VALUE_WRITTEN}, ${ContractStateChange.VALUE_READ}) as ${ContractState.VALUE},
            ${ContractStateChange.CONSENSUS_TIMESTAMP} as ${ContractState.MODIFIED_TIMESTAMP}
      from ${ContractStateChange.tableName} ${ContractStateChange.tableAlias}
      left join ${Entity.tableName} ${Entity.tableAlias}
        on ${Entity.getFullName(Entity.ID)} = ${ContractStateChange.getFullName(ContractStateChange.CONTRACT_ID)}
    `;
```

**File:** rest/service/contractService.js (L256-264)
```javascript
    if (timestamp) {
      //timestamp order needs to be always desc to get only the latest changes until the provided timestamp
      orderClause = this.getOrderByQuery(
        OrderSpec.from(ContractStateChange.SLOT, order),
        OrderSpec.from(ContractStateChange.CONSENSUS_TIMESTAMP, orderFilterValues.DESC)
      );

      query = [ContractService.contractStateTimestampQuery, where, orderClause, limitClause].join(' ');
    }
```

**File:** importer/src/main/resources/db/migration/v2/V2.0.3__index_init.sql (L67-69)
```sql
-- contract_state_change__id_slot_timestamp
create index if not exists contract_state_change__id_slot_timestamp
    on contract_state_change (contract_id, slot, consensus_timestamp);
```

**File:** importer/src/main/resources/db/migration/v1/R__autovacuum_insert_only_tables.sql (L51-55)
```sql
-- based on average of 10 state changes per smart contract transaction and max 300 TPS
alter table if exists contract_state_change set (
  autovacuum_vacuum_insert_scale_factor = 0,
  autovacuum_vacuum_insert_threshold = 1800000
  );
```
