### Title
Unbounded Historical Scan via `DISTINCT ON` in `GET /contracts/:contractId/state?timestamp=lte:<far_future>`

### Summary
The `getContractStateById` handler accepts a single `timestamp=lte:<value>` filter with no lower-bound requirement. When a timestamp is present, `getContractStateByIdAndFilters` switches to `contractStateTimestampQuery`, which uses `SELECT DISTINCT ON (slot) ... ORDER BY slot, consensus_timestamp DESC LIMIT N`. PostgreSQL must scan and sort **all** matching rows across all time partitions before applying `LIMIT`, making the limit ineffective as a scan guard. Any unauthenticated caller can trigger a full historical scan of `contract_state_change` for any active contract.

### Finding Description

**Code path:**

`rest/routes/contractRoute.js:15` → `ContractController.getContractStateById` → `extractContractStateByIdQuery` (lines 894–956, `rest/controllers/contractController.js`) → `ContractService.getContractStateByIdAndFilters` (lines 245–267, `rest/service/contractService.js`).

**Root cause 1 — No lower-bound enforcement on timestamp:**

`extractContractStateByIdQuery` processes the `TIMESTAMP` filter key by directly appending the condition to the SQL `conditions` array with no call to `parseTimestampFilters` and no check that a lower bound exists: [1](#0-0) 

A single `timestamp=lte:<far_future>` is accepted, setting `timestampPresent = true` and generating `consensus_timestamp <= <far_future>` with no lower bound. The `parseTimestampFilters` utility (which has range-validation logic at `rest/utils.js:1657–1665`) is never invoked for this endpoint.

**Root cause 2 — `DISTINCT ON` prevents LIMIT early-exit:**

When `timestamp=true`, the service uses `contractStateTimestampQuery`: [2](#0-1) 

This produces:
```sql
SELECT DISTINCT ON (slot) contract_id, slot, ...
FROM contract_state_change
WHERE contract_id = $1 AND consensus_timestamp <= $2
ORDER BY slot ASC, consensus_timestamp DESC
LIMIT $3
```

In PostgreSQL, `DISTINCT ON` is evaluated **before** `LIMIT`. The planner must read and sort every row satisfying `contract_id = X AND consensus_timestamp <= <far_future>` across all time partitions to compute the per-slot latest value, then truncate to `LIMIT`. The `LIMIT 100` cap does not reduce the number of rows read from disk. [3](#0-2) 

**Root cause 3 — `contract_state_change` is partitioned by `consensus_timestamp`:** [4](#0-3) 

With `consensus_timestamp <= 99999999999999999999`, the query spans every partition, forcing a full cross-partition scan.

### Impact Explanation
A single request against a heavily-used contract (e.g., a popular DeFi contract with millions of historical state changes) forces the database to perform a full sequential scan across all `contract_state_change` partitions for that contract. Repeated requests (easily parallelized) saturate DB I/O and CPU, degrading or denying service for all mirror-node consumers. No authentication is required. The REST API has no per-IP rate limiting visible in the Node.js layer for this endpoint.

### Likelihood Explanation
The exploit requires only knowledge of a contract ID with a large history (publicly discoverable via the same API). The attacker needs no credentials, no tokens, and no special network position. The request is a standard HTTP GET. It is trivially repeatable and parallelizable from a single machine or botnet. Active DeFi contracts on Hedera accumulate millions of state-change records, making the scan cost high.

### Recommendation
1. **Require a bounded timestamp range**: In `extractContractStateByIdQuery`, call `parseTimestampFilters` with `allowOpenRange = false` and enforce a maximum range (e.g., the existing `config.query.maxTimestampRangeNs`). Reject requests that supply only an upper bound without a lower bound.
2. **Rewrite the query to avoid unbounded `DISTINCT ON`**: Use a lateral/correlated subquery or a CTE that iterates over known slots with an index seek per slot, so `LIMIT` can terminate early.
3. **Add a DB-level statement timeout** for this query class to bound worst-case execution time.
4. **Add per-IP or per-client rate limiting** at the REST layer for the `/contracts/:id/state` endpoint.

### Proof of Concept
```
# Step 1: Identify a contract with large history (e.g., contract 0.0.1234)
GET /api/v1/contracts/0.0.1234/state?timestamp=lte:99999999999999&limit=100

# Step 2: Repeat in parallel (e.g., 20 concurrent connections)
for i in $(seq 1 20); do
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1234/state?timestamp=lte:99999999999999&limit=100" &
done
wait

# Result: DB CPU/IO spikes to 100%; other API endpoints time out.
# No authentication required. HTTP 200 is returned (or timeout) for each request.
```

### Citations

**File:** rest/controllers/contractController.js (L909-918)
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

**File:** importer/src/main/resources/db/migration/v2/V2.0.0__create_tables.sql (L172-182)
```sql
create table if not exists contract_state_change
(
    consensus_timestamp bigint  not null,
    contract_id         bigint  not null,
    migration           boolean not null default false,
    payer_account_id    bigint  not null,
    slot                bytea   not null,
    value_read          bytea   not null,
    value_written       bytea   null
) partition by range (consensus_timestamp);
comment on table contract_state_change is 'Contract execution state changes';
```
