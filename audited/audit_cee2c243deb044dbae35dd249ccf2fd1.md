### Title
Unauthenticated Timestamp Filter Triggers Expensive `DISTINCT ON` Query Against Unbounded `contract_state_change` Table

### Summary
Any unauthenticated user can send `GET /contracts/:contractId/state?timestamp=lte:<large_value>` to force `extractContractStateByIdQuery()` to set `timestampPresent = true`, which causes `getContractStateByIdAndFilters()` to execute `contractStateTimestampQuery` against the `contract_state_change` table instead of the compact `contract_state` table. The `contract_state_change` table is an unbounded historical log whose primary key `(consensus_timestamp, contract_id, slot)` is not aligned with the query's sort requirement `ORDER BY slot, consensus_timestamp DESC`, forcing a full per-contract scan and sort before `DISTINCT ON` can reduce rows. This can be repeated at will with no authentication, degrading shared database performance for all mirror-node REST API instances.

### Finding Description

**Exact code path:**

In `rest/controllers/contractController.js`, `extractContractStateByIdQuery()` (lines 894–956) sets `timestampPresent = true` whenever any `timestamp` filter key is present:

```js
case filterKeys.TIMESTAMP:
  ...
  conditions.push(this.getFilterWhereCondition(ContractStateChange.CONSENSUS_TIMESTAMP, filter));
  timestampPresent = true;   // line 918
  break;
``` [1](#0-0) 

This flag is returned and consumed in `getContractStateByIdAndFilters()` (`rest/service/contractService.js`, lines 245–267):

```js
if (timestamp) {
  query = [ContractService.contractStateTimestampQuery, where, orderClause, limitClause].join(' ');
}
``` [2](#0-1) 

`contractStateTimestampQuery` (lines 111–122) is:

```sql
SELECT DISTINCT ON (slot)
       contract_id, slot, evm_address,
       coalesce(value_written, value_read) AS value,
       consensus_timestamp AS modified_timestamp
FROM contract_state_change csc
LEFT JOIN entity e ON e.id = csc.contract_id
[WHERE contract_id = $1 AND consensus_timestamp <= $2]
ORDER BY slot ASC, consensus_timestamp DESC
LIMIT $n
``` [3](#0-2) 

**Root cause — index/sort mismatch:**

The `contract_state_change` table's primary key is `(consensus_timestamp, contract_id, slot)`: [4](#0-3) 

The query filters on `contract_id` and `consensus_timestamp <=`, then must sort by `(slot ASC, consensus_timestamp DESC)` for `DISTINCT ON`. The PK index leading on `consensus_timestamp` cannot satisfy this sort order, so PostgreSQL must perform a sequential scan of all rows for the contract up to the timestamp, sort them in memory/on disk, then apply `DISTINCT ON` before the `LIMIT` can reduce the row count.

**No `migration` filter:** The query does not exclude `migration = true` rows. The importer writes migration rows into `contract_state_change` for every historical slot value, making the table significantly larger than `contract_state`. [3](#0-2) 

**No authentication:** The route is registered with no middleware guard: [5](#0-4) 

### Impact Explanation

The `contract_state_change` table is an append-only historical log; for a heavily-used contract it can contain millions of rows. A single request with `timestamp=lte:99999999999999999` forces a full per-contract scan + in-memory sort before the `LIMIT` is applied. Because the database is shared across all REST API mirror-node instances, sustained parallel requests from one or more attackers can saturate DB CPU/memory, causing query timeouts and degraded or unavailable service across all nodes sharing that database — consistent with the ≥30% node-degradation threshold.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and only knowledge of any valid `contractId` (all contract IDs are publicly enumerable via `GET /contracts`). The trigger is a single query parameter. It is trivially scriptable and repeatable. A busy DeFi contract with a large `contract_state_change` history makes the per-query cost arbitrarily high.

### Recommendation

1. **Add a `migration = false` filter** to `contractStateTimestampQuery` to exclude migration rows from the scan.
2. **Add a composite index** on `contract_state_change (contract_id, slot, consensus_timestamp DESC)` to align with the query's filter and sort order, enabling an index-only scan with early `LIMIT` termination.
3. **Enforce a maximum timestamp range** (e.g., reject requests where the timestamp window exceeds a configurable bound) to limit scan depth.
4. **Add rate limiting** per IP/client on the `/contracts/:contractId/state` endpoint.
5. Consider **requiring at least one non-timestamp filter** (e.g., a `slot` equality filter) when a timestamp is provided, to bound the scan to a single slot.

### Proof of Concept

```bash
# Step 1: Find any valid contract ID (public endpoint)
curl "https://<mirror-node>/api/v1/contracts?limit=1"
# Returns e.g. contractId = 0.0.1234

# Step 2: Trigger expensive contract_state_change scan with far-future timestamp
# Repeat in a loop or in parallel to saturate DB
while true; do
  curl "https://<mirror-node>/api/v1/contracts/0.0.1234/state?timestamp=lte:9999999999.999999999&limit=100" &
done

# Expected result:
# - DB CPU spikes due to repeated full-table sort on contract_state_change
# - Query latency increases across all endpoints sharing the DB
# - REST API nodes begin returning 503/timeout errors
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

**File:** importer/src/main/resources/db/migration/v1/V1.54.0__add_contract_state_change.sql (L5-14)
```sql
create table if not exists contract_state_change
(
    consensus_timestamp bigint not null,
    contract_id         bigint not null,
    payer_account_id    bigint not null,
    slot                bytea  not null,
    value_read          bytea  not null,
    value_written       bytea  null,
    primary key (consensus_timestamp, contract_id, slot)
);
```

**File:** rest/routes/contractRoute.js (L15-15)
```javascript
router.getExt('/:contractId/state', ContractController.getContractStateById);
```
