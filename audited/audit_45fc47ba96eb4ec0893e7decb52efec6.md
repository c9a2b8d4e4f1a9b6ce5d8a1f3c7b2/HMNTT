### Title
Unauthenticated DoS via Unbounded `contract_state_change` Table Scan on GET /contracts/:contractId/state

### Summary
The `extractContractStateByIdQuery()` function silently converts a user-supplied `eq` timestamp operator to `lte`, then routes the query to the `contract_state_change` table (a full historical log, orders of magnitude larger than `contract_state`) with no lower-bound requirement and no `maxTimestampRange` enforcement. An unauthenticated attacker can submit a single request with a far-future timestamp that forces PostgreSQL to scan, sort, and `DISTINCT ON` every historical state-change row for a target contract, exhausting DB I/O and connection-pool slots.

### Finding Description

**Code path:**

1. `getContractStateById` (contractController.js:964) calls `extractContractIdAndFiltersFromValidatedRequest`, which calls `utils.buildAndValidateFilters`. This validates only the *format* of each filter value; it does **not** call `parseTimestampFilters()` and therefore never enforces `maxTimestampRange`.

2. Inside `extractContractStateByIdQuery` (contractController.js:909–918):
```js
case filterKeys.TIMESTAMP:
  if (utils.opsMap.ne === filter.operator) {
    throw new InvalidArgumentError(...);   // only ne is blocked
  }
  if (utils.opsMap.eq === filter.operator) {
    filter.operator = utils.opsMap.lte;   // eq silently becomes lte
  }
  conditions.push(this.getFilterWhereCondition(ContractStateChange.CONSENSUS_TIMESTAMP, filter));
  timestampPresent = true;
```
A user-supplied `timestamp=9999999999` (no operator = `eq`) is rewritten to `consensus_timestamp <= 9999999999000000000`. No lower bound is added; no range width check is performed.

3. Because `timestampPresent = true`, `getContractStateByIdAndFilters` (contractService.js:256–263) selects `contractStateTimestampQuery` instead of `contractStateQuery`:
```js
static contractStateTimestampQuery = `
  with entity as (...)
  select DISTINCT on (csc.slot)
        csc.contract_id, csc.slot, evm_address,
        coalesce(csc.value_written, csc.value_read) as value,
        csc.consensus_timestamp as modified_timestamp
  from contract_state_change csc
  left join entity e on e.id = csc.contract_id
`;
```
The resulting SQL is:
```sql
SELECT DISTINCT ON (slot) ...
FROM contract_state_change
WHERE contract_id = $1 AND consensus_timestamp <= $2
ORDER BY slot, consensus_timestamp DESC
LIMIT $3
```

4. PostgreSQL must scan **all** partitions of `contract_state_change` for the given `contract_id` up to the supplied timestamp, sort the full result set by `(slot, consensus_timestamp DESC)`, and then apply `DISTINCT ON` before the `LIMIT` can reduce the row count. The `LIMIT 100` does not short-circuit the sort.

**Why existing checks fail:**

- `parseTimestampFilters()` (utils.js:1583–1681), which enforces `maxTimestampRange` (default 7 days), is **never called** in this code path. It is only used in `optimizeTimestampFilters()` for the contract-results endpoints.
- The `maxTimestampRange` range check (utils.js:1657–1665) only fires when *both* a lower and upper bound are present (`difference !== null`). A lone `lte` filter has no lower bound, so `difference` is `null` and the check is skipped even if `parseTimestampFilters` were called.
- The `ne` operator guard (contractController.js:910–911) is the only operator-level check; all other operators including the dangerous open-ended `lte` pass through.
- The DB `statementTimeout` of 20 000 ms (docs/configuration.md) limits individual query duration but does not prevent concurrent saturation of the 10-connection pool (`maxConnections: 10`).

### Impact Explanation

`contract_state_change` is a partitioned append-only log of every EVM storage write since genesis. For a heavily-used contract (e.g., a popular DeFi or token contract), this table can contain millions of rows. A single request with `timestamp=9999999999` forces a full-table scan + sort for that contract. With the 10-connection pool and a 20-second statement timeout, ten concurrent requests keep all DB connections occupied for up to 20 seconds each. During this window, the importer's transaction-confirmation queries cannot obtain a connection, stalling consensus-timestamp writes and effectively halting the mirror node's ability to confirm new transactions — a total network-visibility shutdown from the mirror node's perspective.

### Likelihood Explanation

The endpoint requires no authentication. The attack requires only knowledge of a contract ID with significant history (trivially discoverable via `/api/v1/contracts`). The request is a single HTTP GET with one query parameter. It is fully repeatable and scriptable. Any external user can execute it.

### Recommendation

1. **Enforce a lower-bound requirement**: Reject timestamp filters that lack a lower bound (`gte`/`gt`) when the query targets `contract_state_change`. Alternatively, synthesize a default lower bound (e.g., `now - maxTimestampRange`).
2. **Call `parseTimestampFilters()` in `extractContractStateByIdQuery`**: Pass the collected timestamp filters through `parseTimestampFilters(filters, false, false, false, true, true)` to enforce `maxTimestampRange` before building SQL conditions.
3. **Do not silently widen `eq` to `lte`**: If `eq` semantics are needed, implement a point-in-time lookup that uses the primary key index (`contract_id, slot, consensus_timestamp`) rather than a full-table scan.
4. **Add per-IP or global rate limiting** to the REST API for this endpoint.

### Proof of Concept

```bash
# Identify a contract with significant history
CONTRACT_ID="0.0.1234"   # replace with a real high-activity contract

# Single request: eq operator → silently becomes lte → full table scan
curl "https://<mirror-node>/api/v1/contracts/${CONTRACT_ID}/state?timestamp=9999999999"

# Concurrent flood to exhaust the 10-connection pool
for i in $(seq 1 15); do
  curl -s "https://<mirror-node>/api/v1/contracts/${CONTRACT_ID}/state?timestamp=9999999999" &
done
wait
# DB connection pool is now saturated; importer queries time out;
# new transaction confirmations are blocked for up to 20 seconds per wave.
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/utils.js (L1657-1665)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
```
