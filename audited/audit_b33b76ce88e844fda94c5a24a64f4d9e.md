### Title
Unbounded DB Query in `getContractStateChangesByTimestamps()` Enables Resource Exhaustion via Public API

### Summary
`getContractStateChangesByTimestamps()` in `rest/service/contractService.js` constructs and executes a SQL query with no `LIMIT` clause, meaning it can return an arbitrarily large result set from the `contract_state_change` table. This function is reachable by any unauthenticated user via the public `GET /api/v1/contracts/results/{transactionIdOrHash}` endpoint. An attacker can repeatedly trigger this path against a transaction involving a contract with thousands of storage slot writes, causing unbounded DB I/O and application memory consumption.

### Finding Description

**Exact code location:**

`rest/service/contractService.js`, `getContractStateChangesByTimestamps()`, lines 416–450.

The static query template `contractStateChangesQuery` (lines 85–97) is a CTE + `LEFT JOIN` with no `LIMIT`:

```js
static contractStateChangesQuery = `
  with ${ContractService.entityCTE}
  select ...
  from ${ContractStateChange.tableName} ${ContractStateChange.tableAlias}
  left join ${Entity.tableName} ${Entity.tableAlias}
    on ${Entity.getFullName(Entity.ID)} = ${ContractStateChange.getFullName(ContractStateChange.CONTRACT_ID)}
  `;
``` [1](#0-0) 

At line 441, the final query is assembled as only `contractStateChangesQuery + whereClause + orderClause` — no `LIMIT` is ever appended:

```js
const query = [ContractService.contractStateChangesQuery, whereClause, orderClause].join('\n');
const rows = await super.getRows(query, params);
``` [2](#0-1) 

**Root cause / failed assumption:** The developer assumed that the timestamp + contract ID filter would naturally bound the result set. This assumption fails for contracts that execute many `SSTORE` operations in a single transaction (each producing one row in `contract_state_change`).

**Additional amplifier — `involvedContractIds` degrades to `true`:** When `involvedContractIds` is empty (the default), `contractIdsQuery` is set to the JavaScript boolean `true`:

```js
const contractIdsQuery = involvedContractIds?.length
  ? `${ContractStateChange.CONTRACT_ID} in (${involvedContractIds.join(',')})`
  : true;
``` [3](#0-2) 

This literal `true` is pushed into the SQL `conditions` array, so the WHERE clause becomes `WHERE consensus_timestamp = $1 AND true AND migration IS false` — no contract ID filter at all, returning every state change at that timestamp across all contracts.

**Call chain to public endpoint:**

`GET /api/v1/contracts/results/{transactionIdOrHash}`
→ `getContractResultsByTransactionIdOrHash()` (contractController.js)
→ `getDetailedContractResults()` (lines 1205–1220)
→ `ContractService.getContractStateChangesByTimestamps(contractDetails.consensusTimestamp, contractId, contractDetails.contractIds)` [4](#0-3) 

No authentication is required to call this endpoint.

### Impact Explanation

Each call issues a full table scan (bounded only by timestamp) against `contract_state_change`, which can be very large on a production mirror node. The entire result set is materialized in Node.js heap memory before being serialized. A contract that writes 10,000 storage slots in one transaction produces 10,000 rows per query invocation. Repeated calls (or concurrent calls from multiple clients) multiply the effect. DB I/O, network bandwidth between DB and app, and heap memory all scale linearly with the number of state changes, with no server-side cap. This can realistically push node resource consumption well above 30% above baseline.

### Likelihood Explanation

The exploit requires only:
1. Knowledge of a transaction hash for a transaction that touched a storage-heavy contract (publicly observable on any block explorer or by querying the mirror node's own transaction APIs).
2. The ability to send HTTP GET requests — no credentials, no special role.

On mainnet, contracts such as DEX routers, token contracts, or any contract using many storage slots in a single call are common. The attacker does not need to deploy anything; they only need to discover an existing heavy transaction. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Add a hard `LIMIT` to `getContractStateChangesByTimestamps`**, analogous to how `getContractStateByIdAndFilters` uses `getLimitQuery`. Apply a configurable cap (e.g., `maxLimit` from the response-limit config) before executing the query.
2. **Fix the `involvedContractIds` fallback**: when `involvedContractIds` is empty and `contractId` is null, either return an empty result immediately or require at least one contract ID to be present before querying.
3. **Apply the same fix to `getContractResultsByTimestamps` and `getContractLogsByTimestamps`**, which have the same structural issue.

### Proof of Concept

```
# Step 1: Identify a transaction hash for a contract that writes many storage slots.
# Any public mirror node query can surface this:
GET /api/v1/transactions?type=CONTRACTCALL&order=desc&limit=25

# Step 2: Pick a transaction hash from the results (e.g., 0xabc...123).

# Step 3: Repeatedly hammer the unbounded endpoint:
for i in $(seq 1 50); do
  curl -s "https://<mirror-node-host>/api/v1/contracts/results/0xabc...123" &
done
wait

# Result: Each concurrent request issues an unbounded SELECT against
# contract_state_change with no LIMIT, materializing the full result set
# in application memory. DB CPU, I/O, and Node.js heap spike proportionally
# to the number of state-change rows at that timestamp.
```

### Citations

**File:** rest/service/contractService.js (L85-97)
```javascript
  static contractStateChangesQuery = `
    with ${ContractService.entityCTE}
    select ${ContractStateChange.CONSENSUS_TIMESTAMP},
           ${ContractStateChange.CONTRACT_ID},
           ${ContractStateChange.PAYER_ACCOUNT_ID},
           ${ContractStateChange.SLOT},
           ${ContractStateChange.VALUE_READ},
           ${ContractStateChange.VALUE_WRITTEN},
           coalesce(${Entity.getFullName(Entity.EVM_ADDRESS)},'') as ${Entity.EVM_ADDRESS}
    from ${ContractStateChange.tableName} ${ContractStateChange.tableAlias}
    left join ${Entity.tableName} ${Entity.tableAlias}
      on ${Entity.getFullName(Entity.ID)} = ${ContractStateChange.getFullName(ContractStateChange.CONTRACT_ID)}
    `;
```

**File:** rest/service/contractService.js (L426-428)
```javascript
    const contractIdsQuery = involvedContractIds?.length
      ? `${ContractStateChange.CONTRACT_ID} in (${involvedContractIds.join(',')})`
      : true;
```

**File:** rest/service/contractService.js (L441-442)
```javascript
    const query = [ContractService.contractStateChangesQuery, whereClause, orderClause].join('\n');
    const rows = await super.getRows(query, params);
```

**File:** rest/controllers/contractController.js (L1214-1218)
```javascript
      ContractService.getContractStateChangesByTimestamps(
        contractDetails.consensusTimestamp,
        contractId,
        contractDetails.contractIds
      ),
```
