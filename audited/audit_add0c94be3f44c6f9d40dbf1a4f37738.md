### Title
Unbounded Query in `getContractLogsByTimestamps()` Allows Resource Exhaustion via Single Timestamp

### Summary
`getContractLogsByTimestamps()` in `rest/service/contractService.js` constructs and executes a SQL query against the `contract_log` table with no `LIMIT` clause. Any unprivileged user who can identify a consensus timestamp associated with a contract that emitted a large number of logs can trigger this code path via a public REST endpoint, causing the database to return an unbounded result set and the application to buffer all rows in memory.

### Finding Description
**Exact code location:** `rest/service/contractService.js`, `getContractLogsByTimestamps()`, lines 395–414.

The function builds a query by joining `contractLogsWithEvmAddressQuery` (the CTE + left join defined at lines 124–132) with only a `WHERE` clause and an `ORDER BY` clause:

```js
// rest/service/contractService.js lines 408-412
const whereClause = `where ${conditions.join(' and ')}`;
const orderClause = `order by ${ContractLog.CONSENSUS_TIMESTAMP}, ${ContractLog.INDEX}`;

const query = [ContractService.contractLogsWithEvmAddressQuery, whereClause, orderClause].join('\n');
const rows = await super.getRows(query, params);
```

No `LIMIT` is ever appended. The resulting SQL is:

```sql
with entity as (select evm_address, id from entity)
select <contractLogsFields>, evm_address
from contract_log cl
  left join entity e on id = contract_id
where cl.consensus_timestamp = $1          -- or IN (...)
order by cl.consensus_timestamp, cl.index
-- ← NO LIMIT
```

**Call path:** `getContractLogsByTimestamps` is invoked from `contractController.js` inside the `getContractResultsByTimestamp` handler, which services the public endpoint `GET /api/v1/contracts/{contractId}/results/{timestamp}`. The `{timestamp}` path parameter is user-supplied and is validated only for format (nanosecond integer), not for the cardinality of logs it may produce.

**Root cause / failed assumption:** The developer assumed that a single consensus timestamp would correspond to a bounded, small number of contract logs. In practice, a single EVM transaction can emit hundreds or thousands of log events (e.g., a batch-mint or batch-transfer contract), and the Hedera protocol imposes no hard cap small enough to protect this query.

### Impact Explanation
An attacker who identifies (or pre-creates) a contract transaction that emitted a very large number of logs at a known timestamp can repeatedly issue:

```
GET /api/v1/contracts/<contractId>/results/<timestamp>
```

Each request causes:
1. A full sequential scan (or large index range scan) of `contract_log` filtered only by `consensus_timestamp`.
2. A `LEFT JOIN` against the `entity` table for every returned row.
3. All matching rows materialized in the Node.js process heap as `ContractLog` objects before any response is sent.

With enough logs per timestamp (e.g., 10 000+), a single request can consume hundreds of MB of application memory and saturate DB I/O. Repeated requests from one or more clients can push node resource consumption well above 30% above baseline without any brute-force volume of distinct requests.

### Likelihood Explanation
- The endpoint is fully public; no authentication is required.
- The attacker only needs to know one valid `{contractId}` + `{timestamp}` pair with many logs — discoverable by querying `/api/v1/contracts/results/logs` or by deploying their own contract.
- The attack is repeatable and parallelisable with minimal tooling (e.g., `curl` in a loop).
- No per-request result-size guard, no streaming, and no circuit-breaker exists in this code path.

### Recommendation
1. **Add a `LIMIT` clause** to the query built in `getContractLogsByTimestamps()`, consistent with the `defaultLimit` used elsewhere in the service, or accept an explicit `limit` parameter and enforce it.
2. **Stream or paginate** the result rather than buffering all rows before returning.
3. **Add a server-side cap** (e.g., `MAX_CONTRACT_LOGS_PER_TIMESTAMP`) and return an error or truncated result if the cap is exceeded.
4. Apply the same fix to the structurally identical `getContractResultsByTimestamps()` (lines 269–296) and `getContractStateChangesByTimestamps()` (lines 416–449), which share the same missing-`LIMIT` pattern.

### Proof of Concept
**Precondition:** A contract exists on the network that emitted ≥ 10 000 log events in a single transaction at timestamp `T`.

**Steps:**
```bash
# 1. Identify a high-log-count timestamp (or deploy your own contract)
TIMESTAMP="1234567890000000000"
CONTRACT_ID="0.0.12345"

# 2. Issue the request — no auth required
curl "https://<mirror-node>/api/v1/contracts/${CONTRACT_ID}/results/${TIMESTAMP}"

# 3. Observe: DB query returns all N logs with no limit;
#    application buffers all N ContractLog objects in heap;
#    response latency spikes; heap usage grows proportionally to N.

# 4. Repeat in parallel to amplify resource consumption:
for i in $(seq 1 20); do
  curl -s "https://<mirror-node>/api/v1/contracts/${CONTRACT_ID}/results/${TIMESTAMP}" &
done
wait
```

**Expected result:** Node.js heap and DB I/O increase proportionally to the number of logs at `TIMESTAMP`, with no server-side guard preventing unbounded result sets. [1](#0-0) [2](#0-1)

### Citations

**File:** rest/service/contractService.js (L124-132)
```javascript
  static contractLogsWithEvmAddressQuery = `
    with ${ContractService.entityCTE}
    select
      ${contractLogsFields},
      ${Entity.getFullName(Entity.EVM_ADDRESS)} as ${Entity.EVM_ADDRESS}
    from ${ContractLog.tableName} ${ContractLog.tableAlias}
      left join ${Entity.tableName} ${Entity.tableAlias}
      on ${Entity.getFullName(Entity.ID)} = ${ContractLog.getFullName(ContractLog.CONTRACT_ID)}
    `;
```

**File:** rest/service/contractService.js (L395-414)
```javascript
  async getContractLogsByTimestamps(timestamps, involvedContractIds = []) {
    let params = [timestamps];
    let timestampsOpAndValue = '= $1';
    if (Array.isArray(timestamps)) {
      params = timestamps;
      const positions = range(1, timestamps.length + 1).map((i) => `$${i}`);
      timestampsOpAndValue = `in (${positions})`;
    }

    const conditions = [`${ContractLog.CONSENSUS_TIMESTAMP} ${timestampsOpAndValue}`];
    if (involvedContractIds.length) {
      conditions.push(`${ContractLog.CONTRACT_ID} in (${involvedContractIds.join(',')})`);
    }
    const whereClause = `where ${conditions.join(' and ')}`;
    const orderClause = `order by ${ContractLog.CONSENSUS_TIMESTAMP}, ${ContractLog.INDEX}`;

    const query = [ContractService.contractLogsWithEvmAddressQuery, whereClause, orderClause].join('\n');
    const rows = await super.getRows(query, params);
    return rows.map((row) => new ContractLog(row));
  }
```
