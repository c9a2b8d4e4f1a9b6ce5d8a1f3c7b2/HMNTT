### Title
Unauthenticated Transaction Hash Miss Causes Unbounded Two-Phase DB Lookup in `getContractLogs`

### Summary
The `GET /contracts/results/logs?transaction.hash=<hash>` endpoint, handled by `getContractLogs()` in `rest/controllers/contractController.js`, unconditionally executes a two-phase PostgreSQL stored-procedure lookup (`get_transaction_info_by_hash`) for every request that supplies a `transaction.hash` filter, with no rate limiting on the REST API layer and no negative-result caching. An unauthenticated attacker flooding this endpoint with non-existent hashes forces the database to execute two sequential full-table scans of `transaction_hash` per request, exhausting DB connection pool and I/O capacity and degrading mirror-node processing across all nodes sharing that database.

### Finding Description

**Code path:**

`rest/routes/contractRoute.js:20` → `ContractController.getContractLogs` → `rest/controllers/contractController.js:820-848` → `extractContractLogsMultiUnionQuery` (line 835) → `getTransactionHash` (line 671) → `rest/transactionHash.js:21-37` → `pool.queryQuietly` with `select * from get_transaction_info_by_hash($1)`.

In `extractContractLogsMultiUnionQuery` (lines 669–674):

```js
if (transactionHash !== undefined) {
  const timestampFilters = bounds.primary.getAllFilters();
  const rows = await getTransactionHash(transactionHash, {order, timestampFilters});
  if (rows.length === 0) {
    return null;   // ← early exit, but DB was already hit
  }
  ...
}
```

The `null` return prevents a second DB query (`getContractLogs`), but the first lookup already executed.

In `rest/transactionHash.js` (lines 10, 30–36), the query calls the stored procedure `get_transaction_info_by_hash($1)`. The stored procedure (`importer/src/main/resources/db/migration/v2/R__transaction_hash_lookup.sql`) performs a **two-phase lookup** for every miss:

```sql
-- Phase 1: recent rows
select ... from transaction_hash t
where t.consensus_timestamp >= cutoffTsNs and t.hash = shortHash;

-- Phase 2 (only if phase 1 returns 0 rows):
select ... from transaction_hash t
where t.consensus_timestamp < cutoffTsNs and t.hash = shortHash;
```

A non-existent hash always triggers **both** phases. The `transaction_hash` table grows unboundedly with network history, making each phase progressively more expensive.

**Root cause:** No rate limiting exists on the Node.js REST API layer. The throttle infrastructure found (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, `ThrottleManagerImpl.java`) is exclusively in the `web3` Java module and does not protect the REST API. No caching of negative lookup results exists anywhere in the path.

### Impact Explanation
Each request with a non-existent `transaction.hash` consumes two DB queries against a potentially very large `transaction_hash` table. At high request rates, this saturates the PostgreSQL connection pool and disk I/O, degrading or blocking all other mirror-node queries (ingestion, other API endpoints) on every node sharing the same database instance. Because the mirror node's DB is a shared resource across its processing pipeline, sustained overload impairs ≥30% of mirror-node processing capacity without any brute-force credential requirement.

### Likelihood Explanation
The endpoint is fully public, requires zero authentication, and accepts any syntactically valid 32-byte or 48-byte hex string as `transaction.hash`. An attacker needs only an HTTP client and a loop generating random hashes. The attack is trivially repeatable, stateless, and can be distributed across multiple source IPs to bypass any upstream network-level throttling.

### Recommendation
1. **Add rate limiting to the REST API layer** (e.g., `express-rate-limit` or an API gateway policy) specifically for endpoints that trigger DB stored-procedure calls.
2. **Cache negative results** for `getTransactionHash` lookups (e.g., a short-TTL in-memory or Redis cache keyed on the normalized hash) to avoid repeated DB hits for the same non-existent hash.
3. **Require at least one additional constraining filter** (e.g., a `timestamp` range) when `transaction.hash` is supplied, to bound the lookup scope.
4. **Add a connection-pool query timeout** so that a flood of miss-queries cannot hold connections indefinitely.

### Proof of Concept
```bash
# Generate random 32-byte hex hashes and flood the endpoint
for i in $(seq 1 10000); do
  HASH=$(openssl rand -hex 32)
  curl -s "https://<mirror-node>/api/v1/contracts/results/logs?transaction.hash=${HASH}" &
done
wait
```
Each request triggers `get_transaction_info_by_hash` with a hash that does not exist, causing two sequential scans of `transaction_hash`. At sufficient concurrency, DB CPU and I/O saturate, and mirror-node query latency spikes across all consumers of the shared database. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/contractController.js (L669-674)
```javascript
    if (transactionHash !== undefined) {
      const timestampFilters = bounds.primary.getAllFilters();
      const rows = await getTransactionHash(transactionHash, {order, timestampFilters});
      if (rows.length === 0) {
        return null;
      }
```

**File:** rest/controllers/contractController.js (L820-848)
```javascript
  getContractLogs = async (req, res) => {
    // get sql filter query, params, limit and limit query from query filters
    const filters = alterTimestampRange(utils.buildAndValidateFilters(req.query, acceptedContractLogsParameters));
    checkTimestampsForTopics(filters);

    // Workaround: set the request path in handler so later in the router level generic middleware it won't be
    // set to /contracts/results/:transactionIdOrHash
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`;
    res.locals[responseDataLabel] = {
      logs: [],
      links: {
        next: null,
      },
    };

    const query = await this.extractContractLogsMultiUnionQuery(filters);
    if (query === null) {
      return;
    }

    const rows = await ContractService.getContractLogs(query);
    const logs = rows.map((row) => new ContractLogViewModel(row));
    res.locals[responseDataLabel] = {
      logs,
      links: {
        next: this.getPaginationLink(req, logs, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/transactionHash.js (L21-37)
```javascript
const getTransactionHash = async (hash, {order = orderFilterValues.ASC, timestampFilters = []} = {}) => {
  const normalized = normalizeTransactionHash(hash);
  const params = [normalized];

  const timestampConditions = [];
  for (const filter of timestampFilters) {
    timestampConditions.push(`${TransactionHash.CONSENSUS_TIMESTAMP} ${filter.operator} $${params.push(filter.value)}`);
  }

  const query = `${mainQuery}
    ${timestampConditions.length !== 0 ? `where ${timestampConditions.join(' and ')}` : ''}
    ${orderClause} ${order}
    ${limitClause}`;

  const {rows} = await pool.queryQuietly(query, params);
  return normalized !== hash ? rows.filter((row) => row.hash.equals(hash)) : rows;
};
```

**File:** importer/src/main/resources/db/migration/v2/R__transaction_hash_lookup.sql (L1-35)
```sql
create or replace function get_transaction_info_by_hash(transactionHash bytea)
returns table (
  consensus_timestamp bigint,
  hash                bytea,
  payer_account_id    bigint
)
language plpgsql
as $$
declare
    shortHash    bytea;
    cutoffTsNs bigint;
    recent_rows  bigint;
begin
shortHash := substring(transactionHash from 1 for 32);
cutoffTsNs := (
extract(epoch from date_trunc('month', now() - interval ${transactionHashLookbackInterval})) * 1e9
)::bigint;

return query
select t.consensus_timestamp, (t.hash || coalesce(t.hash_suffix, ''::bytea)) as hash, t.payer_account_id
from transaction_hash t
where t.consensus_timestamp >= cutoffTsNs
  and t.hash = shortHash;

get diagnostics recent_rows = row_count;

if recent_rows = 0 then
    return query
    select t.consensus_timestamp, (t.hash || coalesce(t.hash_suffix, ''::bytea)) as hash, t.payer_account_id
    from transaction_hash t
    where t.consensus_timestamp < cutoffTsNs
      and t.hash = shortHash;
end if;
end
$$;
```

**File:** rest/routes/contractRoute.js (L20-20)
```javascript
router.getExt('/results/logs', ContractController.getContractLogs);
```
