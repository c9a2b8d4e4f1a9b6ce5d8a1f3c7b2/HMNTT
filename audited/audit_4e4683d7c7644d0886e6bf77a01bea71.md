### Title
Unauthenticated Concurrent Requests Trigger 3-Subquery UNION Amplification in `getContractLogsQuery()`, Exhausting DB Connection Pool

### Summary
The `getContractLogsQuery()` function in `rest/service/contractService.js` generates a three-subquery UNION SQL statement when a caller supplies both a lower-bound index filter and a timestamp range (lower + upper). Any unauthenticated user can craft such a request. Because the Node.js REST API has no application-level rate limiting, N concurrent such requests cause 3N subqueries to execute against the database, which—combined with a default pool of only 10 connections and a 20-second statement timeout—can saturate the pool and degrade service for all users.

### Finding Description
**Code location:** `rest/service/contractService.js`, lines 323–368 (`getContractLogsQuery`).

```js
const subQueries = [lower, inner, upper]
  .filter((filters) => filters.length !== 0)
  .map((filters) =>
    super.buildSelectQuery(...)
  );
// ...
} else {
  sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion\n'), orderClauseNoAlias, limitClause].join('\n');
}
```

When `lower`, `inner`, and `upper` are all non-empty, three independent full-table-scan subqueries against `contract_log` are issued as a UNION. This is triggered by the documented, publicly accessible filter combination:

```
GET /api/v1/contracts/{id}/results/logs?index=gte:1&timestamp=gte:T1&timestamp=lte:T2
```

This populates all three filter arrays via `extractContractLogsMultiUnionQuery` (controller lines 693–698), which calls `getContractLogsLowerFilters`, `getInnerFilters`, and `getUpperFilters`.

**Root cause / failed assumption:** The design assumes that the 3x query amplification is acceptable because it is bounded. However, no rate limiting exists in the REST layer (`grep` for `rateLimit|throttle` in `rest/**/*.js` returns zero matches). The only throttling found (`ThrottleConfiguration.java`, `ThrottleManagerImpl.java`) belongs to the separate `web3` Java service, not the Node.js REST API. The DB pool defaults to 10 connections (`hiero.mirror.rest.db.pool.maxConnections: 10`, docs/configuration.md line 556) with a 20-second statement timeout (`statementTimeout: 20000`, docs/configuration.md line 557).

### Impact Explanation
With 10 pool connections and a 20-second timeout, an attacker sending ≥4 concurrent three-subquery requests occupies all 10 connections (4 requests × 3 subqueries each = 12 concurrent DB operations, exceeding the pool). All other REST API users receive connection-timeout errors or queued delays for the full 20-second window. The attacker can sustain this indefinitely by re-issuing requests as prior ones complete. The impact is service degradation (griefing) for all users of the mirror node REST API, with no economic cost to the attacker.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and zero knowledge beyond the public OpenAPI spec (which documents the `index=gte:X&timestamp=gte:T1&timestamp=lte:T2` filter combination). It is trivially scriptable with `curl` or any HTTP client. The attacker needs only a network connection to the public endpoint. The attack is repeatable and persistent.

### Recommendation
1. **Add application-level rate limiting** to the Node.js REST API (e.g., `express-rate-limit` per IP) specifically for the contract logs endpoints.
2. **Increase the DB connection pool** size or add a per-IP in-flight request cap at the ingress/middleware layer (the Traefik `inFlightReq` middleware already used for the Rosetta service should be applied to the REST service as well).
3. **Add a query-level cost guard**: if all three of `lower`, `inner`, `upper` are non-empty, enforce a tighter `limit` cap or require authentication.
4. **Set a shorter `statement_timeout`** for the `mirror_rest` DB user to reduce the window each connection is held.

### Proof of Concept
```bash
# Trigger the 3-subquery UNION path (lower + inner + upper all populated)
ENDPOINT="https://<mirror-node>/api/v1/contracts/0.0.1000/results/logs"
PARAMS="?index=gte:0&timestamp=gte:1639010141.000000000&timestamp=lte:1639010161.000000000&limit=100"

# Send 5 concurrent requests (each causes 3 DB subqueries = 15 total, exceeding default pool of 10)
for i in $(seq 1 5); do
  curl -s "$ENDPOINT$PARAMS" &
done
wait
# Legitimate requests from other users will now queue or timeout during the 20s window.
# Repeat in a loop to sustain the exhaustion.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/service/contractService.js (L335-364)
```javascript
    const subQueries = [lower, inner, upper]
      .filter((filters) => filters.length !== 0)
      .map((filters) =>
        super.buildSelectQuery(
          ContractService.contractLogsExtendedQuery,
          params,
          conditions,
          orderClause,
          limitClause,
          filters.map((filter) => ({
            ...filter,
            column: ContractLog.getFullName(ContractService.contractLogsPaginationColumns[filter.key]),
          }))
        )
      );

    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = super.buildSelectQuery(
        ContractService.contractLogsExtendedQuery,
        params,
        conditions,
        orderClause,
        limitClause
      );
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion\n'), orderClauseNoAlias, limitClause].join('\n');
```

**File:** rest/controllers/contractController.js (L693-698)
```javascript
    return {
      ...query,
      lower: this.getContractLogsLowerFilters(bounds),
      inner: this.getInnerFilters(bounds),
      upper: this.getUpperFilters(bounds),
    };
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
