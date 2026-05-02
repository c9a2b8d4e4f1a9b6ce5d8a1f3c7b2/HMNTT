### Title
Unauthenticated DB Query Amplification via `transaction_hash` + Topic Filters in `getContractLogs()`

### Summary
An unprivileged external user can send `GET /contracts/results/logs?transaction.hash=<valid_hash>&topic0=...&topic1=...&topic2=...&topic3=...&timestamp=gte:T1&timestamp=lte:T2`, causing `getContractLogs()` to execute two sequential database queries per request: a stored-procedure call via `getTransactionHash()` and a complex UNION query via `ContractService.getContractLogs()`. Because the REST API layer has no application-level rate limiting, flooding this endpoint with valid hashes degrades database performance for all users.

### Finding Description

**Code path:**

`getContractLogs()` (lines 820–848, `rest/controllers/contractController.js`) calls `checkTimestampsForTopics(filters)` then `this.extractContractLogsMultiUnionQuery(filters)`. [1](#0-0) 

`checkTimestampsForTopics()` (lines 281–306) enforces that a timestamp range is present when any topic filter is supplied. This check passes when the attacker provides a valid timestamp range alongside the topic filters. [2](#0-1) 

Inside `extractContractLogsMultiUnionQuery()` (lines 669–677), when `transactionHash !== undefined`, `getTransactionHash()` is called unconditionally — **DB query 1** (a stored-procedure call `select * from get_transaction_info_by_hash($1)`). [3](#0-2) [4](#0-3) 

If the hash resolves (rows.length > 0), the timestamp bound is replaced with the exact consensus timestamp and `ContractService.getContractLogs(query)` is called — **DB query 2**. This query is built as a UNION of up to three sub-queries (`lower`, `inner`, `upper`), each joining `contract_log` with the `entity` CTE and applying up to four topic conditions. [5](#0-4) [6](#0-5) 

**Root cause:** No application-level rate limiting exists in the REST API (Node.js) layer. The `checkTimestampsForTopics` guard only requires a timestamp to be present — it does not prevent the two-query pattern when `transaction_hash` is combined with topic filters and a valid timestamp range.

**Failed assumption:** The design assumes that requiring a timestamp range with topic filters is sufficient to bound query cost. It does not account for the additional stored-procedure call introduced by `transaction_hash`, nor for the absence of per-IP or per-endpoint rate limiting.

### Impact Explanation

Each flood request causes: (1) a stored-procedure invocation against the transaction hash table, and (2) a UNION of up to three sub-queries against `contract_log` with four topic conditions and an entity CTE join. Sustained flooding exhausts database connection pool capacity and query throughput, degrading or denying service for all legitimate users of the mirror node REST API. No funds are at risk; impact is availability only (griefing).

### Likelihood Explanation

Valid transaction hashes are publicly observable on any Hedera network explorer. The attacker needs no credentials, no special knowledge beyond a valid hash, and no on-chain funds. The attack is trivially scriptable (e.g., `ab`, `wrk`, or a simple loop). The REST API's lack of application-level rate limiting means the only protection is infrastructure-level (load balancer / reverse proxy), which may not be uniformly deployed across all mirror node operators.

### Recommendation

1. **Add per-IP rate limiting** at the application layer for `/contracts/results/logs` (e.g., via `express-rate-limit` or equivalent middleware).
2. **Enforce a maximum concurrency / query timeout** for the stored-procedure call in `getTransactionHash()`.
3. **Consider requiring authentication or an API key** for requests that combine `transaction_hash` with topic filters, as this combination is the most expensive path.
4. **Add a circuit-breaker** that returns 429 when the DB connection pool utilization exceeds a threshold.

### Proof of Concept

**Preconditions:** Obtain any valid Ethereum-format transaction hash from the public Hedera network (e.g., from HashScan).

**Trigger:**
```bash
# Flood with concurrent requests
for i in $(seq 1 500); do
  curl -s "https://<mirror-node>/api/v1/contracts/results/logs?\
transaction.hash=0x<valid_32byte_hash>&\
topic0=0x0000000000000000000000000000000000000000000000000000000000000001&\
topic1=0x0000000000000000000000000000000000000000000000000000000000000002&\
topic2=0x0000000000000000000000000000000000000000000000000000000000000003&\
topic3=0x0000000000000000000000000000000000000000000000000000000000000004&\
timestamp=gte:1700000000.000000000&timestamp=lte:1700604800.000000000" &
done
wait
```

**Result:** Each request triggers `get_transaction_info_by_hash()` (stored procedure) followed by a three-way UNION query on `contract_log` with four topic conditions. Under sustained load, database query latency rises and other API endpoints degrade.

### Citations

**File:** rest/controllers/contractController.js (L281-306)
```javascript
const checkTimestampsForTopics = (filters) => {
  let hasTopic = false;
  const timestampFilters = [];
  for (const filter of filters) {
    switch (filter.key) {
      case filterKeys.TOPIC0:
      case filterKeys.TOPIC1:
      case filterKeys.TOPIC2:
      case filterKeys.TOPIC3:
        hasTopic = true;
        break;
      case filterKeys.TIMESTAMP:
        timestampFilters.push(filter);
        break;
      default:
        break;
    }
  }
  if (hasTopic) {
    try {
      utils.parseTimestampFilters(timestampFilters);
    } catch (e) {
      throw new InvalidArgumentError(`Cannot search topics without a valid timestamp range: ${e.message}`);
    }
  }
};
```

**File:** rest/controllers/contractController.js (L669-677)
```javascript
    if (transactionHash !== undefined) {
      const timestampFilters = bounds.primary.getAllFilters();
      const rows = await getTransactionHash(transactionHash, {order, timestampFilters});
      if (rows.length === 0) {
        return null;
      }

      bounds.primary = new Bound(filterKeys.TIMESTAMP);
      bounds.primary.parse({key: filterKeys.TIMESTAMP, operator: utils.opsMap.eq, value: rows[0].consensus_timestamp});
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

**File:** rest/transactionHash.js (L10-36)
```javascript
const mainQuery = `select * from get_transaction_info_by_hash($1)`;
const orderClause = `order by ${TransactionHash.CONSENSUS_TIMESTAMP}`;

/**
 * Get the transaction hash rows by the hash. Note if the hash is more than 32 bytes, it's queried by the 32-byte prefix
 * then rechecked against the full hash.
 *
 * @param {Buffer} hash
 * @param {{order: string, timestampFilters: Array<{operator: string, value: any}>}} options
 * @returns {Promise<Object[]>}
 */
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
```

**File:** rest/service/contractService.js (L323-368)
```javascript
  getContractLogsQuery({lower, inner, upper, params, conditions, order, limit}) {
    params.push(limit);
    const orderClause = super.getOrderByQuery(
      OrderSpec.from(ContractLog.getFullName(ContractLog.CONSENSUS_TIMESTAMP), order),
      OrderSpec.from(ContractLog.getFullName(ContractLog.INDEX), order)
    );
    const orderClauseNoAlias = super.getOrderByQuery(
      OrderSpec.from(ContractLog.CONSENSUS_TIMESTAMP, order),
      OrderSpec.from(ContractLog.INDEX, order)
    );
    const limitClause = super.getLimitQuery(params.length);

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
    }

    return [sqlQuery, params];
  }
```

**File:** rest/service/contractService.js (L376-393)
```javascript
  async getContractLogs(query) {
    const [sqlQuery, params] = this.getContractLogsQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    if (rows.length === 0) {
      return rows;
    }

    const timestamps = [];
    // The timestamps are ordered, and may have duplicates, dedup them
    rows.forEach((row) => {
      if (row.consensus_timestamp !== timestamps[timestamps.length - 1]) {
        timestamps.push(row.consensus_timestamp);
      }
    });
    const recordFileMap = await RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps);

    return rows.map((cr) => new ContractLog(cr, recordFileMap.get(cr.consensus_timestamp)));
  }
```
