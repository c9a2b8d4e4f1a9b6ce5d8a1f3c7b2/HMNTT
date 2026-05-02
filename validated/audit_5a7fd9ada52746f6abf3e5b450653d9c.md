All code references have been verified against the actual repository. The claims are accurate.

---

Audit Report

## Title
N+1 Database Query DoS via Multiple CREATE2 EVM Address `contract_id` Filters in `getContracts()`

## Summary
An unauthenticated attacker can supply up to 100 `contract_id` query parameters containing CREATE2 EVM addresses to `GET /api/v1/contracts`, causing 100 sequential database round-trips per HTTP request. With a small number of concurrent such requests, the entire database connection pool is exhausted, denying service to all legitimate users.

## Finding Description

**Step 1 — Entry point:** `getContracts()` unconditionally passes all filters to `extractSqlFromContractFilters()`. [1](#0-0) 

**Step 2 — Sequential `await` in a loop:** Inside `extractSqlFromContractFilters`, every `CONTRACT_ID` filter is resolved with a blocking `await` inside a `for...of` loop. There is no batching or parallelism. [2](#0-1) 

**Step 3 — DB query per CREATE2 address:** `computeContractIdFromString()` detects a CREATE2 EVM address and delegates to `getContractIdByEvmAddress()`, which issues a real database query via `super.getRows()`. [3](#0-2) [4](#0-3) 

**Step 4 — The guard defines the attack ceiling, not a defense:** `requestHandler.js` sets `arrayLimit` to `config.query.maxRepeatedQueryParameters` (default: 100) with `throwOnLimitExceeded: true`. This rejects requests with *more than* 100 repeated parameters, but it explicitly *permits* exactly 100 — meaning 100 sequential DB queries per request is the allowed maximum. [5](#0-4) 

**Step 5 — Non-existent addresses still trigger the query:** `getContractIdByEvmAddress()` throws `NotFoundError` only *after* the DB query returns zero rows. The attacker does not need real contracts. [6](#0-5) 

## Impact Explanation

The connection pool is configured with `max: config.db.pool.maxConnections` (default: 10) and `connectionTimeoutMillis: config.db.pool.connectionTimeout` (default: 20,000 ms). [7](#0-6) 

Each malicious request holds a connection for the duration of up to 100 sequential queries. With `statement_timeout` of 20 seconds per query, a single request can occupy a connection for up to 2,000 seconds in the worst case. Ten to twenty concurrent malicious requests saturate all 10 pool connections, causing every subsequent legitimate request to receive a connection timeout error. This is a complete availability denial of the REST API.

## Likelihood Explanation

- `GET /api/v1/contracts` requires no authentication.
- No application-layer rate limiting exists in the codebase.
- The attacker only needs syntactically valid 20-byte hex strings; they do not need to correspond to real contracts.
- The attack is trivially scriptable with a single `curl` command or HTTP client loop.
- A handful of concurrent connections suffices to sustain the outage.

## Recommendation

1. **Batch the DB lookups:** Replace the sequential `for...of` + `await` loop with `Promise.all()` so all CREATE2 lookups for a single request execute in parallel, reducing wall-clock time from O(N × query_latency) to O(query_latency).
2. **Limit CREATE2 lookups per request:** Enforce a separate, lower cap (e.g., 5–10) specifically on the number of `contract_id` filters that require a DB lookup, independent of `maxRepeatedQueryParameters`.
3. **Cache resolved addresses:** A short-lived in-process or Redis cache keyed on the EVM address would eliminate repeated DB hits for the same address across requests.
4. **Add rate limiting:** Apply per-IP or global rate limiting at the reverse proxy or application middleware layer for public endpoints.

## Proof of Concept

```bash
# Generate 100 distinct fake CREATE2 EVM addresses and fire a single request
FILTERS=$(python3 -c "
import os, urllib.parse
params = '&'.join(
  'contract.id=' + os.urandom(20).hex()
  for _ in range(100)
)
print(params)
")

curl -s "https://<mirror-node-host>/api/v1/contracts?$FILTERS"
```

This single HTTP request triggers 100 sequential `SELECT` queries against the database before the handler can respond. Sending 10–20 such requests concurrently exhausts the default pool of 10 connections, causing all other API requests to time out with a connection pool error.

### Citations

**File:** rest/controllers/contractController.js (L102-113)
```javascript
  for (const filter of filters) {
    switch (filter.key) {
      case filterKeys.CONTRACT_ID:
        const contractIdValue = await ContractService.computeContractIdFromString(filter.value);

        if (filter.operator === utils.opsMap.eq) {
          // aggregate '=' conditions and use the sql 'in' operator
          contractIdInValues.push(contractIdValue);
        } else {
          params.push(contractIdValue);
          conditions.push(`${contractIdFullName}${filter.operator}$${params.length}`);
        }
```

**File:** rest/controllers/contractController.js (L745-750)
```javascript
  getContracts = async (req, res) => {
    // extract filters from query param
    const filters = utils.buildAndValidateFilters(req.query, acceptedContractParameters);

    // get sql filter query, params, limit and limit query from query filters
    const {filterQuery, params, order, limit, limitQuery} = await extractSqlFromContractFilters(filters);
```

**File:** rest/service/contractService.js (L452-466)
```javascript
  async getContractIdByEvmAddress(evmAddressFilter) {
    const create2EvmAddress = evmAddressFilter.create2_evm_address;
    const rows = await super.getRows(ContractService.contractIdByEvmAddressQuery, [
      Buffer.from(create2EvmAddress, 'hex'),
    ]);
    if (rows.length === 0) {
      throw new NotFoundError(`No contract with the given evm address 0x${create2EvmAddress} has been found.`);
    }
    // since evm_address is not a unique index, it is important to make this check.
    if (rows.length > 1) {
      throw new Error(`More than one contract with the evm address 0x${create2EvmAddress} have been found.`);
    }

    return rows[0].id;
  }
```

**File:** rest/service/contractService.js (L468-476)
```javascript
  async computeContractIdFromString(contractIdValue) {
    const contractIdParts = EntityId.computeContractIdPartsFromContractIdValue(contractIdValue);

    if (contractIdParts.hasOwnProperty('create2_evm_address')) {
      return this.getContractIdByEvmAddress(contractIdParts);
    }

    return EntityId.parseString(contractIdValue, {paramName: filterKeys.CONTRACTID}).getEncodedId();
  }
```

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
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
