### Title
N+1 Database Query DoS via Multiple CREATE2 EVM Address `contract_id` Filters in `getContracts()`

### Summary
An unprivileged external user can supply an arbitrary number of `contract_id` query parameters containing CREATE2 EVM addresses to the `GET /api/v1/contracts` endpoint. For each such filter, `extractSqlFromContractFilters()` serially awaits a separate database lookup via `computeContractIdFromString()` → `getContractIdByEvmAddress()`, creating a true N+1 query pattern. There is no cap on the number of `contract_id` filters processed, enabling a low-effort database exhaustion attack.

### Finding Description

**Exact code path:**

`getContracts` (line 750) calls `extractSqlFromContractFilters(filters)`: [1](#0-0) 

Inside `extractSqlFromContractFilters`, every filter is iterated in a `for` loop. For each `CONTRACT_ID` filter, `computeContractIdFromString` is `await`-ed individually: [2](#0-1) 

`computeContractIdFromString` detects a CREATE2 EVM address and issues a live database query: [3](#0-2) 

`getContractIdByEvmAddress` executes `contractIdByEvmAddressQuery` — a real `SELECT` against the `entity` table — once per filter value: [4](#0-3) 

The query itself: [5](#0-4) 

**Root cause:** The loop in `extractSqlFromContractFilters` serially `await`s a DB round-trip for every CREATE2 EVM address filter value. There is no batching, no deduplication, and no upper bound on the number of `contract_id` parameters accepted before the DB lookups begin.

**Why existing checks fail:** `buildAndValidateFilters` (line 747) validates format and operator legality but does not cap the count of repeated `contract_id` parameters. A syntactically valid 40-hex-character EVM address passes all validation and proceeds directly to the DB lookup loop.

### Impact Explanation
Each request with N CREATE2 EVM address filters consumes N database connections/queries before the main contracts query runs. An attacker sending concurrent requests each carrying hundreds of `contract_id=0x<random_evm_addr>` parameters can saturate the database connection pool, starve legitimate queries, and cause service-wide degradation or outage of the mirror node REST API. Because each lookup hits a non-unique index on `evm_address`, the queries are not trivially fast under load.

### Likelihood Explanation
No authentication or API key is required. The endpoint is public. The attack requires only an HTTP client capable of sending GET requests with many repeated query parameters — trivially scriptable. The attacker does not need valid contract addresses; random 20-byte hex strings are syntactically valid and each still triggers a full DB query (returning 0 rows after a full index scan). The attack is repeatable and parallelizable.

### Recommendation
1. **Cap repeated `contract_id` filters** before entering the resolution loop — reject requests with more than a small fixed number (e.g., 20) of `contract_id` parameters.
2. **Batch the EVM address lookups** into a single `WHERE evm_address = ANY($1)` query instead of one query per filter value, eliminating the N+1 pattern entirely.
3. **Deduplicate** filter values before lookup so repeated identical addresses do not multiply DB queries.

### Proof of Concept

```bash
# Send a single request with 200 distinct random CREATE2 EVM addresses as contract_id filters
python3 - <<'EOF'
import requests, secrets

base = "https://<mirror-node-host>/api/v1/contracts"
params = [("contract.id", "0x" + secrets.token_hex(20)) for _ in range(200)]
r = requests.get(base, params=params)
print(r.status_code, r.elapsed)
EOF
```

**What happens:**
1. `buildAndValidateFilters` accepts all 200 parameters (valid hex EVM addresses).
2. `extractSqlFromContractFilters` loops 200 times, each iteration `await`-ing `computeContractIdFromString`.
3. Each call reaches `getContractIdByEvmAddress` and executes `SELECT id FROM entity WHERE deleted <> true AND type = 'CONTRACT' AND evm_address = $1` — 200 sequential DB queries per HTTP request.
4. Sending this request concurrently from multiple clients exhausts the DB connection pool and degrades or denies service to all users.

### Citations

**File:** rest/controllers/contractController.js (L102-114)
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
        break;
```

**File:** rest/controllers/contractController.js (L745-751)
```javascript
  getContracts = async (req, res) => {
    // extract filters from query param
    const filters = utils.buildAndValidateFilters(req.query, acceptedContractParameters);

    // get sql filter query, params, limit and limit query from query filters
    const {filterQuery, params, order, limit, limitQuery} = await extractSqlFromContractFilters(filters);
    const query = getContractsQuery(filterQuery, limitQuery, order);
```

**File:** rest/service/contractService.js (L146-151)
```javascript
  static contractIdByEvmAddressQuery = `
    select ${Entity.ID}
    from ${Entity.tableName} ${Entity.tableAlias}
    where ${Entity.DELETED} <> true and
      ${Entity.TYPE} = 'CONTRACT' and
      ${Entity.EVM_ADDRESS} = $1`;
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
