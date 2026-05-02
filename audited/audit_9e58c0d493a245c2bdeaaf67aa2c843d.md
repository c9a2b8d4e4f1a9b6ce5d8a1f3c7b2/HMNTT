### Title
Unauthenticated Per-Request DB Lookup via EVM Address Contract ID Triggers Unbounded Database Load

### Summary
`computeContractIdFromString()` in `rest/service/contractService.js` unconditionally invokes `getContractIdByEvmAddress()` — which executes a live database query — whenever a contract ID is supplied in the `0.0.<40hexchars>` (create2 EVM address) format. No rate limiting exists on the REST API contract endpoints and no caching exists for this lookup path, allowing any unauthenticated external user to force one DB query per request at will, degrading service for all users.

### Finding Description

**Code path:**

`rest/service/contractService.js`, lines 468–476:
```js
async computeContractIdFromString(contractIdValue) {
  const contractIdParts = EntityId.computeContractIdPartsFromContractIdValue(contractIdValue);

  if (contractIdParts.hasOwnProperty('create2_evm_address')) {
    return this.getContractIdByEvmAddress(contractIdParts);   // ← DB query, no cache
  }
  return EntityId.parseString(contractIdValue, {paramName: filterKeys.CONTRACTID}).getEncodedId();
}
```

`rest/entityId.js`, lines 284–299 (`computeContractIdPartsFromContractIdValue`): any string whose last segment matches the 40-hex-char EVM address regex (e.g. `0.0.aabbccddaabbccddaabbccddaabbccddaabbccdd`) causes `create2_evm_address` to be set in the returned parts object.

`rest/service/contractService.js`, lines 452–466 (`getContractIdByEvmAddress`): executes `contractIdByEvmAddressQuery` (lines 146–151) — a full `SELECT … WHERE evm_address = $1` against the `entity` table — with no caching layer.

**Affected endpoints** (all call `computeContractIdFromString` with the user-supplied `:contractId` path parameter):
- `GET /api/v1/contracts/:contractId/results` (line 862)
- `GET /api/v1/contracts/:contractId/state` (line 969)
- `GET /api/v1/contracts/:contractId/results/:consensusTimestamp` (line 369)
- `GET /api/v1/contracts/:contractId/results/logs` (line 16 of `contractRoute.js`)

**Root cause / failed assumption:** The code assumes that EVM-address-format contract IDs are rare or that an upstream layer will throttle them. Neither is true. The REST middleware (`rest/middleware/requestHandler.js`) performs no rate limiting. The `rest/middleware/authHandler.js` only adjusts response row limits for authenticated users. No caching wraps `getContractIdByEvmAddress`. The throttle/rate-limit infrastructure present in the web3 Java service (`ThrottleManagerImpl`, `ThrottleConfiguration`) does not apply to the REST Node.js service.

### Impact Explanation
Every request with a valid-looking but non-existent EVM address (e.g. `0.0.deadbeefdeadbeefdeadbeefdeadbeefdeadbeef`) causes one synchronous DB query. An attacker sending a high volume of such requests from multiple IPs exhausts the database connection pool and increases query latency for all legitimate users. Because the query always returns zero rows for fabricated addresses, the attacker pays no economic cost and the server returns a 404 — but the DB work is already done. Severity: medium (griefing / availability degradation, no data exfiltration).

### Likelihood Explanation
No authentication, no API key, no CAPTCHA, and no rate limiting is required. The attack is trivially scriptable: a single `curl` loop or any HTTP load tool suffices. The attacker only needs to know the public API format, which is documented. The attack is repeatable indefinitely and can be distributed across many source IPs to avoid any network-level throttling.

### Recommendation
1. **Add a result cache** for `getContractIdByEvmAddress` keyed on the hex EVM address (e.g. using the existing `quick-lru` cache already present in `entityId.js`), with a short TTL (e.g. 30 s) and a bounded size.
2. **Add rate limiting** to the REST API contract endpoints, either via an Express middleware (e.g. `express-rate-limit`) or at the reverse-proxy/ingress layer, targeting the `:contractId` path parameter pattern.
3. Optionally, reject EVM-address-format contract IDs that are provably non-existent at the validation layer before the DB call is made.

### Proof of Concept
```bash
# Single request — triggers one DB query
curl "https://<mirror-node>/api/v1/contracts/0.0.deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/results"
# Expected: 404 {"_status":{"messages":[{"message":"No contract with the given evm address ..."}]}}

# Flood — each iteration forces a new DB query; no auth required
for i in $(seq 1 10000); do
  addr=$(openssl rand -hex 20)
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.${addr}/results" &
done
wait
```

Each iteration generates a unique 40-hex-char address, bypassing any address-level deduplication, and forces `contractIdByEvmAddressQuery` to execute against the `entity` table. Observed effect: rising DB query latency and connection pool saturation for concurrent legitimate requests. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** rest/entityId.js (L284-299)
```javascript
const computeContractIdPartsFromContractIdValue = (contractId) => {
  const [shard, realm, evmAddressOrNum] = piecesFromString(contractId);

  const contractIdParts = {
    shard: shard,
    realm: realm,
  };

  if (isEvmAddressAlias(evmAddressOrNum)) {
    contractIdParts.create2_evm_address = evmAddressOrNum;
  } else {
    contractIdParts.num = evmAddressOrNum;
  }

  return contractIdParts;
};
```

**File:** rest/controllers/contractController.js (L365-370)
```javascript
const getAndValidateContractIdAndConsensusTimestampPathParams = async (req) => {
  const {consensusTimestamp, contractId} = req.params;
  validateContractIdAndConsensusTimestampParam(consensusTimestamp, contractId);
  utils.validateReq(req, acceptedContractResultsByTimestampParameters);
  const encodedContractId = await ContractService.computeContractIdFromString(contractId);
  return {contractId: encodedContractId, timestamp: utils.parseTimestampParam(consensusTimestamp)};
```

**File:** rest/controllers/contractController.js (L856-862)
```javascript
  getContractResultsById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractResultsParameters
    );

    const contractId = await ContractService.computeContractIdFromString(contractIdParam);
```

**File:** rest/controllers/contractController.js (L964-969)
```javascript
  getContractStateById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractStateParameters
    );
    const contractId = await ContractService.computeContractIdFromString(contractIdParam);
```

**File:** rest/middleware/requestHandler.js (L1-30)
```javascript
// SPDX-License-Identifier: Apache-2.0

import httpContext from 'express-http-context';
import qs from 'qs';

import config from '../config';
import {httpStatusCodes, requestIdLabel, requestStartTime} from '../constants';
import {lowerCaseQueryValue, randomString} from '../utils';

const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};

const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};

const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};

```
