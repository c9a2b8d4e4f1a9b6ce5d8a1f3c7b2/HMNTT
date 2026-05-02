### Title
Unauthenticated EVM Address Lookup DoS via Uncached, Unthrottled DB Queries in `getAccountCryptoAllowances`

### Summary
The `getAccountCryptoAllowances` handler in `rest/controllers/cryptoAllowanceController.js` accepts an EVM address as a path parameter and unconditionally issues a raw database query via `EntityService.getEntityIdFromEvmAddress()` with no caching and no rate limiting on the REST layer. An unprivileged attacker can flood the endpoint with many distinct, syntactically valid but non-existent EVM addresses, causing a unique DB query per request, saturating database I/O, and degrading or denying service to all mirror node consumers including transaction confirmation lookups.

### Finding Description

**Entry point** — `rest/controllers/cryptoAllowanceController.js` line 77: [1](#0-0) 

`getEncodedId` is called with the raw path parameter. Inside `EntityService.getEncodedId` (`rest/service/entityService.js` lines 118–137): [2](#0-1) 

When the input matches `isValidEntityId` and `EntityId.parseString` produces a non-null `evmAddress` field (i.e., the address is not a long-form `0x000…<num>` alias), execution falls into `getEntityIdFromEvmAddress`: [3](#0-2) 

The query executed is: [4](#0-3) 

**No caching exists** around this query. `entityService.js` has no LRU or Redis wrapper on `getEntityIdFromEvmAddress`. The `quick-lru` import in `entityId.js` covers only EntityId string parsing, not DB results. [5](#0-4) 

**No rate limiting exists** in the REST Node.js service. A grep across `rest/**/*.js` for `rateLimit`, `throttle`, `helmet`, `express-rate`, or `slowDown` returns only a single hit in a test utility file. The throttle infrastructure found in the codebase (`web3/src/main/java/…/ThrottleConfiguration.java`) applies exclusively to the Java `web3` module, not to the Node.js REST service. [6](#0-5) 

**Exploit flow:**
1. Attacker generates thousands of random 40-hex-char strings prefixed with `0x` — all syntactically valid per `evmAddressRegex`.
2. Each is sent as `GET /api/v1/accounts/0x<random>/allowances/crypto`.
3. `isValidEntityId` returns `true`; `parseString` sets `evmAddress` to the hex string (non-null) because the address is not a long-form alias.
4. `getEntityIdFromEvmAddress` fires `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1` against the DB.
5. Zero rows returned → `NotFoundError` thrown → HTTP 404 returned.
6. Because every address is distinct, there is no cache to warm; every request is a fresh sequential DB I/O operation.
7. Under sustained flood, the DB connection pool and I/O bandwidth are exhausted, causing all other queries (including transaction record lookups) to queue or time out.

### Impact Explanation
The mirror node's PostgreSQL instance is shared across all REST endpoints. Saturating it with uncached EVM address lookups degrades or denies service to all consumers: transaction confirmation queries, account balance lookups, and any downstream application relying on the mirror node. The mirror node itself does not process consensus transactions, so the Hedera network's consensus layer is unaffected; however, the mirror node's ability to serve transaction confirmation and state queries — its primary purpose — is directly impaired. Severity is **High** (availability impact on the mirror node service).

### Likelihood Explanation
The attack requires no authentication, no special account, and no prior knowledge of the system state. Any internet-accessible mirror node deployment is reachable. Generating valid random EVM addresses is trivial (any 40-hex-char string). The attack is easily automated with standard HTTP load tools (e.g., `wrk`, `ab`, `k6`). The existing k6 load test for this exact endpoint (`tools/k6/src/rest/test/accountsCryptoAllowance.js`) demonstrates the endpoint is already considered a performance-sensitive path. [7](#0-6) 

### Recommendation
1. **Add a caching layer** in `EntityService.getEntityIdFromEvmAddress` (e.g., a bounded LRU cache keyed on the hex EVM address) so repeated lookups for the same address — including non-existent ones — do not hit the DB. Cache negative results with a short TTL.
2. **Add rate limiting** to the Node.js REST service at the middleware level (e.g., `express-rate-limit`) scoped to endpoints that trigger DB lookups by EVM address or alias.
3. **Validate long-form addresses early**: if the EVM address decodes to a valid long-form `0x000…<num>` alias, resolve it arithmetically without a DB round-trip (as `DomainUtils.fromEvmAddress` does in the Java layer) before falling back to a DB query.

### Proof of Concept
```bash
# Generate 10,000 distinct random EVM addresses and flood the endpoint
for i in $(seq 1 10000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node-host>/api/v1/accounts/0x${ADDR}/allowances/crypto" &
done
wait
```
Each request triggers `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1` with a unique parameter, producing a cache-miss DB query. Under sustained load, DB connection pool exhaustion and I/O saturation will cause legitimate queries to fail with timeouts or connection errors.

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-78)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-104)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
  }
```

**File:** rest/service/entityService.js (L118-127)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
```

**File:** rest/entityId.js (L5-6)
```javascript
import quickLru from 'quick-lru';

```

**File:** rest/routes/accountRoute.js (L17-17)
```javascript
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
```

**File:** tools/k6/src/rest/test/accountsCryptoAllowance.js (L8-21)
```javascript
const urlTag = '/accounts/{id}/allowances/crypto';

const getUrl = (testParameters) =>
  `/accounts/${testParameters['DEFAULT_ACCOUNT_ID_CRYPTO_ALLOWANCE']}/allowances/crypto`;

const {options, run, setup} = new RestTestScenarioBuilder()
  .name('accountCryptoAllowancesResults') // use unique scenario name among all tests
  .tags({url: urlTag})
  .request((testParameters) => {
    const url = `${testParameters['BASE_URL_PREFIX']}${getUrl(testParameters)}`;
    return http.get(url);
  })
  .requiredParameters('DEFAULT_ACCOUNT_ID_CRYPTO_ALLOWANCE')
  .check('Account crypto allowances results OK', (r) => isValidListResponse(r, allowanceListName))
```
