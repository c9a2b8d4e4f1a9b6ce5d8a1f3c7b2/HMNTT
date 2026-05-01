### Title
Unauthenticated DB Existence Check Per Request via Non-Existent Account IDs on `/rewards` and `/tokens` Endpoints

### Summary
Any unprivileged external user can send an unbounded stream of GET requests to `/api/v1/accounts/<non-existent-id>/rewards` or `/api/v1/accounts/<non-existent-id>/tokens` with fabricated numeric account IDs. Each request unconditionally executes a database existence check via `EntityService.isValidAccount()`, and because 404 responses are never cached, every repeated request re-hits the database, enabling sustained DB load griefing with no authentication or economic cost.

### Finding Description

**Code path — `/rewards`:** [1](#0-0) 

**Code path — `/tokens`:** [2](#0-1) 

**The DB query issued on every call:** [3](#0-2) 

**`isValidAccount` implementation:** [4](#0-3) 

For a numeric account ID (e.g., `0.0.999999999`), `EntityService.getEncodedId()` resolves the ID purely in-memory (no DB call), then immediately calls `isValidAccount(accountId)`, which fires `SELECT type FROM entity WHERE id = $1` against the database. If the account does not exist, a `NotFoundError` (HTTP 404) is thrown.

**Why the cache does not help:** [5](#0-4) 

The response cache only stores successful (2xx) responses. A 404 from a non-existent account is never written to cache, so every subsequent request with the same non-existent ID bypasses the cache check and re-executes the DB query.

**Why rate limiting does not help:**
The throttle/rate-limit infrastructure found in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the `web3` module (contract calls). [6](#0-5) 

No rate-limiting middleware is applied to the `AccountRoutes` router or any REST API route.

### Impact Explanation
An attacker can drive an arbitrary number of `SELECT` queries against the `entity` table with zero authentication, zero cost, and no throttle. Each query is a full indexed lookup (`WHERE id = $1`) but the aggregate load from a high-rate flood (thousands of requests per second from a single client or botnet) can saturate DB connection pools, increase query latency for legitimate users, and degrade overall mirror-node availability. The scope is griefing with no direct economic damage to network participants, consistent with the stated severity classification.

### Likelihood Explanation
The attack requires no credentials, no on-chain activity, and no special knowledge beyond the public API documentation. The endpoint accepts any syntactically valid account ID string. A single attacker with a commodity HTTP flood tool (e.g., `wrk`, `ab`, `hey`) can sustain thousands of requests per second. The attack is trivially repeatable and automatable.

### Recommendation
1. **Cache 404 responses** for a short TTL (e.g., 5–10 s) keyed on the request URL, so repeated lookups for the same non-existent ID do not re-hit the database.
2. **Apply rate limiting** to the REST API router, mirroring the bucket4j throttle already present in the `web3` module, or introduce an IP-based rate limiter (e.g., `express-rate-limit`) in `server.js` before the account routes are registered.
3. **Combine the existence check with the primary query**: instead of a separate `isValidAccount` round-trip, fold the account existence condition into the staking-rewards or token-relationships query itself and return an empty result or 404 based on whether the join produces rows, eliminating the extra DB call entirely.

### Proof of Concept
```bash
# Flood /rewards with a non-existent account ID (no auth required)
# Each request triggers SELECT type FROM entity WHERE id = <encoded_id>
# and returns HTTP 404 (never cached)

for i in $(seq 1 10000); do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/accounts/0.0.999999999/rewards" &
done
wait

# Repeat identically for /tokens:
for i in $(seq 1 10000); do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/accounts/0.0.999999999/tokens" &
done
wait

# Observe: DB query count rises linearly with request count;
# no caching or throttle prevents re-execution of the existence check.
```

### Citations

**File:** rest/controllers/accountController.js (L170-175)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L28-30)
```javascript
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/middleware/responseCacheHandler.js (L95-97)
```javascript
  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
```

**File:** rest/server.js (L100-103)
```javascript
// accounts routes
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);
```
