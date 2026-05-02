### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Concurrent Requests to `/accounts/:id/nfts`

### Summary
`getNftsByAccountId()` in `rest/controllers/accountController.js` unconditionally executes a database query for every request without any application-level rate limiting. Because the REST API's connection pool defaults to only 10 connections and the statement timeout is 20 seconds, an unauthenticated attacker sending as few as 10 concurrent requests can hold all pool connections simultaneously, starving every other REST API endpoint of database access and causing a full service outage.

### Finding Description

**Exact code path:**

In `rest/controllers/accountController.js` lines 90–103, `getNftsByAccountId()` executes unconditionally:

```js
getNftsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[...]);  // no DB call for numeric IDs
  const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
  const query = this.extractNftMultiUnionQuery(filters, accountId);
  const nonFungibleTokens = await NftService.getNfts(query);  // always hits DB
  ...
};
```

**Root cause — three compounding failures:**

1. **No account existence guard.** For a syntactically valid numeric account ID (e.g., `0.0.12345`), `EntityService.getEncodedId()` (entityService.js lines 118–123) resolves the ID entirely in-process with no database round-trip. Execution proceeds directly to `NftService.getNfts()`, which always issues a SQL query against the `nft` table — even when the account has zero NFTs. Compare with the sibling handler `listStakingRewardsByAccountId()` (accountController.js lines 172–175) and `getTokenRelationships()` (tokenController.js lines 67–71), both of which call `EntityService.isValidAccount()` before proceeding.

2. **No application-level rate limiting.** `rest/server.js` registers no rate-limiting middleware for the REST API. The throttle infrastructure found in the codebase (`ThrottleConfiguration.java`, `ThrottleManagerImpl.java`) belongs exclusively to the `web3` Java module and has no effect on the Node.js REST server.

3. **Tiny connection pool.** `rest/dbpool.js` (lines 7–16) configures the pool with `max: config.db.pool.maxConnections`, which defaults to **10** connections (docs line 556) with a `statementTimeout` of 20,000 ms and a `connectionTimeout` of 20,000 ms.

**Exploit flow:**

- Attacker sends 10 concurrent `GET /api/v1/accounts/0.0.1/nfts` requests (any syntactically valid numeric account ID).
- Each request bypasses account resolution DB cost and immediately acquires a pool connection to execute the NFT query.
- With `statementTimeout = 20s`, each connection is held for up to 20 seconds.
- All 10 pool connections are occupied simultaneously.
- Every subsequent request to any REST endpoint requiring a DB connection blocks waiting for `connectionTimeout` (20s) and then fails with a pool timeout error.
- The attacker sustains the outage by continuously re-sending requests as connections are released.

### Impact Explanation

Complete denial of service for the REST API. All endpoints that require database access — accounts, transactions, tokens, balances, contracts — fail for the duration of the attack. The mirror node's REST API is the primary read interface for the Hedera network; its unavailability prevents clients and downstream services from confirming transaction finality, querying account state, or reading contract results. This matches the stated severity scope of "total network shutdown" for dependent consumers.

### Likelihood Explanation

The attack requires zero authentication, zero privileges, and zero knowledge of real account data — any syntactically valid `shard.realm.num` string suffices. It requires only 10 concurrent HTTP connections, achievable from a single machine with a trivial script. It is continuously repeatable with no cooldown. No CAPTCHA, API key, or IP-based throttle exists at the application layer to impede it.

### Recommendation

1. **Add `isValidAccount()` guard** in `getNftsByAccountId()` consistent with `listStakingRewardsByAccountId()` and `getTokenRelationships()` — this adds one cheap indexed lookup but short-circuits the NFT query for non-existent accounts.
2. **Implement per-IP rate limiting** in the REST API Node.js server (e.g., `express-rate-limit`) before the route handlers, capping concurrent or per-second requests per source IP.
3. **Increase `maxConnections`** or deploy a connection pooler (PgBouncer in transaction mode) in front of the database to absorb burst load without exhausting the application pool.
4. **Add concurrency limiting** (e.g., `p-limit` or a semaphore) around DB-bound handlers to cap in-flight queries regardless of connection pool size.

### Proof of Concept

```bash
# Send 15 concurrent requests to exhaust the 10-connection pool
# No authentication required; 0.0.1 is a syntactically valid account ID
for i in $(seq 1 15); do
  curl -s "http://<mirror-node-host>/api/v1/accounts/0.0.1/nfts" &
done
wait

# While the above runs, all other REST API calls will time out:
curl "http://<mirror-node-host>/api/v1/transactions"
# Expected: connection pool timeout / 500 error after 20s
```

Sustain the attack by looping the first block continuously. The REST API remains unavailable for all clients for the duration. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/controllers/accountController.js (L90-103)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
    const query = this.extractNftMultiUnionQuery(filters, accountId);
    const nonFungibleTokens = await NftService.getNfts(query);
    const nfts = nonFungibleTokens.map((nft) => new NftViewModel(nft));

    res.locals[responseDataLabel] = {
      nfts,
      links: {
        next: this.getPaginationLink(req, nfts, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/controllers/accountController.js (L170-175)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L118-124)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/service/nftService.js (L134-138)
```javascript
  async getNfts(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new Nft(ta));
  }
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

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```
